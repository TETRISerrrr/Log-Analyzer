
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
import csv
import re


@dataclass
class LogEvent:
    timestamp: datetime
    ip: str
    username: str
    event_type: str
    message: str


# Apache Access Log (Common / Combined)
APACHE_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"'
    r'\s+(?P<status>\d{3})\s+\S+'
)

# Apache Error Log
APACHE_ERROR_RE = re.compile(
    r'^\[(?P<time>[^\]]+)\]\s+'
    r'\[(?P<module>[^]]+)\]\s+'
    r'(?:\[pid\s+\d+(?::tid\s+\d+)?\]\s+)?'
    r'(?:\[client\s+(?P<ip>[^\]]+)\]\s+)?'
    r'(?P<message>.*)$'
)

# SSH / Linux syslog
SSH_RE = re.compile(
    r'^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+'
    r'\d{2}:\d{2}:\d{2})\s+'
    r'\S+\s+sshd(?:\[\d+\])?:\s*'
    r'(?P<message>.*)$'
)

FAILED_SSH_RE = re.compile(
    r'(?:Failed password|Failed publickey|'
    r'authentication failure|maximum authentication attempts exceeded)',
    re.IGNORECASE
)

INVALID_USER_RE = re.compile(
    r'\bInvalid user\s+(\S+)\s+from\s+(\S+)',
    re.IGNORECASE
)

SSH_USER_IP_RE = re.compile(
    r'(?:Failed password for (?:invalid user )?|'
    r'Accepted (?:password|publickey) for )'
    r'(\S+)\s+from\s+(\S+)',
    re.IGNORECASE
)


def normalize_timestamp(value: datetime) -> datetime:
    """Convert timezone-aware timestamps to naive UTC."""
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def parse_csv_line(line: str) -> LogEvent | None:
    try:
        row = next(csv.reader(StringIO(line)))

        if len(row) < 5:
            return None

        timestamp = datetime.strptime(
            row[0].strip(),
            "%Y-%m-%d %H:%M:%S"
        )

        return LogEvent(
            timestamp=timestamp,
            ip=row[1].strip(),
            username=row[2].strip(),
            event_type=row[3].strip().upper(),
            message=",".join(row[4:]).strip()
        )

    except (ValueError, StopIteration):
        return None


def parse_apache_access(line: str) -> LogEvent | None:
    match = APACHE_ACCESS_RE.match(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        timestamp = datetime.strptime(
            data["time"],
            "%d/%b/%Y:%H:%M:%S %z"
        )
        timestamp = normalize_timestamp(timestamp)
    except ValueError:
        return None

    status = int(data["status"])
    event_type = (
        "ERROR" if status >= 500
        else f"HTTP_{status}"
    )

    return LogEvent(
        timestamp=timestamp,
        ip=data["ip"],
        username="" if data["user"] == "-" else data["user"],
        event_type=event_type,
        message=(
            f'HTTP {status}: {data["request"]}'
        )
    )


def parse_apache_error(line: str) -> LogEvent | None:
    match = APACHE_ERROR_RE.match(line)

    if not match:
        return None

    data = match.groupdict()

    try:
        # Modern Apache error log:
        # [Thu Oct 09 20:10:15.123456 2026]
        timestamp_text = data["time"].split("]")[0].strip()

        timestamp = None

        for fmt in (
            "%a %b %d %H:%M:%S.%f %Y",
            "%a %b %d %H:%M:%S %Y",
        ):
            try:
                timestamp = datetime.strptime(
                    timestamp_text, fmt
                )
                break
            except ValueError:
                continue

        if timestamp is None:
            return None

    except (ValueError, TypeError):
        return None

    module = data["module"]
    message = data["message"].strip()

    # Example module: authz_core:error
    level = module.rsplit(":", 1)[-1].lower()

    event_type = (
        "ERROR"
        if level in {"error", "crit", "alert", "emerg"}
        else "APACHE_WARNING"
        if level == "warn"
        else "APACHE_INFO"
    )

    client_ip = data.get("ip") or ""

    if client_ip:
        # Remove the port from IPv4 client addresses.
        # Preserve IPv6 addresses when a port is ambiguous.
        ipv4_port = re.fullmatch(
            r"(\d{1,3}(?:\.\d{1,3}){3}):\d+",
            client_ip
        )
        if ipv4_port:
            client_ip = ipv4_port.group(1)

    return LogEvent(
        timestamp=timestamp,
        ip=client_ip,
        username="",
        event_type=event_type,
        message=f"[{module}] {message}"
    )


def parse_ssh(line: str) -> LogEvent | None:
    match = SSH_RE.match(line)

    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    # Syslog timestamps do not contain a year.
    # Use the current year; adjust for year rollover if necessary.
    now = datetime.now()
    try:
        timestamp = datetime.strptime(
            data["time"], "%b %d %H:%M:%S"
        ).replace(year=now.year)

        # If a December log is read in January, it may belong
        # to the previous year.
        if timestamp > now and timestamp.month == 12 and now.month == 1:
            timestamp = timestamp.replace(year=now.year - 1)

    except ValueError:
        return None

    ip = ""
    username = ""

    invalid_user = INVALID_USER_RE.search(message)
    user_match = SSH_USER_IP_RE.search(message)

    if invalid_user:
        username = invalid_user.group(1)
        ip = invalid_user.group(2)
    elif user_match:
        username = user_match.group(1)
        ip = user_match.group(2)

    if FAILED_SSH_RE.search(message) or invalid_user:
        event_type = "FAILED_LOGIN"
    elif re.search(r"\bAccepted (password|publickey)\b", message):
        event_type = "SUCCESS_LOGIN"
    else:
        event_type = "SSH_EVENT"

    return LogEvent(
        timestamp=timestamp,
        ip=ip,
        username=username,
        event_type=event_type,
        message=message
    )


def parse_line(line: str) -> LogEvent | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    # Try CSV first, preserving the existing project format.
    csv_event = parse_csv_line(line)
    if csv_event is not None:
        return csv_event

    # Detect SSH before other syslog-like formats.
    ssh_event = parse_ssh(line)
    if ssh_event is not None:
        return ssh_event

    # Apache access logs usually contain a quoted request.
    access_event = parse_apache_access(line)
    if access_event is not None:
        return access_event

    error_event = parse_apache_error(line)
    if error_event is not None:
        return error_event

    return None


def parse_file(path: str) -> tuple[list[LogEvent], int]:
    events = []
    invalid_lines = 0

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as file:
        for line in file:
            event = parse_line(line)

            if event is None:
                if line.strip() and not line.lstrip().startswith("#"):
                    invalid_lines += 1
            else:
                events.append(event)

    # All timezone-aware Apache access timestamps are normalized
    # to naive UTC; other timestamps are naive local/log time.
    events.sort(key=lambda event: event.timestamp)

    return events, invalid_lines