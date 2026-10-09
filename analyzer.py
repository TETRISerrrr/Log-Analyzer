from collections import Counter, defaultdict

import config

from parser import LogEvent


FAILED_LOGIN_TYPES = {
    "FAILED_LOGIN",
    "AUTH_FAIL"
}


def get_failed_logins(
    events: list[LogEvent]
) -> list[LogEvent]:

    return [
        event
        for event in events
        if event.event_type in FAILED_LOGIN_TYPES
    ]


def detect_brute_force(
    events: list[LogEvent]
) -> list[dict]:

    failed_by_ip = defaultdict(list)


    for event in get_failed_logins(events):

        failed_by_ip[event.ip].append(event)

    alerts = []

    for ip, ip_events in failed_by_ip.items():

        start = 0

        for end, current_event in enumerate(ip_events):

            # Move the window forward
            while (
                current_event.timestamp
                - ip_events[start].timestamp
            ).total_seconds() > (
                config.BRUTE_FORCE_WINDOW_MINUTES * 60
            ):

                start += 1

            attempts = end - start + 1

            if attempts >= config.BRUTE_FORCE_FAILED_ATTEMPTS:

                first_event = ip_events[start]

                alerts.append({
                    "created_at": current_event.timestamp.isoformat(
                        sep=" "
                    ),

                    "severity": "HIGH",

                    "rule": "BRUTE_FORCE",

                    "ip": ip,

                    "description": (
                        f"Possible brute-force attack: "
                        f"{attempts} failed logins from "
                        f"{ip} within "
                        f"{config.BRUTE_FORCE_WINDOW_MINUTES} "
                        f"minutes."
                    )
                })

                break

    return alerts


def detect_suspicious_ips(
    events: list[LogEvent]
) -> list[dict]:

    failed_events = get_failed_logins(events)

    counts = Counter(
        event.ip
        for event in failed_events
    )

    alerts = []

    for ip, count in counts.items():

        if count >= config.SUSPICIOUS_IP_FAILED_ATTEMPTS:

            ip_events = [
                event
                for event in failed_events
                if event.ip == ip
            ]

            last_event = max(
                ip_events,
                key=lambda event: event.timestamp
            )

            alerts.append({
                "created_at": last_event.timestamp.isoformat(
                    sep=" "
                ),

                "severity": "MEDIUM",

                "rule": "SUSPICIOUS_IP",

                "ip": ip,

                "description": (
                    f"IP {ip} generated "
                    f"{count} failed login attempts "
                    f"in the analyzed log."
                )
            })

    return alerts


def detect_repeated_errors(
    events: list[LogEvent]
) -> list[dict]:

    errors = [
        event
        for event in events
        if event.event_type == "ERROR"
    ]

    errors_by_message = defaultdict(list)

    for event in errors:

        errors_by_message[
            event.message
        ].append(event)

    alerts = []

    for message, group in errors_by_message.items():

        if len(group) >= config.REPEATED_ERROR_THRESHOLD:

            last_event = group[-1]

            alerts.append({
                "created_at": last_event.timestamp.isoformat(
                    sep=" "
                ),

                "severity": "LOW",

                "rule": "REPEATED_ERROR",

                "ip": last_event.ip,

                "description": (
                    f"Repeated error occurred "
                    f"{len(group)} times: "
                    f"{message}"
                )
            })

    return alerts


def analyze(
    events: list[LogEvent]
) -> list[dict]:

    alerts = []

    alerts.extend(
        detect_brute_force(events)
    )

    alerts.extend(
        detect_suspicious_ips(events)
    )

    alerts.extend(
        detect_repeated_errors(events)
    )

    unique_alerts = {}

    for alert in alerts:

        key = (
            alert["rule"],
            alert.get("ip"),
            alert["description"]
        )

        unique_alerts[key] = alert

    return sorted(
        unique_alerts.values(),
        key=lambda alert: alert["created_at"]
    )


def statistics(
    events: list[LogEvent]
) -> dict:

    event_types = Counter(
        event.event_type
        for event in events
    )

    ips = Counter(
        event.ip
        for event in events
    )

    failed_by_ip = Counter(
        event.ip
        for event in get_failed_logins(events)
    )

    users = Counter(
        event.username
        for event in events
        if event.username not in {"", "-"}
    )

    return {
        "total_events": len(events),

        "event_types": event_types,

        "top_ips": ips.most_common(10),

        "failed_by_ip": failed_by_ip.most_common(10),

        "top_users": users.most_common(10)
    }