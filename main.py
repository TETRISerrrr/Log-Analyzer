import argparse

from pathlib import Path

from analyzer import (
    analyze,
    statistics
)

from database import Database

from exporter import (
    export_csv,
    export_json
)

from graph import create_graph

from parser import parse_file


def print_banner():

    print(r"""

█░░ █▀█ █▀▀   ▄▀█ █▄░█ ▄▀█ █░░ █▄█ ▀█ █▀▀ █▀█
█▄▄ █▄█ █▄█   █▀█ █░▀█ █▀█ █▄▄ ░█░ █▄ ██▄ █▀▄

▀█▀ █▀▀ ▀█▀ █▀█ █ █▀ █▀▀ █▀█ █▀█ █▀█
░█░ ██▄ ░█░ █▀▄ █ ▄█ ██▄ █▀▄ █▀▄ █▀▄
""")


def print_alerts(
    alerts: list[dict]
):

    if not alerts:

        print(
            "\n[OK] No alerts detected."
        )

        return

    print(
        f"\n[!] Alerts detected: "
        f"{len(alerts)}\n"
    )

    for alert in alerts:

        print(
            f"[{alert['severity']}] "
            f"{alert['rule']}"
        )

        print(
            f"IP: {alert.get('ip', '-')}"
        )

        print(
            f"Time: {alert['created_at']}"
        )

        print(
            f"{alert['description']}\n"
        )


def print_stats(
    stats: dict
):

    print(
        "\n========== STATISTICS =========="
    )

    print(
        f"Total events: "
        f"{stats['total_events']}"
    )

    print("\nEvent types:")

    for event_type, count in (
        stats["event_types"].most_common()
    ):

        print(
            f"  {event_type:<20} {count}"
        )

    print("\nTop IPs:")

    for ip, count in stats["top_ips"]:

        print(
            f"  {ip:<20} {count}"
        )

    print("\nFailed logins by IP:")

    for ip, count in stats["failed_by_ip"]:

        print(
            f"  {ip:<20} {count}"
        )

    print("\nTop users:")

    for user, count in stats["top_users"]:

        print(
            f"  {user:<20} {count}"
        )


def build_parser():

    parser = argparse.ArgumentParser(
        description=(
            "Educational "
            "Log Analyzer / Mini SIEM"
        )
    )

    parser.add_argument(
        "--log",
        required=True,
        help="Path to log file"
    )

    parser.add_argument(
        "--db",
        default="data/siem.db",
        help="SQLite database path"
    )

    parser.add_argument(
        "--alerts",
        action="store_true",
        help="Show detected alerts"
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show statistics"
    )

    parser.add_argument(
        "--export-json",
        metavar="PATH",
        help="Export alerts to JSON"
    )

    parser.add_argument(
        "--export-csv",
        metavar="PATH",
        help="Export events to CSV"
    )

    parser.add_argument(
        "--graph",
        action="store_true",
        help="Create event graph"
    )

    parser.add_argument(
        "--clear-db",
        action="store_true",
        help="Clear previous database data"
    )

    return parser


def main():

    args = build_parser().parse_args()

    print_banner()

    log_path = Path(
        args.log
    )

    if not log_path.exists():

        print(
            f"[ERROR] File not found: "
            f"{log_path}"
        )

        return 1

    print(
        f"[+] Reading log: "
        f"{log_path}"
    )

    events, invalid = parse_file(
        str(log_path)
    )

    print(
        f"[+] Parsed events: "
        f"{len(events)}"
    )

    if invalid:

        print(
            f"[!] Invalid/skipped lines: "
            f"{invalid}"
        )

    database = Database(
        args.db
    )

    if args.clear_db:

        database.clear_events()

        database.clear_alerts()

    database.insert_events(
        events
    )

    print(
        "[+] Events saved to SQLite"
    )

    alerts = analyze(
        events
    )

    database.insert_alerts(
        alerts
    )

    print(
        f"[+] Detection finished. "
        f"Alerts: {len(alerts)}"
    )

    # If no additional command was specified,
    # show alerts automatically.

    no_extra_commands = not any([
        args.stats,
        args.export_json,
        args.export_csv,
        args.graph
    ])

    if args.alerts or no_extra_commands:

        print_alerts(
            alerts
        )

    if args.stats:

        print_stats(
            statistics(events)
        )

    if args.export_json:

        export_json(
            alerts,
            args.export_json
        )

        print(
            f"[+] JSON exported: "
            f"{args.export_json}"
        )

    if args.export_csv:

        export_csv(
            database.get_events(),
            args.export_csv
        )

        print(
            f"[+] CSV exported: "
            f"{args.export_csv}"
        )

    if args.graph:

        try:

            path = create_graph(
                events
            )

            print(
                f"[+] Graph created: "
                f"{path}"
            )

        except RuntimeError as error:

            print(
                f"[ERROR] {error}"
            )

    database.close()

    return 0


if __name__ == "__main__":

    raise SystemExit(
        main()
    )