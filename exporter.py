import csv
import json

from pathlib import Path


def export_json(
    alerts: list[dict],
    path: str
):

    Path(path).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4,
            ensure_ascii=False
        )


def export_csv(
    events,
    path: str
):

    Path(path).parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "id",
            "timestamp",
            "ip",
            "username",
            "event_type",
            "message"
        ])

        for event in events:

            writer.writerow([
                event["id"],
                event["timestamp"],
                event["ip"],
                event["username"],
                event["event_type"],
                event["message"]
            ])