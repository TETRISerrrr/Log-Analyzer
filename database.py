import sqlite3

from pathlib import Path

from parser import LogEvent


class Database:

    def __init__(
        self,
        path: str = "data/siem.db"
    ):

        Path(path).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.connection = sqlite3.connect(path)

        self.connection.row_factory = sqlite3.Row

        self.create_tables()

    def create_tables(self):

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS events (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                ip TEXT NOT NULL,

                username TEXT,

                event_type TEXT NOT NULL,

                message TEXT

            )
        """)

        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                created_at TEXT NOT NULL,

                severity TEXT NOT NULL,

                rule TEXT NOT NULL,

                ip TEXT,

                description TEXT NOT NULL

            )
        """)

        self.connection.commit()

    def clear_events(self):

        self.connection.execute(
            "DELETE FROM events"
        )

        self.connection.commit()

    def clear_alerts(self):

        self.connection.execute(
            "DELETE FROM alerts"
        )

        self.connection.commit()

    def insert_events(
        self,
        events: list[LogEvent]
    ):

        self.connection.executemany(
            """
            INSERT INTO events
            (
                timestamp,
                ip,
                username,
                event_type,
                message
            )

            VALUES (?, ?, ?, ?, ?)
            """,

            [
                (
                    event.timestamp.isoformat(
                        sep=" "
                    ),

                    event.ip,

                    event.username,

                    event.event_type,

                    event.message
                )

                for event in events
            ]
        )

        self.connection.commit()

    def insert_alerts(
        self,
        alerts: list[dict]
    ):

        self.connection.executemany(
            """
            INSERT INTO alerts
            (
                created_at,
                severity,
                rule,
                ip,
                description
            )

            VALUES (?, ?, ?, ?, ?)
            """,

            [
                (
                    alert["created_at"],
                    alert["severity"],
                    alert["rule"],
                    alert.get("ip"),
                    alert["description"]
                )

                for alert in alerts
            ]
        )

        self.connection.commit()

    def get_events(self):

        return self.connection.execute(
            """
            SELECT *
            FROM events
            ORDER BY timestamp
            """
        ).fetchall()

    def get_alerts(self):

        return self.connection.execute(
            """
            SELECT *
            FROM alerts
            ORDER BY created_at
            """
        ).fetchall()

    def close(self):

        self.connection.close()