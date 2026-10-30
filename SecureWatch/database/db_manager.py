"""Transactional SQLite storage for SecureWatch records."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any


def timestamp_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class DatabaseManager:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        schema_path = Path(__file__).with_name("schema.sql")
        with self.connect() as connection:
            connection.executescript(schema_path.read_text(encoding="utf-8"))
            self._migrate_alert_columns(connection)
            self._migrate_file_columns(connection)
            self._migrate_windows_event_columns(connection)
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity_status ON alerts(severity,status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint,timestamp)"
            )
            connection.execute("DROP INDEX IF EXISTS idx_windows_events_identity")
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS idx_windows_events_record
                   ON windows_events(log_name,record_id) WHERE record_id != ''"""
            )

    @staticmethod
    def _migrate_alert_columns(connection: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(alerts)")
        }
        migrations = {
            "rule_id": "TEXT NOT NULL DEFAULT ''",
            "fingerprint": "TEXT NOT NULL DEFAULT ''",
            "status": "TEXT NOT NULL DEFAULT 'Open'",
            "reviewed_at": "TEXT",
        }
        for name, definition in migrations.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")

    @staticmethod
    def _migrate_file_columns(connection: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(file_scans)")
        }
        migrations = {
            "extension": "TEXT NOT NULL DEFAULT ''",
            "modified_at": "TEXT NOT NULL DEFAULT ''",
            "result": "TEXT NOT NULL DEFAULT 'No local indicator match'",
        }
        for name, definition in migrations.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE file_scans ADD COLUMN {name} {definition}")

    @staticmethod
    def _migrate_windows_event_columns(connection: sqlite3.Connection) -> None:
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(windows_events)")
        }
        if "record_id" not in columns:
            connection.execute(
                "ALTER TABLE windows_events ADD COLUMN record_id TEXT NOT NULL DEFAULT ''"
            )

    def create_alert(
        self,
        severity: str,
        title: str,
        details: str,
        source: str = "SecureWatch",
        rule_id: str = "",
        cooldown_seconds: int = 0,
        fingerprint: str | None = None,
    ) -> int | None:
        normalized = fingerprint or hashlib.sha256(
            f"{rule_id}\0{source}\0{title}\0{details}".encode("utf-8")
        ).hexdigest()
        now = datetime.now().astimezone()
        cutoff = (now - timedelta(seconds=max(0, cooldown_seconds))).isoformat(timespec="seconds")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if cooldown_seconds > 0:
                recent = connection.execute(
                    "SELECT id FROM alerts WHERE fingerprint=? AND timestamp>=? LIMIT 1",
                    (normalized, cutoff),
                ).fetchone()
                if recent:
                    return None
            cursor = connection.execute(
                """INSERT INTO alerts
                   (timestamp,severity,title,details,source,rule_id,fingerprint,status)
                   VALUES(?,?,?,?,?,?,?,'Open')""",
                (now.isoformat(timespec="seconds"), severity, title, details,
                 source, rule_id, normalized),
            )
            return int(cursor.lastrowid)

    def alerts(self, limit: int = 500, severity: str | None = None,
               search: str = "", status: str | None = None,
               start_date: str | None = None,
               end_date: str | None = None) -> list[sqlite3.Row]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if severity and severity != "All":
            clauses.append("severity = ?")
            parameters.append(severity)
        if status and status != "All":
            clauses.append("status = ?")
            parameters.append(status)
        if start_date:
            date.fromisoformat(start_date)
            clauses.append("date(timestamp) >= ?")
            parameters.append(start_date)
        if end_date:
            date.fromisoformat(end_date)
            clauses.append("date(timestamp) <= ?")
            parameters.append(end_date)
        if search.strip():
            clauses.append("(title LIKE ? OR details LIKE ? OR rule_id LIKE ?)")
            term = f"%{search.strip()}%"
            parameters.extend((term, term, term))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(int(limit), 10000)))
        with self.connect() as connection:
            return connection.execute(
                f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?", parameters
            ).fetchall()

    def add_file_scan(self, path: str | Path, size: int, sha256: str,
                      extension: str = "", modified_at: str = "",
                      result: str = "No local indicator match") -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO file_scans
                   (timestamp,path,size,sha256,extension,modified_at,result)
                   VALUES(?,?,?,?,?,?,?)""",
                (timestamp_text(), str(path), int(size), sha256, extension,
                 modified_at, result),
            )
            return int(cursor.lastrowid)

    def file_scans(self, limit: int = 1000) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM file_scans ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 10000)),),
            ).fetchall()

    def set_config(self, key: str, value: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO monitoring_config(key,value,updated_at) VALUES(?,?,?)
                   ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                   updated_at=excluded.updated_at""",
                (key, value, timestamp_text()),
            )

    def get_config(self) -> dict[str, str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT key,value FROM monitoring_config ORDER BY key"
            ).fetchall()
        return {row["key"]: row["value"] for row in rows}

    def review_alert(self, alert_id: int) -> bool:
        now = timestamp_text()
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE alerts SET status='Reviewed', reviewed_at=? WHERE id=?",
                (now, int(alert_id)),
            )
            if cursor.rowcount:
                connection.execute(
                    "INSERT INTO audit_records(timestamp,action,result) VALUES(?,?,?)",
                    (now, "Review alert", f"Alert {alert_id} marked reviewed"),
                )
            return cursor.rowcount > 0

    def add_investigation_note(self, alert_id: int, note: str) -> int:
        if not note.strip():
            raise ValueError("Investigation note cannot be empty.")
        now = timestamp_text()
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO investigation_notes(alert_id,timestamp,note) VALUES(?,?,?)",
                (int(alert_id), now, note.strip()),
            )
            connection.execute(
                "INSERT INTO audit_records(timestamp,action,result) VALUES(?,?,?)",
                (now, "Add investigation note", f"Note added to alert {alert_id}"),
            )
            return int(cursor.lastrowid)

    def notes_for_alert(self, alert_id: int) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM investigation_notes WHERE alert_id=? ORDER BY id",
                (int(alert_id),),
            ).fetchall()

    def add_audit_record(self, action: str, result: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO audit_records(timestamp,action,result) VALUES(?,?,?)",
                (timestamp_text(), action, result),
            )

    def add_action(self, action: str, result: str) -> None:
        now = timestamp_text()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO actions(timestamp,action,result) VALUES(?,?,?)",
                (now, action, result),
            )
            connection.execute(
                "INSERT INTO audit_records(timestamp,action,result) VALUES(?,?,?)",
                (now, action, result),
            )

    def add_event_finding(self, rule_id: str, severity: str, title: str,
                          evidence: str, source: str) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO event_findings
                   (timestamp,rule_id,severity,title,evidence,source)
                   VALUES(?,?,?,?,?,?)""",
                (timestamp_text(), rule_id, severity, title, evidence, source),
            )
            return int(cursor.lastrowid)

    def add_windows_events(self, log_name: str, events: list[dict[str, Any]]) -> None:
        with self.connect() as connection:
            connection.executemany(
                """INSERT OR IGNORE INTO windows_events
                   (timestamp,log_name,event_id,record_id,level,provider,message)
                   VALUES(?,?,?,?,?,?,?)""",
                [
                    self._event_row(log_name, event)
                    for event in events
                ],
            )

    @staticmethod
    def _event_row(log_name: str, event: dict[str, Any]) -> tuple[str, ...]:
        timestamp = str(event.get("Time", ""))
        event_id = str(event.get("Id", ""))
        provider = str(event.get("ProviderName", ""))
        message = " ".join(str(event.get("Message") or "").split())[:1800]
        record_id = str(event.get("RecordId") or "")
        if not record_id:
            identity = hashlib.sha256(
                f"{timestamp}\0{event_id}\0{provider}\0{message}".encode("utf-8")
            ).hexdigest()
            record_id = f"fallback:{identity}"
        return (
            timestamp, log_name, event_id, record_id,
            str(event.get("LevelDisplayName", "")), provider, message,
        )

    def add_monitoring_run(self, summary: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO monitoring_runs(timestamp,summary) VALUES(?,?)",
                (timestamp_text(), summary),
            )

    def add_defender_detections(self, detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
        inserted: list[dict[str, Any]] = []
        with self.connect() as connection:
            for detection in detections:
                details = json.dumps(detection, ensure_ascii=False, sort_keys=True, default=str)
                identity = str(
                    detection.get("DetectionID")
                    or hashlib.sha256(details.encode("utf-8")).hexdigest()
                )
                cursor = connection.execute(
                    """INSERT OR IGNORE INTO defender_detections
                       (detection_key,timestamp,threat_id,threat_name,action_success,
                        process_name,resources,details)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        identity,
                        str(detection.get("InitialDetectionTime") or "Unavailable"),
                        str(detection.get("ThreatID") or "Unavailable"),
                        str(detection.get("ThreatName") or "Unavailable"),
                        str(detection.get("ActionSuccess") if detection.get("ActionSuccess") is not None
                            else "Unavailable"),
                        str(detection.get("ProcessName") or "Unavailable"),
                        json.dumps(detection.get("Resources") or [], ensure_ascii=False, default=str),
                        details,
                    ),
                )
                if cursor.rowcount:
                    inserted.append(detection)
        return inserted

    def defender_detections(self, limit: int = 100) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM defender_detections ORDER BY id DESC LIMIT ?",
                (max(1, min(int(limit), 1000)),),
            ).fetchall()

    def prune_retained_observations(self, retention_days: int) -> int:
        if isinstance(retention_days, bool) or not 1 <= retention_days <= 3650:
            raise ValueError("Observation retention must be between 1 and 3650 days.")
        cutoff = (
            datetime.now().astimezone() - timedelta(days=retention_days)
        ).isoformat(timespec="seconds")
        with self.connect() as connection:
            events = connection.execute(
                "DELETE FROM windows_events WHERE datetime(timestamp) < datetime(?)",
                (cutoff,),
            ).rowcount
            runs = connection.execute(
                "DELETE FROM monitoring_runs WHERE datetime(timestamp) < datetime(?)",
                (cutoff,),
            ).rowcount
            detections = connection.execute(
                """DELETE FROM defender_detections
                   WHERE datetime(timestamp) < datetime(?)
                   AND timestamp != 'Unavailable'""",
                (cutoff,),
            ).rowcount
            findings = connection.execute(
                "DELETE FROM event_findings WHERE datetime(timestamp) < datetime(?)",
                (cutoff,),
            ).rowcount
            return events + runs + detections + findings
