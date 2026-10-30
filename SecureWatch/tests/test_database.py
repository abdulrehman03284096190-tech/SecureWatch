import sqlite3

from database.db_manager import DatabaseManager


def test_database_records_alerts_and_review_notes(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    alert_id = database.create_alert(
        "Medium", "Repeated failures", "Observed five failed logons",
        "Windows Security", "SW-EVT-FAILED-LOGON",
    )
    assert alert_id is not None
    assert database.alerts()[0]["rule_id"] == "SW-EVT-FAILED-LOGON"
    assert database.review_alert(alert_id)
    database.add_investigation_note(alert_id, "Expected test activity.")
    assert database.alerts()[0]["status"] == "Reviewed"
    assert database.notes_for_alert(alert_id)[0]["note"] == "Expected test activity."
    with database.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0] == 2


def test_database_migrates_existing_mvp_schema(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE alerts (
               id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,
               severity TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL,
               source TEXT NOT NULL)"""
        )
        connection.execute(
            "INSERT INTO alerts(timestamp,severity,title,details,source) "
            "VALUES('2025-01-01','Low','Old alert','Existing record','MVP')"
        )
    database = DatabaseManager(path)
    row = database.alerts()[0]
    assert row["title"] == "Old alert"
    assert row["status"] == "Open"
    assert row["rule_id"] == ""


def test_alert_cooldown_prevents_duplicates(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    first = database.create_alert(
        "Low", "Rule", "Evidence", rule_id="R1",
        cooldown_seconds=60, fingerprint="same",
    )
    second = database.create_alert(
        "Low", "Rule", "Evidence changed", rule_id="R1",
        cooldown_seconds=60, fingerprint="same",
    )
    assert first is not None
    assert second is None
    assert len(database.alerts()) == 1


def test_retention_removes_expired_observations_but_preserves_alerts(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    alert_id = database.create_alert("Low", "Retained", "Evidence")
    database.add_windows_events(
        "System",
        [{"Time": "2000-01-01T00:00:00+00:00", "Id": 1}],
    )
    database.add_monitoring_run('{"sample":"old"}')
    with database.connect() as connection:
        connection.execute(
            "UPDATE monitoring_runs SET timestamp='2000-01-01T00:00:00+00:00'"
        )
    removed = database.prune_retained_observations(30)
    assert removed == 2
    assert len(database.alerts()) == 1
    assert database.review_alert(alert_id)


def test_defender_detection_history_persists_and_deduplicates(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    detection = {
        "DetectionID": "D-1",
        "InitialDetectionTime": "2026-01-01T10:00:00+00:00",
        "ThreatID": "T-1",
        "ThreatName": "Test indicator",
        "ActionSuccess": True,
        "Resources": ["C:\\sample.txt"],
    }
    assert database.add_defender_detections([detection]) == [detection]
    assert database.add_defender_detections([detection]) == []
    row = database.defender_detections()[0]
    assert row["threat_name"] == "Test indicator"
    assert row["action_success"] == "True"


def test_windows_event_deduplication_uses_event_record_id(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    first = {
        "Time": "2026-01-01T10:00:00+00:00",
        "Id": 4625,
        "RecordId": 1001,
        "ProviderName": "Security-Auditing",
    }
    same = dict(first)
    different = {**first, "RecordId": 1002}
    database.add_windows_events("Security", [first, same, different])
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT record_id FROM windows_events ORDER BY record_id"
        ).fetchall()
    assert [row["record_id"] for row in rows] == ["1001", "1002"]


def test_database_migrates_previous_event_identity_index(tmp_path):
    path = tmp_path / "previous.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """CREATE TABLE windows_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,
               log_name TEXT NOT NULL,event_id TEXT NOT NULL,level TEXT NOT NULL,
               provider TEXT NOT NULL,message TEXT NOT NULL)"""
        )
        connection.execute(
            """CREATE UNIQUE INDEX idx_windows_events_identity
               ON windows_events(timestamp,log_name,event_id,provider)"""
        )
    database = DatabaseManager(path)
    observed = {
        "Time": "2026-01-01T10:00:00+00:00",
        "Id": 4625,
        "ProviderName": "Security-Auditing",
    }
    database.add_windows_events(
        "Security",
        [{**observed, "RecordId": 2001}, {**observed, "RecordId": 2002}],
    )
    with database.connect() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM windows_events"
        ).fetchone()[0] == 2


def test_alert_filters_apply_date_severity_and_search_before_limit(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    old_id = database.create_alert("Low", "old matching", "old", "test")
    new_id = database.create_alert("High", "new", "matching", "test")
    with database.connect() as connection:
        connection.execute(
            "UPDATE alerts SET timestamp='2020-01-02T10:00:00+00:00' WHERE id=?",
            (old_id,),
        )
        connection.execute(
            "UPDATE alerts SET timestamp='2026-01-02T10:00:00+00:00' WHERE id=?",
            (new_id,),
        )
    rows = database.alerts(
        limit=10, severity="Low", search="matching",
        start_date="2020-01-01", end_date="2020-12-31",
    )
    assert [row["id"] for row in rows] == [old_id]
