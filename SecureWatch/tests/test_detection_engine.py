from datetime import datetime, timedelta

from core.detection_engine import DetectionEngine
from database.db_manager import DatabaseManager


def test_failed_logon_rule_is_explainable_and_deduplicated(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    engine = DetectionEngine(database, failed_logon_threshold=3, cooldown_seconds=600)
    event_time = datetime.now().astimezone().isoformat()
    events = [
        {"Id": 4625, "Time": event_time, "Message": f"test {index}"}
        for index in range(3)
    ]
    assert len(engine.analyze_events(events)) == 1
    assert engine.analyze_events(events) == []
    alert = database.alerts()[0]
    assert alert["rule_id"] == "SW-EVT-FAILED-LOGON"
    assert "Recommended investigation" in alert["details"]


def test_high_resource_alert_requires_repeated_observations(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    engine = DetectionEngine(
        database, cpu_threshold_percent=95, resource_observation_count=3,
    )
    process = {"pid": 41, "name": "test-process", "cpu_percent": 99, "memory_percent": 4}
    assert engine.analyze_processes([process]) == []
    assert engine.analyze_processes([process]) == []
    assert len(engine.analyze_processes([process])) == 1
    alert = database.alerts()[0]
    assert alert["severity"] == "Low"


def test_listening_port_uses_configured_expected_ports(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    engine = DetectionEngine(database, expected_listening_ports=[443])
    rows = [
        {"status": "LISTEN", "local_port": 443, "pid": 1},
        {"status": "LISTEN", "local_port": 65000, "pid": 2, "process": "test"},
    ]
    assert len(engine.analyze_connections(rows)) == 1
    assert database.alerts()[0]["rule_id"] == "SW-NET-UNEXPECTED-LISTENER"


def test_listener_detection_is_disabled_without_expected_port_policy(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    engine = DetectionEngine(database)
    assert engine.analyze_connections(
        [{"status": "LISTEN", "local_port": 65000, "pid": 2}]
    ) == []
    assert database.alerts() == []


def test_old_events_outside_window_do_not_alert(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    engine = DetectionEngine(database, failed_logon_threshold=1)
    old = (datetime.now().astimezone() - timedelta(hours=1)).isoformat()
    assert engine.analyze_events([{"Id": 4625, "Time": old}]) == []


def test_defender_detection_creates_review_alert(tmp_path):
    database = DatabaseManager(tmp_path / "securewatch.db")
    engine = DetectionEngine(database)
    assert len(engine.analyze_defender_detections([
        {"DetectionID": "D-2", "ThreatName": "Test", "ActionSuccess": False}
    ])) == 1
    alert = database.alerts()[0]
    assert alert["rule_id"] == "SW-DEFENDER-DETECTION"
    assert "Review Defender's recorded action" in alert["details"]
