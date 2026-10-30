import json

import pytest

from core import defender_manager, event_collector


def test_defender_status_parses_powershell_response(monkeypatch):
    monkeypatch.setattr(defender_manager.platform, "system", lambda: "Windows")
    scripts = []

    def fake_run(script, **kwargs):
        scripts.append(script)
        return True, '{"AntivirusEnabled":true}'

    monkeypatch.setattr(
        defender_manager, "run_powershell", fake_run,
    )
    assert defender_manager.get_defender_status() == {"AntivirusEnabled": True}
    assert "QuickScanStartTime" in scripts[0]
    assert "4294967295" in scripts[0]


def test_defender_history_handles_empty_array(monkeypatch):
    monkeypatch.setattr(defender_manager.platform, "system", lambda: "Windows")
    scripts = []

    def fake_run(script, **kwargs):
        scripts.append(script)
        return True, "[]"

    monkeypatch.setattr(
        defender_manager, "run_powershell", fake_run,
    )
    assert defender_manager.get_defender_detections() == []
    assert "InitialDetectionTime.ToString('o')" in scripts[0]


def test_custom_scan_escapes_powershell_quotes(monkeypatch, tmp_path):
    monkeypatch.setattr(defender_manager.platform, "system", lambda: "Windows")
    folder = tmp_path / "folder's name"
    folder.mkdir()
    observed = {}

    def fake_run(script, **kwargs):
        observed["script"] = script
        return True, "accepted"

    monkeypatch.setattr(defender_manager, "run_powershell", fake_run)
    assert defender_manager.request_scan("CustomScan", folder) == "accepted"
    assert "folder''s name" in observed["script"]
    assert "does not confirm that the scan is complete" in observed["script"]


@pytest.mark.parametrize("log_name", ["System", "Application", "Security"])
def test_event_collector_parses_bounded_log_response(monkeypatch, log_name):
    monkeypatch.setattr(event_collector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        event_collector, "run_powershell",
        lambda script, **kwargs: (
            True,
            json.dumps([{"Id": 4625, "RecordId": 15, "LogName": log_name}]),
        ),
    )
    assert event_collector.collect_events(log_name, 25) == [
        {"Id": 4625, "RecordId": 15, "LogName": log_name}
    ]


def test_event_collector_rejects_untrusted_log_and_unbounded_limit(monkeypatch):
    monkeypatch.setattr(event_collector.platform, "system", lambda: "Windows")
    with pytest.raises(ValueError):
        event_collector.collect_events("Security'; Remove-Item")
    with pytest.raises(ValueError):
        event_collector.collect_events("Security", 2001)


def test_event_collector_treats_no_matching_events_as_empty(monkeypatch):
    monkeypatch.setattr(event_collector.platform, "system", lambda: "Windows")
    scripts = []

    def fake_run(script, **kwargs):
        scripts.append(script)
        return True, "[]"

    monkeypatch.setattr(event_collector, "run_powershell", fake_run)

    assert event_collector.collect_events("Application", 20) == []
    assert "NoMatchingEventsFound" in scripts[0]


def test_event_collector_preserves_access_denied_error(monkeypatch):
    monkeypatch.setattr(event_collector.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        event_collector,
        "run_powershell",
        lambda script, **kwargs: (False, "UnauthorizedAccessException"),
    )

    with pytest.raises(RuntimeError, match="UnauthorizedAccessException"):
        event_collector.collect_events("Security", 20)
