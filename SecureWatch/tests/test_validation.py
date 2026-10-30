import json

import pytest

from utils.validation import DEFAULT_SETTINGS, load_settings, save_settings, validate_settings


def test_validate_and_save_settings(tmp_path):
    path = tmp_path / "config.json"
    settings = {**DEFAULT_SETTINGS, "monitoring_interval_seconds": 45}
    saved = save_settings(path, settings)
    assert saved["monitoring_interval_seconds"] == 45
    assert load_settings(path) == saved


@pytest.mark.parametrize(
    "change",
    [
        {"monitoring_interval_seconds": 0},
        {"event_query_limit": 5000},
        {"failed_logon_threshold": 0},
        {"security_error_threshold": 10001},
        {"event_window_minutes": 0},
        {"cpu_threshold_percent": 100.1},
        {"appearance": "unknown"},
        {"known_hashes": ["not-a-sha256"]},
        {"expected_listening_ports": [0]},
        {"expected_listening_ports": [65536]},
    ],
)
def test_invalid_settings_are_rejected(change):
    with pytest.raises(ValueError):
        validate_settings({**DEFAULT_SETTINGS, **change})


def test_settings_file_must_contain_json_object(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(["bad shape"]), encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        load_settings(path)


def test_expected_ports_are_normalized():
    settings = validate_settings({"expected_listening_ports": [443, 80, 443]})
    assert settings["expected_listening_ports"] == [80, 443]


def test_numeric_strings_are_coerced_for_settings():
    settings = validate_settings({
        "monitoring_interval_seconds": "45",
        "alert_cooldown_seconds": "120",
        "failed_logon_threshold": "7",
        "cpu_threshold_percent": "88.5",
        "ram_threshold_percent": "92",
        "expected_listening_ports": ["443", "80", "443"],
    })
    assert settings["monitoring_interval_seconds"] == 45
    assert settings["alert_cooldown_seconds"] == 120
    assert settings["failed_logon_threshold"] == 7
    assert settings["cpu_threshold_percent"] == 88.5
    assert settings["ram_threshold_percent"] == 92.0
    assert settings["expected_listening_ports"] == [80, 443]
