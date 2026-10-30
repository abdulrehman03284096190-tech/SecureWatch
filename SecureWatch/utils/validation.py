"""Validation for local application settings and hash indicators."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DEFAULT_SETTINGS: dict[str, Any] = {
    "monitoring_interval_seconds": 30,
    "alert_cooldown_seconds": 300,
    "cpu_threshold_percent": 90.0,
    "ram_threshold_percent": 90.0,
    "resource_observation_count": 3,
    "event_query_limit": 100,
    "failed_logon_threshold": 5,
    "security_error_threshold": 10,
    "event_window_minutes": 10,
    "report_directory": str(Path.home() / "Documents"),
    "known_hashes": [],
    "expected_listening_ports": [],
    "appearance": "dark",
    "log_retention_days": 30,
}
_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")


def _coerce_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer.")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise ValueError(f"{field_name} must be an integer.")
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError(f"{field_name} must be an integer.")
        try:
            integer = int(stripped)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be an integer.") from exc
        if str(integer) != stripped and not (stripped.startswith("+") and str(integer) == stripped[1:]):
            # Accept whole-number strings without floating-point notation only.
            if stripped.lower() not in {"nan", "inf", "-inf", "+inf"}:
                try:
                    float_value = float(stripped)
                    if float_value.is_integer():
                        return int(float_value)
                except ValueError:
                    pass
            raise ValueError(f"{field_name} must be an integer.")
        return integer
    raise ValueError(f"{field_name} must be an integer.")


def validate_settings(settings: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise ValueError("Settings must be provided as a JSON object.")
    validated = {**DEFAULT_SETTINGS, **settings}
    integer_ranges = {
        "monitoring_interval_seconds": (5, 3600),
        "alert_cooldown_seconds": (0, 86400),
        "resource_observation_count": (1, 100),
        "event_query_limit": (1, 2000),
        "failed_logon_threshold": (1, 1000),
        "security_error_threshold": (1, 10000),
        "event_window_minutes": (1, 1440),
        "log_retention_days": (1, 3650),
    }
    for key, (minimum, maximum) in integer_ranges.items():
        value = _coerce_int(validated[key], key)
        if not minimum <= value <= maximum:
            raise ValueError(f"{key} must be between {minimum} and {maximum}.")
        validated[key] = value
    for key in ("cpu_threshold_percent", "ram_threshold_percent"):
        value = validated[key]
        if isinstance(value, bool):
            raise ValueError(f"{key} must be a number.")
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError(f"{key} must be a number.")
            try:
                value = float(stripped)
            except ValueError as exc:
                raise ValueError(f"{key} must be a number.") from exc
        elif not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be a number.")
        if not 1 <= float(value) <= 100:
            raise ValueError(f"{key} must be between 1 and 100.")
        validated[key] = float(value)
    if validated["appearance"] not in {"dark", "light", "system"}:
        raise ValueError("appearance must be dark, light, or system.")
    if not isinstance(validated["report_directory"], str) or not validated["report_directory"].strip():
        raise ValueError("report_directory must be a non-empty path.")
    report_path = Path(validated["report_directory"]).expanduser()
    if not report_path.is_absolute():
        report_path = Path.home() / report_path
    validated["report_directory"] = str(report_path)
    if not isinstance(validated["known_hashes"], list):
        raise ValueError("known_hashes must be a list of SHA-256 digests.")
    normalized_hashes: list[str] = []
    for digest in validated["known_hashes"]:
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest.strip()):
            raise ValueError(f"Invalid SHA-256 indicator: {digest!r}")
        normalized_hashes.append(digest.strip().lower())
    validated["known_hashes"] = sorted(set(normalized_hashes))
    expected_ports = validated["expected_listening_ports"]
    if not isinstance(expected_ports, list):
        raise ValueError("expected_listening_ports must be a list of TCP/UDP port numbers.")
    normalized_ports: list[int] = []
    for port in expected_ports:
        if isinstance(port, bool):
            raise ValueError(f"Invalid expected listening port: {port!r}")
        port_value = _coerce_int(port, "expected_listening_ports")
        if not 1 <= port_value <= 65535:
            raise ValueError(f"Invalid expected listening port: {port!r}")
        normalized_ports.append(port_value)
    validated["expected_listening_ports"] = sorted(set(normalized_ports))
    return validated


def load_settings(path: str | Path) -> dict[str, Any]:
    settings_path = Path(path)
    if not settings_path.exists():
        return validate_settings({})
    try:
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read settings file: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("Settings file must contain a JSON object.")
    return validate_settings(raw)


def save_settings(path: str | Path, settings: dict[str, Any]) -> dict[str, Any]:
    validated = validate_settings(settings)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(validated, indent=2) + "\n", encoding="utf-8")
    temp.replace(target)
    return validated
