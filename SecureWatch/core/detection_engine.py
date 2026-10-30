"""Explainable local rules for observed events and monitoring snapshots."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import threading
from typing import Any, Iterable

from database.db_manager import DatabaseManager


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    description: str
    data_source: str
    severity: str
    investigation: str


RULES = (
    DetectionRule("SW-EVT-FAILED-LOGON", "Repeated failed logons",
                  "Several failed logon events were observed in the configured time window.",
                  "Windows Security event log", "Medium",
                  "Review event details, account context, and whether the activity is expected."),
    DetectionRule("SW-EVT-ERROR-BURST", "Repeated security-relevant errors",
                  "Multiple error or critical events were observed in the configured time window.",
                  "Windows event logs", "Low",
                  "Review event providers and messages; an error by itself is not evidence of compromise."),
    DetectionRule("SW-FILE-KNOWN-HASH", "Known local hash indicator",
                  "A scanned file matched a locally configured SHA-256 indicator.",
                  "Local file scanner", "Medium",
                  "Verify the indicator source and investigate the file; the match alone is not a verdict."),
    DetectionRule("SW-RESOURCE-SUSTAINED", "Sustained high resource use",
                  "A process exceeded a configured resource threshold over repeated observations.",
                  "Process monitor", "Low",
                  "Identify expected workload and inspect the process owner and path."),
    DetectionRule("SW-NET-UNEXPECTED-LISTENER", "Unconfigured listening port",
                  "A listening port is not included in the local expected-port configuration.",
                  "Network monitor", "Medium",
                  "Identify the owning process and validate whether the service is expected."),
    DetectionRule("SW-DEFENDER-DETECTION", "Microsoft Defender detection",
                  "Microsoft Defender reported a retained threat detection.",
                  "Microsoft Defender history", "Medium",
                  "Review Defender's recorded action and detection details in Windows Security."),
)


def _event_time(event: dict[str, Any]) -> datetime | None:
    value = event.get("TimeCreated") or event.get("Time") or event.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone() if parsed.tzinfo else parsed.astimezone()
    except ValueError:
        return None


class DetectionEngine:
    def __init__(
        self,
        database: DatabaseManager,
        *,
        cooldown_seconds: int = 300,
        failed_logon_threshold: int = 5,
        error_threshold: int = 10,
        event_window_minutes: int = 10,
        cpu_threshold_percent: float = 90.0,
        ram_threshold_percent: float = 90.0,
        resource_observation_count: int = 3,
        expected_listening_ports: Iterable[int] = (),
    ):
        self.database = database
        self.cooldown_seconds = max(0, cooldown_seconds)
        self.failed_logon_threshold = max(1, failed_logon_threshold)
        self.error_threshold = max(1, error_threshold)
        self.event_window = timedelta(minutes=max(1, event_window_minutes))
        self.cpu_threshold_percent = cpu_threshold_percent
        self.ram_threshold_percent = ram_threshold_percent
        self.resource_observation_count = max(1, resource_observation_count)
        self.expected_ports = set(expected_listening_ports)
        self._lock = threading.RLock()
        self._resource_history: dict[int, deque[tuple[bool, bool]]] = defaultdict(
            lambda: deque(maxlen=self.resource_observation_count)
        )

    def analyze_events(self, events: Iterable[dict[str, Any]]) -> list[int]:
        materialized = list(events)
        now = datetime.now().astimezone()
        window_events = [
            event for event in materialized
            if (event_time := _event_time(event)) is not None
            and now - self.event_window <= event_time <= now + timedelta(minutes=1)
        ]
        created: list[int] = []
        failed_logons = [
            event for event in window_events
            if str(event.get("Id", event.get("EventID", ""))) == "4625"
            and str(event.get("LogName", "Security")).lower() == "security"
        ]
        if len(failed_logons) >= self.failed_logon_threshold:
            evidence = f"{len(failed_logons)} failed-logon events (4625) in {self.event_window}."
            alert_id = self._alert(
                RULES[0], evidence, fingerprint=f"failed-logons:{self._window_key(now)}"
            )
            if alert_id:
                created.append(alert_id)
        errors = [
            event for event in window_events
            if str(event.get("LevelDisplayName", event.get("level", ""))).lower()
            in {"error", "critical"}
        ]
        if len(errors) >= self.error_threshold:
            evidence = f"{len(errors)} error/critical events in {self.event_window}."
            alert_id = self._alert(
                RULES[1], evidence, fingerprint=f"event-errors:{self._window_key(now)}"
            )
            if alert_id:
                created.append(alert_id)
        return created

    def analyze_file(self, path: str, sha256: str, indicators: Iterable[str]) -> int | None:
        known = {item.strip().lower() for item in indicators}
        if sha256.lower() not in known:
            return None
        evidence = f"Path: {path}\nSHA-256: {sha256.lower()}"
        return self._alert(
            RULES[2], evidence,
            fingerprint=f"file-hash:{sha256.lower()}",
        )

    def analyze_processes(self, processes: Iterable[dict[str, Any]]) -> list[int]:
        with self._lock:
            return self._analyze_processes(processes)

    def _analyze_processes(self, processes: Iterable[dict[str, Any]]) -> list[int]:
        created: list[int] = []
        seen: set[int] = set()
        for process in processes:
            try:
                pid = int(process["pid"])
            except (KeyError, TypeError, ValueError):
                continue
            seen.add(pid)
            cpu_high = float(process.get("cpu_percent") or 0) >= self.cpu_threshold_percent
            ram_high = float(process.get("memory_percent") or 0) >= self.ram_threshold_percent
            history = self._resource_history[pid]
            history.append((cpu_high, ram_high))
            sustained_cpu = len(history) == self.resource_observation_count and all(
                cpu for cpu, _ in history
            )
            sustained_ram = len(history) == self.resource_observation_count and all(
                ram for _, ram in history
            )
            if sustained_cpu or sustained_ram:
                evidence = (
                    f"PID {pid} ({process.get('name', 'Unavailable')}) exceeded "
                    f"{'CPU' if sustained_cpu else 'RAM'} threshold in "
                    f"{self.resource_observation_count} consecutive observations."
                )
                alert_id = self._alert(
                    RULES[3], evidence, fingerprint=f"resource:{pid}"
                )
                if alert_id:
                    created.append(alert_id)
        for stale_pid in set(self._resource_history) - seen:
            del self._resource_history[stale_pid]
        return created

    def analyze_connections(self, connections: Iterable[dict[str, Any]]) -> list[int]:
        if not self.expected_ports:
            return []
        created: list[int] = []
        for connection in connections:
            if str(connection.get("status", "")).upper() != "LISTEN":
                continue
            try:
                port = int(connection["local_port"])
            except (KeyError, TypeError, ValueError):
                continue
            if port in self.expected_ports:
                continue
            pid = connection.get("pid")
            evidence = (
                f"Listening port {port}; PID {pid if pid is not None else 'Unavailable'}; "
                f"process {connection.get('process', 'Unavailable')}."
            )
            alert_id = self._alert(
                RULES[4], evidence, fingerprint=f"listener:{pid}:{port}"
            )
            if alert_id:
                created.append(alert_id)
        return created

    def analyze_defender_detections(
        self, detections: Iterable[dict[str, Any]]
    ) -> list[int]:
        created: list[int] = []
        for detection in detections:
            evidence = (
                f"Threat: {detection.get('ThreatName') or 'Unavailable'} "
                f"(ID {detection.get('ThreatID') or 'Unavailable'}); "
                f"action success: {detection.get('ActionSuccess', 'Unavailable')}; "
                f"process: {detection.get('ProcessName') or 'Unavailable'}; "
                f"resources: {detection.get('Resources') or 'Unavailable'}."
            )
            detection_id = str(detection.get("DetectionID") or evidence)
            alert_id = self._alert(
                RULES[5], evidence,
                fingerprint=f"defender-detection:{detection_id}",
            )
            if alert_id:
                created.append(alert_id)
        return created

    def _alert(self, rule: DetectionRule, evidence: str, fingerprint: str) -> int | None:
        full_details = (
            f"{rule.description}\nEvidence: {evidence}\n"
            f"Recommended investigation: {rule.investigation}"
        )
        identifier = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        alert_id = self.database.create_alert(
            rule.severity, rule.name, full_details, rule.data_source, rule.rule_id,
            cooldown_seconds=self.cooldown_seconds, fingerprint=identifier,
        )
        if alert_id is not None:
            self.database.add_event_finding(
                rule.rule_id, rule.severity, rule.name, evidence, rule.data_source
            )
        return alert_id

    @staticmethod
    def _window_key(value: datetime) -> str:
        return value.replace(
            minute=(value.minute // 10) * 10, second=0, microsecond=0
        ).isoformat()
