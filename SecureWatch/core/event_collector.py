"""Bounded Windows Event Log collection through Get-WinEvent."""
from __future__ import annotations

import json
import platform
from typing import Any

from utils.powershell import run_powershell

ALLOWED_LOGS = {"System", "Application", "Security"}


def collect_events(log_name: str, limit: int = 100) -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        raise RuntimeError("Windows Event Viewer is available on Windows only.")
    if log_name not in ALLOWED_LOGS:
        raise ValueError("Unsupported event log.")
    if isinstance(limit, bool) or not 1 <= limit <= 2000:
        raise ValueError("Event query limit must be between 1 and 2000.")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"try {{ $items = @(Get-WinEvent -LogName '{log_name}' "
        f"-MaxEvents {limit} -ErrorAction Stop) }} catch {{ "
        "if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') "
        "{ '[]'; exit 0 }; throw }; "
        "$items = $items | "
        "Select-Object @{Name='Time';Expression={$_.TimeCreated.ToString('o')}},"
        "Id,RecordId,LogName,LevelDisplayName,ProviderName,Message; "
        "$items | ConvertTo-Json -Depth 3 -Compress"
    )
    succeeded, output = run_powershell(script, timeout=45)
    if not succeeded:
        raise RuntimeError(output)
    if not output:
        return []
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PowerShell returned invalid event JSON.") from exc
    items = result if isinstance(result, list) else [result]
    return [item for item in items if isinstance(item, dict)]
