"""Microsoft Defender status and scan requests via supported PowerShell cmdlets."""
from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any

from utils.powershell import run_powershell


def get_defender_status() -> dict[str, Any]:
    if platform.system() != "Windows":
        raise RuntimeError("Microsoft Defender integration is available on Windows only.")
    script = (
        "$ErrorActionPreference='Stop'; "
        "$status = Get-MpComputerStatus; "
        "$quickAge = if ([uint64]$status.QuickScanAge -eq 4294967295) {$null} "
        "else {$status.QuickScanAge}; "
        "$fullAge = if ([uint64]$status.FullScanAge -eq 4294967295) {$null} "
        "else {$status.FullScanAge}; "
        "$signatureUpdated = if ($status.AntivirusSignatureLastUpdated) "
        "{$status.AntivirusSignatureLastUpdated.ToString('o')} else {$null}; "
        "$quickStart = if ($status.QuickScanStartTime) "
        "{$status.QuickScanStartTime.ToString('o')} else {$null}; "
        "$quickEnd = if ($status.QuickScanEndTime) "
        "{$status.QuickScanEndTime.ToString('o')} else {$null}; "
        "$fullStart = if ($status.FullScanStartTime) "
        "{$status.FullScanStartTime.ToString('o')} else {$null}; "
        "$fullEnd = if ($status.FullScanEndTime) "
        "{$status.FullScanEndTime.ToString('o')} else {$null}; "
        "[pscustomobject]@{"
        "AMServiceEnabled=$status.AMServiceEnabled;"
        "AntivirusEnabled=$status.AntivirusEnabled;"
        "RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled;"
        "AntivirusSignatureLastUpdated=$signatureUpdated;"
        "AntivirusSignatureVersion=$status.AntivirusSignatureVersion;"
        "QuickScanAgeDays=$quickAge;QuickScanStartTime=$quickStart;"
        "QuickScanEndTime=$quickEnd;FullScanAgeDays=$fullAge;"
        "FullScanStartTime=$fullStart;FullScanEndTime=$fullEnd"
        "} | ConvertTo-Json -Compress"
    )
    succeeded, output = run_powershell(script)
    if not succeeded:
        raise RuntimeError(output)
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Microsoft Defender returned invalid status data.") from exc
    if not isinstance(result, dict):
        raise RuntimeError("Microsoft Defender status was empty or unexpected.")
    return result


def get_defender_detections(limit: int = 100) -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        raise RuntimeError("Microsoft Defender history is available on Windows only.")
    if isinstance(limit, bool) or not 1 <= limit <= 1000:
        raise ValueError("Defender history limit must be between 1 and 1000.")
    script = (
        "$ErrorActionPreference='Stop'; "
        f"$items = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First {limit}); "
        "$normalized = @($items | ForEach-Object { "
        "[pscustomobject]@{"
        "InitialDetectionTime=if ($_.InitialDetectionTime) "
        "{$_.InitialDetectionTime.ToString('o')} else {$null};"
        "LastThreatStatusChangeTime=if ($_.LastThreatStatusChangeTime) "
        "{$_.LastThreatStatusChangeTime.ToString('o')} else {$null};"
        "ThreatID=$_.ThreatID;ThreatName=$_.ThreatName;Resources=$_.Resources;"
        "ProcessName=$_.ProcessName;ActionSuccess=$_.ActionSuccess;"
        "CurrentThreatExecutionStatusID=$_.CurrentThreatExecutionStatusID;"
        "DetectionID=$_.DetectionID"
        "} }); "
        "ConvertTo-Json -InputObject @($normalized) -Depth 4 -Compress"
    )
    succeeded, output = run_powershell(script, timeout=45)
    if not succeeded:
        raise RuntimeError(output)
    try:
        result = json.loads(output) if output else []
    except json.JSONDecodeError as exc:
        raise RuntimeError("Microsoft Defender returned invalid threat history data.") from exc
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
        raise RuntimeError("Microsoft Defender threat history had an unexpected format.")
    return result


def request_scan(scan_type: str, folder: str | Path | None = None) -> str:
    if platform.system() != "Windows":
        raise RuntimeError("Microsoft Defender scans are available on Windows only.")
    if scan_type not in {"QuickScan", "FullScan", "CustomScan"}:
        raise ValueError("Unsupported Defender scan type.")
    if scan_type == "CustomScan":
        if folder is None:
            raise ValueError("A directory is required for a custom scan.")
        path = Path(folder)
        if not path.is_dir():
            raise ValueError("Custom scan path must be an existing directory.")
        escaped = str(path.resolve()).replace("'", "''")
        path_argument = f" -ScanPath '{escaped}'"
    else:
        if folder is not None:
            raise ValueError("A folder can only be used with a custom scan.")
        path_argument = ""
    script = (
        "$ErrorActionPreference='Stop'; "
        f"Start-MpScan -ScanType {scan_type}{path_argument}; "
        f"'Scan request accepted by PowerShell: {scan_type}. "
        "This does not confirm that the scan is complete.'"
    )
    succeeded, output = run_powershell(script, timeout=60)
    if not succeeded:
        raise RuntimeError(output)
    return output
