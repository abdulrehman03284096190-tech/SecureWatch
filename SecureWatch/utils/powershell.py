"""Bounded PowerShell execution for supported Windows read and scan requests."""
from __future__ import annotations

import platform
import shutil
import subprocess


def run_powershell(script: str, timeout: int = 30) -> tuple[bool, str]:
    if platform.system() != "Windows":
        return False, "This feature is available on Windows only."
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        return False, "PowerShell was not found."
    if not 1 <= timeout <= 600:
        raise ValueError("PowerShell timeout must be between 1 and 600 seconds.")
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            capture_output=True, text=True, timeout=timeout, encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "PowerShell command timed out."
    except OSError as exc:
        return False, f"Could not start PowerShell: {exc}"
    if result.returncode:
        return False, (result.stderr or result.stdout or "PowerShell command failed").strip()
    return True, result.stdout.strip()
