"""Explicit UAC-based permission handling for Windows-only observations."""
from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path


def build_administrator_command(
    executable: str,
    *,
    frozen: bool,
    script_path: str | Path,
    arguments: list[str],
) -> tuple[str, str]:
    command_arguments = list(arguments)
    if not frozen:
        command_arguments.insert(0, str(Path(script_path).resolve()))
    return executable, subprocess.list2cmdline(command_arguments)


def is_running_as_administrator() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, ctypes.ArgumentError):
        return False


def request_administrator_relaunch() -> tuple[bool, str]:
    if os.name != "nt":
        return False, "Administrator relaunch is available on Windows only."
    if is_running_as_administrator():
        return True, "SecureWatch is already running with administrator permissions."

    executable, parameters = build_administrator_command(
        sys.executable,
        frozen=bool(getattr(sys, "frozen", False)),
        script_path=Path(__file__).resolve().parents[1] / "main.py",
        arguments=list(sys.argv[1:]),
    )
    try:
        shell_execute = ctypes.windll.shell32.ShellExecuteW
        shell_execute.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
        ]
        shell_execute.restype = ctypes.c_void_p
        result = shell_execute(
            None, "runas", executable, parameters,
            str(Path.cwd()), 1,
        )
    except (OSError, ctypes.ArgumentError) as exc:
        return False, f"Windows could not request elevation: {exc}"
    result_code = int(result or 0)
    if result_code <= 32:
        if result_code == 5:
            return False, "Windows denied the elevation request; this can also mean the UAC prompt was declined."
        return False, f"Windows could not start the elevated app (ShellExecute error {result_code})."
    return True, "Windows accepted the elevation request. Complete the UAC prompt to continue."
