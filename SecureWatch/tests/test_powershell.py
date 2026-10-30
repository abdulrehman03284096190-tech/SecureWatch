import subprocess

from utils import powershell


def _mock_windows_powershell(monkeypatch, run):
    monkeypatch.setattr(powershell.platform, "system", lambda: "Windows")
    monkeypatch.setattr(powershell.shutil, "which", lambda _name: "powershell.exe")
    monkeypatch.setattr(powershell.subprocess, "run", run)


def test_powershell_returns_successful_output(monkeypatch):
    _mock_windows_powershell(
        monkeypatch,
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["powershell.exe"], returncode=0, stdout="  result  ", stderr=""
        ),
    )

    assert powershell.run_powershell("'result'") == (True, "result")


def test_powershell_reports_command_failure(monkeypatch):
    _mock_windows_powershell(
        monkeypatch,
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=["powershell.exe"], returncode=1, stdout="", stderr="Access denied"
        ),
    )

    assert powershell.run_powershell("Get-WinEvent") == (False, "Access denied")


def test_powershell_reports_timeout(monkeypatch):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("powershell.exe", 2)

    _mock_windows_powershell(monkeypatch, timeout)

    assert powershell.run_powershell("Get-WinEvent", timeout=2) == (
        False, "PowerShell command timed out."
    )


def test_powershell_reports_missing_executable(monkeypatch):
    monkeypatch.setattr(powershell.platform, "system", lambda: "Windows")
    monkeypatch.setattr(powershell.shutil, "which", lambda _name: None)

    assert powershell.run_powershell("Get-WinEvent") == (
        False, "PowerShell was not found."
    )
