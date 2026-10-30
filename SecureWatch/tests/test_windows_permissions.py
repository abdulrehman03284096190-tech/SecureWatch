import os

import pytest

import utils.windows_permissions as windows_permissions
from utils.windows_permissions import build_administrator_command


@pytest.mark.skipif(os.name != "nt", reason="Windows UAC integration")
def test_elevation_uses_explicit_wide_character_shell_execute(monkeypatch):
    class FakeShellExecute:
        argtypes = None
        restype = None
        arguments = None

        def __call__(self, *arguments):
            self.arguments = arguments
            return 33

    fake_shell_execute = FakeShellExecute()
    monkeypatch.setattr(
        windows_permissions.ctypes.windll.shell32,
        "ShellExecuteW",
        fake_shell_execute,
    )
    monkeypatch.setattr(
        windows_permissions, "is_running_as_administrator", lambda: False
    )
    monkeypatch.setattr(windows_permissions.sys, "executable", "C:\\Python\\python.exe")
    monkeypatch.setattr(windows_permissions.sys, "argv", ["main.py", "--option", "two words"])
    monkeypatch.setattr(windows_permissions.sys, "frozen", False, raising=False)

    succeeded, message = windows_permissions.request_administrator_relaunch()

    assert succeeded
    assert "UAC prompt" in message
    assert fake_shell_execute.argtypes == [
        windows_permissions.ctypes.c_void_p,
        windows_permissions.ctypes.c_wchar_p,
        windows_permissions.ctypes.c_wchar_p,
        windows_permissions.ctypes.c_wchar_p,
        windows_permissions.ctypes.c_wchar_p,
        windows_permissions.ctypes.c_int,
    ]
    assert fake_shell_execute.arguments[1] == "runas"
    assert fake_shell_execute.arguments[2] == "C:\\Python\\python.exe"
    assert fake_shell_execute.arguments[3].endswith('main.py --option "two words"')


def test_source_relaunch_quotes_script_and_arguments():
    executable, parameters = build_administrator_command(
        "C:\\Python\\python.exe",
        frozen=False,
        script_path="C:\\Users\\Example User\\SecureWatch\\main.py",
        arguments=["--example", "value with spaces"],
    )
    assert executable == "C:\\Python\\python.exe"
    assert parameters == (
        '"C:\\Users\\Example User\\SecureWatch\\main.py" '
        '--example "value with spaces"'
    )


def test_packaged_relaunch_does_not_add_python_script_argument():
    executable, parameters = build_administrator_command(
        "C:\\Program Files\\SecureWatch\\SecureWatch.exe",
        frozen=True,
        script_path="C:\\ignored\\main.py",
        arguments=["--mode", "read only"],
    )
    assert executable == "C:\\Program Files\\SecureWatch\\SecureWatch.exe"
    assert parameters == '--mode "read only"'
