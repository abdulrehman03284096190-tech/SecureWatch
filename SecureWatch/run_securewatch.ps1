$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pythonLauncher) {
    & py -m venv .venv
} else {
    $pythonCommand = Get-Command python -ErrorAction Stop
    & $pythonCommand.Source -m venv .venv
}
if ($LASTEXITCODE -ne 0) {
    throw "Could not create .venv. Install Python 3.11 or newer and retry."
}

$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
& $venvPython -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "SecureWatch requires Python 3.11 or newer. Install a supported Python runtime and recreate .venv."
}

& $venvPython -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed. Check network access and requirements.txt."
}

& $venvPython main.py
if ($LASTEXITCODE -ne 0) {
    throw "SecureWatch exited with an error. Check %LOCALAPPDATA%\SecureWatch\securewatch.log."
}
