# SecureWatch — Windows Security & Monitoring System

SecureWatch is a local-first, defensive Windows monitoring application built with
Python and CustomTkinter. It combines system/process observations, bounded
Windows Event Log collection, Microsoft Defender status/scan requests, local
file hashing, network connection snapshots, explainable rule findings, SQLite
history, and CSV/PDF reports.

SecureWatch is an educational monitoring tool. It does not replace Microsoft
Defender, a professional EDR, or an analyst investigation. An alert is a
reason to review evidence; no alert is not a guarantee of security.

## Features

- Dashboard with computer/OS/user, uptime, CPU, memory, disk, process count,
  persisted alert/event counts, Defender query status, and monitoring state.
- Process list with CPU/memory, start time, executable path, username, search,
  CPU/memory sorting, details, and CSV export. Process termination is not
  implemented.
- Latest bounded System, Application, or Security event retrieval with event
  ID/severity/text filtering and CSV export. Event 4624/4625/4688/1102 presence
  is contextual evidence, not proof of an attack.
- Microsoft Defender status query and confirmed Quick, Full, or Custom scan
  requests, plus available retained threat-detection history. A request being
  accepted does not mean the scan has completed.
- File or directory SHA-256 analysis and metadata. Directory traversal does
  not follow symlinks; unreadable and changing files are labeled. Optional
  local SHA-256 indicators are user-managed; matches are not definitive
  malware verdicts. No file contents are uploaded or executed.
- Network connection snapshots with process name, endpoints, state, filter,
  and CSV export. Connections are not automatically blocked.
- Rule engine for repeated failed logons, event error bursts, configured local
  hash matches, sustained resource use, and unconfigured listening ports.
  Rules provide evidence/recommended investigation and persistent cooldown
  deduplication. Resource alerts are Low severity and require repeated samples.
- Periodic monitoring with start/pause/resume/stop controls, one managed worker,
  interval validation, status, and latest cycle summary. It is polling, not an
  instantaneous event subscription.
- SQLite alert review, investigation notes, audit records, file history,
  Windows events, detection findings, settings, and monitoring snapshots.
- Escaped, paginated PDF reports and CSV exports.
- Validated local JSON settings and rotating application logs.

## Requirements

- Windows 10/11 recommended; Python 3.11 or newer.
- PowerShell for Windows Event Log and Defender features.
- Administrator permissions may be needed for the Security log, connection
  ownership, or some Defender operations. SecureWatch does not request
  elevation automatically. The Dashboard has an explicit “Relaunch as
  Administrator” action that asks Windows to show its normal UAC prompt;
  approve that prompt yourself to launch an elevated instance. A standard
  account may require administrator credentials. Declining UAC keeps the
  current app running with available standard-user data.
- Dependencies are listed in `requirements.txt`; the current Windows event
  and Defender integrations use PowerShell.

## Installation and launch in VS Code

Open the `SecureWatch` directory in VS Code, open a PowerShell terminal, and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

For a one-command setup and launch, run the included PowerShell helper:

```powershell
.\run_securewatch.ps1
```

It creates `.venv`, verifies Python 3.11+, installs the dependencies, and starts
the app. It does not elevate the process; use the Dashboard's explicit UAC
relaunch button only when you need administrator-only observations.

To run the packaged Windows build, keep the full `dist\SecureWatch` folder
together and start:

```powershell
.\dist\SecureWatch\SecureWatch.exe
```

The packaged app also starts as a standard user. Its data and logs remain under
`%LOCALAPPDATA%\SecureWatch`; approve the optional Windows UAC prompt only if
you choose to relaunch for administrator-only observations.

If script activation is restricted, run from Command Prompt:

```cmd
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python main.py
```

## Settings and data locations

- Runtime database and settings: `%LOCALAPPDATA%\SecureWatch\securewatch.db`
  and `%LOCALAPPDATA%\SecureWatch\settings.json`.
- Runtime log: `%LOCALAPPDATA%\SecureWatch\securewatch.log`, rotated with
  bounded size and backups.
- `config.json` contains safe defaults used to initialize the local settings.
  Configure interval, cooldown, CPU/RAM thresholds, sustained observation
  count, event retrieval limit, report directory, appearance, and local SHA-256
  indicator list in the Settings tab. Configure expected listening ports to
  enable listener policy checks; leaving that list empty disables those alerts.
  The failed-logon/error event thresholds and analysis window are configurable
  to tune repeated-event rules and reduce noisy findings.
- No credentials, access tokens, or external service keys are stored.

## Tests and checks

```powershell
python -m pytest -q
python -m compileall -q .
python -m pip check
```

The tests use temporary SQLite databases and synthetic event/process/file
fixtures, with mocked Windows integration responses. They do not require
administrator privileges, start Defender scans, or create real security
events. Latest verification on Windows 11 / Python 3.15: **54 passed** with no
skips, compilation succeeded, and `pip check` reported no broken requirements.
A standard-user check confirmed GUI startup, live system/process/network data,
System/Application event queries, and Defender status/history queries. The
Security log was denied by Windows for that account. Event collection's
empty-result and access-denied paths, PowerShell errors/timeouts, and report
empty-database/error paths have automated tests. Elevated access, Defender
scan requests, and data availability still require verification on each target
system; no elevation or scan was initiated during these checks.

## Permissions and limitations

- Reading the Windows Security log and process/network ownership may be denied
  to a standard user. System and Application logs can still be queried
  independently. A denied log query displays the Windows error and points to
  the Dashboard's optional UAC relaunch action; declining the prompt leaves the
  standard-user session running.
- Defender cmdlets may be absent, disabled by policy, or unavailable when a
  third-party antivirus is active. SecureWatch reports query failures and
  does not change Defender configuration or exclusions.
- Event data availability depends on audit configuration and log retention.
- CPU and RAM high-water observations are heuristics and can be normal workload.
- Local hashes only match the user's configured list; "No local indicator
  match" does not establish that a file is safe.
- Reports use retained local observations. If a data source was not queried,
  unavailable data is not fabricated.
- SecureWatch does not kill processes, quarantine/delete files, block
  connections, hide activity, bypass Windows controls, or upload telemetry.

## Troubleshooting

- **Missing package:** activate `.venv`, then `python -m pip install -r
  requirements.txt`.
- **PowerShell/Event Viewer error:** confirm PowerShell is installed, use a
  supported Windows account, and check the selected log's permissions.
- **Defender unavailable:** check whether Microsoft Defender cmdlets are
  present and whether endpoint policy permits status queries.
- **Network ownership unavailable:** refresh without elevation first; fields
  may be unavailable by design.
- **PDF generation error:** ensure ReportLab installed successfully and the
  destination is writable.
- **Settings/database error:** inspect the local log; do not delete the
  database if you need its alert or investigation history.

## Build, install, and uninstall

The build machine needs Windows, the existing PyInstaller payload at
`dist\SecureWatch` (including `SecureWatch.exe` and `_internal`), and Inno Setup
6. The compiler can be installed in the project workspace or a standard Inno
Setup 6 location. The installer build does not need Python or rebuild the app.

From the `SecureWatch` project directory, run:

```powershell
.\build_securewatch_installer.ps1
```

The script validates the app executable and runtime directory, discovers
`ISCC.exe`, and writes the installer to
`..\Output\SecureWatch-Setup.exe` (the workspace root's `Output` directory).
The installer installs for the current user without requiring elevation,
creates a Start Menu shortcut, and offers an optional desktop shortcut and
launch. Python is not required on computers where the installer is run.

To install, run `Output\SecureWatch-Setup.exe` and follow the setup wizard.
To uninstall, use **Settings > Apps > Installed apps > SecureWatch > Uninstall**
or the SecureWatch entry in the Start Menu. Uninstalling removes the installed
application but preserves `%LOCALAPPDATA%\SecureWatch`, including its database,
settings, and logs.

Troubleshooting: if the build reports missing payload files, rebuild the
PyInstaller distribution using `python -m PyInstaller --noconfirm --clean
SecureWatch.spec`. If ISCC is not found, install Inno Setup 6 in the workspace
or a standard install location and rerun the script. If setup is blocked by
Windows, verify the installer source and file properties; this unsigned
installer has no digital signature or publisher certificate. Permissions for
Security logs and some Defender operations still depend on the installed
user's account and the app's optional UAC relaunch action.

## Project layout

```text
tests/      non-privileged unit tests
SecureWatch_Project/
  Inno Setup 6/ISCC.exe             local installer compiler
  Output/SecureWatch-Setup.exe      generated installer
  SecureWatch/
    dist/SecureWatch/
      SecureWatch.exe
      _internal/                     bundled runtime and resources
    SecureWatch.iss
    build_securewatch_installer.ps1
    core/                            collection, analysis, detection, monitoring
    database/                        SQLite schema, migrations, persistence
    reporting/                       PDF and CSV exports
    utils/                           validation, logging, PowerShell helper
    tests/                           non-privileged unit tests
    main.py                          CustomTkinter desktop interface
```
