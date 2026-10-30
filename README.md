# SecureWatch
### Windows Security Monitoring Application

SecureWatch is a Windows security monitoring application designed to help users monitor security-related events, review suspicious activity, and improve their understanding of Windows system security.

The project provides a foundation for Windows security monitoring and analysis, with a packaged Windows application and an installer for convenient installation.

---

## Overview

Windows systems generate security events that can help identify failed login attempts, suspicious activity, and potential security issues. However, reviewing these events manually can be time-consuming.

SecureWatch aims to make security monitoring more accessible through an application that helps users examine relevant Windows security information.

The project is developed for cybersecurity learning, security monitoring, and practical exploration of Windows security logs.

## Features

- **Windows Security Monitoring:** Supports security monitoring functionality implemented in the application.
- **Security Event Analysis:** Helps users examine relevant security events and activity.
- **Windows Application:** Distributed as a Windows executable.
- **Easy Installation:** Includes a Windows setup installer.
- **Start Menu Shortcut:** Provides convenient access after installation.
- **Optional Desktop Shortcut:** Allows users to create a desktop shortcut during installation.
- **Application Data Storage:** Creates application data files as required by its implemented functionality.
- **Uninstallation Support:** Supports removal through the Windows uninstall mechanism.

> Note: The available monitoring capabilities depend on the features implemented in the current version. Do not assume that every Windows security event is collected or that all threats are detected automatically.

---

## Application Preview

Add screenshots of the actual application here.

For example:

```markdown
![SecureWatch Dashboard](screenshots/dashboard.png)
```

Create a `screenshots` folder in the repository and place your application screenshots inside it.

## Technology Stack

The application is distributed as a Windows executable and packaged using Inno Setup.

| Component | Technology |
|---|---|
| Operating system | Microsoft Windows |
| Application | SecureWatch |
| Executable | SecureWatch.exe |
| Installer | Inno Setup 6 |
| Installer configuration | Inno Setup Script (`.iss`) |
| Build automation | PowerShell |
| Version control | Git and GitHub |

Update this table if your implementation uses additional technologies or frameworks.

---

## Download and Installation

### Option 1: Download the Installer from GitHub

1. Open the repository's **Releases** section.
2. Select the latest release.
3. Download `SecureWatch-Setup.exe` from the release assets.
4. Run the installer.
5. Follow the installation instructions.
6. Launch SecureWatch from the Windows Start menu.

**Important:** If no release has been published yet, the installer may not be available in the Releases section.

### Option 2: Download the Project

Clone the repository:

```powershell
git clone https://github.com/abdulrehman03284096190-tech/SecureWatch.git
```

Navigate into the project:

```powershell
cd SecureWatch
```

The repository must contain the relevant application files or build instructions for this method to work.

### Running the Application

If you have the packaged application, launch:

```text
SecureWatch.exe
```

Keep the `_internal` folder alongside `SecureWatch.exe` if it is included in the application distribution.

For a packaged release, using the installer is the recommended installation method.

---

## Build the Windows Installer

The project includes an Inno Setup installer definition and a PowerShell build script.

### Prerequisites

- Windows
- PowerShell
- Inno Setup 6
- The existing SecureWatch application build

### Build Instructions

1. Clone or download the project.
2. Open PowerShell in the project directory.
3. Ensure the application executable and `_internal` folder exist in the expected locations.
4. Ensure Inno Setup 6 is installed.
5. Run the build script:

```powershell
.\build_securewatch_installer.ps1
```

If PowerShell blocks script execution, you can use a process-scoped execution-policy bypass:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\build_securewatch_installer.ps1"
```

Use this only when necessary and after reviewing the script.

### Build Output

After a successful build, the installer should be generated at:

```text
Output/
└── SecureWatch-Setup.exe
```

The installer packages the existing application executable and its required `_internal` dependencies.

The build script and installer definition must be included in the repository for other developers to reproduce the installer build.

---

## Project Structure

The following is an example of the expected distribution structure. Your actual source repository may contain additional files and directories.

```text
SecureWatch/
│
├── README.md
├── .gitignore
├── SecureWatch.iss
├── build_securewatch_installer.ps1
│
├── SecureWatch.exe
├── _internal/
│
└── Output/
    └── SecureWatch-Setup.exe
```

If the project contains a separate source-code directory, document that directory and its contents here.

---

## Security and Permissions

SecureWatch is intended for legitimate Windows security monitoring and analysis.

- Use the application only on systems you own or are authorized to monitor.
- Protect security logs and application data from unauthorized access.
- Do not publish passwords, API keys, access tokens, or other secrets in the repository.
- Review application permissions before deployment.
- Follow organizational security and privacy policies.
- Verify findings before treating an event as evidence of malicious activity.

Windows may restrict access to some security logs depending on user permissions and system configuration.

## Known Limitations

- Monitoring and detection capabilities are limited to the functionality implemented in the current application.
- Some Windows security events may require additional permissions or system auditing configuration.
- A security event does not necessarily indicate malicious activity.
- The installer is currently unsigned, so Windows may display security warnings.
- Detection accuracy and coverage depend on the application's implemented features and the system's configuration.

---

## Future Improvements

Potential future enhancements include:

- Improved security event filtering and analysis.
- A centralized security monitoring dashboard.
- More detailed event summaries.
- Configurable monitoring rules.
- Improved reporting and export functionality.
- Better error handling and diagnostic logging.
- Application version management.
- Code signing and release automation.
- Automated testing and continuous integration.

These are potential improvements, not claims that the features are already implemented.

---

## Contributing

Contributions, suggestions, and bug reports are welcome.

To contribute:

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test your changes.
5. Submit a pull request describing your improvements.

Please avoid committing sensitive information, personal data, or confidential security logs.

## Reporting Issues

If you encounter a bug or installation problem, open a GitHub issue and include:

- Windows version.
- SecureWatch version, if available.
- Steps to reproduce the problem.
- Relevant error messages.
- Expected and actual behavior.

Remove passwords, personal information, and sensitive system details from logs before sharing them.

---

## License

No license has been specified yet.

Before distributing or accepting contributions to this project, add a `LICENSE` file describing the permissions and restrictions you want to apply.

Until a license is added, others generally do not have permission to reuse, modify, or redistribute your copyrighted code beyond rights granted by applicable law.

## Author

**Abdul Rehman**

GitHub: [abdulrehman03284096190-tech](https://github.com/abdulrehman03284096190-tech)

## Disclaimer

SecureWatch is a security monitoring project intended for educational and legitimate defensive security purposes.

It is provided without guarantees of detecting every security threat. Users are responsible for validating findings and ensuring that their use of the application complies with applicable laws and organizational policies.
