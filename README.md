# Windows Update Tweaker

**Version:** 1.0

This Python script provides a graphical user interface (GUI) to apply various tweaks to control and manage Windows Update behavior on Windows 10 and newer operating systems. It aims to give users more granular control over updates by modifying system settings, services, scheduled tasks, and network configurations.

## Features

The tool offers the following reversible tweaks:

1.  **Windows Update Service (wuauserv)**:
    *   Disable the main Windows Update service.
    *   Enable the service (sets to Manual/Demand start).
2.  **Update Medic Service (WaaSMedicSvc)**:
    *   Disable the Windows Update Medic Service.
    *   Attempt to enable the service (sets to Manual/Demand start - see Known Limitations).
3.  **Update Orchestrator Service (UsoSvc)**:
    *   Disable the Update Orchestrator Service.
    *   Enable the service (sets to Manual/Demand start).
4.  **Hosts File Block**:
    *   Add entries to the `hosts` file to block common Windows Update domains by redirecting them to `127.0.0.1`.
    *   Remove these specific entries from the `hosts` file.
5.  **Registry: NoAutoUpdate**:
    *   Set the `NoAutoUpdate` registry key (`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`) to `1` to instruct Windows Update not to automatically download and install updates.
    *   Remove this registry key.
6.  **GPO: DisableWindowsUpdateAccess**:
    *   Set the `DisableWindowsUpdateAccess` Group Policy registry key (`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`) to `1` to disable access to Windows Update features via the Settings UI.
    *   Remove this registry key.
7.  **Lock `wuauclt.exe` (ACL)**:
    *   Modify the Access Control List (ACL) of `C:\Windows\System32\wuauclt.exe` to deny write permissions for `Everyone`. This can prevent the file from being modified or used by certain update processes.
    *   Restore default permissions for `wuauclt.exe`.
8.  **Rename `wuauclt.exe`**:
    *   Rename `C:\Windows\System32\wuauclt.exe` to `wuauclt.exe.bak`, effectively disabling it.
    *   Rename `wuauclt.exe.bak` back to `wuauclt.exe`.
    *   **Note**: This tweak and "Lock `wuauclt.exe`" are mutually exclusive. One must be undone before the other can be applied.
9.  **Scheduled Tasks**: 
    *   Disable a predefined list of Windows Update-related scheduled tasks.
    *   Attempt to re-enable these tasks.
10. **Firewall Block (Outbound)**:
    *   Create an outbound Windows Firewall rule to block connections to a predefined list of Microsoft update-related hostnames. The script attempts to resolve these hostnames to IP addresses at the time of rule creation.
    *   Delete this specific firewall rule.

## Requirements

*   **Operating System**: Windows 10 or newer.
*   **Python**: Python 3.x installed.
*   **Administrator Privileges**: The script **must** be run with Administrator privileges to modify system settings, services, registry, and files in protected locations.

## Usage

1.  Ensure you have Python 3 installed.
2.  Download the script (e.g., `WindowsUpdateTweaker_v1.0_minimal.py`).
3.  Open a Command Prompt (cmd.exe) or PowerShell **as Administrator**.
4.  Navigate to the directory where you saved the script.
5.  Run the script using: `python WindowsUpdateTweaker_v1.0_minimal.py`
6.  The GUI will appear, showing the status of each tweak. Click "Apply" to activate a tweak or "Undo" to revert it.

## How It Works

*   **Services**: Uses `sc.exe` (Service Control) commands to change the start type of services (e.g., `sc config <ServiceName> start= disabled` or `start= demand`).
*   **Hosts File**: Modifies `C:\Windows\System32\drivers\etc\hosts` to add or remove specific blocking entries.
*   **Registry**: Uses `winreg` module to read and write to specified registry keys.
*   **File ACLs & Renaming**: Uses `takeown.exe` and `icacls.exe` to manage file ownership and permissions, and `os.rename` for renaming. It handles `TrustedInstaller` ownership by temporarily taking ownership, performing the action, and then attempting to restore `TrustedInstaller` as the owner.
*   **Scheduled Tasks**: Uses `schtasks.exe` to query, disable, and enable tasks.
*   **Firewall**: Uses `netsh.exe advfirewall` commands to add and delete outbound block rules. It performs a DNS lookup for hostnames before creating the rule.

## Known Limitations & Important Notes

*   **Administrator Rights**: Failure to run the script as Administrator will result in most, if not all, tweaks failing, typically with "Access Denied" errors.
*   **Windows Update Medic Service (WaaSMedicSvc)**: This service is heavily protected by Windows. While the script attempts to disable it and re-enable it (to "Manual" start), re-enabling it often fails with an "Access Denied (Error 5)" message. This is a known Windows behavior. Disabling it might be effective, but reverting it automatically might not always be possible via the script. Refer to `waasmedicsvc_management_notes.md` (if provided with the script) for more details.
*   **Localization**: The script attempts to handle German and English outputs for some commands (e.g., `icacls`, `netsh`, `schtasks`). However, behavior on other localized Windows versions might vary.
*   **Reversibility**: All tweaks are designed to be reversible. However, system configurations can be complex. Always ensure you understand what a tweak does before applying it. Creating a system restore point before making significant changes is recommended.
*   **`wuauclt.exe` Tweaks**: The "Lock `wuauclt.exe` (ACL)" and "Rename `wuauclt.exe`" tweaks are mutually exclusive. If one is active, the other cannot be applied until the first is undone. The GUI provides warnings for this.
*   **Firewall DNS Resolution**: The firewall block relies on DNS resolution at the time the rule is created. If the IP addresses for the update servers change, the rule might become less effective. The script does not dynamically update these IPs.
*   **Log File**: The script creates a `tweak_log.txt` file in the same directory it is run from. This log records all actions, command outputs, and errors, which is useful for troubleshooting.

## Disclaimer

This script modifies system settings. Use it at your own risk. The author is not responsible for any damage or unintended consequences that may arise from its use. Always back up important data and consider creating a system restore point before applying these tweaks.

## License

This project is licensed under the MIT License.

```text
MIT License

Copyright (c) 2025 [Your Name or Organization Here]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or submit a pull request if you have suggestions for improvement.

