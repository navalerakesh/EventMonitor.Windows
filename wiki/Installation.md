# Installation

## Prerequisites

| Requirement | Details |
|:------------|:--------|
| **PowerShell** | 7.4 or later (Core edition) |
| **Operating System** | Windows 10 / 11 / Server 2016+ |
| **Privileges** | Administrator account (event log access requires elevation) |
| **Optional** | Azure Application Insights resource (for cloud telemetry) |

> **Note:** The module does **not** run on Windows PowerShell 5.1. It requires PowerShell 7.4+ (`pwsh.exe`).

### Check Your PowerShell Version

```powershell
$PSVersionTable.PSVersion
```

If you see `5.x`, install PowerShell 7 from the [official releases](https://github.com/PowerShell/PowerShell/releases) or via:

```powershell
winget install Microsoft.PowerShell
```

---

## Install from PowerShell Gallery (Recommended)

```powershell
Install-Module -Name EventMonitor.Windows -Scope CurrentUser
```

To install system-wide (requires elevation):

```powershell
Install-Module -Name EventMonitor.Windows -Scope AllUsers
```

### Verify Installation

```powershell
Get-Module -Name EventMonitor.Windows -ListAvailable

# Expected output:
#   ModuleType Version  Name
#   ---------- -------  ----
#   Script     1.0.1    EventMonitor.Windows
```

---

## Install from Source

```powershell
# Clone the repository
git clone https://github.com/navalerakesh/EventMonitor.Windows.git
cd EventMonitor.Windows

# Import directly from the manifest
Import-Module .\EventMonitor.Windows.psd1 -Force
```

---

## Upgrading

```powershell
# Update to the latest version
Update-Module -Name EventMonitor.Windows

# Verify the new version
Get-Module -Name EventMonitor.Windows -ListAvailable
```

If you have an active monitoring service running, restart it after upgrading:

```powershell
Stop-EventMonitor -TaskName 'WinEventMonitor'
Start-EventMonitor -TaskName 'WinEventMonitor'
```

---

## Uninstalling

### Remove the Scheduled Task First

```powershell
Unregister-EventMonitor -TaskName 'WinEventMonitor'
```

### Remove the Module

```powershell
Uninstall-Module -Name EventMonitor.Windows
```

### Clean Up Data (Optional)

The module stores logs and configuration in `C:\ProgramData\WindowsEventMonitor\`. To remove all data:

```powershell
Remove-Item -Path 'C:\ProgramData\WindowsEventMonitor' -Recurse -Force
```

---

**Next:** [Quick Start Guide](Quick-Start-Guide)
