# Quick Start Guide

Get EventMonitor.Windows running in under 5 minutes.

---

## Step 1 — Install and Import

```powershell
Install-Module -Name EventMonitor.Windows -Scope CurrentUser
Import-Module EventMonitor.Windows
```

## Step 2 — Choose a Monitoring Level

```powershell
# See all available event groups
Get-EventGroups | Format-Table Name, Enabled, EventCount, Description
```

Pick one of four presets:

| Level | Groups | Best For |
|:------|:-------|:---------|
| **Minimum** | 4 groups (Logon, Logoff, SSH, RDP) | Lightweight session tracking |
| **Standard** | 13 groups | Recommended for most environments |
| **High** | All 17 groups | Full security visibility |
| **Custom** | You choose | Fine-grained control |

```powershell
# Option A: Standard (recommended)
Set-MonitoringLevel -Level Standard

# Option B: High (everything)
Set-MonitoringLevel -Level High

# Option C: Custom (only what you need)
Set-MonitoringLevel -Level Custom -Groups 'Logon', 'SSH', 'RDP', 'AuditTampering', 'Persistence'
```

## Step 3 — Register the Service

### Without Application Insights (local-only)

```powershell
Register-EventMonitor
```

Events are logged locally to `C:\ProgramData\WindowsEventMonitor\Logs\`.

### With Application Insights

```powershell
# Set connection string via environment variable (recommended)
[System.Environment]::SetEnvironmentVariable(
    'APPINSIGHTS_CONNECTION_STRING',
    'InstrumentationKey=your-key;IngestionEndpoint=https://....applicationinsights.azure.com/',
    'Machine'
)

# Register the service
Register-EventMonitor
```

> **Tip:** The connection string is resolved from: environment variable → `LogAnalyticsConString.txt` file → parameter. Environment variable is the most secure method.

## Step 4 — Verify It's Running

```powershell
Get-EventMonitor
```

Expected output:

```
TaskName         : WinEventMonitor
Status           : Running
NextRunTime      : (at next boot)
LastRunResult    : 0 (Success)
```

## Step 5 — Done!

The module is now monitoring your system in real-time. Events are captured the instant they occur — no polling delay.

---

## Optional: Enable Event Journal

For structured JSONL output (great for AI tools or SIEM):

```powershell
Set-EventJournal -Enabled $true -RetentionDays 30
```

Journal files are written to `EventMonitor/Telemetry/Journal/EventJournal-YYYY-MM-DD.jsonl`.

## Optional: One-Shot Diagnostic Scan

To test without registering, scan the last 60 minutes:

```powershell
Invoke-EventMonitor -LookBackMinutes 60
```

---

## What's Happening Behind the Scenes

```
┌─────────────────────────────────────────────────────────────┐
│  Windows boots → Task Scheduler starts WinEventMonitor      │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │ EventLog     │───▶│ Event        │───▶│ Telemetry    │   │
│  │ Watcher(s)   │    │ Processors   │    │ Sinks        │   │
│  │ (real-time)  │    │ (17 groups)  │    │ (pluggable)  │   │
│  └──────────────┘    └──────────────┘    └──────────────┘   │
│         ▲                                                    │
│  ┌──────────────┐                                            │
│  │ Watchdog     │  Every 30 min: health check, auto-repair  │
│  │ Service      │  Catch-up sweep for any missed events      │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘
```

---

**Next:** [Configuration](Configuration) · [Event Groups Reference](Event-Groups-Reference)
