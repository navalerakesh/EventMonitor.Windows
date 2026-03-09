# Command Reference

All 21 exported functions organized by category.

---

## Task Management

### `Register-EventMonitor`

Creates and starts a Windows Scheduled Task for real-time event monitoring.

```powershell
Register-EventMonitor
    [-logAnalyticsConString <String>]    # Application Insights connection string (optional)
    [-sessionId <String>]                # Session ID (default: new GUID)
    [-watchdogIntervalMin <Int32>]       # Watchdog interval in minutes (default: 30, range: 5–1440)
    [-scheduledTaskName <String>]        # Task name (default: 'WinEventMonitor')
```

**Examples:**

```powershell
# Register with defaults — local-only monitoring
Register-EventMonitor

# Register with Application Insights and custom task name
Register-EventMonitor -logAnalyticsConString 'InstrumentationKey=...' -scheduledTaskName 'MyMonitor'

# Register with faster watchdog health checks
Register-EventMonitor -watchdogIntervalMin 15
```

---

### `Unregister-EventMonitor`

Removes the event monitor scheduled task. Keeps data files intact.

```powershell
Unregister-EventMonitor [-TaskName <String>]   # default: 'WinEventMonitor'
```

---

### `Uninstall-EventMonitor`

Stops monitoring and removes the scheduled task. Optionally deletes all data.

```powershell
Uninstall-EventMonitor
    [-TaskName <String>]   # default: 'WinEventMonitor'
    [-DeleteData]           # Also remove C:\ProgramData\WindowsEventMonitor\
```

**Examples:**

```powershell
# Remove task, keep data
Uninstall-EventMonitor

# Full cleanup
Uninstall-EventMonitor -DeleteData
```

---

### `Start-EventMonitor`

Starts a previously registered event monitor.

```powershell
Start-EventMonitor [-TaskName <String>]
```

---

### `Stop-EventMonitor`

Stops a running event monitor.

```powershell
Stop-EventMonitor [-TaskName <String>]
```

---

### `Enable-EventMonitor`

Re-enables a disabled event monitor without re-registering it.

```powershell
Enable-EventMonitor [-TaskName <String>]
```

---

### `Disable-EventMonitor`

Disables the event monitor. The task remains registered but won't run.

```powershell
Disable-EventMonitor [-TaskName <String>]
```

---

### `Get-EventMonitor`

Returns the status of the event monitor scheduled task.

```powershell
Get-EventMonitor [-TaskName <String>]
```

**Example output:**

```
TaskName         : WinEventMonitor
Status           : Running
NextRunTime      : 3/8/2026 12:00:00 AM
LastRunResult    : 0
```

---

## Event Collection

### `Invoke-EventMonitor`

Runs a one-shot diagnostic scan of recent events. Does **not** require a registered task — useful for testing.

```powershell
Invoke-EventMonitor
    [-LookBackMinutes <Int32>]  # How far back to scan (default: 60, range: 1–10080)
    [-SessionId <String>]       # Session ID (default: new GUID)
```

**Examples:**

```powershell
# Scan last hour
Invoke-EventMonitor

# Scan last 24 hours
Invoke-EventMonitor -LookBackMinutes 1440
```

---

### `Get-WindowsEventsAndSessions`

Collects logon/logoff events and active sessions for a specific user.

```powershell
Get-WindowsEventsAndSessions
    [-sessionId <String>]
    -timeRangeForEventsBefore <DateTime>   # Look back from this timestamp
    -user <String>                         # Target username
```

---

### `Get-MonitoredEventCategories`

Returns all registered event processors showing what events are monitored.

```powershell
Get-MonitoredEventCategories
```

**Example output:**

```
Category           EventIds       LogSource            Severity
--------           --------       ---------            --------
LogonEvents        4624,4625,4648 Security             High
PersistenceEvents  4697,4698      Security             Critical
DefenderEvents     1116,1117,5001 Windows Defender/Op  Critical
...
```

---

## Monitoring Configuration

### `Set-MonitoringLevel`

Sets which event groups are active.

```powershell
Set-MonitoringLevel
    -Level <String>       # Minimum | Standard | High | Custom
    [-Groups <String[]>]  # Required when Level is 'Custom'
```

**Examples:**

```powershell
Set-MonitoringLevel -Level Standard

Set-MonitoringLevel -Level Custom -Groups 'Logon', 'SSH', 'RDP', 'AuditTampering'
```

---

### `Get-MonitoringConfig`

Returns the full monitoring configuration.

```powershell
Get-MonitoringConfig
```

**Returns:** Level, EnabledGroups, LogLevel, JournalSettings, AvailableGroups.

---

### `Get-EventGroups`

Lists all 17 event groups with descriptions and enabled status.

```powershell
Get-EventGroups
```

**Example:**

```powershell
Get-EventGroups | Format-Table Name, Enabled, EventCount, Description
```

---

### `Set-EventJournal`

Configures JSONL event journal output.

```powershell
Set-EventJournal
    [-Enabled <Boolean>]
    [-MinSeverity <String>]   # Critical | High | Medium | Low | Info
    [-RetentionDays <Int32>]  # Range: 1–365
```

**Examples:**

```powershell
# Enable with defaults
Set-EventJournal -Enabled $true

# High-severity only, 2-week retention
Set-EventJournal -Enabled $true -MinSeverity High -RetentionDays 14
```

---

### `Set-EMLogLevel`

Sets operational log verbosity.

```powershell
Set-EMLogLevel -Level <String>   # Error | Warning | Info | Debug
```

---

### `Get-EventHistory`

Queries the event journal for past events.

```powershell
Get-EventHistory
    [-Days <Int32>]        # Look back N days (default: 7, range: 1–365)
    [-Severity <String>]   # Filter: Critical | High | Medium | Low | Info
    [-EventName <String>]  # Filter by event name
    [-Detailed]            # Show full event properties
    [-Last <Int32>]        # Max results (default: 50, range: 1–10000)
```

**Examples:**

```powershell
# Last 50 events from past 7 days
Get-EventHistory

# Critical events in the last 24 hours
Get-EventHistory -Days 1 -Severity Critical

# Specific event with full details
Get-EventHistory -EventName '4625 Logon Failed' -Detailed -Last 100
```

---

### `Show-EventMonitorHelp`

Displays a quick-start guide with available commands and data locations.

```powershell
Show-EventMonitorHelp
```

---

## Telemetry Sinks

### `Register-TelemetrySink`

Registers a custom telemetry sink that receives all dispatched events.

```powershell
Register-TelemetrySink
    -Name <String>              # Unique name for the sink
    -OnDispatch <ScriptBlock>   # Handler: receives ($Type, $Name, $Properties)
```

**Examples:**

```powershell
# Webhook for critical alerts
Register-TelemetrySink -Name 'CriticalAlerts' -OnDispatch {
    param($Type, $Name, $Properties)
    if ($Properties['Severity'] -eq 'Critical') {
        Invoke-RestMethod -Uri 'https://hooks.example.com/alert' `
            -Method Post -Body ($Properties | ConvertTo-Json)
    }
}

# Local JSON log (works without App Insights)
Register-TelemetrySink -Name 'JsonLog' -OnDispatch {
    param($Type, $Name, $Properties)
    @{ Type=$Type; Event=$Name; Time=(Get-Date -Format 'o') } |
        ConvertTo-Json -Compress | Out-File -Append 'C:\Logs\events.jsonl'
}
```

---

### `Unregister-TelemetrySink`

Removes a registered telemetry sink.

```powershell
Unregister-TelemetrySink -Name <String>
```

---

### `Get-TelemetrySinks`

Lists all registered telemetry sinks.

```powershell
Get-TelemetrySinks
```

---

**Next:** [Telemetry & Sinks](Telemetry-and-Sinks) · [Event Groups Reference](Event-Groups-Reference)
