# Configuration

## Monitoring Levels

EventMonitor.Windows offers four monitoring presets that control which event groups are active.

### Preset Comparison

| Level | Groups Enabled | Description |
|:------|:-:|:------------|
| **Minimum** | 4 | Session tracking only: Logon, Logoff, SSH, RDP |
| **Standard** | 13 | Recommended. Adds account/group management, persistence, audit, firewall, Defender, WinRM, system health |
| **High** | 17 | Everything. Adds privilege use, process tracking, PowerShell script logging, network share access |
| **Custom** | You choose | Enable specific groups by name |

### Set a Monitoring Level

```powershell
# Apply a preset
Set-MonitoringLevel -Level Standard

# Custom: pick exactly the groups you need
Set-MonitoringLevel -Level Custom -Groups 'Logon', 'SSH', 'RDP', 'AuditTampering', 'Persistence'
```

### View Current Configuration

```powershell
# Full configuration summary
Get-MonitoringConfig

# List all groups with enabled/disabled status
Get-EventGroups | Format-Table Name, Enabled, EventCount, Description
```

---

## Event Journal

The event journal captures events to structured JSONL files — ideal for AI tools, SIEM ingestion, or offline forensic analysis.

### Enable / Disable

```powershell
# Enable with 30-day retention
Set-EventJournal -Enabled $true -RetentionDays 30

# Restrict to high-severity events only
Set-EventJournal -Enabled $true -MinSeverity High -RetentionDays 14

# Disable
Set-EventJournal -Enabled $false
```

### Journal File Location

```
EventMonitor/Telemetry/Journal/EventJournal-2026-03-08.jsonl
```

Each line is valid JSON:

```json
{"Timestamp":"2026-03-08T14:23:01Z","EventId":4625,"Name":"Logon Failed","Severity":"High","Properties":{"TargetUserName":"admin","SourceIP":"10.0.0.5"}}
```

### Read Journal Data

```powershell
# Today's events
$today = Get-Date -Format 'yyyy-MM-dd'
Get-Content ".\EventMonitor\Telemetry\Journal\EventJournal-$today.jsonl" |
    ConvertFrom-Json |
    Where-Object Severity -eq 'Critical'
```

---

## Log Levels

Control the verbosity of operational logs written to `C:\ProgramData\WindowsEventMonitor\Logs\`.

| Level | What's Logged |
|:------|:-------------|
| **Error** | Errors only — minimal disk usage |
| **Warning** | Errors + warnings (default) |
| **Info** | Adds operational messages (event counts, watcher status) |
| **Debug** | Everything — for troubleshooting only |

```powershell
# Set log level
Set-EMLogLevel -Level Info

# For troubleshooting
Set-EMLogLevel -Level Debug
```

---

## Configuration Persistence

Configuration is saved to `C:\ProgramData\WindowsEventMonitor\` and automatically restored when the service starts. This survives module updates and reboots.

Saved settings include:
- Active monitoring level and enabled groups
- Event journal settings (enabled, severity filter, retention)
- Log level
- Custom telemetry sinks are **not** persisted (register them in a startup script)

---

**Next:** [Event Groups Reference](Event-Groups-Reference) · [Command Reference](Command-Reference)
