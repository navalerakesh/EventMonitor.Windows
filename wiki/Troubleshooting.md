# Troubleshooting

## Common Issues

### Module won't import

**Error:** `Import-Module: The specified module 'EventMonitor.Windows' was not found`

**Solutions:**
1. Verify installation: `Get-Module -Name EventMonitor.Windows -ListAvailable`
2. Install if missing: `Install-Module -Name EventMonitor.Windows -Scope CurrentUser`
3. Check PowerShell version — must be 7.4+: `$PSVersionTable.PSVersion`
4. Ensure you're running `pwsh.exe`, not `powershell.exe` (Windows PowerShell 5.1)

---

### Scheduled task won't start

**Error:** `Get-EventMonitor returns Status: Ready (not Running)`

**Solutions:**
1. Start manually: `Start-EventMonitor -TaskName 'WinEventMonitor'`
2. Check the task exists: `Get-ScheduledTask -TaskName 'WinEventMonitor'`
3. Verify you have admin privileges (right-click PowerShell → Run as Administrator)
4. Check Task Scheduler for error codes in the Last Run Result column

---

### Access denied / Permission errors

**Error:** `Access is denied` when registering or starting the monitor

**Solutions:**
1. Run PowerShell as **Administrator**
2. The scheduled task runs as `NT AUTHORITY\SYSTEM` — registration requires admin rights
3. Event log access (especially Security log) requires elevation

---

### Events not appearing in Application Insights

**Possible causes:**

| Issue | Fix |
|:------|:----|
| Connection string not set | Set `APPINSIGHTS_CONNECTION_STRING` environment variable |
| Key expired or invalid | Check at https://www.powershellgallery.com/account/apikeys |
| Ingestion delay | AI can have 2–5 min ingestion delay. Wait and check again |
| Wrong workspace | Verify the InstrumentationKey matches your AI resource |
| Module running locally only | Check `Get-TelemetrySinks` — AI sink should be listed |

**Diagnostic steps:**

```powershell
# Check registered sinks
Get-TelemetrySinks

# Run a manual scan to test
Invoke-EventMonitor -LookBackMinutes 5

# Check operational logs for errors
Get-Content 'C:\ProgramData\WindowsEventMonitor\Logs\*.log' | Select-Object -Last 50
```

---

### No events being captured

**Possible causes:**

1. **Monitoring level too restrictive**: Check `Get-MonitoringConfig` and try `Set-MonitoringLevel -Level High`
2. **No events occurring**: Generate a test event (lock/unlock workstation for Logon events)
3. **Windows audit policy not enabled**: Some events require Group Policy settings

**Enable audit policies (if events are missing):**

```powershell
# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Enable process tracking
auditpol /set /subcategory:"Process Creation" /success:enable

# Enable PowerShell Script Block Logging (Group Policy)
# Computer Configuration → Administrative Templates → Windows Components →
# Windows PowerShell → Turn on PowerShell Script Block Logging
```

---

### Watchdog errors in logs

**Symptom:** Logs show "Watchdog detected unhealthy watcher" or "Restarting watcher"

This is **normal behavior** — the watchdog is doing its job by auto-repairing crashed watchers. This can happen when:
- An event log is temporarily unavailable
- System resources are constrained
- Windows Update restarts the Event Log service

Check watchdog health:

```powershell
# In Application Insights
customEvents
| where name == "Watchdog Health Report"
| project timestamp, ActiveWatchers=toint(customDimensions.ActiveWatchers),
          Errors=toint(customDimensions.TotalErrors)
| order by timestamp desc
```

---

### High disk usage from logs

**Solutions:**

```powershell
# Reduce log verbosity
Set-EMLogLevel -Level Error

# Reduce journal retention
Set-EventJournal -Enabled $true -MinSeverity High -RetentionDays 7

# Disable journal entirely
Set-EventJournal -Enabled $false
```

Log files are at `C:\ProgramData\WindowsEventMonitor\Logs\`. Old files can be safely deleted.

---

### Module conflicts with Windows PowerShell 5.1

**Error:** Various incompatibility errors

EventMonitor.Windows requires **PowerShell 7.4+** (Core edition). It will not run on Windows PowerShell 5.1.

```powershell
# Check which PowerShell you're using
$PSVersionTable

# If PSVersion shows 5.x, switch to PowerShell 7:
pwsh
```

---

## Diagnostic Commands

| Command | Purpose |
|:--------|:--------|
| `Get-EventMonitor` | Check task status |
| `Get-MonitoringConfig` | View active configuration |
| `Get-EventGroups \| Format-Table` | See enabled/disabled groups |
| `Get-TelemetrySinks` | Verify telemetry sinks |
| `Get-MonitoredEventCategories` | See all registered processors |
| `Get-EventHistory -Days 1 -Last 10` | Recent captured events |
| `Invoke-EventMonitor -LookBackMinutes 5` | Test scan |
| `Show-EventMonitorHelp` | Quick reference |

## Log File Locations

| Path | Contents |
|:-----|:---------|
| `C:\ProgramData\WindowsEventMonitor\Logs\` | Operational logs |
| `C:\ProgramData\WindowsEventMonitor\Config\` | Saved configuration |
| `EventMonitor\Telemetry\Journal\` | JSONL event files |

---

## Getting Help

- **GitHub Issues:** [Report a bug or request a feature](https://github.com/navalerakesh/EventMonitor.Windows/issues)
- **Discussions:** [Ask questions or share ideas](https://github.com/navalerakesh/EventMonitor.Windows/discussions)
- **Built-in help:** `Show-EventMonitorHelp`

---

**Next:** [Home](Home) · [Quick Start Guide](Quick-Start-Guide)
