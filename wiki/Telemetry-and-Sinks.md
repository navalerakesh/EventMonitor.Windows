# Telemetry & Sinks

EventMonitor.Windows uses a **pluggable sink architecture**. Every detected event is dispatched to all registered sinks. You can run with zero, one, or many sinks simultaneously.

---

## How Sinks Work

```
EventLogWatcher detects event
        │
        ▼
Event Processor enriches data (severity, properties, context)
        │
        ▼
Invoke-TelemetryDispatch($Type, $Name, $Properties)
        │
        ├──▶ Sink 1: Application Insights (built-in)
        ├──▶ Sink 2: Event Journal (JSONL files)
        ├──▶ Sink 3: Your webhook
        └──▶ Sink N: Any custom handler
```

Each sink receives three arguments:

| Argument | Type | Description |
|:---------|:-----|:------------|
| `$Type` | String | `Event`, `Trace`, or `Exception` |
| `$Name` | String | Event name (e.g., `"4625 Logon Failed"`) |
| `$Properties` | Hashtable | Event details (Severity, SourceIP, UserName, etc.) |

---

## Built-in: Application Insights

Azure Application Insights provides cloud-based event storage, alerting, and KQL querying.

### Setup

```powershell
# Option 1: Environment variable (recommended — most secure)
[System.Environment]::SetEnvironmentVariable(
    'APPINSIGHTS_CONNECTION_STRING',
    'InstrumentationKey=your-key;IngestionEndpoint=https://....applicationinsights.azure.com/',
    'Machine'
)

# Option 2: Pass directly during registration
Register-EventMonitor -logAnalyticsConString 'InstrumentationKey=...'
```

The connection string is resolved in priority order:
1. `APPINSIGHTS_CONNECTION_STRING` environment variable
2. `EM_AI_CONNECTION_STRING` environment variable
3. `LogAnalyticsConString.txt` file (ACL-protected)
4. `-logAnalyticsConString` parameter

### What Gets Sent

| Telemetry Type | What It Contains |
|:---------------|:-----------------|
| **CustomEvent** | Security events with properties (Event ID, user, IP, severity) |
| **Trace** | Operational messages (watcher health, config changes) |
| **Exception** | Error details when processing fails |

### Querying (see [KQL Queries](KQL-Queries))

```kusto
customEvents
| where name == "4625 Logon Failed"
| where timestamp > ago(24h)
| summarize count() by tostring(customDimensions.SourceIP)
```

---

## Built-in: Event Journal

JSONL files written locally — works without any cloud service.

### Enable

```powershell
Set-EventJournal -Enabled $true -RetentionDays 30
```

### Severity Filter

```powershell
# Only capture High and Critical events
Set-EventJournal -Enabled $true -MinSeverity High
```

Severity hierarchy: `Critical > High > Medium > Low > Info`

Setting `MinSeverity High` captures both High and Critical events.

### File Location

```
EventMonitor/Telemetry/Journal/EventJournal-2026-03-08.jsonl
```

### File Format

One JSON object per line:

```json
{"Timestamp":"2026-03-08T14:23:01Z","EventId":4625,"Name":"Logon Failed","Severity":"High","Properties":{"TargetUserName":"admin","SourceIP":"10.0.0.5","LogonType":"10"}}
{"Timestamp":"2026-03-08T14:25:12Z","EventId":7045,"Name":"Service Installed","Severity":"Critical","Properties":{"ServiceName":"backdoor","ServiceFileName":"C:\\temp\\svc.exe"}}
```

### Read Journal Data

```powershell
# Today's critical events
$today = Get-Date -Format 'yyyy-MM-dd'
Get-Content ".\EventMonitor\Telemetry\Journal\EventJournal-$today.jsonl" |
    ConvertFrom-Json |
    Where-Object Severity -eq 'Critical'

# Failed logon count by IP
Get-Content ".\EventMonitor\Telemetry\Journal\EventJournal-$today.jsonl" |
    ConvertFrom-Json |
    Where-Object { $_.Name -eq '4625 Logon Failed' } |
    Group-Object { $_.Properties.SourceIP } |
    Sort-Object Count -Descending
```

---

## Custom Sinks

Register any number of custom sinks to route events to any destination.

### Webhook Alerts

```powershell
Register-TelemetrySink -Name 'CriticalAlerts' -OnDispatch {
    param($Type, $Name, $Properties)
    if ($Type -eq 'Event' -and $Properties['Severity'] -eq 'Critical') {
        $body = @{
            text = "🔴 CRITICAL: $Name on $($Properties['MachineName'])"
            details = $Properties
        } | ConvertTo-Json -Depth 3

        Invoke-RestMethod -Uri 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' `
            -Method Post -ContentType 'application/json' -Body $body
    }
}
```

### Email Alerts

```powershell
Register-TelemetrySink -Name 'EmailCritical' -OnDispatch {
    param($Type, $Name, $Properties)
    if ($Properties['Severity'] -eq 'Critical') {
        Send-MailMessage -From 'monitor@company.com' -To 'soc@company.com' `
            -Subject "Critical: $Name" `
            -Body ($Properties | ConvertTo-Json) `
            -SmtpServer 'smtp.company.com'
    }
}
```

### Windows Event Log

```powershell
Register-TelemetrySink -Name 'WinEventLog' -OnDispatch {
    param($Type, $Name, $Properties)
    if ($Type -eq 'Event') {
        Write-EventLog -LogName Application -Source 'EventMonitor' `
            -EntryType Warning -EventId 1000 `
            -Message "$Name`n$($Properties | ConvertTo-Json -Compress)"
    }
}
```

### Syslog / SIEM Forward

```powershell
Register-TelemetrySink -Name 'Syslog' -OnDispatch {
    param($Type, $Name, $Properties)
    $msg = "<14>EventMonitor: $Name $($Properties | ConvertTo-Json -Compress)"
    $udpClient = [System.Net.Sockets.UdpClient]::new()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($msg)
    $udpClient.Send($bytes, $bytes.Length, '10.0.0.100', 514)
    $udpClient.Close()
}
```

### Manage Sinks

```powershell
# List all registered sinks
Get-TelemetrySinks

# Remove a sink
Unregister-TelemetrySink -Name 'CriticalAlerts'
```

> **Note:** Custom sinks are not persisted across restarts. Register them in a startup script or use the event journal for durable capture.

---

## Running Without Application Insights

The module works entirely locally. Without App Insights:

1. Enable the **event journal** for structured file output
2. Register **custom sinks** for webhook/email/SIEM
3. Use **operational logs** at `C:\ProgramData\WindowsEventMonitor\Logs\`

```powershell
# Local-only setup — no cloud required
Import-Module EventMonitor.Windows
Set-MonitoringLevel -Level Standard
Set-EventJournal -Enabled $true -RetentionDays 30
Register-EventMonitor
```

---

**Next:** [Architecture](Architecture) · [KQL Queries](KQL-Queries)
