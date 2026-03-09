# KQL Queries

Ready-to-use Kusto Query Language (KQL) queries for Azure Application Insights. Paste these into **Logs** in your Application Insights resource.

---

## Authentication & Access

### Failed Logon Attempts (Brute-Force Detection)

```kusto
customEvents
| where name == "4625 Logon Failed"
| where timestamp > ago(24h)
| summarize Attempts = count() by
    SourceIP = tostring(customDimensions.SourceIP),
    TargetUser = tostring(customDimensions.TargetUserName)
| where Attempts > 5
| order by Attempts desc
```

### Successful Logons by Type

```kusto
customEvents
| where name == "4624 Logon Success"
| where timestamp > ago(24h)
| summarize count() by
    LogonType = tostring(customDimensions.LogonType),
    UserName = tostring(customDimensions.TargetUserName)
| order by count_ desc
```

### Explicit Credential Usage (RunAs / Pass-the-Hash)

```kusto
customEvents
| where name == "4648 Explicit Credential Logon"
| where timestamp > ago(7d)
| project timestamp,
    SubjectUser = tostring(customDimensions.SubjectUserName),
    TargetUser = tostring(customDimensions.TargetUserName),
    TargetServer = tostring(customDimensions.TargetServerName),
    Process = tostring(customDimensions.ProcessName)
```

---

## Remote Access

### SSH Sessions

```kusto
customEvents
| where name has "SSH"
| where timestamp > ago(7d)
| project timestamp, name,
    User = tostring(customDimensions.UserName),
    SourceIP = tostring(customDimensions.SourceIP)
| order by timestamp desc
```

### RDP Sessions

```kusto
customEvents
| where name has "RDP"
| where timestamp > ago(7d)
| project timestamp, name,
    User = tostring(customDimensions.UserName),
    SourceIP = tostring(customDimensions.SourceAddress)
| order by timestamp desc
```

### WinRM / PowerShell Remoting

```kusto
customEvents
| where name has "WinRM"
| where timestamp > ago(7d)
| project timestamp, name,
    User = tostring(customDimensions.UserName),
    SourceIP = tostring(customDimensions.SourceIP)
```

---

## Persistence & Backdoors

### New Services Installed

```kusto
customEvents
| where name has "Service Installed"
| where timestamp > ago(7d)
| project timestamp,
    Service = tostring(customDimensions.ServiceName),
    Path = tostring(customDimensions.ServiceFileName),
    InstalledBy = tostring(customDimensions.SubjectUserName)
| order by timestamp desc
```

### Scheduled Task Changes

```kusto
customEvents
| where name has_any("Task Created", "Task Deleted", "Task Updated")
| where timestamp > ago(7d)
| project timestamp, name,
    TaskName = tostring(customDimensions.TaskName),
    User = tostring(customDimensions.SubjectUserName)
```

---

## Anti-Forensics & Tampering

### Audit Log Cleared

```kusto
customEvents
| where name == "1102 Audit Log Cleared"
| project timestamp,
    ClearedBy = tostring(customDimensions.SubjectUserName),
    Machine = tostring(customDimensions.MachineName)
```

### Audit Policy Changed

```kusto
customEvents
| where name == "4719 Audit Policy Changed"
| project timestamp,
    ChangedBy = tostring(customDimensions.SubjectUserName),
    Category = tostring(customDimensions.CategoryId)
```

---

## Windows Defender

### Malware Detections

```kusto
customEvents
| where name has_any("Malware Detected", "Malware Action")
| where timestamp > ago(30d)
| project timestamp, name,
    ThreatName = tostring(customDimensions.ThreatName),
    Path = tostring(customDimensions.Path),
    Action = tostring(customDimensions.Action)
| order by timestamp desc
```

### Defender Protection Disabled

```kusto
customEvents
| where name has_any("Real-time Protection Disabled", "Scanning Disabled", "Virus Scanning Disabled")
| project timestamp, name,
    Machine = tostring(customDimensions.MachineName)
```

---

## Account & Group Changes

### Account Created or Deleted

```kusto
customEvents
| where name has_any("Account Created", "Account Deleted")
| where timestamp > ago(30d)
| project timestamp, name,
    TargetAccount = tostring(customDimensions.TargetUserName),
    PerformedBy = tostring(customDimensions.SubjectUserName)
```

### Group Membership Changes

```kusto
customEvents
| where name has_any("Member Added", "Member Removed")
| where timestamp > ago(30d)
| project timestamp, name,
    Group = tostring(customDimensions.TargetUserName),
    Member = tostring(customDimensions.MemberName),
    ChangedBy = tostring(customDimensions.SubjectUserName)
```

---

## System Health

### Unexpected Shutdowns

```kusto
customEvents
| where name has_any("Unexpected Shutdown", "Kernel Power")
| where timestamp > ago(30d)
| project timestamp, name,
    Machine = tostring(customDimensions.MachineName)
| order by timestamp desc
```

### Firewall Rule Changes

```kusto
customEvents
| where name has_any("Firewall Rule Added", "Firewall Rule Modified", "Firewall Rule Deleted")
| where timestamp > ago(7d)
| project timestamp, name,
    RuleName = tostring(customDimensions.RuleName),
    Direction = tostring(customDimensions.Direction)
```

---

## Dashboards & Summaries

### Event Count by Severity (Last 24h)

```kusto
customEvents
| where isnotempty(customDimensions.Severity)
| where timestamp > ago(24h)
| summarize Count = count() by Severity = tostring(customDimensions.Severity)
| order by Count desc
```

### Top 10 Events (Last 24h)

```kusto
customEvents
| where timestamp > ago(24h)
| summarize Count = count() by name
| top 10 by Count
```

### Events Timeline (Hourly)

```kusto
customEvents
| where timestamp > ago(24h)
| summarize Count = count() by bin(timestamp, 1h), name
| render timechart
```

### Watchdog Health Over Time

```kusto
customEvents
| where name == "Watchdog Health Report"
| where timestamp > ago(7d)
| project timestamp,
    ActiveWatchers = toint(customDimensions.ActiveWatchers),
    TotalEvents = toint(customDimensions.TotalEventsProcessed),
    Errors = toint(customDimensions.TotalErrors)
| order by timestamp desc
```

---

## Alerting Recommendations

Set up **Azure Monitor alerts** on these queries for proactive detection:

| Alert | Query Filter | Threshold | Frequency |
|:------|:------------|:----------|:----------|
| Brute Force | `4625 Logon Failed` grouped by IP | > 10 in 5 min | 5 min |
| Audit Cleared | `1102 Audit Log Cleared` | > 0 | 5 min |
| Defender Disabled | `Real-time Protection Disabled` | > 0 | 5 min |
| New Service | `Service Installed` | > 0 | 15 min |
| Task Created | `Task Created` | > 0 | 15 min |

---

**Next:** [Troubleshooting](Troubleshooting) · [Command Reference](Command-Reference)
