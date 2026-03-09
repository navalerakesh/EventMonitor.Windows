<#
.SYNOPSIS
    Example script demonstrating EventMonitor.Windows usage.
.DESCRIPTION
    Shows all major scenarios. This script is a REFERENCE - does NOT run monitoring.
    Read through the sections and copy what you need.
.LINK
    https://github.com/navalerakesh/EventMonitor.Windows
#>

# ============================================================================
# 1. INSTALL & IMPORT
# ============================================================================

# From PowerShell Gallery:
#   Install-Module -Name EventMonitor.Windows -Scope CurrentUser

# From source (after cloning):
#   Import-Module .\EventMonitor.Windows.psd1

Import-Module EventMonitor.Windows -ErrorAction Stop

# ============================================================================
# 2. CHOOSE YOUR MONITORING LEVEL
# ============================================================================

# See all available event groups
Get-EventGroups | Format-Table Name, Enabled, EventCount, Description

# Option A: Minimum (just who logged in/out)
Set-MonitoringLevel -Level Minimum

# Option B: Standard (recommended - covers most security needs)
Set-MonitoringLevel -Level Standard

# Option C: High (everything + event journal)
Set-MonitoringLevel -Level High

# Option D: Custom (pick exactly what you want)
Set-MonitoringLevel -Level Custom -Groups 'Logon', 'SSH', 'RDP', 'AuditTampering', 'Persistence'

# Check current config
Get-MonitoringConfig

# ============================================================================
# 3. REGISTER & START MONITORING
# ============================================================================

# Your Application Insights connection string (from Azure Portal)
$connectionString = 'InstrumentationKey=your-key;IngestionEndpoint=https://....applicationinsights.azure.com/'

# Register the event-driven service (runs at boot, auto-restarts on failure)
Register-EventMonitor -logAnalyticsConString $connectionString

# Custom watchdog interval (default 30 min)
Register-EventMonitor -logAnalyticsConString $connectionString `
    -scheduledTaskName 'MyServerMonitor' `
    -watchdogIntervalMin 15

# ============================================================================
# 4. MANAGE THE SERVICE
# ============================================================================

Get-EventMonitor     -TaskName 'WinEventMonitor'   # Status
Stop-EventMonitor    -TaskName 'WinEventMonitor'   # Stop
Start-EventMonitor   -TaskName 'WinEventMonitor'   # Start
Disable-EventMonitor -TaskName 'WinEventMonitor'   # Disable (keep registered)
Enable-EventMonitor  -TaskName 'WinEventMonitor'   # Re-enable
Unregister-EventMonitor -TaskName 'WinEventMonitor' # Remove completely

# ============================================================================
# 5. EVENT JOURNAL (for AI / SIEM / external tools)
# ============================================================================

# Enable structured JSONL event files
Set-EventJournal -Enabled $true -MinSeverity High -RetentionDays 14

# Files created at: EventMonitor/Telemetry/Journal/EventJournal-YYYY-MM-DD.jsonl
# Each line is JSON - readable by jq, Python, PowerShell, AI bots, SIEM

# Read today is journal:
# Get-Content .\EventMonitor\Telemetry\Journal\EventJournal-$(Get-Date -Format 'yyyy-MM-dd').jsonl |
#     ConvertFrom-Json | Where-Object severity -eq 'Critical'

# ============================================================================
# 6. CUSTOM TELEMETRY SINKS (run WITHOUT or ALONGSIDE App Insights)
# ============================================================================

# Send critical alerts via webhook
Register-TelemetrySink -Name 'CriticalAlerts' -OnDispatch {
    param($Type, $Name, $Properties)
    if ($Properties['Severity'] -eq 'Critical') {
        Invoke-RestMethod -Uri 'https://hooks.example.com/alert' `
            -Method Post -Body ($Properties | ConvertTo-Json)
    }
}

# Log everything to a local JSON file (no App Insights needed)
Register-TelemetrySink -Name 'JsonLog' -OnDispatch {
    param($Type, $Name, $Properties)
    @{ Type=$Type; Event=$Name; Time=(Get-Date -Format 'o') } |
        ConvertTo-Json -Compress | Out-File -Append 'C:\Logs\events.jsonl'
}

# See what sinks are registered
Get-TelemetrySinks

# Remove a sink
Unregister-TelemetrySink -Name 'JsonLog'

# ============================================================================
# 7. CONFIGURE LOGGING
# ============================================================================

# Operational log level (default: Warning)
Set-EMLogLevel -Level Error     # Errors only - minimal disk
Set-EMLogLevel -Level Warning   # Errors + warnings (default)
Set-EMLogLevel -Level Info      # + operational messages
Set-EMLogLevel -Level Debug     # Everything (troubleshooting only)

# ============================================================================
# 8. DIAGNOSTIC SCAN (one-shot, for testing)
# ============================================================================

# Scan last 60 minutes and send to configured sinks
Invoke-EventMonitor -LookBackMinutes 60

# Scan last 24 hours
# Invoke-EventMonitor -LookBackMinutes 1440

# ============================================================================
# 9. KQL QUERIES (for Application Insights)
# ============================================================================

<#
-- Failed logon attempts (brute force detection)
customEvents
| where name == "4625 Logon Failed"
| where timestamp > ago(24h)
| summarize Attempts=count() by tostring(customDimensions.SourceIP),
            tostring(customDimensions.TargetUserName)
| where Attempts > 5
| order by Attempts desc

-- New services installed (persistence detection)
customEvents
| where name has "Service Installed"
| where timestamp > ago(7d)
| project timestamp, Service=tostring(customDimensions.ServiceName),
          Path=tostring(customDimensions.ServiceFileName),
          InstalledBy=tostring(customDimensions.SubjectUserName)

-- Audit log cleared (anti-forensics)
customEvents
| where name == "1102 Audit Log Cleared"
| project timestamp, ClearedBy=tostring(customDimensions.SubjectUserName),
          Machine=tostring(customDimensions.MachineName)

-- All events by severity
customEvents
| where isnotempty(customDimensions.Severity)
| summarize count() by tostring(customDimensions.Severity), name
| order by count_ desc

-- Watchdog health over time
customEvents
| where name == "Watchdog Health Report"
| project timestamp, Watchers=toint(customDimensions.ActiveWatchers),
          Events=toint(customDimensions.TotalEventsProcessed),
          Errors=toint(customDimensions.TotalErrors)
| order by timestamp desc
#>
