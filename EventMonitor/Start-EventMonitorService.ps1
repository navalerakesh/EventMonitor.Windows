#Requires -Version 7.4
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Event-driven entry point for EventMonitor.Windows.
.DESCRIPTION
    Starts real-time event monitoring using EventLogWatcher (zero-polling)
    plus a watchdog timer for health checks and catch-up sweeps.

    This script runs continuously as a long-running process. Use it with:
    - A Windows Service (via NSSM or sc.exe)
    - A Scheduled Task with "Do not start a new instance" + "Run whether user is logged on or not"
    - Direct invocation for testing (Ctrl+C to stop)

    Architecture:
    1. Registers EventLogWatchers for each event category (instant, event-driven)
    2. Starts a watchdog timer (every 30 min by default) that:
       - Checks watcher health and auto-repairs dead watchers
       - Runs a lightweight catch-up sweep for critical events
       - Flushes telemetry and reports health metrics
    3. On shutdown (Ctrl+C or service stop): gracefully disposes all watchers

    Safety guarantees:
    - Every callback is independently try/caught — one bad event never crashes anything
    - Watchdog auto-restarts failed watchers
    - Catch-up sweep ensures zero event loss even during watcher restarts
    - Graceful shutdown with Flush on Ctrl+C
.PARAMETER sessionId
    Correlation identifier for this monitoring session.
.PARAMETER watchdogIntervalMin
    How often the watchdog runs health checks and catch-up sweeps. Default: 30 minutes.
.EXAMPLE
    .\Start-EventMonitorService.ps1 -sessionId (New-Guid).Guid
.EXAMPLE
    # As a Windows Service via NSSM:
    nssm install WindowsEventMonitor "C:\Program Files\PowerShell\7\pwsh.exe"
    nssm set WindowsEventMonitor AppParameters "-NoProfile -File C:\...\Start-EventMonitorService.ps1 -sessionId auto"
    nssm set WindowsEventMonitor ObjectName "LocalSystem"
    nssm start WindowsEventMonitor
#>

param(
    [string]$sessionId = [guid]::NewGuid().Guid,

    [ValidateRange(5, 1440)]
    [int]$watchdogIntervalMin = 30
)

# ── Bootstrap ─────────────────────────────────────────────────────────────────

$modulePath = Join-Path $PSScriptRoot 'WindowsEventMonitor.psm1'
Import-Module $modulePath -Force -ErrorAction Stop

# OS check
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-EMLog -Message "Unsupported OS: $osVersion. Requires Windows 10/Server 2016+." -Level Error
    exit 1
}

# ── Register Telemetry Sinks ──────────────────────────────────────────────────

# App Insights sink (env var > file > skip)
$connectionString = Resolve-AppInsightsConnectionString
if ($connectionString) {
    Register-AppInsightsSink -ConnectionString $connectionString
    Write-EMLog -Message 'AppInsights telemetry sink registered.' -Level Warning
}
else {
    Write-EMLog -Message 'No App Insights connection string found. Register custom sinks or set APPLICATIONINSIGHTS_CONNECTION_STRING / EventMonitorAppInsightsConString env var.' -Level Warning
}

# Additional sinks can be registered here:
# Register-TelemetrySink -Name 'Webhook' -OnDispatch { param($Type, $Name, $Props) ... }

Write-EMLog -Message "=== Event Monitor Service starting (session: $sessionId, mode: event-driven) ==="

# ── Event Callback Factories ─────────────────────────────────────────────────
# Each callback receives an EventRecord and dispatches it to the correct processor.
# These are intentionally simple — the heavy logic lives in the processor functions.

$securityCallback = {
    param($EventRecord, $SessionId)

    $props = New-EventProperties -SessionId $SessionId -EventType 'Info' -Severity 'Info'

    # Merge all event metadata via Send-LogAnalyticsConnectEvents
    $eventId = $EventRecord.Id
    $eventName = switch ($eventId) {
        4624  { $props['EventType'] = 'Connect';    $props['Severity'] = 'Info';     '4624 Logon Success' }
        4625  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4625 Logon Failed' }
        4647  { $props['EventType'] = 'Disconnect';  $props['Severity'] = 'Info';     '4647 Logoff' }
        4648  { $props['EventType'] = 'Connect';    $props['Severity'] = 'Medium';   '4648 Explicit Credential' }
        4672  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4672 Special Privileges' }
        4688  { $props['EventType'] = 'Info';       $props['Severity'] = 'Medium';   '4688 Process Created' }
        4689  { $props['EventType'] = 'Info';       $props['Severity'] = 'Low';      '4689 Process Terminated' }
        4697  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4697 Service Installed' }
        4698  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4698 Task Created' }
        4702  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4702 Task Updated' }
        4719  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4719 Audit Policy Changed' }
        4720  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4720 Account Created' }
        4722  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4722 Account Enabled' }
        4723  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Medium';   '4723 Password Change' }
        4724  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4724 Password Reset' }
        4725  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4725 Account Disabled' }
        4726  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4726 Account Deleted' }
        4732  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4732 Group Member Added' }
        4733  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4733 Group Member Removed' }
        4779  { $props['EventType'] = 'Disconnect';  $props['Severity'] = 'Info';     '4779 Session Disconnect' }
        4800  { $props['EventType'] = 'Info';       $props['Severity'] = 'Info';     '4800 Workstation Locked' }
        4801  { $props['EventType'] = 'Connect';    $props['Severity'] = 'Info';     '4801 Workstation Unlocked' }
        1102  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '1102 Audit Log Cleared' }
        4946  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4946 Firewall Rule Added' }
        4947  { $props['EventType'] = 'Alert';      $props['Severity'] = 'High';     '4947 Firewall Rule Modified' }
        4948  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Critical'; '4948 Firewall Rule Deleted' }
        5140  { $props['EventType'] = 'Connect';    $props['Severity'] = 'Medium';   '5140 Share Accessed' }
        5152  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Medium';   '5152 Packet Dropped' }
        5157  { $props['EventType'] = 'Alert';      $props['Severity'] = 'Medium';   '5157 Connection Blocked' }
        default { "Security Event $eventId" }
    }

    Send-LogAnalyticsConnectEvents `
        -eventName $eventName -Properties $props -sendEvent $EventRecord
}

$systemCallback = {
    param($EventRecord, $SessionId)
    $props = New-EventProperties -SessionId $SessionId -EventType 'Info' -Severity 'Info'

    $eventName = switch ($EventRecord.Id) {
        41   { $props['Severity'] = 'Critical'; '41 Unexpected Shutdown' }
        1074 { '1074 Planned Shutdown' }
        1076 { $props['Severity'] = 'High'; '1076 Unexpected Shutdown Reason' }
        6005 { '6005 EventLog Service Started' }
        6006 { '6006 EventLog Service Stopped' }
        6008 { $props['Severity'] = 'High'; '6008 Unexpected Shutdown' }
        6009 { '6009 OS Version at Boot' }
        6013 { '6013 System Uptime' }
        7045 { $props['EventType'] = 'Alert'; $props['Severity'] = 'High'; '7045 Service Installed' }
        default { "System Event $($EventRecord.Id)" }
    }

    Send-LogAnalyticsConnectEvents `
        -eventName $eventName -Properties $props -sendEvent $EventRecord
}

$rdpCallback = {
    param($EventRecord, $SessionId)
    $eventType = if ($EventRecord.Id -in 21, 25) { 'Connect' } else { 'Disconnect' }
    $props = New-EventProperties -SessionId $SessionId -EventType $eventType -Severity 'Info'

    $description = switch ($EventRecord.Id) {
        21 { 'RDP Session Logon' }
        23 { 'RDP Session Logoff' }
        24 { 'RDP Session Disconnected' }
        25 { 'RDP Session Reconnected' }
    }
    $props['UserName']     = "$($EventRecord.Properties[0].Value)"
    $props['RDPSessionId'] = "$($EventRecord.Properties[1].Value)"
    $props['SourceIP']     = "$($EventRecord.Properties[2].Value)"

    Send-LogAnalyticsConnectEvents `
        -eventName "$($EventRecord.Id) $description" -Properties $props -sendEvent $EventRecord
}

$powershellCallback = {
    param($EventRecord, $SessionId)
    $props = New-EventProperties -SessionId $SessionId -EventType 'Alert' -Severity 'Medium'
    $props['ScriptBlockId'] = "$($EventRecord.Properties[3].Value)"
    $props['ScriptPath']    = "$($EventRecord.Properties[4].Value)"
    $scriptText = "$($EventRecord.Properties[2].Value)"
    if ($scriptText.Length -gt 4000) { $scriptText = $scriptText.Substring(0, 4000) + '...[truncated]' }
    $props['ScriptBlockText'] = $scriptText

    Send-LogAnalyticsConnectEvents `
        -eventName '4104 PowerShell Script Block' -Properties $props -sendEvent $EventRecord
}

$sshCallback = {
    param($EventRecord, $SessionId)
    $propValue = "$($EventRecord.Properties[1].Value)"
    if ($propValue -like 'Accepted publickey*') {
        $props = New-EventProperties -SessionId $SessionId -EventType 'Connect' -Severity 'Info'
        $eventName = 'SSH Connect'
    }
    elseif ($propValue -like 'Disconnected*') {
        $props = New-EventProperties -SessionId $SessionId -EventType 'Disconnect' -Severity 'Info'
        $eventName = 'SSH Disconnect'
    }
    else { return }

    $props['UserSID'] = "$($EventRecord.UserId)"
    Send-LogAnalyticsConnectEvents `
        -eventName $eventName -Properties $props -sendEvent $EventRecord
}

# ── Register All Watchers ─────────────────────────────────────────────────────

Write-EMLog -Message 'Registering event watchers...'

$commonParams = @{
    SessionId        = $sessionId
}

# Security log — all monitored event IDs
$securityIds = @(
    1102, 4624, 4625, 4647, 4648, 4672, 4688, 4689,
    4697, 4698, 4702, 4719, 4720, 4722, 4723, 4724, 4725, 4726,
    4732, 4733, 4779, 4800, 4801,
    4946, 4947, 4948, 5140, 5152, 5157
)
Register-EventWatcher -WatcherName 'Security' -LogName 'Security' `
    -EventIds $securityIds -OnEvent $securityCallback @commonParams

# System log
$systemIds = @(41, 1074, 1076, 6005, 6006, 6008, 6009, 6013, 7045)
Register-EventWatcher -WatcherName 'System' -LogName 'System' `
    -EventIds $systemIds -OnEvent $systemCallback @commonParams

# RDP (TerminalServices) — may not exist on non-RDP machines
Register-EventWatcher -WatcherName 'RDP' `
    -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' `
    -EventIds @(21, 23, 24, 25) -OnEvent $rdpCallback @commonParams

# PowerShell Script Block Logging — may not exist if policy not enabled
Register-EventWatcher -WatcherName 'PowerShell' `
    -LogName 'Microsoft-Windows-PowerShell/Operational' `
    -EventIds @(4104) -OnEvent $powershellCallback @commonParams

# OpenSSH — may not exist if OpenSSH Server not installed
Register-EventWatcher -WatcherName 'SSH' `
    -LogName 'OpenSSH/Operational' `
    -OnEvent $sshCallback @commonParams

# ── Enable All Watchers ──────────────────────────────────────────────────────

foreach ($name in @($script:EventWatchers.Keys)) {
    Enable-EventWatcher -WatcherName $name
}

Write-EMLog -Message "All watchers enabled ($($script:EventWatchers.Count) total)."

# ── Start Watchdog ────────────────────────────────────────────────────────────

Start-Watchdog -IntervalMinutes $watchdogIntervalMin -SessionId $sessionId

# ── Run Until Stopped ─────────────────────────────────────────────────────────
# The watchers and watchdog run on background threads. This main thread just
# waits for Ctrl+C or service stop signal.

Write-EMLog -Message "Event Monitor Service running. Watchers: $($script:EventWatchers.Count), Watchdog: every ${watchdogIntervalMin}min."
Write-EMLog -Message 'Press Ctrl+C to stop (or stop the Windows Service).'

try {
    # Register Ctrl+C handler for graceful shutdown
    $null = [Console]::TreatControlCAsInput = $false

    # Keep alive — sleep in 10-second intervals so Ctrl+C is responsive
    while ($true) {
        Start-Sleep -Seconds 10
    }
}
finally {
    # ── Graceful Shutdown ─────────────────────────────────────────────────
    Write-EMLog -Message '=== Shutting down Event Monitor Service ==='

    Stop-Watchdog
    Stop-AllEventWatchers

    # Final flush
    try { Flush-Telemetry } catch { $null = $null }

    Write-EMLog -Message '=== Event Monitor Service stopped ==='
}
