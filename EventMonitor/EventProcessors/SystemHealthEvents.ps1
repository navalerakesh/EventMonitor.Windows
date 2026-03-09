# ── System Health Events Processor ────────────────────────────────────────────
# Monitors system startup, shutdown, crash, and uptime events.
# Event IDs: 41, 1074, 1076, 6005, 6006, 6008, 6009, 6013 (System log)

<#
.SYNOPSIS
    Collects system health events within the time window.
.DESCRIPTION
    Monitors the System event log for shutdown, restart, crash, and boot events.
    These events are machine-wide and not filtered by user.
#>
function Get-SystemHealthEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 41, 1074, 1076, 6005, 6006, 6008, 6009, 6013 -LogName 'System' -StartTime $StartTime

        foreach ($evt in $events) {
            $description = switch ($evt.Id) {
                41   { 'Unexpected Shutdown (Kernel Power)' }
                1074 { 'Planned Shutdown/Restart' }
                1076 { 'Unexpected Shutdown Reason' }
                6005 { 'Event Log Service Started' }
                6006 { 'Event Log Service Stopped' }
                6008 { 'Unexpected Shutdown Detected' }
                6009 { 'OS Version at Boot' }
                6013 { 'System Uptime' }
            }

            $severity = switch ($evt.Id) {
                41   { 'Critical' }
                1076 { 'High' }
                6008 { 'High' }
                default { 'Info' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Info' -Severity $severity
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-SystemHealthEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-SystemHealthEvents')
    }
}
