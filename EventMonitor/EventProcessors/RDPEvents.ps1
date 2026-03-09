# ── RDP Events Processor ──────────────────────────────────────────────────────
# Monitors Terminal Services-specific events for RDP session lifecycle.
# These provide more detail than the generic Security log events (4624/4779).
#
# Log: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
# Event IDs: 21 (RDP logon), 23 (RDP logoff), 24 (RDP disconnect), 25 (RDP reconnect)
#
# Reference: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-rdp-log-events

<#
.SYNOPSIS
    Collects RDP-specific session lifecycle events within the time window.
.DESCRIPTION
    These events come from the TerminalServices-LocalSessionManager log, which
    provides richer detail than the Security log for RDP sessions, including
    source IP address on every event and session IDs for correlation.
#>
function Get-RDPEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    $logName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'

    try {
        $events = Read-WindowsEvents -EventId 21, 23, 24, 25 -LogName $logName -StartTime $StartTime

        foreach ($evt in $events) {
            # Properties layout for TS-LocalSessionManager events:
            # [0] User (DOMAIN\username)
            # [1] SessionID
            # [2] Source Network Address (IP)

            $description = switch ($evt.Id) {
                21 { 'RDP Session Logon' }
                23 { 'RDP Session Logoff' }
                24 { 'RDP Session Disconnected' }
                25 { 'RDP Session Reconnected' }
            }

            $eventType = switch ($evt.Id) {
                21 { 'Connect' }
                23 { 'Disconnect' }
                24 { 'Disconnect' }
                25 { 'Connect' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType $eventType -Severity 'Info'
            $props['UserName']         = "$($evt.Properties[0].Value)"
            $props['RDPSessionId']     = "$($evt.Properties[1].Value)"
            $props['SourceIP']         = "$($evt.Properties[2].Value)"
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-RDPEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-RDPEvents')
    }
}
