# ── WinRM / PowerShell Remoting Events Processor ──────────────────────────────
# Monitors Windows Remote Management (WinRM) connections — the #1 lateral
# movement tool used by attackers via Invoke-Command, Enter-PSSession, etc.
#
# Log: Microsoft-Windows-WinRM/Operational
# Event ID 6: WSMan session created (inbound remoting connection)
#
# Also monitors Event 91 (connection failed) for brute force detection.
#
# Reference: https://learn.microsoft.com/en-us/windows/win32/winrm/

<#
.SYNOPSIS
    Collects WinRM remoting session events within the time window.
.DESCRIPTION
    Event 6 fires when a WinRM session is established — this means someone
    is executing commands remotely on this machine via PowerShell remoting,
    Invoke-Command, or Enter-PSSession. Critical for lateral movement detection.
#>
function Get-WinRMEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    $logName = 'Microsoft-Windows-WinRM/Operational'

    # Event 6: Session created (inbound connection)
    try {
        $events = Read-WindowsEvents -EventId 6 -LogName $logName -StartTime $StartTime

        foreach ($evt in $events) {
            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'High'
            $props['EventDescription'] = 'WinRM Session Created (Remote PowerShell)'
            $props['ConnectionString'] = "$($evt.Properties[0].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '6 WinRM Session Created' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-WinRMEvents (session created): $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-WinRMEvents')
    }

    # Event 91: Connection failed (brute force indicator)
    try {
        $events = Read-WindowsEvents -EventId 91 -LogName $logName -StartTime $StartTime

        foreach ($evt in $events) {
            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'High'
            $props['EventDescription'] = 'WinRM Connection Failed'

            Send-LogAnalyticsConnectEvents `
                -eventName '91 WinRM Connection Failed' -Properties $props -sendEvent $evt
        }
    }
    catch {
        # Log may not exist or no events — not an error
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-WinRMEvents (connection failed): $($_.Exception.Message)" -Level Error
        }
    }
}
