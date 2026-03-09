# ── Network Share Events Processor ────────────────────────────────────────────
# Monitors network share access events.
# Event ID: 5140 (network share accessed)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5140

<#
.SYNOPSIS
    Collects network share access events for a user within the time window.
#>
function Get-NetworkShareEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 5140 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            # Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName
            #             [3]SubjectLogonId [4]ObjectType [5]IpAddress [6]IpPort
            #             [7]ShareName [8]ShareLocalPath [9]AccessMask [10]AccessList

            if ("$($evt.Properties[1].Value)" -ne $User) { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Connect' -Severity 'Medium'
            $props['UserName']       = "$($evt.Properties[1].Value)"
            $props['AccountDomain']  = "$($evt.Properties[2].Value)"
            $props['LogonSID']       = "$($evt.Properties[0].Value)"
            $props['SourceAddress']  = "$($evt.Properties[5].Value)"
            $props['SourcePort']     = "$($evt.Properties[6].Value)"
            $props['ShareName']      = "$($evt.Properties[7].Value)"
            $props['ShareLocalPath'] = "$($evt.Properties[8].Value)"
            $props['AccessMask']     = "$($evt.Properties[9].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '5140 Network Share Accessed' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-NetworkShareEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-NetworkShareEvents' -User $User)
    }
}
