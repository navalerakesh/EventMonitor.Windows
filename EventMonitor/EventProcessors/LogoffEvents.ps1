# ── Logoff Events Processor ───────────────────────────────────────────────────
# Monitors user session termination and disconnect events.
# Event IDs: 4647 (user-initiated logoff), 4779 (Terminal Services disconnect)

<#
.SYNOPSIS
    Collects all logoff-related security events for a user within the time window.
#>
function Get-LogoffEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    $commonParams = @{
        sessionId             = $sessionId
        StartTime             = $StartTime
        User                  = $User
    }

    Get-Event4647_LogoffInitiated    @commonParams
    Get-Event4779_SessionDisconnect  @commonParams
}

# ── Event 4647: User-Initiated Logoff ─────────────────────────────────────────
# Properties: [0]TargetSID [1]TargetUserName [2]TargetDomainName [3]TargetLogonId

function Get-Event4647_LogoffInitiated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4647 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $targetUser = "$($evt.Properties[1].Value)"
            if ($targetUser -ne $User -and $targetUser -notlike 'ssh_*') { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Disconnect' -Severity 'Info'
            $props['UserName']         = $targetUser
            $props['LogOffSecurityID'] = "$($evt.Properties[0].Value)"
            $props['AccountDomain']    = "$($evt.Properties[2].Value)"
            $props['LogonID']          = "$($evt.Properties[3].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4647 Logoff Initiated' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4647_LogoffInitiated: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4647_LogoffInitiated' -User $User)
    }
}

# ── Event 4779: Terminal Services Session Disconnect ──────────────────────────
# Properties: [0]AccountName [1]AccountDomain [2]LogonID [3]SessionName
#             [4]ClientName [5]ClientAddress

function Get-Event4779_SessionDisconnect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4779 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $accountName = "$($evt.Properties[0].Value)"
            if ($accountName -ne $User -and $accountName -notlike 'ssh_*') { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Disconnect' -Severity 'Info'
            $props['UserName']      = $accountName
            $props['AccountDomain'] = "$($evt.Properties[1].Value)"
            $props['SessionName']   = "$($evt.Properties[3].Value)"
            $props['ClientName']    = "$($evt.Properties[4].Value)"
            $props['ClientAddress'] = "$($evt.Properties[5].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4779 Session Disconnect' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4779_SessionDisconnect: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4779_SessionDisconnect' -User $User)
    }
}
