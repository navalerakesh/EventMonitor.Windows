# ── Account Management Events Processor ───────────────────────────────────────
# Monitors user account lifecycle events — creation, deletion, enable/disable, password changes.
# Critical for detecting unauthorized account manipulation and persistence.
# Event IDs: 4720, 4722, 4723, 4724, 4725, 4726
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/

<#
.SYNOPSIS
    Collects all account management events within the time window.
.DESCRIPTION
    These events are NOT filtered by user — ALL account changes are monitored
    because an attacker's first move is often creating or modifying accounts.
#>
function Get-AccountEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 4720, 4722, 4723, 4724, 4725, 4726 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $eventId = $evt.Id

            # Common property layout for account management events:
            # [0]TargetSID [1]TargetUserName [2]TargetDomainName
            # [4]SubjectSID [5]SubjectUserName [6]SubjectDomainName [7]SubjectLogonId

            $description = switch ($eventId) {
                4720 { 'User Account Created' }
                4722 { 'User Account Enabled' }
                4723 { 'Password Change Attempted' }
                4724 { 'Password Reset Attempted' }
                4725 { 'User Account Disabled' }
                4726 { 'User Account Deleted' }
            }

            $severity = switch ($eventId) {
                4720 { 'Critical' }
                4722 { 'High' }
                4723 { 'Medium' }
                4724 { 'High' }
                4725 { 'High' }
                4726 { 'Critical' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity $severity
            $props['TargetUserName']   = "$($evt.Properties[1].Value)"
            $props['TargetDomain']     = "$($evt.Properties[2].Value)"
            $props['SubjectUserName']  = "$($evt.Properties[5].Value)"
            $props['SubjectDomain']    = "$($evt.Properties[6].Value)"
            $props['SubjectLogonId']   = "$($evt.Properties[7].Value)"
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$eventId $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-AccountEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-AccountEvents')
    }
}
