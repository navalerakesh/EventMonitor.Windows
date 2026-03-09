# ── Group Management Events Processor ─────────────────────────────────────────
# Monitors security group membership changes — privilege escalation indicators.
# Event IDs: 4732 (member added), 4733 (member removed)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732

<#
.SYNOPSIS
    Collects security group membership change events within the time window.
.DESCRIPTION
    Monitors when members are added to or removed from local security groups.
    Critical for detecting privilege escalation — e.g., adding a user to Administrators.
#>
function Get-GroupEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 4732, 4733 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            # Properties: [0]MemberSID [1]MemberName [2]TargetSID [3]TargetUserName
            #             [4]TargetDomainName [5]SubjectSID [6]SubjectUserName
            #             [7]SubjectDomainName [8]SubjectLogonId

            $description = switch ($evt.Id) {
                4732 { 'Member Added to Security Group' }
                4733 { 'Member Removed from Security Group' }
            }

            $severity = switch ($evt.Id) {
                4732 { 'Critical' }
                4733 { 'High' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity $severity
            $props['MemberSID']        = "$($evt.Properties[0].Value)"
            $props['MemberName']       = "$($evt.Properties[1].Value)"
            $props['GroupName']        = "$($evt.Properties[3].Value)"
            $props['GroupDomain']      = "$($evt.Properties[4].Value)"
            $props['SubjectUserName']  = "$($evt.Properties[6].Value)"
            $props['SubjectDomain']    = "$($evt.Properties[7].Value)"
            $props['SubjectLogonId']   = "$($evt.Properties[8].Value)"
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-GroupEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-GroupEvents')
    }
}
