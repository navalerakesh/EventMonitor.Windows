# ── Privilege Use Events Processor ─────────────────────────────────────────────
# Monitors special privilege assignment at logon time.
# Event ID: 4672 — Special privileges assigned to new logon
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672

<#
.SYNOPSIS
    Collects privilege assignment events within the time window.
.DESCRIPTION
    Event 4672 fires when a logon session receives sensitive privileges
    (SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, etc.).
    This identifies admin-level logons and potential privilege abuse.
#>
function Get-PrivilegeEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4672 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            # Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName
            #             [3]SubjectLogonId [4]PrivilegeList
            $subjectUser = "$($evt.Properties[1].Value)"

            # Filter to the monitored user, skip SYSTEM/LOCAL SERVICE noise
            if ($subjectUser -ne $User) { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'High'
            $props['UserName']       = $subjectUser
            $props['AccountDomain']  = "$($evt.Properties[2].Value)"
            $props['LogonId']        = "$($evt.Properties[3].Value)"
            $props['PrivilegeList']  = "$($evt.Properties[4].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4672 Special Privileges Assigned' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-PrivilegeEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-PrivilegeEvents' -User $User)
    }
}
