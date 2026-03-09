# ── Audit Tampering Events Processor ──────────────────────────────────────────
# Monitors audit log clearing and audit policy changes — anti-forensics indicators.
# Event IDs: 1102 (audit log cleared), 4719 (audit policy changed)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4719

<#
.SYNOPSIS
    Collects audit tampering events within the time window.
.DESCRIPTION
    These are the highest-severity events — an attacker covering their tracks
    by clearing the audit log or changing audit policy. NEVER filtered by user.
#>
function Get-AuditEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    Get-Event1102_AuditLogCleared -sessionId $sessionId -StartTime $StartTime
    Get-Event4719_AuditPolicyChanged -sessionId $sessionId -StartTime $StartTime
}

# ── Event 1102: Audit Log Cleared ─────────────────────────────────────────────
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName [3]SubjectLogonId

function Get-Event1102_AuditLogCleared {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 1102 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Critical'
            $props['SubjectUserName']  = "$($evt.Properties[1].Value)"
            $props['SubjectDomain']    = "$($evt.Properties[2].Value)"
            $props['SubjectLogonId']   = "$($evt.Properties[3].Value)"
            $props['EventDescription'] = 'Security Audit Log Cleared'

            Send-LogAnalyticsConnectEvents `
                -eventName '1102 Audit Log Cleared' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event1102_AuditLogCleared: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event1102_AuditLogCleared')
    }
}

# ── Event 4719: System Audit Policy Changed ──────────────────────────────────
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName [3]SubjectLogonId
#             [4]CategoryId [5]SubcategoryId [6]SubcategoryGuid [7]AuditPolicyChanges

function Get-Event4719_AuditPolicyChanged {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 4719 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Critical'
            $props['SubjectUserName']    = "$($evt.Properties[1].Value)"
            $props['SubjectDomain']      = "$($evt.Properties[2].Value)"
            $props['CategoryId']         = "$($evt.Properties[4].Value)"
            $props['SubcategoryId']      = "$($evt.Properties[5].Value)"
            $props['AuditPolicyChanges'] = "$($evt.Properties[7].Value)"
            $props['EventDescription']   = 'System Audit Policy Changed'

            Send-LogAnalyticsConnectEvents `
                -eventName '4719 Audit Policy Changed' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4719_AuditPolicyChanged: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4719_AuditPolicyChanged')
    }
}
