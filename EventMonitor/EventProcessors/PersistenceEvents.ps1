# ── Persistence Events Processor ──────────────────────────────────────────────
# Monitors service installation and scheduled task creation/modification.
# These are key persistence mechanisms used by attackers and malware.
# Event IDs: 4697, 4698, 4702 (Security), 7045 (System)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697

<#
.SYNOPSIS
    Collects persistence-related events within the time window.
.DESCRIPTION
    These events are NOT filtered by user — any service/task install is relevant.
    Attackers frequently install services or scheduled tasks for persistence.
#>
function Get-PersistenceEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    Get-SecurityPersistenceEvents -sessionId $sessionId -StartTime $StartTime
    Get-Event7045_ServiceInstalled -sessionId $sessionId -StartTime $StartTime
}

# ── Events 4697, 4698, 4702: Security Log Persistence ────────────────────────
# 4697: Service installed  — [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName
#       [3]SubjectLogonId [4]ServiceName [5]ServiceFileName [6]ServiceType
#       [7]ServiceStartType [8]ServiceAccount
# 4698: Scheduled task created — [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName
#       [3]SubjectLogonId [4]TaskName [5]TaskContent (XML)
# 4702: Scheduled task updated — same layout as 4698

function Get-SecurityPersistenceEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 4697, 4698, 4699, 4702 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            switch ($evt.Id) {
                4697 {
                    $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Critical'
                    $props['SubjectUserName']  = "$($evt.Properties[1].Value)"
                    $props['SubjectDomain']    = "$($evt.Properties[2].Value)"
                    $props['ServiceName']      = "$($evt.Properties[4].Value)"
                    $props['ServiceFileName']  = "$($evt.Properties[5].Value)"
                    $props['ServiceType']      = "$($evt.Properties[6].Value)"
                    $props['ServiceStartType'] = "$($evt.Properties[7].Value)"
                    $props['ServiceAccount']   = "$($evt.Properties[8].Value)"
                    $props['EventDescription'] = 'Service Installed on System'

                    Send-LogAnalyticsConnectEvents `
                        -eventName '4697 Service Installed' -Properties $props -sendEvent $evt
                }
                { $_ -in 4698, 4699, 4702 } {
                    $description = switch ($evt.Id) {
                        4698 { 'Scheduled Task Created' }
                        4699 { 'Scheduled Task Deleted' }
                        4702 { 'Scheduled Task Updated' }
                    }
                    $severity = switch ($evt.Id) {
                        4698 { 'Critical' }
                        4699 { 'High' }
                        4702 { 'High' }
                    }

                    $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity $severity
                    $props['SubjectUserName']  = "$($evt.Properties[1].Value)"
                    $props['SubjectDomain']    = "$($evt.Properties[2].Value)"
                    $props['TaskName']         = "$($evt.Properties[4].Value)"
                    $props['EventDescription'] = $description
                    # Task XML content can be very large — truncate for telemetry
                    $taskXml = "$($evt.Properties[5].Value)"
                    if ($taskXml.Length -gt 2000) { $taskXml = $taskXml.Substring(0, 2000) + '...[truncated]' }
                    $props['TaskContent'] = $taskXml

                    Send-LogAnalyticsConnectEvents `
                        -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
                }
            }
        }
    }
    catch {
        Write-EMLog -Message "Get-SecurityPersistenceEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-SecurityPersistenceEvents')
    }
}

# ── Event 7045: New Service Installed (System log) ────────────────────────────
# Properties: [0]ServiceName [1]ImagePath [2]ServiceType [3]StartType [4]AccountName

function Get-Event7045_ServiceInstalled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 7045 -LogName 'System' -StartTime $StartTime

        foreach ($evt in $events) {
            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'High'
            $props['ServiceName']      = "$($evt.Properties[0].Value)"
            $props['ImagePath']        = "$($evt.Properties[1].Value)"
            $props['ServiceType']      = "$($evt.Properties[2].Value)"
            $props['StartType']        = "$($evt.Properties[3].Value)"
            $props['AccountName']      = "$($evt.Properties[4].Value)"
            $props['EventDescription'] = 'New Service Installed (System)'

            Send-LogAnalyticsConnectEvents `
                -eventName '7045 Service Installed' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event7045_ServiceInstalled: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event7045_ServiceInstalled')
    }
}
