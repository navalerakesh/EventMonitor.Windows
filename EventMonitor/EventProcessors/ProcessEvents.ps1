# ── Process Tracking Events Processor ─────────────────────────────────────────
# Monitors process creation and termination events.
# Event IDs: 4688 (process created), 4689 (process terminated)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688
# Note: Process command line auditing must be enabled via Group Policy for full value:
#   Computer Configuration > Policies > Windows Settings > Security Settings >
#   Advanced Audit Policy > Detailed Tracking > Audit Process Creation

<#
.SYNOPSIS
    Collects process creation and termination events for a user within the time window.
.DESCRIPTION
    Event 4688 is critical for detecting malware execution, lateral movement, and
    living-off-the-land attacks. Captures the new process name, parent process,
    command line (if audit policy enabled), and the user who created the process.
#>
function Get-ProcessEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    Get-Event4688_ProcessCreated -sessionId $sessionId -StartTime $StartTime -User $User
    Get-Event4689_ProcessTerminated -sessionId $sessionId -StartTime $StartTime -User $User
}

# ── Event 4688: New Process Created ───────────────────────────────────────────
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName [3]SubjectLogonId
#             [4]NewProcessId [5]NewProcessName [6]TokenElevationType [7]ParentProcessName
#             [8]CommandLine [9]TargetSID [10]TargetUserName [11]TargetDomainName
#             [12]TargetLogonId [13]MandatoryLabel

function Get-Event4688_ProcessCreated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4688 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $subjectUser = "$($evt.Properties[1].Value)"
            if ($subjectUser -ne $User) { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Info' -Severity 'Medium'
            $props['SubjectUserName'] = $subjectUser
            $props['SubjectDomain']   = "$($evt.Properties[2].Value)"
            $props['NewProcessId']    = "$($evt.Properties[4].Value)"
            $props['NewProcessName']  = "$($evt.Properties[5].Value)"
            $props['TokenElevation']  = "$($evt.Properties[6].Value)"
            $props['ParentProcess']   = "$($evt.Properties[7].Value)"
            $props['CommandLine']     = "$($evt.Properties[8].Value)"
            $props['TargetUserName']  = "$($evt.Properties[10].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4688 Process Created' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4688_ProcessCreated: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4688_ProcessCreated' -User $User)
    }
}

# ── Event 4689: Process Terminated ────────────────────────────────────────────
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomainName [3]SubjectLogonId
#             [4]Status [5]ProcessId [6]ProcessName

function Get-Event4689_ProcessTerminated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4689 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $subjectUser = "$($evt.Properties[1].Value)"
            if ($subjectUser -ne $User) { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Info' -Severity 'Low'
            $props['SubjectUserName'] = $subjectUser
            $props['SubjectDomain']   = "$($evt.Properties[2].Value)"
            $props['ProcessId']       = "$($evt.Properties[5].Value)"
            $props['ProcessName']     = "$($evt.Properties[6].Value)"
            $props['ExitStatus']      = "$($evt.Properties[4].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4689 Process Terminated' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4689_ProcessTerminated: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4689_ProcessTerminated' -User $User)
    }
}
