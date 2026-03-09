# ── Logon Events Processor ────────────────────────────────────────────────────
# Monitors user authentication and session creation events.
# Event IDs: 4624 (success), 4625 (failure), 4648 (explicit creds), 4800 (lock), 4801 (unlock)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/

<#
.SYNOPSIS
    Collects all logon-related security events for a user within the time window.
.DESCRIPTION
    Orchestrates logon event collection: successful logons (4624), failed logons (4625),
    explicit credential use (4648), workstation lock (4800), and unlock (4801).
.PARAMETER sessionId
    Correlation identifier for this monitoring session.
.PARAMETER StartTime
    Only process events created at or after this timestamp.
.PARAMETER User
    The Windows username to filter events for.
#>
function Get-LogonEvents {
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

    Get-Event4624_LogonSuccess         @commonParams
    Get-Event4625_LogonFailed          @commonParams
    Get-Event4648_ExplicitCredential   @commonParams
    Get-Event4800_WorkstationLocked    @commonParams
    Get-Event4801_WorkstationUnlocked  @commonParams
}

# ── Event 4624: Successful Logon ──────────────────────────────────────────────
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomain [3]SubjectLogonId
#             [4]TargetSID [5]TargetUserName [6]TargetDomain [7]TargetLogonId
#             [8]LogonType [9]LogonProcessName [10]AuthenticationPackage
#             [11]WorkstationName [12]LogonGuid [13]TransmittedServices
#             [14]LmPackageName [15]KeyLength [16]ProcessId [17]ProcessName
#             [18]IpAddress [19]IpPort [20]ImpersonationLevel [21]RestrictedAdminMode
#             [22]TargetOutboundUserName [23]TargetOutboundDomainName
#             [24]VirtualAccount [25]TargetLinkedLogonId [26]ElevatedToken

function Get-Event4624_LogonSuccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4624 -LogName 'Security' -StartTime $StartTime

        # LogonTypes that represent real user activity:
        # 2=Interactive(console), 7=Unlock, 9=NewCredentials(runas), 10=RDP, 11=CachedInteractive
        # Skip: 0=System, 3=Network(too noisy - every SMB/share), 4=Batch, 5=Service, 8=NetworkCleartext
        $interactiveLogonTypes = @('2', '7', '9', '10', '11')

        foreach ($evt in $events) {
            $targetUser = "$($evt.Properties[5].Value)"
            if ($targetUser -ne $User -and $targetUser -notlike 'ssh_*') { continue }

            # Skip system/service account logons — they are noise
            $logonType = "$($evt.Properties[8].Value)"
            if ($logonType -notin $interactiveLogonTypes) { continue }

            $process = "$($evt.Properties[17].Value)"

            $props = New-EventProperties -SessionId $sessionId -EventType 'Connect' -Severity 'Info'
            $props['UserName']      = $targetUser
            $props['AccountDomain'] = "$($evt.Properties[6].Value)"
            $props['LogonSID']      = "$($evt.Properties[4].Value)"
            $props['LogonType']     = "$($evt.Properties[8].Value)"
            $props['LogonProcess']  = "$($evt.Properties[9].Value)"
            $props['Process']       = $process
            $props['SourceIP']      = "$($evt.Properties[18].Value)"
            $props['SourcePort']    = "$($evt.Properties[19].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4624 Logon Success' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4624_LogonSuccess: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4624_LogonSuccess' -User $User)
    }
}

# ── Event 4625: Failed Logon Attempt ──────────────────────────────────────────
# Critical for brute-force detection, unauthorized access attempts.
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomain [3]SubjectLogonId
#             [4]TargetSID [5]TargetUserName [6]TargetDomain [7]Status
#             [8]FailureReason [9]SubStatus [10]LogonType [11]LogonProcessName
#             [12]AuthenticationPackage [13]WorkstationName [14]TransmittedServices
#             [15]LmPackageName [16]KeyLength [17]ProcessId [18]ProcessName
#             [19]IpAddress [20]IpPort

function Get-Event4625_LogonFailed {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4625 -LogName 'Security' -StartTime $StartTime

        # System accounts to ignore for failed logons
        $systemAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'DWM-1', 'DWM-2', 'DWM-3', 'UMFD-0', 'UMFD-1', '')

        foreach ($evt in $events) {
            $targetUser = "$($evt.Properties[5].Value)"

            # Skip failures for system/service accounts
            if ($targetUser -in $systemAccounts -or $targetUser -like 'DWM-*' -or $targetUser -like 'UMFD-*') { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'High'
            $props['TargetUserName']  = $targetUser
            $props['TargetDomain']    = "$($evt.Properties[6].Value)"
            $props['Status']          = "$($evt.Properties[7].Value)"
            $props['FailureReason']   = "$($evt.Properties[8].Value)"
            $props['SubStatus']       = "$($evt.Properties[9].Value)"
            $props['LogonType']       = "$($evt.Properties[10].Value)"
            $props['LogonProcess']    = "$($evt.Properties[11].Value)"
            $props['AuthPackage']     = "$($evt.Properties[12].Value)"
            $props['WorkstationName'] = "$($evt.Properties[13].Value)"
            $props['ProcessName']     = "$($evt.Properties[18].Value)"
            $props['SourceIP']        = "$($evt.Properties[19].Value)"
            $props['SourcePort']      = "$($evt.Properties[20].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4625 Logon Failed' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4625_LogonFailed: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4625_LogonFailed' -User $User)
    }
}

# ── Event 4648: Explicit Credential Logon ─────────────────────────────────────
# Properties: [0]SubjectSID [1]SubjectUserName [2]SubjectDomain [3]SubjectLogonId
#             [4]LogonGuid [5]TargetUserName [6]TargetDomain [7]TargetLogonGuid
#             [8]TargetServerName [9]TargetServerInfo [10]ProcessId [11]ProcessName
#             [12]NetworkAddress [13]NetworkPort

function Get-Event4648_ExplicitCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4648 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $targetUser = "$($evt.Properties[5].Value)"
            if ($targetUser -ne $User -and $targetUser -notlike 'ssh_*') { continue }

            $process = "$($evt.Properties[11].Value)"

            # Skip sshd.exe — SSH connections are tracked by the dedicated SSH processor
            if ($process -like '*sshd.exe') { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Connect' -Severity 'Medium'
            $props['UserName']      = $targetUser
            $props['AccountDomain'] = "$($evt.Properties[2].Value)"
            $props['TargetServer']  = "$($evt.Properties[8].Value)"
            $props['Process']       = $process
            $props['SourceIP']      = "$($evt.Properties[12].Value)"
            $props['SourcePort']    = "$($evt.Properties[13].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4648 Explicit Credential Logon' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4648_ExplicitCredential: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4648_ExplicitCredential' -User $User)
    }
}

# ── Event 4800: Workstation Locked ────────────────────────────────────────────
# Properties: [0]TargetSID [1]TargetUserName [2]TargetDomainName [3]TargetLogonId [4]SessionId

function Get-Event4800_WorkstationLocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4800 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            if ("$($evt.Properties[1].Value)" -ne $User) { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Info' -Severity 'Info'
            $props['UserName']      = "$($evt.Properties[1].Value)"
            $props['LogonSID']      = "$($evt.Properties[0].Value)"
            $props['AccountDomain'] = "$($evt.Properties[2].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4800 Workstation Locked' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4800_WorkstationLocked: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4800_WorkstationLocked' -User $User)
    }
}

# ── Event 4801: Workstation Unlocked ──────────────────────────────────────────
# Properties: [0]TargetSID [1]TargetUserName [2]TargetDomainName [3]TargetLogonId [4]SessionId

function Get-Event4801_WorkstationUnlocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEvents -EventId 4801 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            if ("$($evt.Properties[1].Value)" -ne $User) { continue }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Connect' -Severity 'Info'
            $props['UserName']      = "$($evt.Properties[1].Value)"
            $props['LogonSID']      = "$($evt.Properties[0].Value)"
            $props['AccountDomain'] = "$($evt.Properties[2].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName '4801 Workstation Unlocked' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-Event4801_WorkstationUnlocked: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-Event4801_WorkstationUnlocked' -User $User)
    }
}
