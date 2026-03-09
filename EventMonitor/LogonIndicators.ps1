# ── Logon Indicators ──────────────────────────────────────────────────────────
# Functions that read Windows events indicating a user connection or activity.
# Each function queries a specific Event ID, extracts relevant properties,
# and forwards the enriched data to Application Insights via Send-LogAnalyticsConnectEvents.

<#
.SYNOPSIS
    Orchestrates all logon-indicator event readers for a given user and time window.
.DESCRIPTION
    Calls each logon event reader in sequence: OpenSSH connect, 4624, 4801, 5140, 4648.
    Any individual reader failure is caught and logged without stopping the others.
#>
function Get-UserInteractionEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$sessionId,

        [Parameter(Mandatory)]
        [DateTime]$TimeBefore,

        [Parameter(Mandatory)]
        [string]$User
    )

    $commonParams = @{
        sessionId  = $sessionId
        User       = $User
        TimeBefore = $TimeBefore
    }

    Get-OpenSSHApplication_Event_Connect  @commonParams
    Get-Event_4624                        @commonParams
    Get-Event_4801_MachineUnlocked        @commonParams
    Get-Event_5140_NetworkShareAccess     @commonParams
    Get-Event_4648                        @commonParams
}

# ── OpenSSH Connect ───────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Reads OpenSSH/Operational events for successful SSH public-key authentication.
.NOTES
    Requires the OpenSSH Server feature to be installed. The event log may not
    exist on machines without OpenSSH, which is handled gracefully.
#>
function Get-OpenSSHApplication_Event_Connect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.OpenSSHOperational } -ErrorAction Stop |
            Where-Object { $_.properties[1].Value -like 'Accepted publickey*' -and $_.TimeCreated -ge $TimeBefore }

        foreach ($evt in $events) {
            $message  = $evt.Message
            $parts    = $message -split '\s+'
            $userName = if ($parts.Count -ge 5) { $parts[4] -split '@' | Select-Object -First 1 } else { '' }

            if ($userName -ne $User) { continue }

            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId'] = $sessionId
            $evProps['EventType'] = 'Connect'
            $evProps['UserName']  = $User
            $evProps['Process']   = if ($parts.Count -ge 1) { $parts[0] } else { '' }
            $evProps['IPAddress'] = if ($parts.Count -ge 7) { $parts[6] } else { '' }
            $evProps['IPPort']    = if ($parts.Count -ge 9) { $parts[8] } else { '' }
            $evProps['UserSID']   = "$($evt.UserId)"

            Send-LogAnalyticsConnectEvents -eventName 'OpenSSH/Operational Connect Event' `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-OpenSSHApplication_Event_Connect failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-OpenSSHApplication_Event_Connect'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}

# ── Event 4648: Explicit Credential Logon ─────────────────────────────────────

<#
.SYNOPSIS
    Reads Security event 4648 — explicit credential logon attempts via sshd.exe or svchost.exe.
#>
function Get-Event_4648 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $allEvents = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.Security; id = 4648 } -ErrorAction Stop |
            Where-Object { ($_.properties[5].Value -eq $User -or $_.properties[5].Value -like 'ssh_*') -and $_.TimeCreated -ge $TimeBefore }

        $events = $allEvents | Where-Object { $_.properties[11].Value -like '*sshd.exe' -or $_.properties[11].Value -like '*svchost.exe' }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']     = $sessionId
            $evProps['EventType']     = 'Connect'
            $evProps['AccountDomain'] = "$($evt.properties[2].Value)"
            $evProps['UserName']      = $User
            $evProps['Process']       = "$($evt.properties[11].Value)"

            Send-LogAnalyticsConnectEvents -eventName "$($evt.Id) Connect Event" `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Event_4648 failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-Event_4648'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}

# ── Event 4624: Logon Session Created ─────────────────────────────────────────

<#
.SYNOPSIS
    Reads Security event 4624 — logon session created on destination machine (via SSH or RDP).
#>
function Get-Event_4624 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $allEvents = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.Security; id = 4624 } -ErrorAction Stop |
            Where-Object { ($_.properties[5].Value -eq $User -or $_.properties[5].Value -like 'ssh_*') -and $_.TimeCreated -ge $TimeBefore }

        $events = $allEvents | Where-Object { $_.properties[17].Value -like '*sshd.exe' -or $_.properties[17].Value -like '*svchost.exe' }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']     = $sessionId
            $evProps['EventType']     = 'Connect'
            $evProps['AccountDomain'] = "$($evt.properties[2].Value)"
            $evProps['LogonSID']      = "$($evt.properties[4].Value)"
            $evProps['UserName']      = "$($evt.properties[5].Value)"
            $evProps['LogonType']     = "$($evt.properties[8].Value)"
            $evProps['LogonProcess']  = "$($evt.properties[9].Value)"
            $evProps['Process']       = "$($evt.properties[17].Value)"

            Send-LogAnalyticsConnectEvents -eventName "$($evt.Id) Connect Event" `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Event_4624 failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-Event_4624'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}

# ── Event 5140: Network Share Access ──────────────────────────────────────────

<#
.SYNOPSIS
    Reads Security event 5140 — network share object was accessed.
#>
function Get-Event_5140_NetworkShareAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.Security; id = 5140 } -ErrorAction Stop |
            Where-Object { $_.properties[1].Value -eq $User -and $_.TimeCreated -ge $TimeBefore }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']     = $sessionId
            $evProps['EventType']     = 'Connect'
            $evProps['LogonSID']      = "$($evt.properties[0].Value)"
            $evProps['UserName']      = "$($evt.properties[1].Value)"
            $evProps['AccountDomain'] = "$($evt.properties[3].Value)"
            $evProps['SourceAddress'] = "$($evt.properties[5].Value)"

            Send-LogAnalyticsConnectEvents -eventName "$($evt.Id) Connect Event" `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Event_5140 failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-Event_5140_NetworkShareAccess'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}

# ── Event 4801: Workstation Unlocked ──────────────────────────────────────────

<#
.SYNOPSIS
    Reads Security event 4801 — workstation was unlocked.
#>
function Get-Event_4801_MachineUnlocked {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.Security; id = 4801 } -ErrorAction Stop |
            Where-Object { $_.properties[1].Value -eq $User -and $_.TimeCreated -ge $TimeBefore }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']     = $sessionId
            $evProps['EventType']     = 'Connect'
            $evProps['LogonSID']      = "$($evt.properties[0].Value)"
            $evProps['UserName']      = "$($evt.properties[1].Value)"
            $evProps['AccountDomain'] = "$($evt.properties[3].Value)"

            Send-LogAnalyticsConnectEvents -eventName "$($evt.Id) Connect Event" `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Event_4801 failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-Event_4801_MachineUnlocked'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}
