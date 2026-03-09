# ── Logoff Indicators ─────────────────────────────────────────────────────────
# Functions that read Windows events indicating a user disconnection or idle state.
# Each function queries a specific Event ID, extracts relevant properties,
# and forwards the enriched data to Application Insights.

<#
.SYNOPSIS
    Orchestrates all logoff-indicator event readers for a given user and time window.
.DESCRIPTION
    Calls each logoff event reader in sequence: 4647, 4779, OpenSSH disconnect.
#>
function Get-UserIdleEvents {
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

    Get-Event_4647_LogoffInitiated          @commonParams
    Get-Event_4779_DisconnectsOrSwitch      @commonParams
    Get-OpenSSHApplication_Event_Disconnect @commonParams
}

# ── Event 4647: Logoff Initiated ──────────────────────────────────────────────

<#
.SYNOPSIS
    Reads Security event 4647 — user-initiated logoff.
.DESCRIPTION
    No further user-initiated activity can occur for the related logon session
    after this event is generated.
#>
function Get-Event_4647_LogoffInitiated {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.Security; id = 4647 } -ErrorAction Stop |
            Where-Object { ($_.properties[1].Value -eq $User -or $_.properties[1].Value -like 'ssh_*') -and $_.TimeCreated -ge $TimeBefore }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']        = $sessionId
            $evProps['EventType']        = 'Disconnect'
            $evProps['UserName']         = $User
            $evProps['LogOffSecurityID'] = "$($evt.properties[0].Value)"
            $evProps['AccountDomain']    = "$($evt.properties[2].Value)"
            $evProps['LogonID']          = "$($evt.properties[3].Value)"

            Send-LogAnalyticsConnectEvents -eventName "$($evt.Id) Disconnect Event" `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Event_4647 failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-Event_4647_LogoffInitiated'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}

# ── Event 4779: Terminal Services Disconnect / Fast User Switch ───────────────

<#
.SYNOPSIS
    Reads Security event 4779 — user disconnects from Terminal Services session
    or switches away via Fast User Switching.
#>
function Get-Event_4779_DisconnectsOrSwitch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.Security; id = 4779 } -ErrorAction Stop |
            Where-Object { ($_.properties[1].Value -eq $User -or $_.properties[1].Value -like 'ssh_*') -and $_.TimeCreated -ge $TimeBefore }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']     = $sessionId
            $evProps['EventType']     = 'Disconnect'
            $evProps['UserName']      = $User
            $evProps['AccountDomain'] = "$($evt.properties[1].Value)"
            $evProps['SessionName']   = "$($evt.properties[3].Value)"
            $evProps['ClientName']    = "$($evt.properties[4].Value)"
            $evProps['ClientAddress'] = "$($evt.properties[5].Value)"

            Send-LogAnalyticsConnectEvents -eventName "$($evt.Id) Disconnect Event" `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Event_4779 failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-Event_4779_DisconnectsOrSwitch'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}

# ── OpenSSH Disconnect ────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Reads OpenSSH/Operational events for SSH disconnect requests.
.NOTES
    Less reliable than Security events because the OpenSSH disconnect event
    does not always include the specific user who disconnected.
#>
function Get-OpenSSHApplication_Event_Disconnect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [DateTime]$TimeBefore
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{ logname = $script:EventLogType.OpenSSHOperational } -ErrorAction Stop |
            Where-Object { $_.properties[1].Value -like 'Disconnected*' -and $_.TimeCreated -ge $TimeBefore }

        foreach ($evt in $events) {
            $message = $evt.Message
            $parts   = $message -split '\s+'

            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId'] = $sessionId
            $evProps['EventType'] = 'Disconnect'
            $evProps['UserName']  = $User
            $evProps['Process']   = if ($parts.Count -ge 1) { $parts[0] } else { '' }
            $evProps['IP']        = if ($parts.Count -ge 4) { $parts[3] } else { '' }
            $evProps['Port']      = if ($parts.Count -ge 6) { $parts[5] } else { '' }
            $evProps['UserSID']   = "$($evt.UserId)"

            Send-LogAnalyticsConnectEvents -eventName 'OpenSSHApplication Disconnect Event' `
                -Properties $evProps -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-OpenSSH_Disconnect failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId'] = $sessionId
            $errorProps['User']      = $User
            $errorProps['Function']  = 'Get-OpenSSHApplication_Event_Disconnect'
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}
