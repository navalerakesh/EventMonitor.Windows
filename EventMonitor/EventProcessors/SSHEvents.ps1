# ── SSH Events Processor ──────────────────────────────────────────────────────
# Monitors OpenSSH server connection and disconnection events.
# Uses OpenSSH/Operational log, filtered by message content.

<#
.SYNOPSIS
    Collects SSH connect and disconnect events for a user within the time window.
#>
function Get-SSHEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    Get-SSHConnectEvents    -sessionId $sessionId -StartTime $StartTime -User $User
    Get-SSHDisconnectEvents -sessionId $sessionId -StartTime $StartTime -User $User
    Get-SSHFailedAuthEvents -sessionId $sessionId -StartTime $StartTime
}

# ── SSH Connect (Accepted publickey) ──────────────────────────────────────────

function Get-SSHConnectEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEventsByLog -LogName 'OpenSSH/Operational' -StartTime $StartTime

        foreach ($evt in $events) {
            if ("$($evt.Properties[1].Value)" -notlike 'Accepted publickey*') { continue }

            $message = $evt.Message

            # OpenSSH connect message format:
            #   "Accepted publickey for <user> from <ip> port <port> ssh2: ..."
            $sshUser = if ($message -match 'for (\S+) from') { $Matches[1] } else { '' }
            if ($sshUser -ne $User) { continue }

            $sshIP   = if ($message -match 'from (\d+\.\d+\.\d+\.\d+)') { $Matches[1] } else { '' }
            $sshPort = if ($message -match 'port (\d+)') { $Matches[1] } else { '' }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Connect' -Severity 'Info'
            $props['UserName']  = $sshUser
            $props['IPAddress'] = $sshIP
            $props['IPPort']    = $sshPort
            $props['UserSID']   = "$($evt.UserId)"

            Send-LogAnalyticsConnectEvents `
                -eventName 'SSH Connect' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-SSHConnectEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-SSHConnectEvents' -User $User)
    }
}

# ── SSH Disconnect ────────────────────────────────────────────────────────────

function Get-SSHDisconnectEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime,
        [Parameter(Mandatory)] [string]$User
    )

    try {
        $events = Read-WindowsEventsByLog -LogName 'OpenSSH/Operational' -StartTime $StartTime

        foreach ($evt in $events) {
            if ("$($evt.Properties[1].Value)" -notlike 'Disconnected*') { continue }

            # Extract connection details from the message
            $message = $evt.Message

            # OpenSSH disconnect message formats:
            #   "Disconnected from user <user> <ip> port <port>"
            #   "Disconnected from <ip> port <port>"
            # Extract user from "from user <name>" pattern
            $sshUser = ''
            if ($message -match 'from user (\S+)') {
                $sshUser = $Matches[1]
            }

            # Only track disconnects for the user we're monitoring
            if ($sshUser -and $sshUser -ne $User) { continue }

            # Extract IP and port via regex for reliability
            $sshIP   = if ($message -match '(\d+\.\d+\.\d+\.\d+)') { $Matches[1] } else { '' }
            $sshPort = if ($message -match 'port (\d+)') { $Matches[1] } else { '' }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Disconnect' -Severity 'Info'
            $props['UserName'] = if ($sshUser) { $sshUser } else { $User }
            $props['IP']       = $sshIP
            $props['Port']     = $sshPort
            $props['UserSID']  = "$($evt.UserId)"

            Send-LogAnalyticsConnectEvents `
                -eventName 'SSH Disconnect' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-SSHDisconnectEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-SSHDisconnectEvents' -User $User)
    }
}

# ── SSH Failed Authentication ─────────────────────────────────────────────────
# Detects brute force SSH attacks by looking for "Failed password" and
# "Invalid user" messages in the OpenSSH Operational log.
# NOT filtered by user — all failed SSH auth attempts are security-relevant.

function Get-SSHFailedAuthEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEventsByLog -LogName 'OpenSSH/Operational' -StartTime $StartTime

        foreach ($evt in $events) {
            $propValue = "$($evt.Properties[1].Value)"

            # Match failed auth patterns
            if ($propValue -notlike 'Failed password*' -and
                $propValue -notlike 'Invalid user*' -and
                $propValue -notlike 'Connection closed by*authenticating user*') { continue }

            $message = $evt.Message

            $failUser = ''
            if ($message -match 'for (?:invalid user )?(\S+) from') { $failUser = $Matches[1] }
            $failIP   = if ($message -match 'from (\d+\.\d+\.\d+\.\d+)') { $Matches[1] } else { '' }
            $failPort = if ($message -match 'port (\d+)') { $Matches[1] } else { '' }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'High'
            $props['TargetUserName']   = $failUser
            $props['SourceIP']         = $failIP
            $props['SourcePort']       = $failPort
            $props['FailureDetail']    = $propValue
            $props['EventDescription'] = 'SSH Authentication Failed'
            $props['UserSID']          = "$($evt.UserId)"

            Send-LogAnalyticsConnectEvents `
                -eventName 'SSH Authentication Failed' -Properties $props -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-SSHFailedAuthEvents: $($_.Exception.Message)" -Level Error
            TrackException -ErrorRecord $_ `
                -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-SSHFailedAuthEvents')
        }
    }
}
