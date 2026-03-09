# ── Session Detection ─────────────────────────────────────────────────────────
# Functions that detect active user sessions (RDP via quser), active SSH
# connections (via netstat), and enumerate Windows user profiles.

<#
.SYNOPSIS
    Parses quser output to detect active/idle RDP sessions and reports each to telemetry.
.DESCRIPTION
    Runs "query user" (quser) and parses the tabular output to extract session state,
    idle time, and logon time for each session. Sends each session as a telemetry event.
    Returns $true if at least one session has Active state with zero idle time.
.OUTPUTS
    [bool] $true if an active, non-idle user session exists.
.NOTES
    quser is available on Windows 10/11 Pro, Enterprise, and Server editions.
    It is NOT available on Windows 10/11 Home edition.
#>
function Get-ActiveUsersByQUsers {
    [CmdletBinding()]
    param(
        [string]$sessionId,

        [Parameter(Mandatory)]
        [string]$UserName
    )

    $hasActiveUserSession = $false

    try {
        $quserOutput = query user 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-EMLog -Message "quser returned exit code $LASTEXITCODE — no sessions or command unavailable." -Level Warning
            return $false
        }

        foreach ($line in $quserOutput) {
            $conInfo = ($line -split '\s+') | Where-Object { -not [string]::IsNullOrEmpty($_) }
            if ($null -eq $conInfo -or $conInfo.Count -lt 5) { continue }
            if ($conInfo[0] -like '*USERNAME*') { continue }

            # Active sessions have 8 columns (username, sessionname, id, state, idle, date, time, am/pm)
            # Disconnected sessions have 7 (no sessionname column)
            if ($conInfo.Count -eq 8) {
                $offset      = 0
                $sessionName = $conInfo[1]
            }
            else {
                $offset      = 1
                $sessionName = '-'
            }

            $state = $conInfo[3 - $offset]
            if ($state -eq 'Active' -and $conInfo[4 - $offset] -eq '.') {
                $hasActiveUserSession = $true
            }

            try {
                $idleMinutes = ConvertTo-IdleMinutes -IdleString $conInfo[4 - $offset]
                $quserName = ($conInfo[0]).Trim('>')

                # Filter to the requested user if specified
                if ($UserName -and $quserName -ne $UserName) { continue }

                $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
                $evProps['SessionId']        = $sessionId
                $evProps['USER-NAME']        = $quserName
                $evProps['SESSION-NAME']     = $sessionName
                $evProps['SESSION-ID']       = $conInfo[2 - $offset]
                $evProps['STATE']            = $state
                $evProps['IDLE-FOR-LAST(Min)'] = "$idleMinutes"
                $evProps['LOGON-TIME']       = "$($conInfo[5 - $offset]) $($conInfo[6 - $offset]) $($conInfo[7 - $offset])"

                TrackEvent -Name 'Query Active Session connection' -Properties $evProps
            }
            catch {
                Write-EMLog -Message "Failed to parse quser line: $line — $($_.Exception.Message)" -Level Warning
            }
        }

        return $hasActiveUserSession
    }
    catch {
        Write-EMLog -Message "Get-ActiveUsersByQUsers failed: $($_.Exception.Message)" -Level Error
        $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
        $errorProps['SessionId'] = $sessionId
        $errorProps['UserName']  = $UserName
        $errorProps['Function']  = 'Get-ActiveUsersByQUsers'
        TrackException -ErrorRecord $_ -Properties $errorProps
        return $false
    }
}

<#
.SYNOPSIS
    Converts a quser idle-time string (e.g., "2:30", "1+3:15", "45", ".") into total minutes.
.OUTPUTS
    [int] Total idle minutes.
#>
function ConvertTo-IdleMinutes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$IdleString
    )

    # "." means zero idle time (currently active)
    if ($IdleString -eq '.' -or $IdleString -eq 'none') { return 0 }

    # Pure number = minutes
    if ($IdleString -match '^\d+$') {
        return [int]$IdleString
    }

    # Format: [days+]hours:minutes
    if ($IdleString -match '^(?:(\d+)\+)?(\d+):(\d+)$') {
        $days  = if ($Matches[1]) { [int]$Matches[1] } else { 0 }
        $hours = [int]$Matches[2]
        $mins  = [int]$Matches[3]
        return ($days * 1440) + ($hours * 60) + $mins
    }

    return 0
}

<#
.SYNOPSIS
    Checks whether the machine has any active SSH connections via netstat.
.DESCRIPTION
    Runs "netstat -b" (requires elevation) and looks for sshd.exe in the output.
    Reports the result via telemetry if an active connection is found.
.OUTPUTS
    [bool] $true if an active sshd connection exists.
#>
function Get-ActiveSSHDConnectionByNetStat {
    [CmdletBinding()]
    param(
        [string]$sessionId
    )

    $hasSSHDConnection = $false

    try {
        $nsOutput = netstat -b 2>&1
        foreach ($line in $nsOutput) {
            if ($line -like '*sshd.exe*') {
                $hasSSHDConnection = $true
                break
            }
        }

        if ($hasSSHDConnection) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId']                  = $sessionId
            $evProps['ACTIVE SSH connection exist'] = 'True'
            TrackEvent -Name 'Query Active SSH connection' -Properties $evProps
        }

        return $hasSSHDConnection
    }
    catch {
        Write-EMLog -Message "Get-ActiveSSHDConnectionByNetStat failed: $($_.Exception.Message)" -Level Error
        $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
        $errorProps['SessionId'] = $sessionId
        $errorProps['Function']  = 'Get-ActiveSSHDConnectionByNetStat'
        TrackException -ErrorRecord $_ -Properties $errorProps
        return $false
    }
}

<#
.SYNOPSIS
    Enumerates non-special Windows user profiles on the current machine.
.DESCRIPTION
    Uses Win32_UserProfile CIM class to list real user accounts (excludes system accounts).
    Works on Windows 10, Windows 11, and Windows Server 2016+.
.OUTPUTS
    Array of hashtables with UserName, SID, LastUseTime, Loaded, Special, LocalPath.
#>
function Get-WindowsUsers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$sessionId
    )

    try {
        $users = [System.Collections.ArrayList]::new()
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -Filter "Special = 'False'"

        foreach ($profile in $profiles) {
            try {
                $sid     = $profile.SID
                $objSID  = [System.Security.Principal.SecurityIdentifier]::new($sid)
                $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
                $fullName = $objUser.Value
                # Strip domain prefix (DOMAIN\username -> username)
                # Security log events store just the username without domain
                $shortName = if ($fullName -match '\\(.+)$') { $Matches[1] } else { $fullName }

                [void]$users.Add(@{
                    UserName    = $shortName
                    FullName    = $fullName
                    SID         = $sid
                    LastUseTime = $profile.LastUseTime
                    Loaded      = $profile.Loaded
                    Special     = $profile.Special
                    LocalPath   = $profile.LocalPath
                })
            }
            catch {
                # SID may not translate (orphaned profile) — skip
                Write-Verbose "Skipping profile SID $($profile.SID): $($_.Exception.Message)"
            }
        }

        return $users
    }
    catch {
        Write-EMLog -Message "Get-WindowsUsers failed: $($_.Exception.Message)" -Level Error
        $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
        $errorProps['SessionId'] = $sessionId
        $errorProps['Function']  = 'Get-WindowsUsers'
        TrackException -ErrorRecord $_ -Properties $errorProps
        throw "Failed to enumerate Windows user profiles: $_"
    }
}
