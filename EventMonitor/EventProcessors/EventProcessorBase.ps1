# ── Event Processor Base ──────────────────────────────────────────────────────
# Shared helper functions used by all event processor modules.
# Provides a consistent, performant pattern for reading and processing
# Windows events with proper error handling and time-range filtering.

<#
.SYNOPSIS
    Reads Windows events with time-range filtering pushed down to the EventLog API.
.DESCRIPTION
    Wraps Get-WinEvent with a FilterHashtable that includes StartTime, so
    the Windows EventLog API performs the time filtering instead of pulling
    all events and post-filtering with Where-Object.

    This is critical for performance on machines with large Security logs.
.PARAMETER EventId
    One or more Windows Event IDs to query.
.PARAMETER LogName
    The event log name (Security, System, Application, OpenSSH/Operational, etc.).
.PARAMETER StartTime
    Only return events created at or after this timestamp.
.PARAMETER ProviderName
    Optional provider name filter for the event query.
.OUTPUTS
    Array of EventLogRecord objects, or empty array if no events found.
.EXAMPLE
    Read-WindowsEvents -EventId 4624, 4625 -LogName 'Security' -StartTime (Get-Date).AddMinutes(-5)
#>
function Read-WindowsEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int[]]$EventId,

        [Parameter(Mandatory)]
        [string]$LogName,

        [Parameter(Mandatory)]
        [DateTime]$StartTime,

        [string]$ProviderName
    )

    $filter = @{
        LogName   = $LogName
        Id        = $EventId
        StartTime = $StartTime
    }
    if ($ProviderName) { $filter['ProviderName'] = $ProviderName }

    try {
        Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Read-WindowsEvents($LogName/$($EventId -join ',')): $($_.Exception.Message)" -Level Error
        }
        @()
    }
}

<#
.SYNOPSIS
    Reads all events from a log (no Event ID filter) with time-range filtering.
.DESCRIPTION
    Used for logs like OpenSSH/Operational where events don't have consistent
    numeric IDs and must be filtered by message content post-retrieval.
.PARAMETER LogName
    The event log name.
.PARAMETER StartTime
    Only return events created at or after this timestamp.
.OUTPUTS
    Array of EventLogRecord objects, or empty array if no events found.
#>
function Read-WindowsEventsByLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [Parameter(Mandatory)]
        [DateTime]$StartTime
    )

    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            StartTime = $StartTime
        } -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Read-WindowsEventsByLog($LogName): $($_.Exception.Message)" -Level Error
        }
        @()
    }
}

<#
.SYNOPSIS
    Creates a standard error properties dictionary for exception tracking.
.PARAMETER SessionId
    The monitoring session correlation ID.
.PARAMETER FunctionName
    The name of the function that failed.
.PARAMETER User
    Optional username context.
.OUTPUTS
    Dictionary[string, string] with standard error context fields.
#>
function New-ErrorProperties {
    [CmdletBinding()]
    param(
        [string]$SessionId,

        [Parameter(Mandatory)]
        [string]$FunctionName,

        [string]$User
    )

    $props = [System.Collections.Generic.Dictionary[string, string]]::new()
    if ($SessionId) { $props['SessionId'] = $SessionId }
    $props['Function'] = $FunctionName
    if ($User) { $props['User'] = $User }
    return $props
}

<#
.SYNOPSIS
    Creates a new event properties dictionary with standard fields pre-populated.
.PARAMETER SessionId
    The monitoring session correlation ID.
.PARAMETER EventType
    The event direction/category: Connect, Disconnect, Alert, Info.
.PARAMETER Severity
    Event severity: Critical, High, Medium, Low, Info.
.OUTPUTS
    Dictionary[string, string] ready to have event-specific fields added.
#>
function New-EventProperties {
    [CmdletBinding()]
    param(
        [string]$SessionId,

        [Parameter(Mandatory)]
        [ValidateSet('Connect', 'Disconnect', 'Alert', 'Info')]
        [string]$EventType,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity = 'Info'
    )

    $props = [System.Collections.Generic.Dictionary[string, string]]::new()
    if ($SessionId) { $props['SessionId'] = $SessionId }
    $props['EventType'] = $EventType
    $props['Severity']  = $Severity
    return $props
}

<#
.SYNOPSIS
    Returns the registered event processor categories and their event IDs.
.DESCRIPTION
    Provides a structured inventory of every event category this module monitors,
    including event IDs, log sources, severity, and descriptions. Useful for
    documentation, dashboards, and understanding coverage.
.OUTPUTS
    Array of hashtables with Category, Description, Events (nested array).
.EXAMPLE
    Get-MonitoredEventCategories | Format-Table Category, Description
.EXAMPLE
    Get-MonitoredEventCategories | ForEach-Object { $_.Events } | Format-Table EventId, Severity, Description
#>
function Get-MonitoredEventCategories {
    [CmdletBinding()]
    param()

    @(
        @{
            Category    = 'Logon'
            Description = 'User authentication and session creation events'
            Events      = @(
                @{ EventId = 4624;  Log = 'Security'; Severity = 'Info';     Description = 'Successful logon' }
                @{ EventId = 4625;  Log = 'Security'; Severity = 'High';     Description = 'Failed logon attempt' }
                @{ EventId = 4648;  Log = 'Security'; Severity = 'Medium';   Description = 'Explicit credential logon' }
                @{ EventId = 4800;  Log = 'Security'; Severity = 'Info';     Description = 'Workstation locked' }
                @{ EventId = 4801;  Log = 'Security'; Severity = 'Info';     Description = 'Workstation unlocked' }
            )
        }
        @{
            Category    = 'Logoff'
            Description = 'User session termination and disconnect events'
            Events      = @(
                @{ EventId = 4647;  Log = 'Security'; Severity = 'Info';     Description = 'User-initiated logoff' }
                @{ EventId = 4779;  Log = 'Security'; Severity = 'Info';     Description = 'Terminal Services disconnect' }
            )
        }
        @{
            Category    = 'SSH'
            Description = 'OpenSSH server connection and disconnection events'
            Events      = @(
                @{ EventId = 0;     Log = 'OpenSSH/Operational'; Severity = 'Info'; Description = 'SSH connect (public key accepted)' }
                @{ EventId = 0;     Log = 'OpenSSH/Operational'; Severity = 'Info'; Description = 'SSH disconnect' }
            )
        }
        @{
            Category    = 'AccountManagement'
            Description = 'User account creation, deletion, and modification events'
            Events      = @(
                @{ EventId = 4720;  Log = 'Security'; Severity = 'Critical'; Description = 'User account created' }
                @{ EventId = 4722;  Log = 'Security'; Severity = 'High';     Description = 'User account enabled' }
                @{ EventId = 4723;  Log = 'Security'; Severity = 'Medium';   Description = 'Password change attempted' }
                @{ EventId = 4724;  Log = 'Security'; Severity = 'High';     Description = 'Password reset attempted' }
                @{ EventId = 4725;  Log = 'Security'; Severity = 'High';     Description = 'User account disabled' }
                @{ EventId = 4726;  Log = 'Security'; Severity = 'Critical'; Description = 'User account deleted' }
            )
        }
        @{
            Category    = 'GroupManagement'
            Description = 'Security group membership change events'
            Events      = @(
                @{ EventId = 4732;  Log = 'Security'; Severity = 'Critical'; Description = 'Member added to security group' }
                @{ EventId = 4733;  Log = 'Security'; Severity = 'High';     Description = 'Member removed from security group' }
            )
        }
        @{
            Category    = 'PrivilegeUse'
            Description = 'Special privilege assignment and usage events'
            Events      = @(
                @{ EventId = 4672;  Log = 'Security'; Severity = 'High';     Description = 'Special privileges assigned to logon' }
            )
        }
        @{
            Category    = 'ProcessTracking'
            Description = 'Process creation and termination events'
            Events      = @(
                @{ EventId = 4688;  Log = 'Security'; Severity = 'Medium';   Description = 'New process created' }
                @{ EventId = 4689;  Log = 'Security'; Severity = 'Low';      Description = 'Process terminated' }
            )
        }
        @{
            Category    = 'Persistence'
            Description = 'Service and scheduled task installation events (persistence indicators)'
            Events      = @(
                @{ EventId = 4697;  Log = 'Security'; Severity = 'Critical'; Description = 'Service installed on system' }
                @{ EventId = 4698;  Log = 'Security'; Severity = 'Critical'; Description = 'Scheduled task created' }
                @{ EventId = 4702;  Log = 'Security'; Severity = 'High';     Description = 'Scheduled task updated' }
                @{ EventId = 7045;  Log = 'System';   Severity = 'High';     Description = 'New service installed (System)' }
            )
        }
        @{
            Category    = 'AuditTampering'
            Description = 'Audit log and policy modification events (anti-forensics indicators)'
            Events      = @(
                @{ EventId = 1102;  Log = 'Security'; Severity = 'Critical'; Description = 'Audit log cleared' }
                @{ EventId = 4719;  Log = 'Security'; Severity = 'Critical'; Description = 'System audit policy changed' }
            )
        }
        @{
            Category    = 'PowerShellSecurity'
            Description = 'PowerShell script block logging events'
            Events      = @(
                @{ EventId = 4104;  Log = 'Microsoft-Windows-PowerShell/Operational'; Severity = 'Medium'; Description = 'PowerShell script block executed' }
            )
        }
        @{
            Category    = 'NetworkShare'
            Description = 'Network share access events'
            Events      = @(
                @{ EventId = 5140;  Log = 'Security'; Severity = 'Medium';   Description = 'Network share accessed' }
            )
        }
        @{
            Category    = 'SystemHealth'
            Description = 'System startup, shutdown, and crash events'
            Events      = @(
                @{ EventId = 41;    Log = 'System'; Severity = 'Critical';   Description = 'Unexpected shutdown (kernel power)' }
                @{ EventId = 1074;  Log = 'System'; Severity = 'Info';       Description = 'Planned shutdown/restart' }
                @{ EventId = 1076;  Log = 'System'; Severity = 'High';       Description = 'Unexpected shutdown reason' }
                @{ EventId = 6005;  Log = 'System'; Severity = 'Info';       Description = 'Event Log service started' }
                @{ EventId = 6006;  Log = 'System'; Severity = 'Info';       Description = 'Event Log service stopped' }
                @{ EventId = 6008;  Log = 'System'; Severity = 'High';       Description = 'Unexpected shutdown detected' }
                @{ EventId = 6009;  Log = 'System'; Severity = 'Info';       Description = 'OS version info at boot' }
                @{ EventId = 6013;  Log = 'System'; Severity = 'Info';       Description = 'System uptime' }
            )
        }
        @{
            Category    = 'NetworkFirewall'
            Description = 'Firewall rule changes and blocked connections'
            Events      = @(
                @{ EventId = 4946;  Log = 'Security'; Severity = 'High';     Description = 'Firewall rule added' }
                @{ EventId = 4947;  Log = 'Security'; Severity = 'High';     Description = 'Firewall rule modified' }
                @{ EventId = 4948;  Log = 'Security'; Severity = 'Critical'; Description = 'Firewall rule deleted' }
                @{ EventId = 5152;  Log = 'Security'; Severity = 'Medium';   Description = 'Packet dropped by firewall' }
                @{ EventId = 5157;  Log = 'Security'; Severity = 'Medium';   Description = 'Connection blocked by firewall' }
            )
        }
        @{
            Category    = 'RDP'
            Description = 'Remote Desktop Protocol session lifecycle events'
            Events      = @(
                @{ EventId = 21;  Log = 'TerminalServices-LocalSessionManager/Operational'; Severity = 'Info'; Description = 'RDP session logon' }
                @{ EventId = 23;  Log = 'TerminalServices-LocalSessionManager/Operational'; Severity = 'Info'; Description = 'RDP session logoff' }
                @{ EventId = 24;  Log = 'TerminalServices-LocalSessionManager/Operational'; Severity = 'Info'; Description = 'RDP session disconnected' }
                @{ EventId = 25;  Log = 'TerminalServices-LocalSessionManager/Operational'; Severity = 'Info'; Description = 'RDP session reconnected' }
            )
        }
        @{
            Category    = 'WinRM'
            Description = 'WinRM/PowerShell remoting session events (lateral movement detection)'
            Events      = @(
                @{ EventId = 6;   Log = 'Microsoft-Windows-WinRM/Operational'; Severity = 'High'; Description = 'WinRM session created' }
                @{ EventId = 91;  Log = 'Microsoft-Windows-WinRM/Operational'; Severity = 'High'; Description = 'WinRM connection failed' }
            )
        }
        @{
            Category    = 'Defender'
            Description = 'Windows Defender malware detection and protection state changes'
            Events      = @(
                @{ EventId = 1116; Log = 'Microsoft-Windows-Windows Defender/Operational'; Severity = 'Critical'; Description = 'Malware detected' }
                @{ EventId = 1117; Log = 'Microsoft-Windows-Windows Defender/Operational'; Severity = 'Critical'; Description = 'Malware action taken' }
                @{ EventId = 5001; Log = 'Microsoft-Windows-Windows Defender/Operational'; Severity = 'Critical'; Description = 'Real-time protection disabled' }
            )
        }
    )
}
