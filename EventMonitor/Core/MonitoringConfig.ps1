# ── Monitoring Configuration ──────────────────────────────────────────────────
# Preset monitoring levels and event group management.
#
# Users pick a level: Minimum, Standard, High, or Custom.
# Each level enables a predefined set of event groups.
# Custom mode lets users pick individual groups.
#
# Usage:
#   Set-MonitoringLevel -Level Standard          # most users — just this
#   Set-MonitoringLevel -Level Custom -Groups 'Logon','SSH','RDP'   # pick your own
#   Get-MonitoringConfig                          # see what's active

# ── Module-Scoped Config State ────────────────────────────────────────────────

$script:MonitoringConfig = @{
    Level           = 'Standard'
    EnabledGroups   = @()
    LogLevel        = 'Info'          # Operational log: Error, Warning, Info, Debug
    JournalEnabled  = $true           # Event journal (JSONL) — on by default since events are noise-filtered
    JournalMinSeverity = 'Info'       # Journal all tracked events
    RetentionDays   = 30              # Auto-delete logs/journal files older than this
}

# ── Event Group Definitions ──────────────────────────────────────────────────
# Each group is a named collection of event IDs with their log source.
# These are the building blocks — presets select combinations of groups.

$script:EventGroups = [ordered]@{

    Logon = @{
        Description = 'User authentication — successful and failed logons, lock/unlock'
        EventIds    = @(4624, 4625, 4648, 4800, 4801)
        LogName     = 'Security'
    }

    Logoff = @{
        Description = 'User session termination and disconnect'
        EventIds    = @(4647, 4779)
        LogName     = 'Security'
    }

    SSH = @{
        Description = 'OpenSSH server connections and disconnections'
        EventIds    = @()   # All events from OpenSSH/Operational (filtered by message)
        LogName     = 'OpenSSH/Operational'
    }

    RDP = @{
        Description = 'Remote Desktop session lifecycle (logon, logoff, disconnect, reconnect)'
        EventIds    = @(21, 23, 24, 25)
        LogName     = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    }

    AccountManagement = @{
        Description = 'User account creation, deletion, enable/disable, password changes'
        EventIds    = @(4720, 4722, 4723, 4724, 4725, 4726)
        LogName     = 'Security'
    }

    GroupManagement = @{
        Description = 'Security group membership changes (privilege escalation detection)'
        EventIds    = @(4732, 4733)
        LogName     = 'Security'
    }

    PrivilegeUse = @{
        Description = 'Special privileges assigned at logon (admin detection)'
        EventIds    = @(4672)
        LogName     = 'Security'
    }

    ProcessTracking = @{
        Description = 'Process creation and termination (malware/lateral movement detection)'
        EventIds    = @(4688, 4689)
        LogName     = 'Security'
    }

    Persistence = @{
        Description = 'Service and scheduled task installation (attacker persistence)'
        EventIds    = @(4697, 4698, 4699, 4702)
        LogName     = 'Security'
    }

    PersistenceSystem = @{
        Description = 'New service installed (System log)'
        EventIds    = @(7045)
        LogName     = 'System'
    }

    AuditTampering = @{
        Description = 'Audit log cleared or audit policy changed (anti-forensics)'
        EventIds    = @(1102, 4719)
        LogName     = 'Security'
    }

    PowerShell = @{
        Description = 'PowerShell script block execution logging'
        EventIds    = @(4104)
        LogName     = 'Microsoft-Windows-PowerShell/Operational'
    }

    NetworkShare = @{
        Description = 'Network share access'
        EventIds    = @(5140)
        LogName     = 'Security'
    }

    NetworkFirewall = @{
        Description = 'Firewall rule changes and blocked connections'
        EventIds    = @(4946, 4947, 4948, 5152, 5157)
        LogName     = 'Security'
    }

    SystemHealth = @{
        Description = 'System startup, shutdown, crash, and uptime events'
        EventIds    = @(41, 1074, 1076, 6005, 6006, 6008, 6009, 6013)
        LogName     = 'System'
    }

    WinRM = @{
        Description = 'WinRM/PowerShell remoting session creation (lateral movement detection)'
        EventIds    = @(6, 91)
        LogName     = 'Microsoft-Windows-WinRM/Operational'
    }

    Defender = @{
        Description = 'Windows Defender malware detection and protection state changes'
        EventIds    = @(1116, 1117, 5001, 5010, 5012)
        LogName     = 'Microsoft-Windows-Windows Defender/Operational'
    }
}

# ── Preset Levels ─────────────────────────────────────────────────────────────
# Each level is a predefined selection of event groups.

$script:MonitoringPresets = @{

    # Minimum: just know who logged in/out
    Minimum = @{
        Groups          = @('Logon', 'Logoff', 'SSH', 'RDP')
        LogLevel        = 'Error'
        JournalEnabled  = $false
        Description     = 'Basic logon/logoff tracking only. Lowest resource usage.'
    }

    # Standard: security monitoring without noise
    Standard = @{
        Groups          = @('Logon', 'Logoff', 'SSH', 'RDP', 'AccountManagement',
                           'GroupManagement', 'AuditTampering', 'Persistence',
                           'PersistenceSystem', 'NetworkFirewall', 'SystemHealth',
                           'WinRM', 'Defender')
        LogLevel        = 'Info'
        JournalEnabled  = $true
        Description     = 'Recommended. Covers authentication, account changes, persistence, lateral movement, firewall, Defender, and system health. Event journal enabled.'
    }

    # High: full security monitoring
    High = @{
        Groups          = @('Logon', 'Logoff', 'SSH', 'RDP', 'AccountManagement',
                           'GroupManagement', 'PrivilegeUse', 'ProcessTracking',
                           'Persistence', 'PersistenceSystem', 'AuditTampering',
                           'PowerShell', 'NetworkShare', 'NetworkFirewall', 'SystemHealth',
                           'WinRM', 'Defender')
        LogLevel        = 'Info'
        JournalEnabled  = $true
        Description     = 'Full coverage. All event categories. Event journal enabled. Higher resource usage.'
    }
}

# ── Public Functions ──────────────────────────────────────────────────────────

<#
.SYNOPSIS
    Sets the monitoring level — controls which event groups are active.
.DESCRIPTION
    Choose a preset level for quick setup, or use Custom to pick individual groups.

    Levels:
    - Minimum:  Logon, Logoff, SSH, RDP
    - Standard: + Account, Group, Audit, Persistence, SystemHealth (recommended)
    - High:     All event categories + event journal enabled
    - Custom:   You pick the groups via -Groups parameter

    The configuration is persisted to MonitoringConfig.json so it survives restarts.
.PARAMETER Level
    The monitoring level: Minimum, Standard, High, or Custom.
.PARAMETER Groups
    Required for Custom level. Array of event group names to enable.
    Use Get-EventGroups to see available groups.
.EXAMPLE
    Set-MonitoringLevel -Level Standard
.EXAMPLE
    Set-MonitoringLevel -Level Custom -Groups 'Logon','SSH','RDP','AuditTampering'
.EXAMPLE
    Set-MonitoringLevel -Level High
#>
function Set-MonitoringLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Minimum', 'Standard', 'High', 'Custom')]
        [string]$Level,

        [string[]]$Groups
    )

    if ($Level -eq 'Custom') {
        if (-not $Groups -or $Groups.Count -eq 0) {
            throw "Custom level requires -Groups parameter. Use Get-EventGroups to see available groups."
        }
        # Validate group names
        foreach ($g in $Groups) {
            if (-not $script:EventGroups.Contains($g)) {
                throw "Unknown event group '$g'. Use Get-EventGroups to see available groups."
            }
        }
        $script:MonitoringConfig.Level = 'Custom'
        $script:MonitoringConfig.EnabledGroups = $Groups
        Write-EMLog -Message "Monitoring level set to Custom with groups: $($Groups -join ', ')" -Level Warning
    }
    else {
        $preset = $script:MonitoringPresets[$Level]
        $script:MonitoringConfig.Level = $Level
        $script:MonitoringConfig.EnabledGroups = $preset.Groups
        $script:MonitoringConfig.LogLevel = $preset.LogLevel
        $script:MonitoringConfig.JournalEnabled = $preset.JournalEnabled
        Write-EMLog -Message "Monitoring level set to $Level ($($preset.Description))" -Level Warning
    }

    # Persist config
    Save-MonitoringConfig
}

<#
.SYNOPSIS
    Returns the current monitoring configuration.
.EXAMPLE
    Get-MonitoringConfig
#>
function Get-MonitoringConfig {
    [CmdletBinding()]
    param()

    [PSCustomObject]@{
        Level              = $script:MonitoringConfig.Level
        EnabledGroups      = $script:MonitoringConfig.EnabledGroups
        LogLevel           = $script:MonitoringConfig.LogLevel
        JournalEnabled     = $script:MonitoringConfig.JournalEnabled
        JournalMinSeverity = $script:MonitoringConfig.JournalMinSeverity
        RetentionDays      = $script:MonitoringConfig.RetentionDays
        AvailableGroups    = @($script:EventGroups.Keys)
    }
}

<#
.SYNOPSIS
    Returns all available event groups with their descriptions and event IDs.
.EXAMPLE
    Get-EventGroups
.EXAMPLE
    Get-EventGroups | Format-Table Name, Description, EventCount
#>
function Get-EventGroups {
    [CmdletBinding()]
    param()

    foreach ($key in $script:EventGroups.Keys) {
        $group = $script:EventGroups[$key]
        [PSCustomObject]@{
            Name        = $key
            Description = $group.Description
            LogName     = $group.LogName
            EventIds    = $group.EventIds
            EventCount  = $group.EventIds.Count
            Enabled     = $key -in $script:MonitoringConfig.EnabledGroups
        }
    }
}

<#
.SYNOPSIS
    Configures the event journal (JSONL file capture of security events).
.PARAMETER Enabled
    Enable or disable the event journal.
.PARAMETER MinSeverity
    Minimum event severity to journal: Critical, High, Medium, Low, Info.
.PARAMETER RetentionDays
    Number of days to keep journal files before auto-deletion.
.EXAMPLE
    Set-EventJournal -Enabled $true -MinSeverity High -RetentionDays 14
.EXAMPLE
    Set-EventJournal -Enabled $false
#>
function Set-EventJournal {
    [CmdletBinding()]
    param(
        [bool]$Enabled,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$MinSeverity,

        [ValidateRange(1, 365)]
        [int]$RetentionDays
    )

    if ($PSBoundParameters.ContainsKey('Enabled')) {
        $script:MonitoringConfig.JournalEnabled = $Enabled
        Write-EMLog -Message "Event journal $(if ($Enabled) {'enabled'} else {'disabled'})" -Level Warning
    }
    if ($MinSeverity) {
        $script:MonitoringConfig.JournalMinSeverity = $MinSeverity
    }
    if ($RetentionDays) {
        $script:MonitoringConfig.RetentionDays = $RetentionDays
    }

    Save-MonitoringConfig
}

<#
.SYNOPSIS
    Sets the operational log level (controls verbosity of module diagnostic logs).
.PARAMETER Level
    Error: only errors. Warning: errors + warnings. Info: + operational info. Debug: everything.
.EXAMPLE
    Set-EMLogLevel -Level Info
#>
function Set-EMLogLevel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Error', 'Warning', 'Info', 'Debug')]
        [string]$Level
    )

    $script:MonitoringConfig.LogLevel = $Level
    Write-EMLog -Message "Log level set to $Level" -Level Warning
    Save-MonitoringConfig
}

# ── Config Persistence ────────────────────────────────────────────────────────

function Save-MonitoringConfig {
    [CmdletBinding()]
    param()

    $configPath = Join-Path $script:ConfigDir 'MonitoringConfig.json'
    try {
        $script:MonitoringConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $configPath -Force
    }
    catch {
        Write-EMLog -Message "Failed to save config: $($_.Exception.Message)" -Level Error
    }
}

function Restore-MonitoringConfig {
    [CmdletBinding()]
    param()

    $configPath = Join-Path $script:ConfigDir 'MonitoringConfig.json'
    if (Test-Path $configPath) {
        try {
            $saved = Get-Content -Raw $configPath | ConvertFrom-Json
            $script:MonitoringConfig.Level = $saved.Level
            $script:MonitoringConfig.EnabledGroups = @($saved.EnabledGroups)
            $script:MonitoringConfig.LogLevel = $saved.LogLevel
            $script:MonitoringConfig.JournalEnabled = $saved.JournalEnabled
            $script:MonitoringConfig.JournalMinSeverity = $saved.JournalMinSeverity
            $script:MonitoringConfig.RetentionDays = $saved.RetentionDays
            Write-EMLog -Message "Restored config: Level=$($saved.Level), Groups=$($saved.EnabledGroups -join ',')" -Level Warning
        }
        catch {
            Write-EMLog -Message "Failed to restore config, using defaults: $($_.Exception.Message)" -Level Warning
            Set-MonitoringLevel -Level Standard
        }
    }
    else {
        # First run — apply Standard defaults
        Set-MonitoringLevel -Level Standard
    }
}

<#
.SYNOPSIS
    Returns only the event IDs that should be monitored based on enabled groups.
.DESCRIPTION
    Used by the EventWatcher setup to know which event IDs to subscribe to.
    Groups events by their LogName for efficient watcher registration.
.OUTPUTS
    Hashtable keyed by LogName, values are arrays of event IDs.
#>
function Get-EnabledEventIds {
    [CmdletBinding()]
    param()

    $result = @{}
    foreach ($groupName in $script:MonitoringConfig.EnabledGroups) {
        $group = $script:EventGroups[$groupName]
        if ($null -eq $group) { continue }

        $logName = $group.LogName
        if (-not $result.ContainsKey($logName)) {
            $result[$logName] = [System.Collections.Generic.List[int]]::new()
        }
        foreach ($id in $group.EventIds) {
            if ($id -notin $result[$logName]) {
                $result[$logName].Add($id)
            }
        }
    }
    return $result
}
