# ── Task Management & Event Collection Orchestration ──────────────────────────
# Public functions for managing the Windows Scheduled Task lifecycle and the
# main orchestrator that coordinates event collection for all users.

# ── Event Collection Orchestrator ─────────────────────────────────────────────

<#
.SYNOPSIS
    Collects logon/logoff events and active session data for a single user.
.DESCRIPTION
    Orchestrates the full event collection pipeline for one user:
    1. Reads logon-indicator events (Connect)
    2. Reads logoff-indicator events (Disconnect)
    3. Checks for active quser sessions
    Results are forwarded to all registered telemetry sinks and logged locally.
.PARAMETER sessionId
    Correlation identifier for this monitoring session.
.PARAMETER timeRangeForEventsBefore
    Only process events created after this timestamp.
.PARAMETER user
    The Windows username to collect events for.
.EXAMPLE
    Get-WindowsEventsAndSessions -sessionId $sid -timeRangeForEventsBefore (Get-Date).AddMinutes(-5) -user 'jdoe'
#>
function Get-WindowsEventsAndSessions {
    [CmdletBinding()]
    param(
        [string]$sessionId,

        [Parameter(Mandatory)]
        [DateTime]$timeRangeForEventsBefore,

        [Parameter(Mandatory)]
        [string]$user
    )

    try {
        $commonParams = @{
            sessionId             = $sessionId
            StartTime             = $timeRangeForEventsBefore
            User                  = $user
        }

        $enabled = $script:MonitoringConfig.EnabledGroups

        # Per-user event processors — only run enabled groups
        if ('Logon'          -in $enabled) { Get-LogonEvents        @commonParams }
        if ('Logoff'         -in $enabled) { Get-LogoffEvents       @commonParams }
        if ('SSH'            -in $enabled) { Get-SSHEvents          @commonParams }
        if ('PrivilegeUse'   -in $enabled) { Get-PrivilegeEvents    @commonParams }
        if ('ProcessTracking'-in $enabled) { Get-ProcessEvents      @commonParams }
        if ('NetworkShare'   -in $enabled) { Get-NetworkShareEvents @commonParams }

        $hasActiveSession = Get-ActiveUsersByQUsers -sessionId $sessionId `
            -UserName $user

        Write-EMLog -Message "User '$user' has active session: $hasActiveSession"
    }
    catch {
        Write-EMLog -Message "Get-WindowsEventsAndSessions failed for '$user': $($_.Exception.Message)" -Level Error
        $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
        $errorProps['SessionId'] = $sessionId
        $errorProps['Function']  = 'Get-WindowsEventsAndSessions'
        $errorProps['User']      = $user
        TrackException -ErrorRecord $_ -Properties $errorProps
    }
}

# ── Scheduled Task Registration ───────────────────────────────────────────────

<#
.SYNOPSIS
    Creates, registers, and starts a Windows Scheduled Task for event-driven monitoring.
.DESCRIPTION
    Registers a scheduled task that runs Start-EventMonitorService.ps1 under the SYSTEM
    account as a long-running, event-driven process. The task is configured to:
    - Start at boot (AtStartup trigger)
    - Auto-restart on failure (RestartInterval + RestartCount)
    - Never stop on idle
    - Run whether user is logged on or not

    The service uses EventLogWatcher for instant event detection (zero polling)
    and a watchdog timer for self-healing and telemetry flushing.

    Compatible with Windows 10, Windows 11, and Windows Server 2016+.
.PARAMETER logAnalyticsConString
    Application Insights connection string. Stored securely in a file for the service to read.
    Only used if AppInsights is your telemetry sink.
.PARAMETER sessionId
    Unique identifier for this monitoring session. Defaults to a new GUID.
.PARAMETER watchdogIntervalMin
    How often (in minutes) the watchdog checks health and flushes telemetry. Default: 30.
.PARAMETER scheduledTaskName
    Display name for the scheduled task. Default: 'WinEventMonitor'.
.EXAMPLE
    Register-EventMonitor
    # Local-only mode — events saved to journal, no cloud telemetry
.EXAMPLE
    Register-EventMonitor -logAnalyticsConString 'InstrumentationKey=...'
    # Send events to App Insights + local journal
.EXAMPLE
    Register-EventMonitor -scheduledTaskName 'MyMonitor' -watchdogIntervalMin 15
#>
function Register-EventMonitor {
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$logAnalyticsConString,

        [string]$sessionId = [guid]::NewGuid().Guid,

        [ValidateRange(5, 1440)]
        [int]$watchdogIntervalMin = 30,

        [ValidateNotNullOrEmpty()]
        [string]$scheduledTaskName = 'WinEventMonitor'
    )

    Write-EMLog -Message "Registering scheduled task '$scheduledTaskName' (event-driven mode, session: $sessionId)"

    # Check if task already exists — stop and remove it first
    $existingTask = Get-ScheduledTask -TaskName $scheduledTaskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-EMLog -Message "Task '$scheduledTaskName' already exists — updating." -Level Warning
        try {
            if ($existingTask.State -ne 'Disabled') {
                Stop-ScheduledTask -TaskName $scheduledTaskName -ErrorAction SilentlyContinue
            }
            Unregister-ScheduledTask -TaskName $scheduledTaskName -Confirm:$false
        }
        catch {
            Write-EMLog -Message "Failed to remove existing task: $($_.Exception.Message)" -Level Error
        }
    }

    $taskScriptPath = Join-Path $PSScriptRoot 'Start-EventMonitorService.ps1'
    if (-not (Test-Path $taskScriptPath)) {
        throw "Entry script not found at '$taskScriptPath'. Module installation may be corrupt."
    }

    # Store connection string if provided (for AppInsights sink)
    if ($logAnalyticsConString) {
        $conStringPath = Join-Path $script:SecretsDir 'ConnectionString.txt'
        Set-Content -Path $conStringPath -Value $logAnalyticsConString -Force

        # Restrict ACL to SYSTEM + Administrators only
        try {
            $acl = Get-Acl -Path $conStringPath
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
            $systemRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
            $adminRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                'BUILTIN\Administrators', 'FullControl', 'Allow')
            $acl.AddAccessRule($systemRule)
            $acl.AddAccessRule($adminRule)
            Set-Acl -Path $conStringPath -AclObject $acl
        }
        catch {
            Write-EMLog -Message "Could not restrict ACL on connection string file: $($_.Exception.Message)" -Level Warning
        }

        Write-EMLog -Message "Connection string stored securely at: $conStringPath" -Level Warning
    }

    try {
        # Build the task action — long-running service, only non-secret params on command line
        $taskArgument = "-NoProfile -File `"$taskScriptPath`" " +
            "-sessionId `"$sessionId`" " +
            "-watchdogIntervalMin $watchdogIntervalMin"

        $taskAction = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument $taskArgument

        $taskPrincipal = New-ScheduledTaskPrincipal `
            -UserId 'NT AUTHORITY\SYSTEM' `
            -RunLevel Highest `
            -LogonType ServiceAccount

        # Settings optimized for a long-running event-driven service:
        # - RestartInterval: auto-restart after 1 minute if the process crashes
        # - RestartCount: up to 3 restarts before giving up
        # - ExecutionTimeLimit: no time limit (runs indefinitely)
        # - StopIfGoingOnBatteries/DisallowStartIfOnBatteries: false (always run)
        # - DontStopOnIdleEnd: true (never stop on idle)
        # - MultipleInstances: IgnoreNew (prevent duplicate instances)
        $taskSettings = New-ScheduledTaskSettingsSet `
            -Priority 4 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -RestartCount 3 `
            -ExecutionTimeLimit (New-TimeSpan -Days 0) `
            -DontStopOnIdleEnd `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -MultipleInstances IgnoreNew

        # Single trigger: start at system boot
        $startupTrigger = New-ScheduledTaskTrigger -AtStartup

        $task = Register-ScheduledTask $scheduledTaskName `
            -Action $taskAction `
            -Principal $taskPrincipal `
            -Settings $taskSettings `
            -Trigger $startupTrigger

        $task | Start-ScheduledTask
        Write-EMLog -Message "Scheduled task '$scheduledTaskName' registered and started (event-driven mode)."
    }
    catch {
        Write-EMLog -Message "Failed to register task '$scheduledTaskName': $($_.Exception.Message)" -Level Error
        throw "Failed to register event monitor task: $_"
    }
}

# ── Scheduled Task Lifecycle Functions ────────────────────────────────────────

<#
.SYNOPSIS
    Removes the event monitor scheduled task.
#>
function Unregister-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor'
    )

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-EMLog -Message "Unregistered event monitor task '$TaskName'."
    }
    catch {
        Write-EMLog -Message "Failed to unregister task '$TaskName': $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Stops monitoring and removes the scheduled task. Keeps all data (logs, journal, config).
.DESCRIPTION
    Stops the event monitor service, removes the scheduled task, but preserves all
    captured data in C:\ProgramData\WindowsEventMonitor\. Use this when you want to
    stop monitoring but keep your event history.

    To also delete all data, use: Uninstall-EventMonitor -DeleteData
    To re-deploy later: Register-EventMonitor
.PARAMETER TaskName
    The scheduled task name. Default: 'WinEventMonitor'.
.PARAMETER DeleteData
    Also delete all data (logs, journal, config, secrets) from ProgramData.
    WARNING: This cannot be undone.
.EXAMPLE
    Uninstall-EventMonitor
    # Stops service, keeps data
.EXAMPLE
    Uninstall-EventMonitor -DeleteData
    # Stops service AND deletes all data
#>
function Uninstall-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor',

        [switch]$DeleteData
    )

    # Stop and remove the scheduled task
    try {
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($task.State -ne 'Disabled') {
                Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            }
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            Write-EMLog -Message "Scheduled task '$TaskName' removed." -Level Warning
        }
        else {
            Write-EMLog -Message "Scheduled task '$TaskName' not found — already removed." -Level Warning
        }
    }
    catch {
        Write-EMLog -Message "Failed to remove task: $($_.Exception.Message)" -Level Error
    }

    if ($DeleteData) {
        $dataRoot = Join-Path $env:ProgramData 'WindowsEventMonitor'
        if (Test-Path $dataRoot) {
            Remove-Item -Path $dataRoot -Recurse -Force -ErrorAction Stop
            Write-Warning "All data deleted from $dataRoot"
        }
    }
    else {
        Write-Host ""
        Write-Host "  Monitoring stopped. Data preserved at:" -ForegroundColor Green
        Write-Host "    $script:DataRoot" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  To re-deploy:  Register-EventMonitor" -ForegroundColor Gray
        Write-Host "  To delete data: Uninstall-EventMonitor -DeleteData" -ForegroundColor Gray
        Write-Host ""
    }
}

<#
.SYNOPSIS
    Starts a previously registered event monitor scheduled task.
#>
function Start-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor'
    )

    try {
        Start-ScheduledTask -TaskName $TaskName
        Write-EMLog -Message "Started event monitor task '$TaskName'."
    }
    catch {
        Write-EMLog -Message "Failed to start task '$TaskName': $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Stops a running event monitor scheduled task.
#>
function Stop-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor'
    )

    try {
        Stop-ScheduledTask -TaskName $TaskName
        Write-EMLog -Message "Stopped event monitor task '$TaskName'."
    }
    catch {
        Write-EMLog -Message "Failed to stop task '$TaskName': $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Gets the status of the event monitor scheduled task.
#>
function Get-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor'
    )

    try {
        $task = Get-ScheduledTask -TaskName $TaskName
        Write-EMLog -Message "Retrieved status for task '$TaskName'."
        return $task
    }
    catch {
        Write-EMLog -Message "Failed to get task '$TaskName': $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Disables the event monitor scheduled task without removing it.
#>
function Disable-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor'
    )

    try {
        Disable-ScheduledTask -TaskName $TaskName
        Write-EMLog -Message "Disabled event monitor task '$TaskName'."
    }
    catch {
        Write-EMLog -Message "Failed to disable task '$TaskName': $($_.Exception.Message)" -Level Error
        throw
    }
}

<#
.SYNOPSIS
    Re-enables a previously disabled event monitor scheduled task.
#>
function Enable-EventMonitor {
    [CmdletBinding()]
    param(
        [string]$TaskName = 'WinEventMonitor'
    )

    try {
        Enable-ScheduledTask -TaskName $TaskName
        Write-EMLog -Message "Enabled event monitor task '$TaskName'."
    }
    catch {
        Write-EMLog -Message "Failed to enable task '$TaskName': $($_.Exception.Message)" -Level Error
        throw
    }
}

# ── Diagnostic Scan Function ─────────────────────────────────────────────────

<#
.SYNOPSIS
    Runs a one-shot diagnostic scan of recent Windows security events.
.DESCRIPTION
    Scans the specified time window for all monitored events and dispatches
    them to registered telemetry sinks. Useful for:
    - Testing that the module works before deploying the service
    - Manually scanning a specific time range
    - Debugging and troubleshooting

    For continuous monitoring, use Register-EventMonitor to deploy the
    event-driven service.
.PARAMETER LookBackMinutes
    How far back (in minutes) to read events. Default: 60. Max: 10080 (7 days).
.PARAMETER SessionId
    Correlation identifier for this scan. Defaults to a new GUID.
.EXAMPLE
    Invoke-EventMonitor
.EXAMPLE
    Invoke-EventMonitor -LookBackMinutes 30
.EXAMPLE
    Invoke-EventMonitor -LookBackMinutes 1440   # scan last 24 hours
#>
function Invoke-EventMonitor {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 10080)]
        [int]$LookBackMinutes = 60,

        [string]$SessionId = [guid]::NewGuid().Guid
    )

    Write-EMLog -Message "=== Diagnostic scan started (session: $SessionId, lookback: ${LookBackMinutes}min) ===" -Level Warning
    Write-Verbose "Diagnostic scan: session=$SessionId, lookback=${LookBackMinutes}min"

    # Auto-register App Insights sink if not already registered
    if (-not ($script:TelemetrySinks.Contains('AppInsights'))) {
        $cs = Resolve-AppInsightsConnectionString
        if ($cs) {
            try {
                Register-AppInsightsSink -ConnectionString $cs
                Write-EMLog -Message "AppInsights sink registered ($($cs.Length) char connection string)" -Level Warning
            }
            catch {
                Write-EMLog -Message "Failed to register AppInsights sink: $($_.Exception.Message)" -Level Error
            }
        }
        else {
            Write-EMLog -Message 'No App Insights connection string found. Set EventMonitorAppInsightsConString env var or use Register-TelemetrySink for custom sinks.' -Level Warning
        }
    }
    else {
        Write-EMLog -Message 'AppInsights sink already registered.' -Level Warning
    }

    $startTime = (Get-Date).AddMinutes(-$LookBackMinutes)
    Write-EMLog -Message "Reading events from $startTime onwards." -Level Warning

    # Per-user event collection
    try {
        $windowsUsers = Get-WindowsUsers -sessionId $SessionId
        if ($null -eq $windowsUsers -or $windowsUsers.Count -eq 0) {
            Write-EMLog -Message 'No user profiles found. Skipping per-user event collection.' -Level Warning
        }
        else {
            Write-EMLog -Message "Found $($windowsUsers.Count) user profile(s) to scan." -Level Warning
            foreach ($user in $windowsUsers) {
                Write-EMLog -Message "Scanning events for user: $($user.UserName)" -Level Warning
                Get-WindowsEventsAndSessions `
                    -sessionId $SessionId `
                    -timeRangeForEventsBefore $startTime `
                    -user $user.UserName
            }
        }
    }
    catch {
        Write-EMLog -Message "User event collection failed: $($_.Exception.Message)" -Level Error
    }

    # Active SSH detection
    try {
        $hasSSH = Get-ActiveSSHDConnectionByNetStat -sessionId $SessionId
        Write-EMLog -Message "Active SSH connections detected: $hasSSH"
    }
    catch {
        Write-EMLog -Message "SSH detection failed: $($_.Exception.Message)" -Level Error
    }

    # Machine-wide event processors — only run enabled groups
    $machineParams = @{
        sessionId = $SessionId
        StartTime = $startTime
    }
    $enabled = $script:MonitoringConfig.EnabledGroups

    if ('AccountManagement' -in $enabled) { try { Get-AccountEvents      @machineParams } catch { Write-EMLog -Message "AccountEvents: $($_.Exception.Message)"      -Level Error } }
    if ('GroupManagement'   -in $enabled) { try { Get-GroupEvents        @machineParams } catch { Write-EMLog -Message "GroupEvents: $($_.Exception.Message)"        -Level Error } }
    if ('Persistence' -in $enabled -or 'PersistenceSystem' -in $enabled) { try { Get-PersistenceEvents  @machineParams } catch { Write-EMLog -Message "PersistenceEvents: $($_.Exception.Message)"  -Level Error } }
    if ('AuditTampering'    -in $enabled) { try { Get-AuditEvents        @machineParams } catch { Write-EMLog -Message "AuditEvents: $($_.Exception.Message)"        -Level Error } }
    if ('PowerShell'        -in $enabled) { try { Get-PowerShellEvents   @machineParams } catch { Write-EMLog -Message "PowerShellEvents: $($_.Exception.Message)"   -Level Error } }
    if ('SystemHealth'      -in $enabled) { try { Get-SystemHealthEvents @machineParams } catch { Write-EMLog -Message "SystemHealthEvents: $($_.Exception.Message)" -Level Error } }
    if ('NetworkFirewall'   -in $enabled) { try { Get-NetworkEvents      @machineParams } catch { Write-EMLog -Message "NetworkEvents: $($_.Exception.Message)"      -Level Error } }
    if ('RDP'               -in $enabled) { try { Get-RDPEvents          @machineParams } catch { Write-EMLog -Message "RDPEvents: $($_.Exception.Message)"          -Level Error } }
    if ('WinRM'             -in $enabled) { try { Get-WinRMEvents        @machineParams } catch { Write-EMLog -Message "WinRMEvents: $($_.Exception.Message)"        -Level Error } }
    if ('Defender'          -in $enabled) { try { Get-DefenderEvents     @machineParams } catch { Write-EMLog -Message "DefenderEvents: $($_.Exception.Message)"     -Level Error } }

    # Flush
    try {
        Flush-Telemetry
        Write-EMLog -Message 'Telemetry flushed.'
    }
    catch {
        Write-EMLog -Message "Flush failed: $($_.Exception.Message)" -Level Error
    }

    Write-EMLog -Message "=== Diagnostic scan completed ===" -Level Warning
}
