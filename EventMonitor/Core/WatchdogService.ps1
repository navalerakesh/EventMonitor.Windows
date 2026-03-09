# ── Watchdog Service ──────────────────────────────────────────────────────────
# Health monitoring, auto-repair, and catch-up sweep for event-driven watchers.
#
# Responsibilities:
#   1. Periodically check that all EventLogWatchers are alive and healthy
#   2. Restart any watcher that has died or accumulated too many errors
#   3. Run a lightweight catch-up sweep to process events that may have been
#      missed during watcher restarts or brief outages
#   4. Flush telemetry buffer
#   5. Report overall health via telemetry
#
# Safety:
#   - The watchdog itself runs on a System.Timers.Timer — lightweight, non-blocking
#   - Every operation has a timeout and try/catch
#   - The watchdog NEVER crashes — it logs errors and continues

# ── Constants ─────────────────────────────────────────────────────────────────

$script:WatchdogTimer = $null
$script:WatchdogRunning = $false

# Max consecutive errors before a watcher is restarted
$script:MaxWatcherErrors = 10

# Max minutes without an event before watcher is considered stale (restart it)
# Set high because some logs are naturally quiet
$script:MaxSilentMinutes = 120

<#
.SYNOPSIS
    Starts the watchdog timer that periodically checks watcher health.
.PARAMETER IntervalMinutes
    How often the watchdog runs (default: 30 minutes).
.PARAMETER SessionId
    Monitoring session correlation ID.
#>
function Start-Watchdog {
    [CmdletBinding()]
    param(
        [ValidateRange(5, 1440)]
        [int]$IntervalMinutes = 30,

        [Parameter(Mandatory)]
        [string]$SessionId
    )

    if ($script:WatchdogRunning) {
        Write-EMLog -Message 'Watchdog is already running.' -Level Warning
        return
    }

    Write-EMLog -Message "Starting watchdog (interval: ${IntervalMinutes}min)"

    $script:WatchdogTimer = [System.Timers.Timer]::new($IntervalMinutes * 60 * 1000)
    $script:WatchdogTimer.AutoReset = $true

    $watchdogState = @{
        SessionId        = $SessionId
        IntervalMinutes  = $IntervalMinutes
    }

    $null = Register-ObjectEvent -InputObject $script:WatchdogTimer -EventName 'Elapsed' `
        -MessageData $watchdogState `
        -Action {
            $state = $Event.MessageData
            try {
                Invoke-WatchdogCycle `
                    -SessionId $state.SessionId `
                    -CatchUpMinutes $state.IntervalMinutes
            }
            catch {
                try {
                    $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
                    Add-Content -Path $script:LogFilePath `
                        -Value "$timestamp :: [Error] Watchdog cycle failed: $($_.Exception.Message)" `
                        -ErrorAction SilentlyContinue
                }
                catch { $null = $null }
            }
        }

    $script:WatchdogTimer.Start()
    $script:WatchdogRunning = $true

    Write-EMLog -Message 'Watchdog started.'
}

<#
.SYNOPSIS
    Stops the watchdog timer.
#>
function Stop-Watchdog {
    [CmdletBinding()]
    param()

    if ($null -ne $script:WatchdogTimer) {
        $script:WatchdogTimer.Stop()
        $script:WatchdogTimer.Dispose()
        $script:WatchdogTimer = $null
    }
    $script:WatchdogRunning = $false
    Write-EMLog -Message 'Watchdog stopped.'
}

<#
.SYNOPSIS
    Executes one watchdog cycle: health check, auto-repair, catch-up, flush.
.DESCRIPTION
    Called by the timer callback. Every operation is independently try/caught
    so one failure doesn't prevent the others from running.
#>
function Invoke-WatchdogCycle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [int]$CatchUpMinutes = 30
    )

    Write-EMLog -Message '=== Watchdog cycle started ==='

    $startTime = (Get-Date).AddMinutes(-$CatchUpMinutes)
    $repairsPerformed = $false

    # ── Step 1: Health check & auto-repair ────────────────────────────────
    try {
        $healthResults = Get-EventWatcherHealth
        foreach ($watcher in $healthResults) {
            $needsRestart = $false
            $reason = ''

            # Check: too many errors
            if ($watcher.ErrorCount -ge $script:MaxWatcherErrors) {
                $needsRestart = $true
                $reason = "error count ($($watcher.ErrorCount)) exceeded threshold ($script:MaxWatcherErrors)"
            }

            # Check: watcher is disabled when it should be enabled
            if (-not $watcher.IsEnabled) {
                $needsRestart = $true
                $reason = 'watcher is disabled'
            }

            if ($needsRestart) {
                $repairsPerformed = $true
                Write-EMLog -Message "Auto-repairing watcher '$($watcher.Name)': $reason" -Level Warning

                $healthProps = New-EventProperties -SessionId $SessionId -EventType 'Alert' -Severity 'High'
                $healthProps['WatcherName'] = $watcher.Name
                $healthProps['Reason']      = $reason
                $healthProps['ErrorCount']  = "$($watcher.ErrorCount)"
                TrackEvent -Name 'Watchdog Auto-Repair' -Properties $healthProps

                Restart-EventWatcher -WatcherName $watcher.Name -SessionId $SessionId
            }
        }
    }
    catch {
        Write-EMLog -Message "Watchdog health check failed: $($_.Exception.Message)" -Level Error
    }

    # ── Step 2: Catch-up sweep (ONLY if a watcher was repaired) ──────────
    # Only re-read events when a watcher was down and restarted.
    # This prevents duplicates — if all watchers are healthy, the real-time
    # callbacks already processed every event.
    if ($repairsPerformed) {
        try {
            Write-EMLog -Message 'Running catch-up sweep after watcher repair...'
            Invoke-CatchUpSweep -SessionId $SessionId -StartTime $startTime
        }
        catch {
            Write-EMLog -Message "Watchdog catch-up sweep failed: $($_.Exception.Message)" -Level Error
        }
    }
    else {
        Write-EMLog -Message 'All watchers healthy — skipping catch-up sweep.'
    }

    # ── Step 3: Flush telemetry ───────────────────────────────────────────
    try {
        Flush-Telemetry
    }
    catch {
        Write-EMLog -Message "Watchdog flush failed: $($_.Exception.Message)" -Level Error
    }

    # ── Step 4: Report health telemetry ───────────────────────────────────
    try {
        $healthProps = New-EventProperties -SessionId $SessionId -EventType 'Info' -Severity 'Info'
        $healthStatus = Get-EventWatcherHealth
        $totalEvents = ($healthStatus | Measure-Object -Property EventsProcessed -Sum).Sum
        $totalErrors = ($healthStatus | Measure-Object -Property ErrorCount -Sum).Sum
        $activeCount = ($healthStatus | Where-Object IsEnabled).Count

        $healthProps['ActiveWatchers']     = "$activeCount"
        $healthProps['TotalWatchers']      = "$($healthStatus.Count)"
        $healthProps['TotalEventsProcessed'] = "$totalEvents"
        $healthProps['TotalErrors']        = "$totalErrors"
        $healthProps['MachineName']        = $env:COMPUTERNAME

        TrackEvent -Name 'Watchdog Health Report' -Properties $healthProps
    }
    catch {
        Write-EMLog -Message "Watchdog health report failed: $($_.Exception.Message)" -Level Error
    }

    # ── Step 5: Log and journal cleanup ───────────────────────────────────
    try {
        Invoke-LogCleanup
    }
    catch {
        Write-EMLog -Message "Watchdog log cleanup failed: $($_.Exception.Message)" -Level Error
    }

    Write-EMLog -Message '=== Watchdog cycle completed ==='
}

<#
.SYNOPSIS
    Lightweight catch-up sweep for critical security events that may have been missed.
.DESCRIPTION
    Only checks the highest-severity events (failed logons, account changes,
    audit tampering, persistence). This is NOT the full collection pipeline —
    it's a safety net for the event-driven watchers.
#>
function Invoke-CatchUpSweep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SessionId,

        [Parameter(Mandatory)]
        [DateTime]$StartTime
    )

    Write-EMLog -Message "Catch-up sweep: events since $($StartTime.ToString('yyyy-MM-ddTHH:mm:ss'))"

    # Critical events only — these are the ones we absolutely cannot miss
    $criticalParams = @{
        sessionId = $SessionId
        StartTime = $StartTime
    }

    # Machine-wide critical events (no user filter)
    try { Get-AccountEvents     @criticalParams } catch { Write-EMLog -Message "Catch-up AccountEvents: $($_.Exception.Message)" -Level Error }
    try { Get-GroupEvents       @criticalParams } catch { Write-EMLog -Message "Catch-up GroupEvents: $($_.Exception.Message)"   -Level Error }
    try { Get-PersistenceEvents @criticalParams } catch { Write-EMLog -Message "Catch-up PersistenceEvents: $($_.Exception.Message)" -Level Error }
    try { Get-AuditEvents       @criticalParams } catch { Write-EMLog -Message "Catch-up AuditEvents: $($_.Exception.Message)"  -Level Error }
    try { Get-SystemHealthEvents @criticalParams } catch { Write-EMLog -Message "Catch-up SystemHealthEvents: $($_.Exception.Message)" -Level Error }
}
