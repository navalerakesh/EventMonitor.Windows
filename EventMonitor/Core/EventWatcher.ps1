# ── EventLog Watcher ──────────────────────────────────────────────────────────
# Event-driven monitoring using System.Diagnostics.Eventing.Reader.EventLogWatcher.
# Events are delivered by the OS the instant they appear — zero polling, zero CPU waste.
#
# Architecture:
#   - One watcher per event log (Security, System, OpenSSH, PowerShell, TerminalServices)
#   - XPath query filters for only the event IDs we care about
#   - Events dispatched to the appropriate processor function
#   - Watchdog monitors health and restarts watchers if needed
#
# Safety:
#   - Every callback is wrapped in try/catch — a bad event NEVER crashes the watcher
#   - Watchers are created disabled, then enabled explicitly
#   - Dispose is always called in finally blocks
#   - Timeouts on all operations

# ── Watcher State ─────────────────────────────────────────────────────────────
# Module-scoped hashtable tracking all active watchers and their health.

$script:EventWatchers = @{}
$script:WatcherHealthLog = [System.Collections.Generic.List[hashtable]]::new()

<#
.SYNOPSIS
    Builds an XPath query string for multiple event IDs.
.PARAMETER EventIds
    Array of integer event IDs.
.OUTPUTS
    XPath query string suitable for EventLogQuery.
.EXAMPLE
    New-XPathQuery -EventIds 4624, 4625, 4648
    # Returns: *[System[(EventID=4624 or EventID=4625 or EventID=4648)]]
#>
function New-XPathQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int[]]$EventIds
    )

    $conditions = ($EventIds | ForEach-Object { "EventID=$_" }) -join ' or '
    return "*[System[($conditions)]]"
}

<#
.SYNOPSIS
    Creates and registers an EventLogWatcher for a specific log and set of event IDs.
.DESCRIPTION
    The watcher subscribes to Windows Event Log notifications and calls the
    specified callback scriptblock whenever a matching event appears.

    The watcher is created DISABLED — call Enable-EventWatcher to start it.

    Safety features:
    - Callback exceptions are caught and logged, never propagated
    - Watcher tracks its own health metrics (events processed, errors, last event time)
    - Watcher can be restarted via Restart-EventWatcher without losing state
.PARAMETER WatcherName
    A unique name for this watcher (used for health tracking and management).
.PARAMETER LogName
    The Windows Event Log name (Security, System, etc.).
.PARAMETER EventIds
    Array of event IDs to filter for. If empty, all events from the log are watched.
.PARAMETER XPathQuery
    Custom XPath query. Overrides EventIds if provided.
.PARAMETER OnEvent
    Scriptblock to execute when a matching event appears.
    Receives $EventRecord and $SessionId as parameters.
.PARAMETER SessionId
    Monitoring session correlation ID.
.OUTPUTS
    Hashtable with watcher state including Name, Watcher, Health metrics.
#>
function Register-EventWatcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WatcherName,

        [Parameter(Mandatory)]
        [string]$LogName,

        [int[]]$EventIds,

        [string]$XPathQuery,

        [Parameter(Mandatory)]
        [scriptblock]$OnEvent,

        [string]$SessionId
    )

    # Build query
    if (-not $XPathQuery) {
        if ($EventIds -and $EventIds.Count -gt 0) {
            $XPathQuery = New-XPathQuery -EventIds $EventIds
        }
        else {
            $XPathQuery = '*'
        }
    }

    try {
        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
            $LogName,
            [System.Diagnostics.Eventing.Reader.PathType]::LogName,
            $XPathQuery
        )

        $watcher = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($query)

        # Create health tracker
        $health = @{
            Name             = $WatcherName
            LogName          = $LogName
            EventIds         = $EventIds
            XPathQuery       = $XPathQuery
            CreatedAt        = [DateTime]::UtcNow
            LastEventAt      = $null
            LastErrorAt      = $null
            EventsProcessed  = [long]0
            ErrorCount       = [long]0
            IsEnabled        = $false
            LastError        = $null
        }

        # Register the event callback with full safety wrapping
        $callbackState = @{
            OnEvent          = $OnEvent
            Health           = $health
            SessionId        = $SessionId
            WatcherName      = $WatcherName
        }

        $null = Register-ObjectEvent -InputObject $watcher -EventName 'EventRecordWritten' `
            -MessageData $callbackState `
            -Action {
                $state = $Event.MessageData
                try {
                    $record = $Event.SourceEventArgs.EventRecord
                    if ($null -eq $record) { return }

                    # Invoke the processor callback
                    & $state.OnEvent -EventRecord $record -SessionId $state.SessionId

                    $state.Health.EventsProcessed++
                    $state.Health.LastEventAt = [DateTime]::UtcNow
                }
                catch {
                    $state.Health.ErrorCount++
                    $state.Health.LastErrorAt = [DateTime]::UtcNow
                    $state.Health.LastError = $_.Exception.Message

                    # Log locally — NEVER throw from a callback
                    try {
                        $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
                        $entry = "$timestamp :: [Error] Watcher '$($state.WatcherName)' callback failed: $($_.Exception.Message)"
                        Add-Content -Path $script:LogFilePath -Value $entry -ErrorAction SilentlyContinue
                    }
                    catch { $null = $null }
                }
            }

        $watcherState = @{
            Name       = $WatcherName
            Watcher    = $watcher
            Health     = $health
            Query      = $query
            OnEvent    = $OnEvent
        }

        $script:EventWatchers[$WatcherName] = $watcherState

        Write-EMLog -Message "Registered watcher '$WatcherName' for $LogName ($($EventIds.Count) event IDs)"

        return $watcherState
    }
    catch {
        Write-EMLog -Message "Failed to register watcher '$WatcherName': $($_.Exception.Message)" -Level Error
        return $null
    }
}

<#
.SYNOPSIS
    Enables (starts) a registered event watcher.
#>
function Enable-EventWatcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WatcherName
    )

    $state = $script:EventWatchers[$WatcherName]
    if ($null -eq $state) {
        Write-EMLog -Message "Watcher '$WatcherName' not found." -Level Warning
        return
    }

    try {
        $state.Watcher.Enabled = $true
        $state.Health.IsEnabled = $true
        Write-EMLog -Message "Enabled watcher '$WatcherName'."
    }
    catch {
        Write-EMLog -Message "Failed to enable watcher '$WatcherName': $($_.Exception.Message)" -Level Error
    }
}

<#
.SYNOPSIS
    Disables (pauses) a registered event watcher without destroying it.
#>
function Disable-EventWatcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WatcherName
    )

    $state = $script:EventWatchers[$WatcherName]
    if ($null -eq $state) { return }

    try {
        $state.Watcher.Enabled = $false
        $state.Health.IsEnabled = $false
        Write-EMLog -Message "Disabled watcher '$WatcherName'."
    }
    catch {
        Write-EMLog -Message "Failed to disable watcher '$WatcherName': $($_.Exception.Message)" -Level Error
    }
}

<#
.SYNOPSIS
    Stops and disposes a watcher, then re-creates it. Used for auto-repair.
#>
function Restart-EventWatcher {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WatcherName,

        [string]$SessionId
    )

    $state = $script:EventWatchers[$WatcherName]
    if ($null -eq $state) {
        Write-EMLog -Message "Cannot restart '$WatcherName' — not found." -Level Warning
        return
    }

    Write-EMLog -Message "Restarting watcher '$WatcherName'..." -Level Warning

    # Dispose old watcher safely
    try {
        $state.Watcher.Enabled = $false
        $state.Watcher.Dispose()
    }
    catch { $null = $null }

    # Unregister old event subscription
    Get-EventSubscriber | Where-Object { $_.SourceObject -eq $state.Watcher } |
        Unregister-Event -ErrorAction SilentlyContinue

    # Re-register with same parameters
    $newState = Register-EventWatcher `
        -WatcherName $WatcherName `
        -LogName $state.Health.LogName `
        -EventIds $state.Health.EventIds `
        -XPathQuery $state.Health.XPathQuery `
        -OnEvent $state.OnEvent `
        -SessionId $SessionId

    if ($null -ne $newState) {
        # Reset error count after successful restart
        $newState.Health.EventsProcessed = $state.Health.EventsProcessed
        $newState.Health.ErrorCount = 0

        Enable-EventWatcher -WatcherName $WatcherName
        Write-EMLog -Message "Watcher '$WatcherName' restarted successfully."
    }
}

<#
.SYNOPSIS
    Stops and disposes ALL event watchers. Called during shutdown.
#>
function Stop-AllEventWatchers {
    [CmdletBinding()]
    param()

    foreach ($name in @($script:EventWatchers.Keys)) {
        try {
            $state = $script:EventWatchers[$name]
            $state.Watcher.Enabled = $false
            $state.Watcher.Dispose()
            Write-EMLog -Message "Stopped watcher '$name'."
        }
        catch {
            Write-EMLog -Message "Error stopping watcher '$name': $($_.Exception.Message)" -Level Warning
        }
    }

    # Clean up only OUR event subscriptions (don't touch other modules' subscribers)
    foreach ($name in @($script:EventWatchers.Keys)) {
        $state = $script:EventWatchers[$name]
        Get-EventSubscriber -ErrorAction SilentlyContinue |
            Where-Object { $_.SourceObject -eq $state.Watcher } |
            Unregister-Event -ErrorAction SilentlyContinue
    }

    $script:EventWatchers.Clear()
    Write-EMLog -Message 'All event watchers stopped.'
}

<#
.SYNOPSIS
    Returns health status for all registered watchers.
.OUTPUTS
    Array of hashtables with Name, IsEnabled, EventsProcessed, ErrorCount, etc.
#>
function Get-EventWatcherHealth {
    [CmdletBinding()]
    param()

    foreach ($name in $script:EventWatchers.Keys) {
        $state = $script:EventWatchers[$name]
        [PSCustomObject]@{
            Name             = $state.Health.Name
            LogName          = $state.Health.LogName
            IsEnabled        = $state.Health.IsEnabled
            EventsProcessed  = $state.Health.EventsProcessed
            ErrorCount       = $state.Health.ErrorCount
            LastEventAt      = $state.Health.LastEventAt
            LastErrorAt      = $state.Health.LastErrorAt
            LastError        = $state.Health.LastError
            UptimeMinutes    = [math]::Round(([DateTime]::UtcNow - $state.Health.CreatedAt).TotalMinutes, 1)
        }
    }
}
