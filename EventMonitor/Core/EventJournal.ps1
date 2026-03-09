# ── Event Journal ─────────────────────────────────────────────────────────────
# Structured JSONL file capture of security events.
# Registered as a telemetry sink — receives events from the dispatcher.
#
# Purpose: Provides a clean, pre-filtered, structured log that can be read by
# AI tools, SIEM systems, or scripts WITHOUT needing Windows Event Log access.
#
# Files: EventMonitor/Telemetry/Journal/EventJournal-YYYY-MM-DD.jsonl
# Format: One JSON object per line (JSON Lines)
# Retention: Configurable via Set-EventJournal -RetentionDays N

# ── Severity ordering for comparison ─────────────────────────────────────────

$script:SeverityOrder = @{
    'Critical' = 5
    'High'     = 4
    'Medium'   = 3
    'Low'      = 2
    'Info'     = 1
}

<#
.SYNOPSIS
    Registers the event journal as a telemetry sink.
.DESCRIPTION
    Once registered, all events dispatched via TrackEvent are also written
    to daily JSONL files (filtered by minimum severity).
    Call this in the service startup or after Set-EventJournal -Enabled $true.
#>
function Register-EventJournalSink {
    [CmdletBinding()]
    param()

    $journalDir = $script:JournalDir
    if (-not (Test-Path $journalDir)) {
        New-Item -Path $journalDir -ItemType Directory -Force | Out-Null
    }

    Register-TelemetrySink -Name 'EventJournal' -OnDispatch {
        param($Type, $Name, $Properties, $Metrics, $ErrorRecord)

        # Only journal events (not traces or internal exceptions)
        if ($Type -ne 'Event') { return }

        # Check if journal is enabled (can be toggled at runtime)
        if (-not $script:MonitoringConfig.JournalEnabled) { return }

        # Severity filter
        $eventSeverity = if ($Properties -and $Properties.ContainsKey('Severity')) { $Properties['Severity'] } else { 'Info' }
        $minSeverity = $script:MonitoringConfig.JournalMinSeverity
        if ($script:SeverityOrder[$eventSeverity] -lt $script:SeverityOrder[$minSeverity]) { return }

        # Build journal entry
        $entry = [ordered]@{
            t        = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ'
            event    = $Name
            severity = $eventSeverity
            type     = if ($Properties -and $Properties.ContainsKey('EventType')) { $Properties['EventType'] } else { '' }
        }

        # Add key properties (not all — keep journal entries compact)
        if ($Properties) {
            foreach ($key in @('UserName', 'TargetUserName', 'SubjectUserName', 'SourceIP',
                              'SourceAddress', 'ProcessName', 'NewProcessName', 'ServiceName',
                              'TaskName', 'ShareName', 'SessionId', 'MachineName', 'EventId',
                              'AccountDomain', 'ClientAddress', 'RDPSessionId', 'EventDescription')) {
                if ($Properties.ContainsKey($key) -and $Properties[$key]) {
                    $entry[$key] = $Properties[$key]
                }
            }
        }

        # Write to daily file
        $journalDir = $script:JournalDir
        $journalFile = Join-Path $journalDir "EventJournal-$(Get-Date -Format 'yyyy-MM-dd').jsonl"
        try {
            ($entry | ConvertTo-Json -Compress) | Add-Content -Path $journalFile -ErrorAction Stop
        }
        catch {
            continue # Silent failure — journal is optional, never block telemetry
        }
    }

    Write-EMLog -Message 'Event journal sink registered.' -Level Warning
}

<#
.SYNOPSIS
    Removes old journal and operational log files beyond the retention period.
.DESCRIPTION
    Called by the watchdog during each cycle. Removes files older than
    the configured retention days from both the Journal/ and Logs/ directories.
#>
function Invoke-LogCleanup {
    [CmdletBinding()]
    param()

    $retentionDays = $script:MonitoringConfig.RetentionDays
    if ($retentionDays -le 0) { return }

    $cutoff = (Get-Date).AddDays(-$retentionDays)

    # Clean journal files
    $journalDir = $script:JournalDir
    if (Test-Path $journalDir) {
        Get-ChildItem -Path $journalDir -Filter '*.jsonl' |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-EMLog -Message "Cleaned up old journal file: $($_.Name)" -Level Info
            }
    }

    # Clean old operational log files (daily .log files)
    if (Test-Path $script:LogDir) {
        Get-ChildItem -Path $script:LogDir -Filter '*.log' |
            Where-Object { $_.LastWriteTime -lt $cutoff } |
            ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                Write-EMLog -Message "Cleaned up old log file: $($_.Name)" -Level Info
            }
    }
}
