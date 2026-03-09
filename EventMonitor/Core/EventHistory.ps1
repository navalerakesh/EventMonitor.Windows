# ── Event History ─────────────────────────────────────────────────────────────
# Reads captured event journal (JSONL files) and presents them in a clean,
# searchable format. Provides both table output and file path for deep analysis.

<#
.SYNOPSIS
    Shows history of tracked security events from the event journal.
.DESCRIPTION
    Reads the JSONL event journal files and presents a formatted table of
    recent events. Each event includes timestamp, name, severity, user, and IP.

    For full event details, use -Detailed or open the JSONL file directly.

    Requires the event journal to be enabled (Set-EventJournal -Enabled $true).
.PARAMETER Days
    How many days of history to show. Default: 7. Max: 365.
.PARAMETER Severity
    Filter by minimum severity: Critical, High, Medium, Low, Info. Default: all.
.PARAMETER EventName
    Filter by event name (supports wildcards). Example: '*SSH*', '*4625*'
.PARAMETER Detailed
    Show all properties for each event instead of the summary table.
.PARAMETER Last
    Show only the last N events. Default: 50.
.EXAMPLE
    Get-EventHistory
.EXAMPLE
    Get-EventHistory -Days 1 -Severity High
.EXAMPLE
    Get-EventHistory -EventName '*SSH*' -Last 20
.EXAMPLE
    Get-EventHistory -Days 3 -Detailed
#>
function Get-EventHistory {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 365)]
        [int]$Days = 7,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [string]$EventName,

        [switch]$Detailed,

        [ValidateRange(1, 10000)]
        [int]$Last = 50
    )

    $journalDir = $script:JournalDir
    # Also check if called from EventMonitor root
    if (-not (Test-Path $journalDir)) {
        $journalDir = $script:JournalDir
    }

    if (-not (Test-Path $journalDir)) {
        Write-Warning "Event journal directory not found at '$journalDir'."
        Write-Warning "Enable the journal first: Set-EventJournal -Enabled `$true"
        Write-Warning "Then run Invoke-EventMonitor to capture events."
        return
    }

    # Find journal files within the date range
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $journalFiles = Get-ChildItem -Path $journalDir -Filter 'EventJournal-*.jsonl' |
        Where-Object { $_.LastWriteTime -ge $cutoffDate } |
        Sort-Object Name

    if ($journalFiles.Count -eq 0) {
        Write-Warning "No journal files found for the last $Days day(s)."
        Write-Warning "Run: Invoke-EventMonitor -LookBackMinutes 60"
        return
    }

    # Severity ordering for filtering
    $severityOrder = @{ 'Critical' = 5; 'High' = 4; 'Medium' = 3; 'Low' = 2; 'Info' = 1 }
    $minSeverityLevel = if ($Severity) { $severityOrder[$Severity] } else { 0 }

    # Read and parse all matching events
    $allEvents = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($file in $journalFiles) {
        $lines = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue
        foreach ($line in $lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $evt = $line | ConvertFrom-Json

                # Severity filter
                $evtSev = if ($evt.severity) { $evt.severity } else { 'Info' }
                if ($severityOrder[$evtSev] -lt $minSeverityLevel) { continue }

                # Event name filter
                if ($EventName -and $evt.event -notlike $EventName) { continue }

                $allEvents.Add([PSCustomObject]@{
                    Time        = $evt.t
                    Event       = $evt.event
                    Severity    = $evtSev
                    Type        = if ($evt.type) { $evt.type } else { '' }
                    User        = if ($evt.UserName) { $evt.UserName }
                                  elseif ($evt.TargetUserName) { $evt.TargetUserName }
                                  elseif ($evt.SubjectUserName) { $evt.SubjectUserName }
                                  else { '' }
                    SourceIP    = if ($evt.SourceIP) { $evt.SourceIP }
                                  elseif ($evt.SourceAddress) { $evt.SourceAddress }
                                  elseif ($evt.IPAddress) { $evt.IPAddress }
                                  elseif ($evt.ClientAddress) { $evt.ClientAddress }
                                  else { '' }
                    Details     = if ($evt.EventDescription) { $evt.EventDescription } else { '' }
                    _Raw        = $evt
                })
            }
            catch {
                continue # Skip malformed JSON lines
            }
        }
    }

    if ($allEvents.Count -eq 0) {
        Write-Warning "No events match the specified filters."
        return
    }

    # Sort by time descending, take last N
    $results = $allEvents | Sort-Object Time -Descending | Select-Object -First $Last

    # Display summary
    $totalFiles = $journalFiles.Count
    $dateRange = "$($journalFiles[0].Name -replace 'EventJournal-|\.jsonl','') to $($journalFiles[-1].Name -replace 'EventJournal-|\.jsonl','')"

    Write-Host ""
    Write-Host "  Event History: $($results.Count) events (of $($allEvents.Count) total)" -ForegroundColor Cyan
    Write-Host "  Date range: $dateRange ($totalFiles file(s))" -ForegroundColor DarkGray
    Write-Host "  Journal path: $journalDir" -ForegroundColor DarkGray
    Write-Host ""

    if ($Detailed) {
        $results | ForEach-Object {
            Write-Host "[$($_.Severity.PadRight(8))] $($_.Time) — $($_.Event)" -ForegroundColor $(
                switch ($_.Severity) {
                    'Critical' { 'Red' }
                    'High'     { 'Yellow' }
                    'Medium'   { 'DarkYellow' }
                    default    { 'Gray' }
                }
            )
            $_._Raw | ConvertTo-Json -Depth 2 | Write-Host -ForegroundColor DarkGray
            Write-Host ""
        }
    }
    else {
        $results | Select-Object Time, Severity, Event, User, SourceIP, Details |
            Format-Table -AutoSize -Wrap
    }

    # Show file paths for deep analysis
    Write-Host "  Journal files:" -ForegroundColor DarkGray
    foreach ($f in $journalFiles) {
        Write-Host "    $($f.FullName)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "  Tip: Get-Content '$($journalFiles[-1].FullName)' | ConvertFrom-Json | Where-Object severity -eq 'Critical'" -ForegroundColor DarkGray
    Write-Host ""
}
