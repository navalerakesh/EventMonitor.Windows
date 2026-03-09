# ── Module Help ───────────────────────────────────────────────────────────────
# Provides a quick-start guide and function reference when users run Get-Help
# or Show-EventMonitorHelp.

<#
.SYNOPSIS
    Shows a quick-start guide and available commands for EventMonitor.Windows.
.DESCRIPTION
    Displays an overview of the module, available commands grouped by category,
    monitoring levels, event groups, and common usage examples.
.EXAMPLE
    Show-EventMonitorHelp
.EXAMPLE
    # Also works via standard PowerShell help:
    Get-Command -Module EventMonitor.Windows
#>
function Show-EventMonitorHelp {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║          EventMonitor.Windows v1.0.1                     ║" -ForegroundColor Cyan
    Write-Host "  ║  Real-time Windows security event monitoring            ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  QUICK START" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────"
    Write-Host "    1. Set-MonitoringLevel -Level Standard        # choose coverage"
    Write-Host "    2. Register-EventMonitor -logAnalyticsConString `$cs   # deploy service"
    Write-Host "    3. Get-EventHistory                           # view tracked events"
    Write-Host ""
    Write-Host "    Or for a quick test without deploying:"
    Write-Host "    Invoke-EventMonitor -LookBackMinutes 30       # one-shot scan"
    Write-Host ""

    Write-Host "  COMMANDS" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────"

    Write-Host "  Monitoring Setup:" -ForegroundColor Green
    Write-Host "    Set-MonitoringLevel       Set level: Minimum | Standard | High | Custom"
    Write-Host "    Get-MonitoringConfig      View current configuration"
    Write-Host "    Get-EventGroups           List all event groups and their status"
    Write-Host ""

    Write-Host "  Service Management:" -ForegroundColor Green
    Write-Host "    Register-EventMonitor     Register & start the monitoring service"
    Write-Host "    Uninstall-EventMonitor    Stop service, keep data (-DeleteData to wipe)"
    Write-Host "    Unregister-EventMonitor   Remove the scheduled task"
    Write-Host "    Start-EventMonitor        Start the service"
    Write-Host "    Stop-EventMonitor         Stop the service"
    Write-Host "    Enable-EventMonitor       Re-enable a disabled service"
    Write-Host "    Disable-EventMonitor      Disable without removing"
    Write-Host "    Get-EventMonitor          Check service status"
    Write-Host ""

    Write-Host "  Event Data:" -ForegroundColor Green
    Write-Host "    Invoke-EventMonitor       Run a one-shot diagnostic scan"
    Write-Host "    Get-EventHistory          View tracked events (table + JSONL path)"
    Write-Host "    Get-MonitoredEventCategories   List all event IDs with severity"
    Write-Host ""

    Write-Host "  Configuration:" -ForegroundColor Green
    Write-Host "    Set-EventJournal          Enable/disable JSONL event journal"
    Write-Host "    Set-EMLogLevel            Set log verbosity (Error|Warning|Info|Debug)"
    Write-Host ""

    Write-Host "  Telemetry Sinks:" -ForegroundColor Green
    Write-Host "    Register-TelemetrySink    Add custom destination (webhook, email, etc.)"
    Write-Host "    Unregister-TelemetrySink  Remove a sink"
    Write-Host "    Get-TelemetrySinks        List registered sinks"
    Write-Host ""

    Write-Host "  MONITORING LEVELS" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────"
    Write-Host "    Minimum   4 groups   Logon, Logoff, SSH, RDP"
    Write-Host "    Standard  13 groups  + Account, Group, Audit, Persistence, Firewall," -ForegroundColor White
    Write-Host "                           SystemHealth, WinRM, Defender  (recommended)"
    Write-Host "    High      17 groups  + Privilege, Process, PowerShell, NetworkShare"
    Write-Host "    Custom    You pick   Set-MonitoringLevel -Level Custom -Groups ..."
    Write-Host ""

    Write-Host "  DATA LOCATION" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────"
    Write-Host "    Config:   $script:ConfigDir"
    Write-Host "    Logs:     $script:LogDir"
    Write-Host "    Journal:  $script:JournalDir"
    Write-Host "    Secrets:  $script:SecretsDir"
    Write-Host ""

    Write-Host "  CONNECTION STRING (pick one):" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────"
    Write-Host "    Env var:  `$env:APPLICATIONINSIGHTS_CONNECTION_STRING"
    Write-Host "    Env var:  `$env:EventMonitorAppInsightsConString"
    Write-Host "    File:     $script:SecretsDir\ConnectionString.txt"
    Write-Host "    Param:    Register-EventMonitor -logAnalyticsConString '...'"
    Write-Host ""

    Write-Host "  EXAMPLES" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────────────────────"
    Write-Host '    # Quick test — scan last 30 minutes'
    Write-Host '    Invoke-EventMonitor -LookBackMinutes 30'
    Write-Host ''
    Write-Host '    # View recent critical events'
    Write-Host '    Get-EventHistory -Severity Critical -Days 1'
    Write-Host ''
    Write-Host '    # See what groups are active'
    Write-Host '    Get-EventGroups | Format-Table Name, Enabled, Description'
    Write-Host ''
    Write-Host '    # Add a webhook for critical alerts'
    Write-Host '    Register-TelemetrySink -Name "Webhook" -OnDispatch {'
    Write-Host '        param($Type, $Name, $Properties)'
    Write-Host '        if ($Properties["Severity"] -eq "Critical") {'
    Write-Host '            Invoke-RestMethod -Uri "https://..." -Method Post -Body ($Properties | ConvertTo-Json)'
    Write-Host '        }'
    Write-Host '    }'
    Write-Host ''
    Write-Host '    # Deploy as a service'
    Write-Host '    Register-EventMonitor -logAnalyticsConString $connStr'
    Write-Host ""
    Write-Host "  More info: https://github.com/navalerakesh/EventMonitor.Windows" -ForegroundColor DarkGray
    Write-Host ""
}
