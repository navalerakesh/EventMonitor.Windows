#Requires -Version 7.4

<#
.SYNOPSIS
    WindowsEventMonitor - Root module for monitoring Windows security events.
.DESCRIPTION
    Monitors Windows logon/logoff events, active RDP/SSH sessions, and configurable
    miscellaneous events. Forwards structured event data to Azure Application Insights
    for centralized analysis. Designed to run as a Windows Scheduled Task under SYSTEM.
#>

# ── Module-Scoped Configuration ──────────────────────────────────────────────

$script:EventLogType = @{
    Security           = 'Security'
    System             = 'System'
    Application        = 'Application'
    Setup              = 'Setup'
    OpenSSHOperational = 'OpenSSH/Operational'
}

# ── Data Directory (ProgramData — survives module updates) ────────────────────
# All writable data goes here: logs, journal, config, connection string.
# Module install directory stays read-only (code + DLL only).
$script:DataRoot   = Join-Path $env:ProgramData 'WindowsEventMonitor'
$script:LogDir     = Join-Path $script:DataRoot 'Logs'
$script:JournalDir = Join-Path $script:DataRoot 'Journal'
$script:ConfigDir  = Join-Path $script:DataRoot 'Config'
$script:SecretsDir = Join-Path $script:DataRoot 'Secrets'

# Cached telemetry client (singleton pattern)
$script:TelemetryClient    = $null
$script:TelemetryConfig    = $null
$script:TelemetryDllLoaded = $false

# Ensure data directories exist BEFORE setting log path
foreach ($dir in @($script:DataRoot, $script:LogDir, $script:JournalDir, $script:ConfigDir, $script:SecretsDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

# Set log file path AFTER directories exist
$script:LogFilePath = Join-Path $script:LogDir "Operational-$(Get-Date -Format 'yyyy-MM-dd').log"

# ── Dot-Source All Function Files (order matters for dependencies) ────────────

# Core infrastructure (must load first)
. "$PSScriptRoot\TelemetryClient.ps1"
. "$PSScriptRoot\EventDispatch.ps1"
. "$PSScriptRoot\SessionDetection.ps1"

# Monitoring configuration and event journal (before processors so config is available)
. "$PSScriptRoot\Core\MonitoringConfig.ps1"
. "$PSScriptRoot\Core\EventJournal.ps1"
. "$PSScriptRoot\Core\EventHistory.ps1"
. "$PSScriptRoot\Core\ModuleHelp.ps1"

# Event processor base (helpers used by all processors)
. "$PSScriptRoot\EventProcessors\EventProcessorBase.ps1"

# Modular event processors
. "$PSScriptRoot\EventProcessors\LogonEvents.ps1"
. "$PSScriptRoot\EventProcessors\LogoffEvents.ps1"
. "$PSScriptRoot\EventProcessors\SSHEvents.ps1"
. "$PSScriptRoot\EventProcessors\AccountEvents.ps1"
. "$PSScriptRoot\EventProcessors\GroupEvents.ps1"
. "$PSScriptRoot\EventProcessors\PrivilegeEvents.ps1"
. "$PSScriptRoot\EventProcessors\ProcessEvents.ps1"
. "$PSScriptRoot\EventProcessors\PersistenceEvents.ps1"
. "$PSScriptRoot\EventProcessors\AuditEvents.ps1"
. "$PSScriptRoot\EventProcessors\PowerShellEvents.ps1"
. "$PSScriptRoot\EventProcessors\NetworkShareEvents.ps1"
. "$PSScriptRoot\EventProcessors\SystemHealthEvents.ps1"
. "$PSScriptRoot\EventProcessors\NetworkEvents.ps1"
. "$PSScriptRoot\EventProcessors\RDPEvents.ps1"
. "$PSScriptRoot\EventProcessors\WinRMEvents.ps1"
. "$PSScriptRoot\EventProcessors\DefenderEvents.ps1"

# Event-driven infrastructure
. "$PSScriptRoot\Core\EventWatcher.ps1"
. "$PSScriptRoot\Core\WatchdogService.ps1"

# Task management & orchestration (depends on everything above)
. "$PSScriptRoot\TaskManagement.ps1"

# ── Load Saved Configuration ─────────────────────────────────────────────────
$isFirstRun = -not (Test-Path (Join-Path $script:ConfigDir 'MonitoringConfig.json'))
Restore-MonitoringConfig

# Register event journal sink if enabled in config
if ($script:MonitoringConfig.JournalEnabled) {
    Register-EventJournalSink
}

# Log module version on every load (for diagnostics)
$script:ModuleVersion = (Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot '..' 'EventMonitor.Windows.psd1')).ModuleVersion
Write-EMLog -Message "EventMonitor.Windows v$script:ModuleVersion loaded. Level=$($script:MonitoringConfig.Level), Groups=$($script:MonitoringConfig.EnabledGroups.Count)"

# ── First-Run Welcome ────────────────────────────────────────────────────────
if ($isFirstRun) {
    Write-Host ""
    Write-Host "  EventMonitor.Windows installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Get started:" -ForegroundColor Cyan
    Write-Host "    Register-EventMonitor                              # start monitoring (local-only)"
    Write-Host "    Register-EventMonitor -logAnalyticsConString `$cs   # with App Insights"
    Write-Host ""
    Write-Host "  Quick test (no service deployment):"
    Write-Host "    Invoke-EventMonitor -LookBackMinutes 30"
    Write-Host ""
    Write-Host "  Commands & help:"
    Write-Host "    Show-EventMonitorHelp"
    Write-Host ""
}
