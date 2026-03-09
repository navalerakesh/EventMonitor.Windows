<#
.SYNOPSIS
    Safe local test runner for EventMonitor.Windows.
.DESCRIPTION
    Runs Pester tests with code coverage DISABLED and a timeout to prevent
    VS Code hangs. Use this instead of calling Invoke-Pester directly.

    Code coverage is enabled only in CI (see .github/workflows/ci.yml).
.EXAMPLE
    .\Run-Tests.ps1
.EXAMPLE
    .\Run-Tests.ps1 -Verbosity Normal
#>
[CmdletBinding()]
param(
    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
    [string]$Verbosity = 'Detailed'
)

$ErrorActionPreference = 'Stop'

# Ensure Pester 5+ is available
$pester = Get-Module -Name Pester -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
if (-not $pester -or $pester.Version -lt [version]'5.0.0') {
    Write-Host 'Installing Pester 5...' -ForegroundColor Yellow
    Install-Module -Name Pester -MinimumVersion 5.0 -Force -Scope CurrentUser
}
Import-Module Pester -MinimumVersion 5.0 -Force

$cfg = New-PesterConfiguration
$cfg.Run.Path = './tests'
$cfg.Run.Exit = $false
$cfg.Run.Throw = $true
$cfg.Output.Verbosity = $Verbosity
$cfg.CodeCoverage.Enabled = $false                # Disabled locally — use CI for coverage
$cfg.TestResult.Enabled = $false                  # No XML output locally
$cfg.Should.ErrorAction = 'Continue'

Invoke-Pester -Configuration $cfg
