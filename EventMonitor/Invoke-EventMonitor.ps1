#Requires -Version 7.4
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Thin wrapper script — delegates to the Invoke-EventMonitor module function.
.DESCRIPTION
    This script exists for backward compatibility and for use by the scheduled task.
    Prefer calling Invoke-EventMonitor directly after Import-Module.
.PARAMETER LookBackMinutes
    How far back (in minutes) to read events. Default: 60.
.PARAMETER SessionId
    Correlation identifier. Defaults to a new GUID.
#>
param(
    [ValidateRange(1, 10080)]
    [int]$LookBackMinutes = 60,

    [string]$SessionId = [guid]::NewGuid().Guid
)

$modulePath = Join-Path $PSScriptRoot 'WindowsEventMonitor.psm1'
Import-Module $modulePath -Force -ErrorAction Stop

Invoke-EventMonitor -LookBackMinutes $LookBackMinutes -SessionId $SessionId
