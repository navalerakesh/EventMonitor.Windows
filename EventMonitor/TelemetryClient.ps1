# ── Telemetry Dispatcher ──────────────────────────────────────────────────────
# Pluggable telemetry architecture. Event processors call TrackEvent/TrackTrace/
# TrackException without knowing where events go. The dispatcher routes to all
# registered sinks (Application Insights, future: OTel, email, webhook, etc.).
#
# Built-in sink: Application Insights (loaded when connection string is present).
# To add a sink:  Register-TelemetrySink -Name 'MySink' -OnEvent { param($Name, $Props) ... }
# To remove:      Unregister-TelemetrySink -Name 'MySink'

# ── Sink Registry ────────────────────────────────────────────────────────────

$script:TelemetrySinks = [ordered]@{}

<#
.SYNOPSIS
    Registers a telemetry sink that receives all tracked events/traces/exceptions.
.DESCRIPTION
    A sink is a scriptblock that receives dispatched telemetry. Register multiple
    sinks to fan out events to different destinations simultaneously.

    Each sink receives these parameters via $args or named params in the scriptblock:
    - Type:       'Event', 'Trace', or 'Exception'
    - Name:       Event name or trace message
    - Properties: Dictionary[string,string] of key-value pairs
    - Metrics:    Dictionary[string,double] of numeric metrics (events only)
    - ErrorRecord: The original ErrorRecord (exceptions only)

    Sink exceptions are caught and logged — a failing sink never blocks others.
.PARAMETER Name
    Unique name for this sink (used for management and logging).
.PARAMETER OnDispatch
    Scriptblock to execute when telemetry is dispatched.
.EXAMPLE
    # Log all events to a file
    Register-TelemetrySink -Name 'FileLog' -OnDispatch {
        param($Type, $Name, $Properties)
        "$Type : $Name" | Out-File -Append 'C:\Logs\events.txt'
    }
.EXAMPLE
    # Send critical alerts via webhook
    Register-TelemetrySink -Name 'Webhook' -OnDispatch {
        param($Type, $Name, $Properties)
        if ($Properties['Severity'] -eq 'Critical') {
            Invoke-RestMethod -Uri 'https://hooks.example.com/alert' -Method Post -Body ($Properties | ConvertTo-Json)
        }
    }
#>
function Register-TelemetrySink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$OnDispatch
    )

    $script:TelemetrySinks[$Name] = @{
        Name       = $Name
        OnDispatch = $OnDispatch
        Enabled    = $true
    }
    Write-EMLog -Message "Telemetry sink '$Name' registered."
}

<#
.SYNOPSIS
    Removes a registered telemetry sink.
#>
function Unregister-TelemetrySink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($script:TelemetrySinks.Contains($Name)) {
        $script:TelemetrySinks.Remove($Name)
        Write-EMLog -Message "Telemetry sink '$Name' unregistered."
    }
}

<#
.SYNOPSIS
    Returns the list of registered telemetry sinks.
#>
function Get-TelemetrySinks {
    [CmdletBinding()]
    param()

    foreach ($key in $script:TelemetrySinks.Keys) {
        $sink = $script:TelemetrySinks[$key]
        [PSCustomObject]@{
            Name    = $sink.Name
            Enabled = $sink.Enabled
        }
    }
}

# ── Internal Dispatch ─────────────────────────────────────────────────────────

function Invoke-TelemetryDispatch {
    param(
        [string]$Type,
        [string]$Name,
        [System.Collections.Generic.Dictionary[string, string]]$Properties,
        [System.Collections.Generic.Dictionary[string, double]]$Metrics,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    foreach ($key in @($script:TelemetrySinks.Keys)) {
        $sink = $script:TelemetrySinks[$key]
        if (-not $sink.Enabled) { continue }

        try {
            & $sink.OnDispatch $Type $Name $Properties $Metrics $ErrorRecord
        }
        catch {
            # A failing sink never blocks other sinks or the caller
            Write-EMLog -Message "Telemetry sink '$($sink.Name)' failed: $($_.Exception.Message)" -Level Error
        }
    }
}

# ── Application Insights Sink (Built-in) ─────────────────────────────────────

<#
.SYNOPSIS
    Ensures the Application Insights DLL is loaded and returns a cached TelemetryClient.
#>
function Initialize-TelemetryClient {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ConnectionString
    )

    if (-not $script:TelemetryDllLoaded) {
        # Check if the type is already loaded (e.g., from a previous import or direct Add-Type)
        $typeLoaded = [System.AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Microsoft.ApplicationInsights' }

        if (-not $typeLoaded) {
            $dllPath = Join-Path $PSScriptRoot 'Telemetry' 'Microsoft.ApplicationInsights.dll'
            if (-not (Test-Path $dllPath)) {
                throw "Microsoft.ApplicationInsights.dll not found at '$dllPath'. See README for installation."
            }
            Add-Type -Path $dllPath
        }
        $script:TelemetryDllLoaded = $true
    }

    if ($null -ne $script:TelemetryClient -and
        $null -ne $script:TelemetryConfig -and
        $script:TelemetryConfig.ConnectionString -eq $ConnectionString) {
        return $script:TelemetryClient
    }

    if ($null -ne $script:TelemetryClient) {
        try { $script:TelemetryClient.Flush() } catch { $null = $null }
    }
    if ($null -ne $script:TelemetryConfig) {
        try { $script:TelemetryConfig.Dispose() } catch { $null = $null }
    }

    $script:TelemetryConfig = New-Object Microsoft.ApplicationInsights.Extensibility.TelemetryConfiguration
    $script:TelemetryConfig.ConnectionString = $ConnectionString
    $script:TelemetryClient = New-Object Microsoft.ApplicationInsights.TelemetryClient($script:TelemetryConfig)

    return $script:TelemetryClient
}

<#
.SYNOPSIS
    Resolves the Application Insights connection string from multiple sources.
.DESCRIPTION
    Checks sources in priority order:
    1. Environment variable: APPLICATIONINSIGHTS_CONNECTION_STRING (Azure standard)
    2. Environment variable: EventMonitorAppInsightsConString (custom)
    3. File: Telemetry/LogAnalyticsConString.txt
    Returns $null if no connection string is found anywhere.
.OUTPUTS
    Connection string or $null.
#>
function Resolve-AppInsightsConnectionString {
    [CmdletBinding()]
    param()

    # Priority 1: Azure standard env var
    $cs = $env:APPLICATIONINSIGHTS_CONNECTION_STRING
    if (-not [string]::IsNullOrWhiteSpace($cs)) {
        Write-EMLog -Message 'Connection string resolved from APPLICATIONINSIGHTS_CONNECTION_STRING env var.' -Level Warning
        return $cs.Trim()
    }

    # Priority 2: Custom env var
    $cs = $env:EventMonitorAppInsightsConString
    if (-not [string]::IsNullOrWhiteSpace($cs)) {
        Write-EMLog -Message 'Connection string resolved from EventMonitorAppInsightsConString env var.' -Level Warning
        return $cs.Trim()
    }

    # Priority 3: File (new standard location)
    $conStringPath = Join-Path $script:SecretsDir 'ConnectionString.txt'
    if (Test-Path $conStringPath) {
        $cs = (Get-Content -Path $conStringPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($cs)) {
            Write-EMLog -Message 'Connection string resolved from ConnectionString.txt file.' -Level Warning
            return $cs
        }
    }

    # Priority 4: Legacy file location (backward compat)
    $legacyPath = Join-Path $PSScriptRoot 'Telemetry' 'LogAnalyticsConString.txt'
    if (Test-Path $legacyPath) {
        $cs = (Get-Content -Path $legacyPath -Raw).Trim()
        if (-not [string]::IsNullOrWhiteSpace($cs)) {
            Write-EMLog -Message 'Connection string resolved from legacy LogAnalyticsConString.txt.' -Level Warning
            return $cs
        }
    }

    Write-EMLog -Message 'No App Insights connection string found in env vars or file.' -Level Warning
    return $null
}

<#
.SYNOPSIS
    Registers the built-in Application Insights sink.
.DESCRIPTION
    Called automatically when a connection string is provided. You don't need
    to call this manually unless you removed the sink and want to re-add it.
#>
function Register-AppInsightsSink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConnectionString
    )

    # Store connection string at module scope for the sink callback
    $script:AppInsightsConnectionString = $ConnectionString

    Register-TelemetrySink -Name 'AppInsights' -OnDispatch {
        param($Type, $Name, $Properties, $Metrics, $ErrorRecord)

        $client = Initialize-TelemetryClient -ConnectionString $script:AppInsightsConnectionString

        switch ($Type) {
            'Event'     { $client.TrackEvent($Name, $Properties, $Metrics) }
            'Trace'     { $client.TrackTrace($Name, $Properties) }
            'Exception' { $client.TrackException($ErrorRecord.Exception, $Properties, $Metrics) }
        }
    }
}

# ── Public Dispatch Functions ─────────────────────────────────────────────────
# These are the functions that event processors call. They dispatch to ALL
# registered sinks. The logAnalyticsConString parameter is kept for backward
# compatibility but is optional — if the AppInsights sink is already registered,
# it uses the stored connection string.

<#
.SYNOPSIS
    Sends a custom event to all registered telemetry sinks.
.PARAMETER Name
    The event name.
.PARAMETER Properties
    Optional string key-value pairs attached to the event.
.PARAMETER Metrics
    Optional numeric key-value pairs attached to the event.
#>
function TrackEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [System.Collections.Generic.Dictionary[string, string]]$Properties,

        [System.Collections.Generic.Dictionary[string, double]]$Metrics
    )

    try {
        Invoke-TelemetryDispatch -Type 'Event' -Name $Name -Properties $Properties -Metrics $Metrics
    }
    catch {
        Write-EMLog -Message "TrackEvent dispatch failed for '$Name': $($_.Exception.Message)" -Level Error
    }
}

<#
.SYNOPSIS
    Sends a trace message to all registered telemetry sinks.
#>
function TrackTrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [System.Collections.Generic.Dictionary[string, string]]$Properties
    )

    try {
        Invoke-TelemetryDispatch -Type 'Trace' -Name $Message -Properties $Properties
    }
    catch {
        Write-EMLog -Message "TrackTrace dispatch failed: $($_.Exception.Message)" -Level Error
    }
}

<#
.SYNOPSIS
    Sends an exception to all registered telemetry sinks.
#>
function TrackException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [System.Collections.Generic.Dictionary[string, string]]$Properties,

        [System.Collections.Generic.Dictionary[string, double]]$Metrics
    )

    try {
        Invoke-TelemetryDispatch -Type 'Exception' -Name $ErrorRecord.Exception.Message `
            -Properties $Properties -Metrics $Metrics -ErrorRecord $ErrorRecord
    }
    catch {
        Write-EMLog -Message "TrackException dispatch failed: $($_.Exception.Message)" -Level Error
    }
}

<#
.SYNOPSIS
    Flushes all telemetry sinks that support flushing.
.DESCRIPTION
    Currently flushes the Application Insights client. Future sinks that
    buffer data should be flushed here too.
#>
function Flush-Telemetry {
    [CmdletBinding()]
    param()

    # Flush App Insights if active
    if ($null -ne $script:TelemetryClient) {
        try {
            $script:TelemetryClient.Flush()
        }
        catch {
            Write-EMLog -Message "Flush-Telemetry (AppInsights) failed: $($_.Exception.Message)" -Level Error
        }
    }
}
