# ── Logging & Event Dispatch ──────────────────────────────────────────────────
# Centralized logging helper and the function that enriches Windows events
# with full metadata before forwarding them to Application Insights.

<#
.SYNOPSIS
    Writes a timestamped, leveled entry to the local operational log file.
.DESCRIPTION
    All module components use this single function for local file logging.
    Respects the configured log level — messages below the threshold are silently dropped.
    Log levels (in order): Debug < Info < Warning < Error
.PARAMETER Message
    The log message text.
.PARAMETER Level
    Debug, Info, Warning, or Error. Defaults to Info.
#>
function Write-EMLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )

    # Level filtering — skip messages below the configured threshold
    $levelOrder = @{ 'Debug' = 0; 'Info' = 1; 'Warning' = 2; 'Error' = 3 }
    $configLevel = if ($script:MonitoringConfig) { $script:MonitoringConfig.LogLevel } else { 'Info' }
    if ($levelOrder[$Level] -lt $levelOrder[$configLevel]) {
        # Still mirror to verbose for interactive debugging even if not logged
        Write-Verbose "$Level :: $Message"
        return
    }

    $timestamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
    $entry = "$timestamp :: [$Level] $Message"

    try {
        # Daily log file path (updates if date rolls over during long-running service)
        $script:LogFilePath = Join-Path $script:LogDir "Operational-$(Get-Date -Format 'yyyy-MM-dd').log"
        Add-Content -Path $script:LogFilePath -Value $entry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log: $entry"
    }

    # Mirror to verbose stream for interactive debugging
    Write-Verbose $entry
}

<#
.SYNOPSIS
    Enriches a Windows event with full metadata and dispatches it to all telemetry sinks.
.DESCRIPTION
    Merges caller-supplied properties with all available fields from the raw
    EventRecord (Id, Message, TimeCreated, MachineName, all indexed properties, etc.)
    and dispatches the combined payload via TrackEvent.
.PARAMETER eventName
    Name for the telemetry event.
.PARAMETER Properties
    Caller-supplied key-value properties (SessionId, EventType, UserName, etc.).
.PARAMETER sendEvent
    The raw Windows EventRecord to extract metadata from.
#>
function Send-LogAnalyticsConnectEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$eventName,

        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, string]]$Properties,

        [System.Diagnostics.Eventing.Reader.EventRecord]$sendEvent
    )

    try {
        # Build a merged property dictionary: caller props + event metadata
        $allProps = [System.Collections.Generic.Dictionary[string, string]]::new()

        foreach ($key in $Properties.Keys) {
            $allProps[$key] = $Properties[$key]
        }

        if ($null -ne $sendEvent) {
            $allProps['EventId']           = "$($sendEvent.Id)"
            $allProps['Message']           = "$($sendEvent.Message)"
            $allProps['TimeCreated']       = "$($sendEvent.TimeCreated)"
            $allProps['Level']             = "$($sendEvent.Level)"
            $allProps['Keywords']          = "$($sendEvent.Keywords)"
            $allProps['RecordId']          = "$($sendEvent.RecordId)"
            $allProps['ProviderId']        = "$($sendEvent.ProviderId)"
            $allProps['ProviderName']      = "$($sendEvent.ProviderName)"
            $allProps['ThreadId']          = "$($sendEvent.ThreadId)"
            $allProps['MachineName']       = "$($sendEvent.MachineName)"
            $allProps['UserId']            = "$($sendEvent.UserId)"
            $allProps['ActivityId']        = "$($sendEvent.ActivityId)"
            $allProps['RelatedActivityId'] = "$($sendEvent.RelatedActivityId)"
            $allProps['ContainerLog']      = "$($sendEvent.ContainerLog)"
            $allProps['MatchedQueryIds']   = "$($sendEvent.MatchedQueryIds)"
            $allProps['LevelDisplayName']  = "$($sendEvent.LevelDisplayName)"
            $allProps['TaskDisplayName']   = "$($sendEvent.TaskDisplayName)"

            $idx = 0
            foreach ($p in $sendEvent.Properties) {
                $idx++
                $allProps["Property[$idx]"] = "$($p.Value)"
            }
        }

        TrackEvent -Name $eventName -Properties $allProps
    }
    catch {
        Write-EMLog -Message "Send-LogAnalyticsConnectEvents failed for '$eventName': $($_.Exception.Message)" -Level Error
        $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
        $errorProps['Function']  = 'Send-LogAnalyticsConnectEvents'
        $errorProps['EventName'] = $eventName
        TrackException -ErrorRecord $_ -Properties $errorProps
    }
}
