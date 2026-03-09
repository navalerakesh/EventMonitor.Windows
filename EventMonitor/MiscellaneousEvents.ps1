# ── Miscellaneous Events ──────────────────────────────────────────────────────
# Generic event reader that queries any Windows event ID from any supported
# log type (Security, System, Application). Configured dynamically at task
# registration time via the -trackMiscellaneousEvents parameter.

<#
.SYNOPSIS
    Reads events matching a specific Event ID and log type, then sends each to telemetry.
.DESCRIPTION
    This function enables dynamic tracking of arbitrary Windows events beyond the
    built-in logon/logoff indicators. The event ID and log type are provided at
    runtime, allowing operators to monitor shutdown events, BSOD indicators,
    service state changes, etc.
.PARAMETER sessionId
    Correlation session identifier.
.PARAMETER TimeRangeForEventsBefore
    Only process events created after this timestamp.
.PARAMETER specialEventId
    The Windows Event ID to query.
.PARAMETER specialEventLogType
    The event log name to query (Security, System, or Application).
#>
function Get-Miscellaneous_Events {
    [CmdletBinding()]
    param(
        [string]$sessionId,

        [Parameter(Mandatory)]
        [DateTime]$TimeRangeForEventsBefore,

        [Parameter(Mandatory)]
        [string]$specialEventId,

        [Parameter(Mandatory)]
        [ValidateSet('Security', 'System', 'Application')]
        [string]$specialEventLogType
    )

    try {
        $events = Get-WinEvent -FilterHashtable @{
            logname = $specialEventLogType
            id      = $specialEventId
        } -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $TimeRangeForEventsBefore }

        foreach ($evt in $events) {
            $evProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $evProps['SessionId'] = $sessionId
            $evProps['EventType'] = 'Miscellaneous'

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) Miscellaneous Event" `
                -Properties $evProps `
                -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*') {
            Write-EMLog -Message "Get-Miscellaneous_Events($specialEventLogType/$specialEventId) failed: $($_.Exception.Message)" -Level Error
            $errorProps = [System.Collections.Generic.Dictionary[string, string]]::new()
            $errorProps['SessionId']           = $sessionId
            $errorProps['Function']            = 'Get-Miscellaneous_Events'
            $errorProps['EventId']             = $specialEventId
            $errorProps['SpecialEventLogType'] = $specialEventLogType
            TrackException -ErrorRecord $_ -Properties $errorProps
        }
    }
}
