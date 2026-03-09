# ── PowerShell Security Events Processor ──────────────────────────────────────
# Monitors PowerShell script block logging for detecting PowerShell-based attacks.
# Event ID: 4104 (Script Block Logging)
#
# Requires: Group Policy > Computer Configuration > Administrative Templates >
#   Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging
#
# Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows

<#
.SYNOPSIS
    Collects PowerShell script block execution events within the time window.
.DESCRIPTION
    Event 4104 captures the actual PowerShell code being executed, which is
    critical for detecting obfuscated attacks, fileless malware, and
    living-off-the-land techniques.
    Only logs scripts flagged as suspicious by the PowerShell engine
    (ScriptBlockLogging level 'Warning') to reduce noise, unless all
    script block logging is desired.
#>
function Get-PowerShellEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 4104 -LogName 'Microsoft-Windows-PowerShell/Operational' -StartTime $StartTime

        foreach ($evt in $events) {
            # Properties: [0]MessageNumber [1]MessageTotal [2]ScriptBlockText [3]ScriptBlockId [4]Path

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Medium'
            $props['ScriptBlockId']  = "$($evt.Properties[3].Value)"
            $props['ScriptPath']     = "$($evt.Properties[4].Value)"
            $props['MessageNumber']  = "$($evt.Properties[0].Value)"
            $props['MessageTotal']   = "$($evt.Properties[1].Value)"

            # Script block text can be very large — truncate for telemetry
            $scriptText = "$($evt.Properties[2].Value)"
            if ($scriptText.Length -gt 4000) {
                $scriptText = $scriptText.Substring(0, 4000) + '...[truncated]'
            }
            $props['ScriptBlockText'] = $scriptText

            Send-LogAnalyticsConnectEvents `
                -eventName '4104 PowerShell Script Block' -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-PowerShellEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-PowerShellEvents')
    }
}
