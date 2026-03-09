# ── Network & Firewall Events Processor ───────────────────────────────────────
# Monitors Windows Filtering Platform (WFP) connection events and firewall rule changes.
# Event IDs: 5156 (connection allowed), 5157 (connection blocked), 5152 (packet dropped)
#             4946 (firewall rule added), 4947 (rule modified), 4948 (rule deleted)
#
# Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-connection
# Note: Requires "Audit Filtering Platform Connection" audit policy to be enabled for 5156/5157/5152.
#       Firewall rule events (4946-4948) require "Audit MPSSVC Rule-Level Policy Change".

<#
.SYNOPSIS
    Collects network and firewall events within the time window.
.DESCRIPTION
    Monitors firewall rule changes (always) and optionally connection events.
    Connection events (5156/5157) can be very high volume — they are filtered
    to only report blocked connections and connections involving non-standard ports.
#>
function Get-NetworkEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    Get-FirewallRuleEvents -sessionId $sessionId -StartTime $StartTime
    Get-BlockedConnectionEvents -sessionId $sessionId -StartTime $StartTime
}

# ── Events 4946/4947/4948: Firewall Rule Changes ─────────────────────────────
# Always relevant — an attacker modifying firewall rules is a strong indicator.
# 4946 Properties: [0]ProfileChanged [1]RuleName [2]RuleAttr
# 4947 Properties: [0]ProfileChanged [1]RuleName [2]RuleAttr
# 4948 Properties: [0]ProfileChanged [1]RuleName [2]RuleAttr

function Get-FirewallRuleEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 4946, 4947, 4948 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $description = switch ($evt.Id) {
                4946 { 'Firewall Rule Added' }
                4947 { 'Firewall Rule Modified' }
                4948 { 'Firewall Rule Deleted' }
            }

            $severity = switch ($evt.Id) {
                4946 { 'High' }
                4947 { 'High' }
                4948 { 'Critical' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity $severity
            $props['ProfileChanged']   = "$($evt.Properties[0].Value)"
            $props['RuleName']         = "$($evt.Properties[1].Value)"
            $props['RuleAttributes']   = "$($evt.Properties[2].Value)"
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-FirewallRuleEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-FirewallRuleEvents')
    }
}

# ── Events 5157/5152: Blocked Connections & Dropped Packets ───────────────────
# Only blocked/dropped — allowed connections (5156) are too noisy for default monitoring.
# 5157 Properties: [0]ProcessId [1]Application [2]Direction [3]SourceAddress [4]SourcePort
#                  [5]DestAddress [6]DestPort [7]Protocol [8]FilterRTID [9]LayerName [10]LayerRTID
# 5152 Properties: same layout as 5157

function Get-BlockedConnectionEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    try {
        $events = Read-WindowsEvents -EventId 5157, 5152 -LogName 'Security' -StartTime $StartTime

        foreach ($evt in $events) {
            $description = switch ($evt.Id) {
                5157 { 'Connection Blocked by Firewall' }
                5152 { 'Packet Dropped by Firewall' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Medium'
            $props['ProcessId']        = "$($evt.Properties[0].Value)"
            $props['Application']      = "$($evt.Properties[1].Value)"
            $props['Direction']        = "$($evt.Properties[2].Value)"
            $props['SourceAddress']    = "$($evt.Properties[3].Value)"
            $props['SourcePort']       = "$($evt.Properties[4].Value)"
            $props['DestAddress']      = "$($evt.Properties[5].Value)"
            $props['DestPort']         = "$($evt.Properties[6].Value)"
            $props['Protocol']         = "$($evt.Properties[7].Value)"
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        Write-EMLog -Message "Get-BlockedConnectionEvents: $($_.Exception.Message)" -Level Error
        TrackException -ErrorRecord $_ `
            -Properties (New-ErrorProperties -SessionId $sessionId -FunctionName 'Get-BlockedConnectionEvents')
    }
}
