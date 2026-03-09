# ── Windows Defender Events Processor ─────────────────────────────────────────
# Monitors Windows Defender/Antimalware for malware detection and protection
# state changes. Critical for detecting when an attacker disables security.
#
# Log: Microsoft-Windows-Windows Defender/Operational
# Event IDs:
#   1116 — Malware detected
#   1117 — Action taken on malware
#   5001 — Real-time protection disabled
#   5010 — Scanning for malware disabled
#   5012 — Virus scanning disabled
#
# Reference: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus

<#
.SYNOPSIS
    Collects Windows Defender security events within the time window.
.DESCRIPTION
    Monitors two categories:
    1. Malware detection (1116/1117) — something malicious was found
    2. Protection disabled (5001/5010/5012) — attacker disabling AV
    Both are extremely high-signal, low-volume events.
#>
function Get-DefenderEvents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$sessionId,
        [Parameter(Mandatory)] [DateTime]$StartTime
    )

    $logName = 'Microsoft-Windows-Windows Defender/Operational'

    # Malware detection events
    try {
        $events = Read-WindowsEvents -EventId 1116, 1117 -LogName $logName -StartTime $StartTime

        foreach ($evt in $events) {
            $description = switch ($evt.Id) {
                1116 { 'Malware Detected' }
                1117 { 'Malware Action Taken' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Critical'
            $props['EventDescription'] = $description
            # Defender events typically have: [0]ThreatName [1]Severity [2]Category
            # [3]Path [4]Process [5]User [6]Action
            $props['ThreatName'] = "$($evt.Properties[0].Value)"
            $props['ThreatSeverity'] = "$($evt.Properties[1].Value)"
            $props['Category']   = "$($evt.Properties[2].Value)"
            $props['FilePath']   = "$($evt.Properties[3].Value)"
            $props['Process']    = "$($evt.Properties[4].Value)"
            $props['DetectedBy'] = "$($evt.Properties[5].Value)"

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*' -and
            $_.Exception.Message -notlike '*not found*') {
            Write-EMLog -Message "Get-DefenderEvents (malware): $($_.Exception.Message)" -Level Error
        }
    }

    # Protection disabled events
    try {
        $events = Read-WindowsEvents -EventId 5001, 5010, 5012 -LogName $logName -StartTime $StartTime

        foreach ($evt in $events) {
            $description = switch ($evt.Id) {
                5001 { 'Real-Time Protection DISABLED' }
                5010 { 'Malware Scanning DISABLED' }
                5012 { 'Virus Scanning DISABLED' }
            }

            $props = New-EventProperties -SessionId $sessionId -EventType 'Alert' -Severity 'Critical'
            $props['EventDescription'] = $description

            Send-LogAnalyticsConnectEvents `
                -eventName "$($evt.Id) $description" -Properties $props -sendEvent $evt
        }
    }
    catch {
        if ($_.Exception.Message -notlike '*No events were found*' -and
            $_.Exception.Message -notlike '*not found*') {
            Write-EMLog -Message "Get-DefenderEvents (protection): $($_.Exception.Message)" -Level Error
        }
    }
}
