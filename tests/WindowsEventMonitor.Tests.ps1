#Requires -Module Pester

<#
.SYNOPSIS
    Comprehensive Pester 5 test suite for EventMonitor.Windows.
.DESCRIPTION
    Tests module structure, function exports, configuration, telemetry sinks,
    event processors, and security checks. All Windows-specific commands are
    mocked — safe to run on any machine and in CI/CD.

    Run via: .\Run-Tests.ps1
#>

BeforeAll {
    $env:WINDOWSEVENTMONITOR_TESTING = '1'
    $script:manifestPath = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'EventMonitor.Windows.psd1'
}

# ═══════════════════════════════════════════════════════════════════════════════
# Module Manifest Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Module Manifest' {
    It 'Has a valid module manifest' {
        { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Manifest specifies correct RootModule' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.RootModule | Should -Be '.\EventMonitor\WindowsEventMonitor.psm1'
    }

    It 'Requires PowerShell 7.4' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.PowerShellVersion | Should -Be '7.4'
    }

    It 'Targets PowerShell Core edition' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.CompatiblePSEditions | Should -Contain 'Core'
    }

    It 'Does not export variables' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.VariablesToExport | Should -Be @()
    }

    It 'ModuleVersion is valid semver' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.ModuleVersion | Should -Match '^\d+\.\d+\.\d+$'
    }

    It 'GUID is a valid GUID' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        { [guid]::Parse($m.GUID) } | Should -Not -Throw
    }

    It 'Has a non-empty Description' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.Description | Should -Not -BeNullOrEmpty
    }

    It 'Has ProjectUri pointing to GitHub' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.PrivateData.PSData.ProjectUri | Should -BeLike '*github.com*'
    }

    It 'Has LicenseUri' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.PrivateData.PSData.LicenseUri | Should -Not -BeNullOrEmpty
    }

    It 'Has Tags for PSGallery discovery' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.PrivateData.PSData.Tags.Count | Should -BeGreaterThan 0
    }

    It 'Has ReleaseNotes' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.PrivateData.PSData.ReleaseNotes | Should -Not -BeNullOrEmpty
    }

    It 'Author is Rakesh Navale' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.Author | Should -Be 'Rakesh Navale'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Exported Functions Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Exported Functions' {
    It 'Exports exactly 21 functions' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $m.FunctionsToExport.Count | Should -Be 21
    }

    It 'Exports all expected functions' {
        $m = Import-PowerShellDataFile -Path $manifestPath
        $expected = @(
            'Register-EventMonitor', 'Unregister-EventMonitor', 'Uninstall-EventMonitor',
            'Start-EventMonitor', 'Stop-EventMonitor', 'Enable-EventMonitor',
            'Disable-EventMonitor', 'Get-EventMonitor',
            'Invoke-EventMonitor', 'Get-WindowsEventsAndSessions',
            'Get-MonitoredEventCategories',
            'Set-MonitoringLevel', 'Get-MonitoringConfig', 'Get-EventGroups',
            'Set-EventJournal', 'Set-EMLogLevel', 'Get-EventHistory',
            'Show-EventMonitorHelp',
            'Register-TelemetrySink', 'Unregister-TelemetrySink', 'Get-TelemetrySinks'
        )
        foreach ($fn in $expected) {
            $m.FunctionsToExport | Should -Contain $fn -Because "$fn should be exported"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# File Structure Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Module File Structure' {
    It 'Root module exists' {
        Join-Path $PSScriptRoot '..' 'EventMonitor' 'WindowsEventMonitor.psm1' | Should -Exist
    }

    It 'All core files exist' {
        $files = @('TelemetryClient.ps1', 'EventDispatch.ps1', 'SessionDetection.ps1', 'TaskManagement.ps1')
        foreach ($f in $files) {
            Join-Path $PSScriptRoot '..' 'EventMonitor' $f | Should -Exist -Because "$f is required"
        }
    }

    It 'All Core infrastructure files exist' {
        $files = @('EventWatcher.ps1', 'WatchdogService.ps1', 'MonitoringConfig.ps1',
                   'EventJournal.ps1', 'EventHistory.ps1', 'ModuleHelp.ps1')
        foreach ($f in $files) {
            Join-Path $PSScriptRoot '..' 'EventMonitor' 'Core' $f | Should -Exist -Because "$f is required"
        }
    }

    It 'All EventProcessor files exist' {
        $files = @('EventProcessorBase.ps1', 'LogonEvents.ps1', 'LogoffEvents.ps1',
                   'SSHEvents.ps1', 'RDPEvents.ps1', 'AccountEvents.ps1', 'GroupEvents.ps1',
                   'PrivilegeEvents.ps1', 'ProcessEvents.ps1', 'PersistenceEvents.ps1',
                   'AuditEvents.ps1', 'PowerShellEvents.ps1', 'NetworkShareEvents.ps1',
                   'NetworkEvents.ps1', 'SystemHealthEvents.ps1',
                   'WinRMEvents.ps1', 'DefenderEvents.ps1')
        foreach ($f in $files) {
            Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventProcessors' $f | Should -Exist -Because "$f is required"
        }
    }

    It 'Start-EventMonitorService.ps1 entry point exists' {
        Join-Path $PSScriptRoot '..' 'EventMonitor' 'Start-EventMonitorService.ps1' | Should -Exist
    }

    It 'Application Insights DLL exists' {
        Join-Path $PSScriptRoot '..' 'EventMonitor' 'Telemetry' 'Microsoft.ApplicationInsights.dll' | Should -Exist
    }

    It 'All source files parse without errors' {
        $files = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'EventMonitor') -Include '*.ps1','*.psm1' -Recurse |
            Where-Object { $_.Name -notin 'LogonIndicators.ps1','LogoffIndicators.ps1','MiscellaneousEvents.ps1' }
        foreach ($file in $files) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0 -Because "$($file.Name) should parse without errors"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Monitoring Configuration Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Monitoring Configuration' {
    BeforeAll {
        # Dot-source the config file for isolated testing
        $script:MonitoringConfig = @{ Level='Standard'; EnabledGroups=@(); LogLevel='Info';
            JournalEnabled=$true; JournalMinSeverity='Info'; RetentionDays=30 }
        $script:ConfigDir = Join-Path $TestDrive 'Config'
        $script:LogDir = Join-Path $TestDrive 'Logs'
        $script:JournalDir = Join-Path $TestDrive 'Journal'
        $script:SecretsDir = Join-Path $TestDrive 'Secrets'
        $script:DataRoot = $TestDrive
        $script:LogFilePath = Join-Path $script:LogDir 'test.log'
        $script:TelemetrySinks = [ordered]@{}

        New-Item -Path $script:ConfigDir, $script:LogDir, $script:JournalDir, $script:SecretsDir -ItemType Directory -Force | Out-Null

        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TelemetryClient.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventDispatch.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'Core' 'MonitoringConfig.ps1')
    }

    It 'Get-MonitoringConfig returns correct structure' {
        $cfg = Get-MonitoringConfig
        $cfg.Level | Should -Not -BeNullOrEmpty
        $cfg.AvailableGroups.Count | Should -BeGreaterThan 10
    }

    It 'Get-EventGroups returns 17 groups' {
        (Get-EventGroups).Count | Should -Be 17
    }

    It 'Set-MonitoringLevel -Level Minimum enables 4 groups' {
        Set-MonitoringLevel -Level Minimum
        (Get-MonitoringConfig).EnabledGroups.Count | Should -Be 4
    }

    It 'Set-MonitoringLevel -Level Standard enables 13 groups' {
        Set-MonitoringLevel -Level Standard
        (Get-MonitoringConfig).EnabledGroups.Count | Should -Be 13
    }

    It 'Set-MonitoringLevel -Level High enables all 17 groups' {
        Set-MonitoringLevel -Level High
        (Get-MonitoringConfig).EnabledGroups.Count | Should -Be 17
    }

    It 'Set-MonitoringLevel -Level Custom with valid groups works' {
        Set-MonitoringLevel -Level Custom -Groups 'Logon','SSH'
        $cfg = Get-MonitoringConfig
        $cfg.Level | Should -Be 'Custom'
        $cfg.EnabledGroups.Count | Should -Be 2
    }

    It 'Set-MonitoringLevel -Level Custom with invalid group throws' {
        { Set-MonitoringLevel -Level Custom -Groups 'FakeGroup' } | Should -Throw
    }

    It 'Set-MonitoringLevel -Level Custom without -Groups throws' {
        { Set-MonitoringLevel -Level Custom } | Should -Throw
    }

    It 'Config persists to disk' {
        Set-MonitoringLevel -Level Minimum
        $configFile = Join-Path $script:ConfigDir 'MonitoringConfig.json'
        Test-Path $configFile | Should -BeTrue
        $saved = Get-Content $configFile -Raw | ConvertFrom-Json
        $saved.Level | Should -Be 'Minimum'
    }

    It 'Config restores from disk' {
        Set-MonitoringLevel -Level High
        Restore-MonitoringConfig
        (Get-MonitoringConfig).Level | Should -Be 'High'
    }

    It 'Set-EMLogLevel changes log level' {
        Set-EMLogLevel -Level Error
        (Get-MonitoringConfig).LogLevel | Should -Be 'Error'
        Set-EMLogLevel -Level Info
    }

    It 'Set-EventJournal enables/disables journal' {
        Set-EventJournal -Enabled $false
        (Get-MonitoringConfig).JournalEnabled | Should -BeFalse
        Set-EventJournal -Enabled $true
        (Get-MonitoringConfig).JournalEnabled | Should -BeTrue
    }

    It 'Set-EventJournal configures retention' {
        Set-EventJournal -RetentionDays 14
        (Get-MonitoringConfig).RetentionDays | Should -Be 14
    }

    AfterAll {
        Set-MonitoringLevel -Level Standard
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Telemetry Sink Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Telemetry Sinks' {
    BeforeAll {
        $script:MonitoringConfig = @{ Level='Standard'; EnabledGroups=@(); LogLevel='Info';
            JournalEnabled=$false; JournalMinSeverity='Info'; RetentionDays=30 }
        $script:LogDir = Join-Path $TestDrive 'Logs'
        $script:LogFilePath = Join-Path $script:LogDir 'test.log'
        $script:TelemetrySinks = [ordered]@{}
        $script:TelemetryDllLoaded = $false
        $script:TelemetryClient = $null
        $script:TelemetryConfig = $null

        New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null

        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TelemetryClient.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventDispatch.ps1')
    }

    It 'Register-TelemetrySink adds a sink' {
        Register-TelemetrySink -Name 'TestSink' -OnDispatch { }
        (Get-TelemetrySinks).Count | Should -Be 1
    }

    It 'Get-TelemetrySinks returns registered sink' {
        $sinks = Get-TelemetrySinks
        $sinks[0].Name | Should -Be 'TestSink'
        $sinks[0].Enabled | Should -BeTrue
    }

    It 'Unregister-TelemetrySink removes a sink' {
        Unregister-TelemetrySink -Name 'TestSink'
        (Get-TelemetrySinks).Count | Should -Be 0
    }

    It 'TrackEvent dispatches to registered sink' {
        $script:testReceived = $false
        Register-TelemetrySink -Name 'DispatchTest' -OnDispatch {
            param($Type, $Name) $script:testReceived = $true
        }
        TrackEvent -Name 'TestEvent'
        $script:testReceived | Should -BeTrue
        Unregister-TelemetrySink -Name 'DispatchTest'
    }

    It 'Failing sink does not crash TrackEvent' {
        Register-TelemetrySink -Name 'FailSink' -OnDispatch { throw 'deliberate failure' }
        { TrackEvent -Name 'TestEvent' } | Should -Not -Throw
        Unregister-TelemetrySink -Name 'FailSink'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Write-EMLog Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Write-EMLog' {
    BeforeAll {
        $script:MonitoringConfig = @{ LogLevel = 'Info' }
        $script:LogDir = Join-Path $TestDrive 'LogTest'
        New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null
        $script:LogFilePath = Join-Path $script:LogDir 'test.log'

        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventDispatch.ps1')
    }

    BeforeEach {
        if (Test-Path $script:LogFilePath) { Remove-Item $script:LogFilePath }
    }

    It 'Writes Info level entry' {
        Write-EMLog -Message 'test info' -Level Info
        Get-Content $script:LogFilePath | Should -Match '\[Info\] test info'
    }

    It 'Writes Warning level entry' {
        Write-EMLog -Message 'test warn' -Level Warning
        Get-Content $script:LogFilePath | Should -Match '\[Warning\] test warn'
    }

    It 'Writes Error level entry' {
        Write-EMLog -Message 'test error' -Level Error
        Get-Content $script:LogFilePath | Should -Match '\[Error\] test error'
    }

    It 'Respects log level filtering' {
        $script:MonitoringConfig.LogLevel = 'Error'
        Write-EMLog -Message 'should be skipped' -Level Info
        Test-Path $script:LogFilePath | Should -BeFalse
        $script:MonitoringConfig.LogLevel = 'Info'
    }

    It 'Uses ISO 8601 timestamp format' {
        Write-EMLog -Message 'timestamp test'
        Get-Content $script:LogFilePath | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# ConvertTo-IdleMinutes Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'ConvertTo-IdleMinutes' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'SessionDetection.ps1')
    }

    It 'Returns 0 for dot (active)' { ConvertTo-IdleMinutes -IdleString '.' | Should -Be 0 }
    It 'Returns 0 for none' { ConvertTo-IdleMinutes -IdleString 'none' | Should -Be 0 }
    It 'Parses raw minutes' { ConvertTo-IdleMinutes -IdleString '45' | Should -Be 45 }
    It 'Parses hours:minutes' { ConvertTo-IdleMinutes -IdleString '2:30' | Should -Be 150 }
    It 'Parses days+hours:minutes' { ConvertTo-IdleMinutes -IdleString '1+3:15' | Should -Be 1635 }
    It 'Returns 0 for unrecognized' { ConvertTo-IdleMinutes -IdleString 'unknown' | Should -Be 0 }
}

# ═══════════════════════════════════════════════════════════════════════════════
# EventProcessorBase Helper Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'EventProcessorBase Helpers' {
    BeforeAll {
        $script:MonitoringConfig = @{ LogLevel = 'Error' }
        $script:LogDir = Join-Path $TestDrive 'Logs'
        $script:LogFilePath = Join-Path $script:LogDir 'test.log'
        New-Item -Path $script:LogDir -ItemType Directory -Force | Out-Null

        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventDispatch.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventProcessors' 'EventProcessorBase.ps1')
    }

    It 'New-EventProperties creates dictionary with SessionId and EventType' {
        $p = New-EventProperties -SessionId 'test-sess' -EventType 'Alert' -Severity 'High'
        $p | Should -BeOfType 'System.Collections.Generic.Dictionary[string,string]'
        $p['SessionId'] | Should -Be 'test-sess'
        $p['EventType'] | Should -Be 'Alert'
        $p['Severity'] | Should -Be 'High'
    }

    It 'New-ErrorProperties creates dictionary with FunctionName' {
        $p = New-ErrorProperties -SessionId 'sess1' -FunctionName 'TestFunc' -User 'testuser'
        $p['Function'] | Should -Be 'TestFunc'
        $p['User'] | Should -Be 'testuser'
    }

    It 'Get-MonitoredEventCategories returns 16 categories' {
        (Get-MonitoredEventCategories).Count | Should -Be 16
    }

    It 'Every category has Events array' {
        $categories = Get-MonitoredEventCategories
        foreach ($cat in $categories) {
            $cat.Events | Should -Not -BeNullOrEmpty -Because "$($cat.Category) should have events"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Task Management Mocked Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Task Management Functions (Mocked)' {
    BeforeAll {
        $script:EventLogType = @{ Security='Security'; System='System'; Application='Application';
            Setup='Setup'; OpenSSHOperational='OpenSSH/Operational' }
        $script:MonitoringConfig = @{ Level='Standard'; EnabledGroups=@('Logon','Logoff');
            LogLevel='Error'; JournalEnabled=$false; JournalMinSeverity='Info'; RetentionDays=30 }
        $script:DataRoot = $TestDrive
        $script:LogDir = Join-Path $TestDrive 'Logs'
        $script:JournalDir = Join-Path $TestDrive 'Journal'
        $script:ConfigDir = Join-Path $TestDrive 'Config'
        $script:SecretsDir = Join-Path $TestDrive 'Secrets'
        $script:LogFilePath = Join-Path $script:LogDir 'test.log'
        $script:TelemetrySinks = [ordered]@{}
        $script:TelemetryDllLoaded = $false
        $script:TelemetryClient = $null
        $script:TelemetryConfig = $null

        New-Item -Path $script:LogDir, $script:JournalDir, $script:ConfigDir, $script:SecretsDir -ItemType Directory -Force | Out-Null

        # Dot-source all needed files
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TelemetryClient.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventDispatch.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'SessionDetection.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'Core' 'MonitoringConfig.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'Core' 'EventJournal.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventProcessors' 'EventProcessorBase.ps1')
        Get-ChildItem (Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventProcessors') -Filter '*.ps1' |
            Where-Object Name -ne 'EventProcessorBase.ps1' | ForEach-Object { . $_.FullName }
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'Core' 'EventWatcher.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'Core' 'WatchdogService.ps1')
        . (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TaskManagement.ps1')

        # Mock ALL ScheduledTask cmdlets at Describe level
        Mock Start-ScheduledTask { }
        Mock Stop-ScheduledTask { }
        Mock Enable-ScheduledTask { }
        Mock Disable-ScheduledTask { }
        Mock Get-ScheduledTask { [PSCustomObject]@{ TaskName='WinEventMonitor'; State='Ready' } }
        Mock Unregister-ScheduledTask { }
    }

    It 'Start-EventMonitor calls Start-ScheduledTask' {
        Start-EventMonitor
        Should -Invoke Start-ScheduledTask -Times 1
    }

    It 'Stop-EventMonitor calls Stop-ScheduledTask' {
        Stop-EventMonitor
        Should -Invoke Stop-ScheduledTask -Times 1
    }

    It 'Enable-EventMonitor calls Enable-ScheduledTask' {
        Enable-EventMonitor
        Should -Invoke Enable-ScheduledTask -Times 1
    }

    It 'Disable-EventMonitor calls Disable-ScheduledTask' {
        Disable-EventMonitor
        Should -Invoke Disable-ScheduledTask -Times 1
    }

    It 'Get-EventMonitor returns task object' {
        $result = Get-EventMonitor
        $result.TaskName | Should -Be 'WinEventMonitor'
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# Security Tests
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'Security Checks' {
    It 'No hardcoded instrumentation keys in source' {
        $files = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'EventMonitor') -Include '*.ps1','*.psm1' -Recurse
        foreach ($file in $files) {
            $content = Get-Content -Raw $file.FullName
            $content | Should -Not -Match 'InstrumentationKey=[0-9a-f-]{30,}' -Because "$($file.Name) must not contain hardcoded keys"
        }
    }

    It 'Connection string is NOT passed as command-line argument' {
        $content = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TaskManagement.ps1')
        $funcBody = [regex]::Match($content, 'function Register-EventMonitor.*?(?=\nfunction\s|\z)',
            [System.Text.RegularExpressions.RegexOptions]::Singleline).Value
        $funcBody | Should -Not -Match 'taskArgument.*logAnalyticsConString'
    }

    It 'No -ExecutionPolicy Bypass in scheduled task' {
        $content = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TaskManagement.ps1')
        $content | Should -Not -Match 'ExecutionPolicy Bypass'
    }

    It 'Start-EventMonitorService requires RunAsAdministrator' {
        $content = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'EventMonitor' 'Start-EventMonitorService.ps1')
        $content | Should -Match '#Requires -RunAsAdministrator'
    }

    It 'TrackEvent catch blocks do NOT call TrackException' {
        $content = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'EventMonitor' 'TelemetryClient.ps1')
        $funcBody = [regex]::Match($content, 'function TrackEvent.*?(?=function\s|\z)',
            [System.Text.RegularExpressions.RegexOptions]::Singleline).Value
        $catchBlock = [regex]::Match($funcBody, 'catch\s*\{.*?\}',
            [System.Text.RegularExpressions.RegexOptions]::Singleline).Value
        $codeOnly = ($catchBlock -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $codeOnly | Should -Not -Match 'TrackException'
    }

    It 'Event processors do not redefine $EventLogType' {
        $processorDir = Join-Path $PSScriptRoot '..' 'EventMonitor' 'EventProcessors'
        Get-ChildItem -Path $processorDir -Filter '*.ps1' | ForEach-Object {
            $content = Get-Content -Raw $_.FullName
            $content | Should -Not -Match '\$EventLogType\s*=' -Because "$($_.Name) should not redefine EventLogType"
        }
    }

    It 'No source file uses Write-Host except help and UI functions' {
        $files = Get-ChildItem -Path (Join-Path $PSScriptRoot '..' 'EventMonitor') -Include '*.ps1' -Recurse |
            Where-Object { $_.Name -notin 'ModuleHelp.ps1','EventHistory.ps1','TaskManagement.ps1','LogonIndicators.ps1','LogoffIndicators.ps1','MiscellaneousEvents.ps1' }
        foreach ($file in $files) {
            $content = Get-Content -Raw $file.FullName
            $content | Should -Not -Match '\bWrite-Host\b' -Because "$($file.Name) should use Write-EMLog"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PSGallery Release Readiness
# ═══════════════════════════════════════════════════════════════════════════════

Describe 'PSGallery Release Readiness' {
    It 'LICENSE file exists' {
        Join-Path $PSScriptRoot '..' 'LICENSE' | Should -Exist
    }

    It 'README.md exists' {
        Join-Path $PSScriptRoot '..' 'README.md' | Should -Exist
    }

    It 'CHANGELOG.md exists and has current version' {
        $path = Join-Path $PSScriptRoot '..' 'CHANGELOG.md'
        $path | Should -Exist
        $m = Import-PowerShellDataFile -Path $manifestPath
        $changelog = Get-Content -Raw $path
        $changelog | Should -Match "\[$([regex]::Escape($m.ModuleVersion))\]"
    }

    It 'CHANGELOG follows Keep a Changelog format' {
        $changelog = Get-Content -Raw (Join-Path $PSScriptRoot '..' 'CHANGELOG.md')
        $changelog | Should -Match 'keepachangelog\.com'
        $changelog | Should -Match 'semver\.org'
        $changelog | Should -Match '\[Unreleased\]'
    }
}

AfterAll {
    Remove-Item Env:\WINDOWSEVENTMONITOR_TESTING -ErrorAction SilentlyContinue
}
