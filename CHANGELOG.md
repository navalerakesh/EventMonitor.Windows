# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-03-08
- Auto release creation 

## [1.0.2] - 2026-03-08
- Telemetry input and version fix

## [1.0.1] - 2026-03-08

### Added
- **Event-driven architecture** — real-time event monitoring via `EventLogWatcher` (zero polling)
- **Self-healing watchdog** — auto-restarts failed watchers, catch-up sweep, health telemetry
- **14 modular event processors** in `EventProcessors/` covering 40+ event IDs across 15 groups
- **Monitoring levels** — `Minimum`, `Standard`, `High`, `Custom` with preset event group selection
- **Pluggable telemetry sinks** — `Register-TelemetrySink` for webhooks, SIEM, email, or custom destinations
- **Event journal** — optional JSONL file capture for AI tools/SIEM without Event Log access
- **Configurable log level** — `Set-EMLogLevel` (Error/Warning/Info/Debug), default Warning
- **RDP session events** (21, 23, 24, 25) from TerminalServices-LocalSessionManager log
- **Firewall/network events** (4946-4948 rule changes, 5152/5157 blocked connections)
- **Failed logon detection** (4625) — brute force attack detection
- **Account management** (4720-4726) — account creation, deletion, password changes
- **Group changes** (4732, 4733) — privilege escalation detection
- **Privilege use** (4672) — admin logon detection
- **Process tracking** (4688, 4689) — process creation/termination with command line
- **Persistence detection** (4697, 4698, 4702, 7045) — service/task installation
- **Audit tampering** (1102, 4719) — log clearing, audit policy changes
- **PowerShell** (4104) — script block logging
- `Start-EventMonitorService.ps1` — event-driven entry point (replaces polling)
- `Invoke-EventMonitor` — exported module function for diagnostic one-shot scan
- `Read-WindowsEvents` helper with `StartTime` in FilterHashtable for API-level filtering
- `Set-MonitoringLevel`, `Get-MonitoringConfig`, `Get-EventGroups` — configuration management
- `Set-EventJournal` — JSONL event journal configuration
- `Register-TelemetrySink`, `Unregister-TelemetrySink`, `Get-TelemetrySinks` — sink management
- `Get-MonitoredEventCategories` — lists all events with severity
- `Flush-Telemetry` — batched telemetry dispatch
- `Core/` directory: `EventWatcher.ps1`, `WatchdogService.ps1`, `MonitoringConfig.ps1`, `EventJournal.ps1`
- Config persistence to `MonitoringConfig.json` — survives restarts
- Log file auto-cleanup via watchdog (configurable retention days)
- `Bump-Version.ps1` + GitHub Actions workflow for automated version bumping
- Application Insights DLL 3.0.0 (net9.0, 122 KB)
- Pester 5 test suite, GitHub Actions CI/CD (lint, test, publish)

### Security
- Connection string stored in file, never exposed in process arguments or logs
- No hardcoded instrumentation keys in source
- Telemetry sink callbacks are isolated — one failing sink never blocks others
