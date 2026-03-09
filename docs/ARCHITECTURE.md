# Architecture

EventMonitor.Windows internal architecture and data flow documentation.

---

## High-Level Architecture

```
                        ┌─────────────────────────────────────┐
                        │     Windows Event Logs              │
                        │  Security │ System │ OpenSSH │ RDP  │
                        │  PowerShell/Operational             │
                        └──────────────┬──────────────────────┘
                                       │
                          EventLogWatcher (real-time, zero-polling)
                                       │
                        ┌──────────────▼──────────────────────┐
                        │   Start-EventMonitorService.ps1     │
                        │   (Long-running entry point)        │
                        │                                     │
                        │   ┌─────────────┐  ┌──────────────┐ │
                        │   │ Watcher:    │  │ Watcher:     │ │
                        │   │ Security    │  │ System       │ │
                        │   │ (30 IDs)    │  │ (9 IDs)      │ │
                        │   └──────┬──────┘  └──────┬───────┘ │
                        │          │                │         │
                        │   ┌──────┴──┐  ┌──────────┴───────┐ │
                        │   │ RDP     │  │ PowerShell/SSH   │ │
                        │   │ Watcher │  │ Watchers         │ │
                        │   └──────┬──┘  └──────────┬───────┘ │
                        └──────────┼────────────────┼─────────┘
                                   │                │
                        ┌──────────▼────────────────▼─────────┐
                        │     Event Callback Dispatcher       │
                        │  Maps EventID -> severity/type      │
                        │  Enriches with EventRecord metadata │
                        └──────────────┬──────────────────────┘
                                       │
                        ┌──────────────▼──────────────────────┐
                        │     Telemetry Sink Dispatcher       │
                        │  Invoke-TelemetryDispatch           │
                        │                                     │
                        │  Registered sinks (fan-out):        │
                        │  ├── AppInsights (built-in)         │
                        │  ├── EventJournal (JSONL files)     │
                        │  └── Custom sinks (webhook, etc.)   │
                        └─────────────────────────────────────┘
                                       │
                        ┌──────────────▼───────────────────────┐
                        │     Watchdog Timer (every 30 min)    │
                        │  1. Health check & auto-repair       │
                        │  2. Catch-up sweep (if repair needed)│
                        │  3. Flush telemetry                  │
                        │  4. Report health metrics            │
                        │  5. Clean up old log/journal files   │
                        └──────────────────────────────────────┘
```

## Module Loading

`WindowsEventMonitor.psm1` dot-sources files in dependency order:

1. **Core infrastructure**: `TelemetryClient.ps1`, `EventDispatch.ps1`, `SessionDetection.ps1`
2. **Configuration**: `Core/MonitoringConfig.ps1`, `Core/EventJournal.ps1`
3. **Event processors**: `EventProcessors/EventProcessorBase.ps1` + 14 processor files
4. **Event-driven infra**: `Core/EventWatcher.ps1`, `Core/WatchdogService.ps1`
5. **Orchestration**: `TaskManagement.ps1`
6. **Startup**: Restores saved config, registers journal sink if enabled

## Entry Points

| Script | Purpose | Lifetime |
|--------|---------|----------|
| `Start-EventMonitorService.ps1` | **Primary**. Event-driven monitoring with watchdog. | Long-running (service) |
| `Invoke-EventMonitor` | Module function. Diagnostic one-shot scan of recent events. | Run once and return |

## Core Components

### TelemetryClient.ps1 — Pluggable Sink Dispatcher

Events flow through `TrackEvent` / `TrackTrace` / `TrackException` which dispatch to ALL registered sinks:

- **AppInsights sink**: Auto-registered when connection string file exists
- **EventJournal sink**: Writes filtered events to daily JSONL files
- **Custom sinks**: Add via `Register-TelemetrySink -Name 'X' -OnDispatch { ... }`

No function takes a connection string parameter — sinks are configured once at startup.

### Core/EventWatcher.ps1 — Real-Time Event Subscriptions

Uses `System.Diagnostics.Eventing.Reader.EventLogWatcher` for zero-polling event delivery:
- One watcher per event log (Security, System, RDP, PowerShell, SSH)
- XPath queries filter to only monitored event IDs
- Every callback is try/catch wrapped — a bad event never crashes a watcher
- Health metrics tracked per watcher (events processed, errors, uptime)

### Core/WatchdogService.ps1 — Self-Healing Health Monitor

Runs on a `System.Timers.Timer` (default: every 30 minutes):
1. Checks all watchers for errors or disabled state
2. Auto-restarts broken watchers
3. Runs catch-up sweep **only if a watcher was repaired** (prevents duplicates)
4. Flushes telemetry buffer
5. Reports health metrics via telemetry
6. Cleans up old log/journal files beyond retention period

### Core/MonitoringConfig.ps1 — Monitoring Levels & Event Groups

**15 event groups** organized into 4 preset levels:

| Level | Groups Enabled | Use Case |
|-------|---------------|----------|
| **Minimum** | Logon, Logoff, SSH, RDP | Low resource, basic tracking |
| **Standard** | + Account, Group, Audit, Persistence, PersistenceSystem, SystemHealth | Recommended |
| **High** | All 15 groups + event journal | Full security monitoring |
| **Custom** | User-selected groups | Tailored coverage |

Config persisted to `Telemetry/MonitoringConfig.json` — survives restarts.

### Core/EventJournal.ps1 — Structured Event Log Files

Optional JSONL file capture registered as a telemetry sink:
- Files: `Telemetry/Journal/EventJournal-YYYY-MM-DD.jsonl`
- Severity-filtered (configurable minimum)
- Compact JSON with key fields only
- Designed for AI tools and SIEM that don't have Windows Event Log access
- Auto-cleaned by watchdog after retention period

## EventProcessors (14 files)

Each processor follows the same pattern:
- Accepts `$sessionId`, `$StartTime`, optionally `$User`
- Calls `Read-WindowsEvents` (pushes `StartTime` to Windows API)
- Builds properties via `New-EventProperties` (includes severity)
- Dispatches via `Send-LogAnalyticsConnectEvents` (enriches with EventRecord metadata)

## Scheduled Task Configuration

`Register-EventMonitor` creates a scheduled task with:
- **Trigger**: `AtStartup` (starts at boot)
- **Auto-restart**: `RestartInterval` = 1 minute, `RestartCount` = 3
- **Runs as**: `NT AUTHORITY\SYSTEM` at Highest RunLevel
- **No time limit**: `ExecutionTimeLimit` = 0 (runs indefinitely)
- **No idle stop**: `DontStopOnIdleEnd` = true
- **Single instance**: `MultipleInstances` = IgnoreNew

## Security Model

- Connection string stored in `Telemetry/LogAnalyticsConString.txt` (NTFS ACLs)
- Connection string never logged, never in process arguments
- `#Requires -RunAsAdministrator` on entry scripts
- All telemetry sink callbacks are isolated — one failing sink never blocks others
