# Architecture

## High-Level Data Flow

```
┌────────────────────────────────────────────────────────────────────┐
│  Windows Event Logs                                                │
│  ┌────────────┐ ┌────────┐ ┌─────────┐ ┌─────┐ ┌──────┐ ┌───────┐  │
│  │  Security  │ │ System │ │ OpenSSH │ │ RDP │ │ PS   │ │ WinRM │  │
│  └──────┬─────┘ └───┬────┘ └────┬────┘ └──┬──┘ └──┬───┘ └───┬───┘  │
└─────────┼────────────┼──────────┼─────────┼───────┼──────────┼─────┘
          │            │          │         │       │          │
          ▼            ▼          ▼         ▼       ▼          ▼
┌────────────────────────────────────────────────────────────────────┐
│  EventLogWatcher Subscriptions (real-time, zero-polling)           │
│  One watcher per log × XPath filter for enabled event IDs          │
└────────────────────────────┬───────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────────┐
│  Event Processors (17 groups)                                      │
│  ┌────────┐ ┌────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ Logon  │ │ SSH    │ │ Defender │ │ Persist  │ │ Audit    │ ...  │
│  └───┬────┘ └───┬────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘      │
└──────┼──────────┼───────────┼────────────┼────────────┼────────────┘
       │          │           │            │            │
       ▼          ▼           ▼            ▼            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Telemetry Dispatch                                                  │
│  ┌──────────────────┐  ┌───────────────┐  ┌───────────────────────┐  │
│  │ App Insights     │  │ JSONL Journal │  │ Custom Sinks          │  │
│  │ (cloud)          │  │ (local files) │  │ (webhook/email/SIEM)  │  │
│  └──────────────────┘  └───────────────┘  └───────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
          ▲
┌─────────┴────────────────────────────────────────────────────────────┐
│  Watchdog Service (every 30 min)                                     │
│  • Health check each watcher                                         │
│  • Auto-restart crashed watchers                                     │
│  • Catch-up sweep for missed events                                  │
│  • Report health telemetry                                           │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Module Loading Order

The root module `WindowsEventMonitor.psm1` dot-sources files in strict dependency order:

```
Phase 1 — Core Infrastructure
  ├── TelemetryClient.ps1        Pluggable sink dispatcher, AI client
  ├── EventDispatch.ps1          Write-EMLog, Send-LogAnalyticsConnectEvents
  └── SessionDetection.ps1       quser/netstat user enumeration

Phase 2 — Configuration
  ├── Core/MonitoringConfig.ps1  17 event groups, 4 levels, persistence
  └── Core/EventJournal.ps1      JSONL file sink

Phase 3 — Event Processors
  ├── EventProcessors/EventProcessorBase.ps1  Common base + registry
  ├── EventProcessors/LogonEvents.ps1
  ├── EventProcessors/LogoffEvents.ps1
  ├── EventProcessors/SSHEvents.ps1
  ├── EventProcessors/RDPEvents.ps1
  ├── EventProcessors/AccountEvents.ps1
  ├── EventProcessors/GroupEvents.ps1
  ├── EventProcessors/PrivilegeEvents.ps1
  ├── EventProcessors/ProcessEvents.ps1
  ├── EventProcessors/PersistenceEvents.ps1
  ├── EventProcessors/AuditEvents.ps1
  ├── EventProcessors/PowerShellEvents.ps1
  ├── EventProcessors/NetworkShareEvents.ps1
  ├── EventProcessors/NetworkEvents.ps1
  ├── EventProcessors/SystemHealthEvents.ps1
  ├── EventProcessors/WinRMEvents.ps1
  └── EventProcessors/DefenderEvents.ps1

Phase 4 — Event-Driven Infrastructure
  ├── Core/EventWatcher.ps1      EventLogWatcher lifecycle
  └── Core/WatchdogService.ps1   Health checks, auto-repair

Phase 5 — Orchestration
  ├── TaskManagement.ps1         Scheduled task CRUD
  ├── Invoke-EventMonitor.ps1    One-shot diagnostic scan
  ├── LogonIndicators.ps1        Logon event readers
  ├── LogoffIndicators.ps1       Logoff event readers
  └── MiscellaneousEvents.ps1    Dynamic event tracking

Phase 6 — Help & History
  ├── Core/ModuleHelp.ps1        Show-EventMonitorHelp
  └── Core/EventHistory.ps1      Get-EventHistory
```

---

## Scheduled Task Configuration

The registered scheduled task runs under SYSTEM with these settings:

| Setting | Value |
|:--------|:------|
| **Principal** | `NT AUTHORITY\SYSTEM` |
| **Run Level** | Highest |
| **Trigger** | AtStartup |
| **Execution Time Limit** | Unlimited (0) |
| **Auto-Restart** | 1 minute interval, 3 retries |
| **Action** | `pwsh.exe -NoProfile -WindowStyle Hidden -File Start-EventMonitorService.ps1` |

The task survives reboots and automatically restarts on failure.

---

## Key Design Decisions

### Why EventLogWatcher Instead of Polling?

| Aspect | EventLogWatcher | Polling (Get-WinEvent) |
|:-------|:---------------|:----------------------|
| **Latency** | Sub-second | Depends on interval |
| **CPU** | Zero when idle | Constant |
| **Missed Events** | None (OS-guaranteed delivery) | Possible between polls |
| **Scalability** | Handles high event rates | Degrades with volume |

### Why Dot-Sourcing Instead of Nested Modules?

- **Shared state**: All functions share `$script:` variables without cross-module complexity
- **No circular dependencies**: Dot-sourcing in order eliminates `Import-Module` cycles
- **Simpler debugging**: One module scope, one breakpoint context

### Why a Singleton TelemetryClient?

- Application Insights SDK recommends one `TelemetryClient` per process
- Module-scoped `$script:TelemetryClient` prevents DLL reload issues
- Lazy initialization: client is only created when first event triggers

### Data Persistence

All persistent data lives in `C:\ProgramData\WindowsEventMonitor\`:

```
C:\ProgramData\WindowsEventMonitor\
├── Logs\                    Operational logs (Write-EMLog)
├── Config\                  Saved monitoring configuration
└── Journal\                 JSONL event files (if enabled)
```

This directory survives module updates and is ACL-protected when a connection string file is present.

---

## File Structure

```
EventMonitor.Windows/
├── EventMonitor.Windows.psd1              Module manifest
├── EventMonitor/
│   ├── WindowsEventMonitor.psm1           Root module (dot-sources everything)
│   ├── TelemetryClient.ps1                Sink dispatcher + AI client
│   ├── EventDispatch.ps1                  Logging + event dispatch
│   ├── SessionDetection.ps1               User session enumeration
│   ├── TaskManagement.ps1                 Scheduled task lifecycle
│   ├── Invoke-EventMonitor.ps1            One-shot scan
│   ├── LogonIndicators.ps1                Logon event readers
│   ├── LogoffIndicators.ps1               Logoff event readers
│   ├── MiscellaneousEvents.ps1            Dynamic event tracking
│   ├── Start-EventMonitorService.ps1      Service entry point
│   ├── Core/
│   │   ├── EventHistory.ps1               Event journal queries
│   │   ├── EventJournal.ps1               JSONL file capture
│   │   ├── EventWatcher.ps1               EventLogWatcher management
│   │   ├── ModuleHelp.ps1                 Help display
│   │   ├── MonitoringConfig.ps1           Groups, levels, persistence
│   │   └── WatchdogService.ps1            Health + auto-repair
│   ├── EventProcessors/
│   │   ├── EventProcessorBase.ps1         Base class + registry
│   │   ├── AccountEvents.ps1
│   │   ├── AuditEvents.ps1
│   │   ├── DefenderEvents.ps1
│   │   ├── GroupEvents.ps1
│   │   ├── LogoffEvents.ps1
│   │   ├── LogonEvents.ps1
│   │   ├── NetworkEvents.ps1
│   │   ├── NetworkShareEvents.ps1
│   │   ├── PersistenceEvents.ps1
│   │   ├── PowerShellEvents.ps1
│   │   ├── PrivilegeEvents.ps1
│   │   ├── ProcessEvents.ps1
│   │   ├── RDPEvents.ps1
│   │   ├── SSHEvents.ps1
│   │   ├── SystemHealthEvents.ps1
│   │   └── WinRMEvents.ps1
│   └── Telemetry/
│       ├── Microsoft.ApplicationInsights.dll
│       └── MonitoringConfig.json
├── tests/
│   └── WindowsEventMonitor.Tests.ps1      54 Pester 5 tests
├── Examples/
│   └── Monitor-WindowsEvents.ps1
├── docs/
│   ├── ARCHITECTURE.md
│   └── SECURITY-DESIGN.md
└── .github/workflows/
    ├── release.yml                        CI/CD pipeline
    └── bump-version.yml                   Version management
```

---

**Next:** [Event Groups Reference](Event-Groups-Reference) · [Troubleshooting](Troubleshooting)
