# EventMonitor.Windows

<div align="center">

**Real-time Windows security event monitoring with zero-polling architecture**

[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/EventMonitor.Windows?label=PSGallery&color=blue)](https://www.powershellgallery.com/packages/EventMonitor.Windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/navalerakesh/EventMonitor.Windows/blob/main/LICENSE)
[![PowerShell 7.4+](https://img.shields.io/badge/PowerShell-7.4%2B-blue)](https://github.com/PowerShell/PowerShell)

</div>

---

## What Is EventMonitor.Windows?

EventMonitor.Windows is a PowerShell module that provides **instant, event-driven detection** of 40+ Windows security events across 17 categories. It uses native `EventLogWatcher` APIs — **no polling, no CPU waste** — with a self-healing watchdog and pluggable telemetry sinks.

```
Windows Event Logs ──▶ EventLogWatcher (real-time) ──▶ Telemetry Sinks
                                                          ├─ Application Insights
                                                          ├─ JSONL Event Journal
                                                          └─ Custom (webhook, SIEM, email...)
```

## Key Features

| Feature | Description |
|:--------|:------------|
| **Zero-Polling** | Uses OS-level `EventLogWatcher` for sub-second event delivery |
| **17 Event Groups** | Logon, Logoff, SSH, RDP, Defender, persistence, audit tampering, and more |
| **Self-Healing** | Watchdog auto-restarts crashed watchers, runs catch-up sweeps |
| **Pluggable Sinks** | Application Insights built-in; add webhooks, SIEM, or custom sinks |
| **JSONL Journal** | Structured event files for AI tools, SIEM ingestion, or offline analysis |
| **4 Monitoring Levels** | Minimum → Standard → High → Custom granularity |
| **21 Functions** | Full lifecycle management: register, configure, monitor, diagnose |
| **Zero Dependencies** | One Microsoft DLL included. No external modules required |

## Quick Install

```powershell
Install-Module -Name EventMonitor.Windows -Scope CurrentUser
Import-Module EventMonitor.Windows
Register-EventMonitor
```

## Wiki Navigation

| Page | Description |
|:-----|:------------|
| **[Installation](Installation)** | Prerequisites, install methods, upgrading |
| **[Quick Start Guide](Quick-Start-Guide)** | Get monitoring running in 5 minutes |
| **[Configuration](Configuration)** | Monitoring levels, event journal, log levels |
| **[Event Groups Reference](Event-Groups-Reference)** | All 17 groups with event IDs and descriptions |
| **[Command Reference](Command-Reference)** | All 21 exported functions with parameters and examples |
| **[Telemetry & Sinks](Telemetry-and-Sinks)** | Application Insights, custom sinks, JSONL journal |
| **[Architecture](Architecture)** | Module internals, loading order, data flow |
| **[KQL Queries](KQL-Queries)** | Ready-to-use Kusto queries for Application Insights |
| **[Troubleshooting](Troubleshooting)** | Common issues and solutions |
| **[Contributing](Contributing)** | How to contribute, development setup |

## Requirements

| Requirement | Version |
|:------------|:--------|
| PowerShell | 7.4+ (Core edition) |
| Windows | 10 / 11 / Server 2016+ |
| Privileges | Administrator (for event log access) |
| Optional | Azure Application Insights resource |

---

<div align="center">
<sub>Created by <a href="https://github.com/navalerakesh">Rakesh Navale</a> · Licensed under MIT</sub>
</div>
