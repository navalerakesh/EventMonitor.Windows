# Security & Reliability Design

<p align="center">
  <img src="../assets/icon.svg" alt="EventMonitor.Windows" width="200"/>
</p>

Why EventMonitor.Windows is secure, reliable, and built for the AI era.

---

## Zero External Dependencies

EventMonitor.Windows ships with a single binary dependency: `Microsoft.ApplicationInsights.dll` (Microsoft's official SDK, included in the module). Everything else is pure PowerShell using built-in Windows APIs.

| What We Use | Source | Why It Matters |
|---|---|---|
| `EventLogWatcher` | .NET BCL (built into Windows) | No third-party event collection library |
| `Get-WinEvent` | PowerShell built-in | No wrapper modules |
| `ScheduledTask` cmdlets | Windows built-in | No task scheduler libraries |
| `Win32_UserProfile` | WMI/CIM (built into Windows) | No AD modules required |
| `query user` / `netstat` | Windows built-in commands | No session detection packages |

**No npm, no pip, no NuGet package restore, no supply chain to attack.** The module is self-contained. A dependency vulnerability in a nested package cannot compromise your security monitor.

## How Secrets Are Protected

### Connection String

The Application Insights connection string (containing the instrumentation key) is handled with defense-in-depth:

1. **Never in command-line arguments** — The scheduled task doesn't receive the connection string as a parameter. It reads it from a file at runtime, so `wmic process` or `Get-Process` never expose the key.

2. **ACL-restricted file** — When `Register-EventMonitor` stores the connection string, it immediately sets the file ACL to SYSTEM + Administrators only. Standard users cannot read it.

3. **Not in source control** — The file is in `C:\ProgramData\WindowsEventMonitor\Secrets\`, outside the module directory and outside any git repo.

4. **Environment variable priority** — The recommended approach is to use `APPLICATIONINSIGHTS_CONNECTION_STRING` or `EventMonitorAppInsightsConString` environment variables, which are standard Azure practice and never written to disk.

5. **Optional** — The module works without App Insights. Events are always captured to the local JSONL journal. App Insights is an add-on, not a requirement.

### No Credentials Stored

The module never stores, processes, or transmits user passwords, tokens, or authentication credentials. It reads Windows Event Log metadata only — the same data that Windows Event Viewer shows.

## Why It Won't Crash Your Machine

### Event-Driven, Not Polling

The core monitoring engine uses `System.Diagnostics.Eventing.Reader.EventLogWatcher` — a .NET API where the **Windows kernel** delivers events to the monitor. This means:

- **Zero CPU when idle** — No timer loops, no periodic log scans
- **No full log reads** — The kernel filters and delivers only matching events
- **Instant detection** — Sub-second latency from event to telemetry
- **No memory accumulation** — Events are processed one at a time, not buffered

### Self-Healing Watchdog

Every 30 minutes (configurable), the watchdog:

1. **Health check** — Verifies each EventLogWatcher is alive and responsive
2. **Auto-repair** — If a watcher has died or accumulated errors, it's automatically disposed and re-created
3. **Error reset** — After successful restart, the error counter resets to zero (no restart loops)
4. **Catch-up sweep** — Only runs if a watcher was actually repaired, filling exactly the gap. No duplicate events.
5. **Log cleanup** — Removes old files beyond the retention period
6. **Health telemetry** — Reports watcher count, event count, and error count

### Crash Recovery

| Failure | Recovery | Time |
|---|---|---|
| EventLogWatcher dies | Watchdog auto-restarts it | < 30 min |
| PowerShell process crashes | Task Scheduler auto-restarts | 1 minute |
| Machine reboots | AtStartup trigger starts service | At boot |
| 3 consecutive crashes | Task Scheduler stops retrying | Manual intervention needed |

### Callback Safety

Every event callback is wrapped in `try/catch`:
- A malformed event **never** crashes the watcher
- A failing telemetry sink **never** blocks other sinks
- An error in the watchdog **never** prevents the next watchdog cycle
- `TrackEvent` failures **never** call `TrackException` (prevents infinite recursion)

## Noise Reduction

Security monitoring is useless if it floods you with noise. EventMonitor.Windows filters at every level:

### Source-Level Filtering

| What's Filtered | Why |
|---|---|
| LogonType 0 (System), 4 (Batch), 5 (Service) | Internal Windows operations, thousands per hour |
| System accounts (SYSTEM, DWM-*, UMFD-*) | Windows desktop services, not user activity |
| SSH events for non-monitored users | Prevents cross-user attribution |
| `sshd.exe` from 4648 events | SSH is tracked by its own dedicated processor |

### Group-Level Filtering

Monitoring levels control which event categories are active:

| Level | Groups | Typical Events/Hour |
|---|---|---|
| Minimum | 4 groups | ~5-10 |
| Standard | 13 groups | ~20-50 |
| High | 17 groups | ~100-500 |

### No Duplicate Events

- Catch-up sweeps only run when a watcher was repaired
- Each scan session has a unique SessionId for correlation
- The module never re-reads events it has already processed in the current session

## Why This Matters in the AI Era

### The Problem No One Is Talking About

Every developer now runs AI tools locally — GitHub Copilot, coding agents, MCP servers, automation bots, agentic AI frameworks. These tools execute code on your machine **with your full user permissions**. They can:

- Run shell commands and PowerShell scripts as you
- Open outbound network connections to any endpoint
- Install npm/pip/NuGet packages (which pull in transitive dependencies you never reviewed)
- Create Windows services or scheduled tasks that persist after the tool closes
- Access your file shares, SSH keys, and local network
- Modify firewall rules to allow inbound connections

**This is not theoretical.** Supply chain attacks via package registries are documented. Prompt injection can cause AI tools to execute unintended commands. MCP servers open your machine to tool calls from remote agents. Every one of these actions leaves a trace in Windows Event Logs — but nobody is watching.

EventMonitor.Windows watches. It runs silently in the background and catches exactly these scenarios:

### Real Scenarios EventMonitor.Windows Detects

| What Happens | How You Find Out |
|---|---|
| An npm package installs a Windows service as a backdoor | Event 4697/7045: service installed — you get an alert |
| A coding agent creates a scheduled task to phone home | Event 4698: task created — captured with task XML content |
| An MCP server opens your machine to inbound connections | Firewall rule change (4946) or blocked connection (5157) |
| Someone brute-forces your SSH or RDP from the internet | Failed logon events (4625) + SSH failed auth — pattern visible |
| A bot disables Windows Defender to run unsigned code | Event 5001: real-time protection disabled — critical alert |
| An attacker clears the audit log to cover their tracks | Event 1102: audit log cleared — highest severity alert |
| PowerShell remoting is used for lateral movement | WinRM Event 6: remote session created |
| Ransomware modifies firewall rules to spread | Events 4946/4947/4948: firewall rule added/modified/deleted |
| An unknown process runs under your account | Event 4688: process created (enable High monitoring level) |

### Why Existing Tools Don't Cover This

| Tool | Gap |
|---|---|
| Windows Defender | Catches known malware signatures — not novel AI-driven attacks or living-off-the-land techniques |
| Windows Event Viewer | Shows events but requires manual checking — nobody does this |
| EDR solutions (CrowdStrike, etc.) | Enterprise-grade, expensive, not available for individual developers |
| Firewall | Blocks incoming traffic but doesn't alert on outgoing connections or rule changes |

EventMonitor.Windows fills the gap: real-time, event-driven, zero-cost, runs on any Windows machine, no cloud subscription required.

### The Event Journal as an AI-Readable Security Log

The JSONL event journal (`C:\ProgramData\WindowsEventMonitor\Journal\`) provides a clean, structured, pre-filtered view of security events. Unlike the raw Windows Event Log (which requires admin access, complex XPath queries, and understanding of 200+ event schemas), the journal:

- **Is readable by any tool** — JSON Lines format, one object per line
- **Doesn't require admin** — Standard file access to ProgramData
- **Is pre-filtered** — Only security-relevant events, no noise
- **Has consistent schema** — Same fields across all event types (time, event, severity, user, IP)
- **Is searchable** via `Get-EventHistory` or any JSON parser

### Local-First, Cloud-Optional

All event data is captured locally before (optionally) being sent to cloud telemetry. If your network is down, if App Insights is unreachable, if you don't trust cloud services — your security data is still there, on disk, queryable.

## Architecture Principles

1. **No dependencies beyond Windows** — Pure PowerShell + one Microsoft DLL
2. **Defense in depth** — Every component assumes the others can fail
3. **Local-first** — Events are always journaled locally, cloud is optional
4. **Noise-free** — Filter at source, not after ingestion
5. **Self-healing** — Watchdog monitors the monitor
6. **Pluggable output** — Any telemetry destination via Register-TelemetrySink
7. **Idempotent operations** — Call Register-EventMonitor as many times as you want
8. **Data survives updates** — Config, logs, and journal in ProgramData, not the module directory
