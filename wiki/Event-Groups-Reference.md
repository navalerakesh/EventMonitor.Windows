# Event Groups Reference

EventMonitor.Windows monitors **40+ event IDs** across **17 groups**, covering 7 Windows event logs.

---

## Event Logs Monitored

| Event Log | Groups Using It |
|:----------|:---------------|
| Security | Logon, Logoff, AccountManagement, GroupManagement, PrivilegeUse, ProcessTracking, Persistence, AuditTampering, NetworkShare, NetworkFirewall |
| System | PersistenceSystem, SystemHealth |
| OpenSSH/Operational | SSH |
| Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | RDP |
| Microsoft-Windows-PowerShell/Operational | PowerShell |
| Microsoft-Windows-WinRM/Operational | WinRM |
| Microsoft-Windows-Windows Defender/Operational | Defender |

---

## All 17 Event Groups

### Logon
**Preset:** Minimum, Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4624 | Successful logon | Info |
| 4625 | Failed logon attempt | High |
| 4648 | Explicit credential logon (RunAs) | Medium |
| 4800 | Workstation locked | Info |
| 4801 | Workstation unlocked | Info |

> **Security value:** Detects brute-force attacks (repeated 4625), credential theft (4648), and tracks all user sessions.

---

### Logoff
**Preset:** Minimum, Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4647 | User-initiated logoff | Info |
| 4779 | Session disconnected | Info |

---

### SSH
**Preset:** Minimum, Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| *(all)* | All OpenSSH/Operational events | Medium |

> **Security value:** Detects unauthorized SSH connections, key-based authentication, and lateral movement via SSH.

---

### RDP
**Preset:** Minimum, Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 21 | RDP session logon succeeded | Info |
| 23 | RDP session logoff | Info |
| 24 | RDP session disconnected | Info |
| 25 | RDP session reconnected | Info |

> **Security value:** Tracks remote desktop sessions for unauthorized access and lateral movement.

---

### AccountManagement
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4720 | User account created | High |
| 4722 | User account enabled | Medium |
| 4723 | Password change attempted | Medium |
| 4724 | Password reset attempted | Medium |
| 4725 | User account disabled | Medium |
| 4726 | User account deleted | High |

> **Security value:** Detects rogue account creation, unauthorized password resets, and account manipulation.

---

### GroupManagement
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4732 | Member added to security group | High |
| 4733 | Member removed from security group | Medium |

> **Security value:** Detects privilege escalation via group membership changes (e.g., adding to Administrators).

---

### PrivilegeUse
**Preset:** High only

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4672 | Special privileges assigned to new logon | Medium |

> **Security value:** Identifies logons with admin-level privileges. High volume — best for targeted investigation.

---

### ProcessTracking
**Preset:** High only

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4688 | New process created | Info |
| 4689 | Process exited | Info |

> **Security value:** Full process execution audit trail. High volume — enable command-line auditing via Group Policy for best results.

---

### Persistence
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4697 | Service installed in the system | Critical |
| 4698 | Scheduled task created | Critical |
| 4699 | Scheduled task deleted | Medium |
| 4702 | Scheduled task updated | Medium |

> **Security value:** Detects backdoor installation via services and scheduled tasks — top persistence techniques used by attackers.

---

### PersistenceSystem
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 7045 | New service installed (System log) | Critical |

> **Security value:** Catches service installations not covered by the Security log.

---

### AuditTampering
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 1102 | Audit log cleared | Critical |
| 4719 | System audit policy changed | Critical |

> **Security value:** Detects anti-forensic activity — attackers often clear logs or disable auditing after compromising a system.

---

### PowerShell
**Preset:** High only

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4104 | PowerShell script block logged | Medium |

> **Security value:** Captures executed PowerShell code, including obfuscated scripts that are logged after deobfuscation. Requires Script Block Logging enabled via Group Policy.

---

### NetworkShare
**Preset:** High only

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 5140 | Network share accessed | Medium |

> **Security value:** Tracks file share access for data exfiltration detection and lateral movement.

---

### NetworkFirewall
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 4946 | Firewall exception rule added | High |
| 4947 | Firewall exception rule modified | High |
| 4948 | Firewall exception rule deleted | Medium |
| 5152 | Windows Filtering Platform blocked a packet | Info |
| 5157 | Windows Filtering Platform blocked a connection | Info |

> **Security value:** Detects firewall rule tampering that could open ports for C2 communication.

---

### SystemHealth
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 41 | Unexpected shutdown (kernel power) | High |
| 1074 | System shutdown/restart initiated | Info |
| 1076 | Unexpected shutdown reason recorded | Medium |
| 6005 | Event Log service started | Info |
| 6006 | Event Log service stopped | Info |
| 6008 | Unexpected shutdown (previous) | High |
| 6009 | OS version info at boot | Info |
| 6013 | System uptime | Info |

> **Security value:** Detects system instability, unexpected reboots (possible crash exploits), and boot patterns.

---

### WinRM
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 6 | WinRM session created | Medium |
| 91 | WinRM session closed | Info |

> **Security value:** Detects PowerShell Remoting / WinRM lateral movement.

---

### Defender
**Preset:** Standard, High

| Event ID | Description | Severity |
|:---------|:------------|:---------|
| 1116 | Malware detected | Critical |
| 1117 | Malware action taken | High |
| 5001 | Real-time protection disabled | Critical |
| 5010 | Scanning for malware disabled | High |
| 5012 | Virus scanning disabled | High |

> **Security value:** Detects active malware and, critically, attackers disabling Defender as a precursor to deploying payloads.

---

## Monitoring Level Coverage Matrix

| Group | Minimum | Standard | High |
|:------|:-------:|:--------:|:----:|
| Logon | ✅ | ✅ | ✅ |
| Logoff | ✅ | ✅ | ✅ |
| SSH | ✅ | ✅ | ✅ |
| RDP | ✅ | ✅ | ✅ |
| AccountManagement | | ✅ | ✅ |
| GroupManagement | | ✅ | ✅ |
| PrivilegeUse | | | ✅ |
| ProcessTracking | | | ✅ |
| Persistence | | ✅ | ✅ |
| PersistenceSystem | | ✅ | ✅ |
| AuditTampering | | ✅ | ✅ |
| PowerShell | | | ✅ |
| NetworkShare | | | ✅ |
| NetworkFirewall | | ✅ | ✅ |
| SystemHealth | | ✅ | ✅ |
| WinRM | | ✅ | ✅ |
| Defender | | ✅ | ✅ |
| **Total groups** | **4** | **13** | **17** |

---

**Next:** [Command Reference](Command-Reference) · [Telemetry & Sinks](Telemetry-and-Sinks)
