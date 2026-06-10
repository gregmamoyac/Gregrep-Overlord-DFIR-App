# Gregrep-Overlord — Coverage Gap Analysis
## vs. Eric Zimmerman Tools, KAPE, and the Master Triage Script

This document maps every data source collected by Gregrep-Overlord against known
forensic tools and explains the **gaps it fills** beyond each.

---

## What the Original Master Triage Script Covered

| Function | Scope |
|---|---|
| `Get-EventLogIOCs` | Event IDs 4698, 4688, 4624, Sysmon 1/3/7/11 |
| `Get-BrowserArtifacts` | Chrome/Edge/Firefox history & downloads |
| `Get-ScheduledTaskAnomalies` | Tasks with scripting engine actions |
| `Get-PrefetchEvidence` | Executables from temp/unusual paths |
| `Get-CertUtilCache` | INetCache certutil drops |

---

## What KAPE Collects (and how Overlord compares)

KAPE is a **collection engine** — it copies files for offline analysis via targets
(`.tkape`) and processes them with modules (`.mkape`). It does not flag IOCs or
generate a triage report natively.

| KAPE Source | Gregrep-Overlord Equivalent | Notes |
|---|---|---|
| `$MFT`, `$J`, `$LogFile` | `FileSystemAnomalies` (live query) | Overlord reads live FS; no raw MFT parser (EZ Tools' MFTECmd needed for offline) |
| `Prefetch` | `Invoke-Prefetch` module | Native PS, no binary required |
| `AmCache.hve` | `Invoke-AmCache` module | Uses reg.exe hive load |
| `SYSTEM/SOFTWARE hives` | `Persistence`, `BAM`, `RegistryRun` | Live registry query |
| `Event Logs (EVTX)` | `Invoke-EventLogs` | Full coverage inc. Sysmon, PS, WinRM |
| `Browser DBs` | `Invoke-BrowserArtifacts` | SQLite string extraction (no SQLite binary needed) |
| `$Recycle.Bin` | `FileSystemAnomalies` (partial) | Not fully implemented; future module |
| `LNK / Jump Lists` | `UserActivity` module | Enumerates, does not parse binary LNK |
| `Scheduled Tasks XML` | `Invoke-ScheduledTasks` | Full XML parsed via Get-ScheduledTask |
| `WMI subs` | `Invoke-WMISubscriptions` | Full coverage |
| `SRUM database` | ❌ Not covered | Future: SRUM-DUMP or offline parse |
| `Windows.edb` | ❌ Not covered | Requires ESE DB tools |

---

## What EZ Tools Cover (and how Overlord compares)

Eric Zimmerman's tools operate on **offline copies** of artifacts (raw files).
Overlord queries **live systems** without file copies. This is the key trade-off:

| EZ Tool | What It Does | Overlord Equivalent |
|---|---|---|
| `MFTECmd` | Parse raw $MFT for file timeline | `FileSystemAnomalies` (find-based, no raw MFT) |
| `PECmd` | Full Prefetch binary parser (run times, loaded DLLs) | `Invoke-Prefetch` — filename & timestamps only |
| `AmcacheParser` | Full AmCache.hve parser | `Invoke-AmCache` — reg.exe hive load |
| `AppCompatCacheParser` | ShimCache from SYSTEM hive | `Invoke-ShimCache` — planned |
| `RECmd` (Registry Explorer) | Offline hive analysis | `Persistence`, `BAM`, `RegistryRun` — live |
| `LECmd` | LNK file parser (shell item metadata) | `UserActivity` — directory listing only |
| `JLECmd` | Jump list parser | `UserActivity` — count only |
| `RBCmd` | Recycle Bin parser | ❌ Future module |
| `SrumECmd` | SRUM database parser | ❌ Future module |
| `WxTCmd` | Windows Timeline (ActivitiesCache.db) | ❌ Future module |
| `Timeline Explorer` | GUI timeline viewer | HTML report with sortable table |
| `EvtxECmd` | EVTX parser with sigma rules | `Invoke-EventLogs` — broader coverage |

**Key Insight:** EZ Tools excel at *deep forensic parsing* of individual artifacts
with offline copies. Overlord excels at *live triage* across all attack surfaces
simultaneously — producing a complete picture in a single run on a live or
compromised host.

---

## Gaps Gregrep-Overlord Fills vs. Both Tools

These are **attack surfaces neither KAPE targets nor EZ Tools cover** natively:

| Surface | Gregrep-Overlord Module | Why It Matters |
|---|---|---|
| Active network connections (live) | `NetworkConnections` | Real-time C2 beacon detection |
| DNS cache (live) | `NetworkConnections` | In-memory IOCs lost on reboot |
| Running process tree with parent-child | `ProcessTree` | Detect suspicious spawns |
| WMI event subscriptions (live) | `WMISubscriptions` | Fileless persistence check |
| PowerShell ConsoleHost history | `PowerShellHistory` | Command-level attacker footprint |
| Defender exclusions and status | `DefenderLogs` | Tamper detection |
| Credential Manager / DPAPI vaults | `CredentialAccess` | Harvest artifact detection |
| Browser extension permissions | `BrowserArtifacts` | Extension-based attack surface |
| LSASS dump files in temp paths | `CredentialAccess` | Credential dump detection |
| COM hijacking (HKCU InprocServer32) | `Persistence` | User-level persistent DLL inject |
| AppInit_DLLs | `Persistence` | Classic DLL hijack |
| Alternate Data Streams | `FileSystemAnomalies` | Hidden payload detection |
| VSS shadow copy deletion | `ShadowCopies` | Ransomware early indicator |
| RDP session events (TS log) | `LateralMovement` | Lateral movement tracking |
| BAM execution records | `BAM` | User-specific execution history |
| Firewall rule changes | `EventLogs` (4946/4947) | Defense evasion |
| Kerberoasting indicators | `EventLogs` (4769) | Kerberos ticket anomalies |
| WinRM remote sessions | `EventLogs` | Remote execution tracking |
| **macOS: SIP/Gatekeeper status** | `SecurityConfig` | macOS security baseline |
| **macOS: LaunchAgent/Daemon** | `Persistence` | macOS persistence equivalents |
| **macOS: Unified Log (auth/sudo)** | `UnifiedLogs` | macOS event log equivalent |
| **macOS: DYLD injection** | `MalwareArtifacts` | macOS dylib hijack |
| **macOS: TCC database** | `SecurityConfig` | Privacy permission abuse |
| **macOS: Quarantine database** | `MalwareArtifacts` | Download origin tracking |
| **macOS: Shell history (zsh/bash)** | `UserActivity` | Command-level visibility |
| **macOS: SSH authorized_keys** | `RemoteAccess` | Backdoor key detection |

---

## Future Modules (Planned)

| Module | Data Source | Priority |
|---|---|---|
| `SRUM` | SRUM database (network/process history) | HIGH |
| `WindowsTimeline` | ActivitiesCache.db | MEDIUM |
| `RecycleBin` | $Recycle.Bin per user | MEDIUM |
| `ThumbCache` | Thumbnail cache viewer | LOW |
| `JumpListDeep` | Binary LNK/JumpList parsing | MEDIUM |
| `ShimCache` | AppCompatCache from SYSTEM hive | HIGH |
| `EventLogForwarding` | WEF subscription audit | MEDIUM |
| `CloudStorage` | OneDrive/Dropbox/Google Drive sync | MEDIUM |
| **macOS: FSEvents** | macOS file system event log | HIGH |
| **macOS: Spotlight** | .store.db metadata | MEDIUM |
| **macOS: KnowledgeC** | User activity timeline db | HIGH |

---

## Module-to-MITRE ATT&CK Mapping

| Module | MITRE Techniques |
|---|---|
| EventLogs | T1059, T1053, T1078, T1021, T1136 |
| BrowserArtifacts | T1185, T1189, T1176 |
| ScheduledTasks | T1053.005 |
| Prefetch | T1059, execution evidence |
| CertUtil | T1140, T1105, T1218.003 |
| Persistence | T1547, T1546, T1546.015 |
| NetworkConnections | T1071, T1090, T1095 |
| ProcessTree | T1059, T1055, T1036 |
| WMISubscriptions | T1546.003 |
| PowerShellHistory | T1059.001 |
| LateralMovement | T1021, T1075, T1076 |
| DefenderLogs | T1562.001 |
| CredentialAccess | T1003.001, T1555 |
| ShadowCopies | T1490 |
| BAM / AmCache | Execution evidence |
| FileSystemAnomalies | T1564.004, T1027 |
| SecurityConfig (macOS) | T1553, T1562 |
| MalwareArtifacts (macOS) | T1543.004, T1574.006 |
