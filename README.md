# Gregrep Overlord DFIR Application

**Forensic Triage Orchestrator** — Windows & macOS  
*A live-system digital forensic and incident response tool that goes beyond what your SIEM dashboard shows you.*

Gregrep-Overlord is the only tool that combines live-system triage (no file copying, 
no agent), cross-platform coverage (Windows + macOS natively), IOC-aware reporting 
(findings scored by severity), and alert-scenario presets (pre-mapped to EDR alert 
types) — in a single script with zero dependencies.
<img width="1539" height="901" alt="GrepOverloard-Dash" src="https://github.com/user-attachments/assets/6d3dfe86-e71d-4ca0-94a2-e2f621104270" />

---

## What It Is

Gregrep-Overlord is a standalone forensic triage engine written in **native PowerShell (Windows)** and **Bash (macOS)**. No binary dependencies. No KAPE install. No EZ Tools required. Run it on any live system and get a complete, analyst-ready HTML report plus per-module CSVs — in a single command.

It was built to answer the question every responder faces after an EDR alert:  
> *"My SIEM and EDR alert tells me what was detected — but what else happened on this machine?"*

---

## What It Does That Your EDR Dashboard Doesn't

| Your EDR Shows | Gregrep-Overlord Also Finds |
|---|---|
| Alert process + parent | Full process tree with spawn anomaly detection |
| Network event for C2 | Active TCP connections mapped to processes, DNS cache, suspicious ports |
| Detection timestamp | Full 7-day (configurable) timeline across all artifact sources |
| Single detection | Cross-artifact corroboration: event log + prefetch + BAM + browser + PS history |
| Windows only | macOS: LaunchAgents, UnifiedLog, SIP/Gatekeeper, TCC, DYLD, quarantine DB |

---

## Quick Start

### Windows (Run as Administrator)

```powershell
# Full triage — all modules, last 7 days
.\Invoke-GregrepOverlord.ps1

# Alert-focused — known user and process, last 3 days
.\Invoke-GregrepOverlord.ps1 -TimeframeDays 3 -SuspectUser "jsmith" -SuspectProcess "powershell.exe"

# Interactive scenario picker (recommended after an EDR alert)
.\Quick-Launch.ps1

# Direct scenario launch
.\Quick-Launch.ps1 -Scenario CredentialDump -SuspectUser "jsmith"
```

### macOS (Run as root)

```bash
# Full triage
sudo bash Invoke-GregrepOverlord-macOS.sh

# Alert-focused
sudo bash Invoke-GregrepOverlord-macOS.sh -d 3 -u jsmith -p Terminal

# Skip specific modules
sudo bash Invoke-GregrepOverlord-macOS.sh -s "UnifiedLogs,NetworkConfig"
```

---

## Output

Every run produces a timestamped output folder:

```
GregrepOverlord-Output/
└── HOSTNAME-20250101-123456/
    ├── GregrepOverlord-Report_HOSTNAME_20250101-123456.html   ← Open this first
    ├── triage.log
    └── csv/
        ├── FINDINGS_SUMMARY.csv    ← All flagged IOCs for SIEM import
        ├── EventLogs.csv
        ├── BrowserArtifacts.csv
        ├── ProcessTree.csv
        ├── NetworkConnections.csv
        ├── Persistence.csv
        ├── ... (one CSV per module)
```

The **HTML report** is self-contained (no external dependencies) — open it in any browser. It includes:
- Risk level banner (CRITICAL / HIGH / MEDIUM / LOW)
- Module summary grid with per-module finding counts
- Interactive findings table with severity filter and search
- Full detail for every flagged IOC

The **FINDINGS_SUMMARY.csv** can be imported directly into a SIEM (Splunk, QRadar, Elastic) or pasted into a ticket.

---

## Alert Scenarios (Quick-Launch)

`Quick-Launch.ps1` pre-configures the right modules and timeframe for each alert type:

| # | Scenario | Activated When |
|---|---|---|
| 1 | **PhishingClick** | User clicked link or opened attachment |
| 2 | **RansomwareIndicator** | File encryption, VSS deletion, mass write |
| 3 | **CredentialDump** | LSASS dump, Mimikatz, procdump detected |
| 4 | **LateralMovement** | PsExec, WMI, RDP, pass-the-hash |
| 5 | **PersistenceDetected** | New service, Run key, task, WMI sub |
| 6 | **SuspiciousPS** | Encoded PowerShell, AMSI bypass, download cradle |
| 7 | **LOLBin** | certutil, mshta, regsvr32 misuse |
| 8 | **C2Beacon** | Periodic outbound, beaconing behavior |
| 9 | **FullTriage** | All modules, deepest coverage |

---

## Windows Modules

| Module | What It Collects |
|---|---|
| `EventLogs` | Security (30+ event IDs), Sysmon, PowerShell 4104, WinRM |
| `BrowserArtifacts` | Chrome/Edge/Firefox history + extension permissions |
| `ScheduledTasks` | All tasks — scripting engine actions, suspicious paths |
| `Prefetch` | Execution evidence from .pf files |
| `CertUtil` | INetCache drops, temp executables, LOLBin artifacts |
| `Persistence` | Startup folders, Run keys, AppInit_DLLs, COM hijack |
| `NetworkConnections` | Live TCP + DNS cache + suspicious port/IP flags |
| `ProcessTree` | All processes, parent-child anomaly detection |
| `UserActivity` | Recent docs, jump lists, logged-on users |
| `WMISubscriptions` | Event filters, command consumers, script consumers |
| `PowerShellHistory` | PSReadLine history from all user profiles |
| `LateralMovement` | PsExec artifacts, RDP events, admin shares |
| `DefenderLogs` | Detections, exclusions, feature disable events |
| `ServicesDrivers` | Services in suspicious paths, SYSTEM in user dirs |
| `AmCache` | Application execution history (AmCache.hve) |
| `BAM` | Background Activity Moderator execution records |
| `CredentialAccess` | DPAPI vaults, SAM backup, LSASS dump files |
| `FileSystemAnomalies` | Recent executables, Alternate Data Streams |
| `ShadowCopies` | VSS presence/deletion — ransomware indicator |

## macOS Modules

| Module | What It Collects |
|---|---|
| `UnifiedLogs` | Apple Unified Log — auth, sudo, SSH, PAM events |
| `BrowserArtifacts` | Chrome, Safari, Firefox history + extensions |
| `Persistence` | LaunchAgents/Daemons, cron, at, Login Items, profiles |
| `NetworkConnections` | lsof -i, DNS cache, firewall rules |
| `ProcessTree` | ps aux with command analysis |
| `UserActivity` | bash/zsh history, recent scripts, last/lastb logins |
| `SecurityConfig` | SIP, Gatekeeper, FileVault, AMFI, XProtect, TCC, kexts |
| `MalwareArtifacts` | Quarantine DB, hidden executables, DYLD injection, stray apps |
| `RemoteAccess` | authorized_keys, stray private keys, SSH config, RDP |
| `NetworkConfig` | /etc/hosts anomalies, proxy, DNS servers, ARP cache |

---

## Customization

### Focus on a specific alert

Pass context flags to any run:

```powershell
.\Invoke-GregrepOverlord.ps1 `
  -SuspectUser "jsmith" `
  -SuspectProcess "powershell.exe" `
  -SuspectIP "45.33.32.156" `
  -TimeframeDays 2
```

### Configure IOCs

Edit `config/ioc-config.txt` to add:
- Known bad IPs from your threat intel
- Custom suspicious process names  
- Your trusted internal IP ranges (reduces false positives)
- Environment-specific whitelists

### Run specific modules only

```powershell
# Only persistence and credential modules
.\Invoke-GregrepOverlord.ps1 -Modules "Persistence,CredentialAccess,WMISubscriptions"

# Everything except the slow browser module
.\Invoke-GregrepOverlord.ps1 -SkipModules "BrowserArtifacts"
```

---

## Comparison to EZ Tools / KAPE

See [`docs/COVERAGE-GAPS.md`](docs/COVERAGE-GAPS.md) for the full breakdown.

**Short version:**

- **KAPE** is a collection engine — it copies files. Overlord queries a live system and flags IOCs.
- **EZ Tools** do deep offline parsing of individual artifacts. Overlord does broad live coverage across all surfaces.
- **Overlord** fills the gap: live triage with IOC-aware reporting, no tool staging required.

---

## Requirements

### Windows
- PowerShell 5.1 or later (built into Windows 10/Server 2016+)
- Local Administrator or SYSTEM privileges (some modules limited without it)
- No external tools required

### macOS
- Bash 3.2+ (built in) or zsh
- Root privileges (`sudo`) for full coverage
- Python 3 (for JSON parsing in extension module — optional, degrades gracefully)

---

## Frequently Asked Questions

**Does this require KAPE or EZ Tools installed?**  
No. Gregrep-Overlord is entirely self-contained PowerShell and Bash. It was designed as an alternative for environments where staging tools is impractical or adds risk.

**Can I run this remotely across multiple hosts?**  
Yes — copy the script to a network share and invoke via `Invoke-Command` or PSExec. The output directory parameter lets you write to a central share:
```powershell
Invoke-Command -ComputerName WORKSTATION-042 -ScriptBlock {
    & \\fileshare\tools\Invoke-GregrepOverlord.ps1 -OutputPath "\\fileshare\output\"
}
```

**How long does a full triage take?**  
Typically 2–8 minutes on a standard endpoint. The `EventLogs` and `FileSystemAnomalies` modules are the slowest. Use `-Modules` to scope down for faster runs.

**Will this trigger EDR alerts itself?**  
Possibly — particularly the registry and process enumeration modules. Run with your SOC's knowledge and, where possible, whitelist the script path in your EDR before deployment.

**Can I add custom modules?**  
Yes — add a function `Invoke-YourModule` in the Windows script and add it to the `$ModuleFunctions` hashtable. Use `Save-ModuleCSV` and `Add-Finding` to integrate with the reporting pipeline.

---

## Roadmap

- [ ] SRUM database module (execution + network activity history)
- [ ] ShimCache (AppCompatCache) parser
- [ ] Windows Timeline (ActivitiesCache.db)
- [ ] macOS KnowledgeC.db parser (Biome / Screen Time activity)
- [ ] macOS FSEvents log parser
- [ ] Hash verification against NSRL and local blocklist
- [ ] Multi-host remote triage wrapper
- [ ] SIEM export format presets (Splunk, Elastic, QRadar)
- [ ] Sigma rule matching against collected events

---

## License

MIT License — free to use, fork, and modify. Contributions welcome.

---

*Built for incident responders who need answers fast, not another tool to install.*

---

## Acknowledgement

Inspired by the forensic coverage philosophy of [Eric Zimmerman's Tools](https://ericzimmerman.github.io/) 
and the collection architecture of [KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape). 
Event log hunting concepts were informed by [DeepBlueCLI](https://github.com/sans-holiday/DeepBlueCLI) 
by Eric Conrad and the SANS community. No code from any of these projects was used.
