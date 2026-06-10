#Requires -Version 5.1
<#
.SYNOPSIS
    Gregrep-Overlord Quick Launch — Alert-Scenario Shortcuts
    
.DESCRIPTION
    Pre-configured triage launches for the most common alert types received from
    SentinelOne, Rapid7 InsightIDR, or Windows Defender. Each scenario activates
    the relevant module set and flags appropriate IOC patterns.

    Run this script and pick a scenario, or pass -Scenario directly.

.PARAMETER Scenario
    One of: PhishingClick, RansomwareIndicator, Creds entialDump, LateralMovement,
            PersistenceDetected, SuspiciousPS, LOLBin, C2Beacon, FullTriage, Custom

.PARAMETER SuspectUser
    Username from alert (maps to -SuspectUser in main script)

.PARAMETER SuspectProcess
    Process name from alert

.PARAMETER SuspectIP
    IP address from alert or threat intel

.PARAMETER TimeframeDays
    Override default timeframe (default varies per scenario)

.EXAMPLE
    # Launch ransomware scenario
    .\Quick-Launch.ps1 -Scenario RansomwareIndicator

.EXAMPLE
    # Credential dump focused on specific user
    .\Quick-Launch.ps1 -Scenario CredentialDump -SuspectUser "jsmith" -TimeframeDays 1

.EXAMPLE
    # Interactive picker
    .\Quick-Launch.ps1
#>

[CmdletBinding()]
param(
    [ValidateSet("PhishingClick","RansomwareIndicator","CredentialDump","LateralMovement",
                 "PersistenceDetected","SuspiciousPS","LOLBin","C2Beacon","FullTriage","Custom")]
    [string]$Scenario = "",
    [string]$SuspectUser = "",
    [string]$SuspectProcess = "",
    [string]$SuspectIP = "",
    [int]$TimeframeDays = 0
)

# Scenario definitions
$Scenarios = [ordered]@{
    "1" = @{
        Name        = "PhishingClick"
        Description = "User clicked a phishing link/attachment — Office macro or browser download"
        Modules     = "EventLogs,BrowserArtifacts,ProcessTree,Prefetch,FileSystemAnomalies,DefenderLogs,CertUtil"
        Days        = 3
        Focus       = "Office child processes, browser downloads, temp drops, Defender detections"
    }
    "2" = @{
        Name        = "RansomwareIndicator"
        Description = "Ransomware indicators — file encryption, VSS deletion, rapid writes"
        Modules     = "EventLogs,ShadowCopies,ProcessTree,FileSystemAnomalies,ServicesDrivers,DefenderLogs,ScheduledTasks"
        Days        = 1
        Focus       = "VSS deletion commands, mass file operations, Defender detections, new services"
    }
    "3" = @{
        Name        = "CredentialDump"
        Description = "Credential harvesting — LSASS dump, SAM access, Mimikatz indicators"
        Modules     = "EventLogs,CredentialAccess,ProcessTree,AmCache,BAM,Prefetch,PowerShellHistory"
        Days        = 2
        Focus       = "Sysmon 10 LSASS access, procdump, dump files, suspicious PS history"
    }
    "4" = @{
        Name        = "LateralMovement"
        Description = "Lateral movement — PsExec, WMI, RDP, pass-the-hash, SMB"
        Modules     = "EventLogs,LateralMovement,NetworkConnections,ProcessTree,UserActivity,ServicesDrivers"
        Days        = 3
        Focus       = "4624 type 3/10, 4648, RDP events, PsExec artifacts, admin shares"
    }
    "5" = @{
        Name        = "PersistenceDetected"
        Description = "Persistence mechanism — new startup item, Run key, scheduled task, WMI"
        Modules     = "Persistence,ScheduledTasks,WMISubscriptions,RegistryRun,ServicesDrivers,EventLogs"
        Days        = 7
        Focus       = "All persistence surfaces, 4698/7045, registry run keys, COM hijack"
    }
    "6" = @{
        Name        = "SuspiciousPS"
        Description = "Suspicious PowerShell — encoded commands, AMSI bypass, download cradle"
        Modules     = "EventLogs,PowerShellHistory,ProcessTree,FileSystemAnomalies,BAM,AmCache,DefenderLogs"
        Days        = 3
        Focus       = "4104 script blocks, encoded PS, bypass flags, download strings"
    }
    "7" = @{
        Name        = "LOLBin"
        Description = "Living-off-the-land — certutil, mshta, regsvr32, bitsadmin misuse"
        Modules     = "EventLogs,Prefetch,ProcessTree,CertUtil,ScheduledTasks,BAM,AmCache"
        Days        = 3
        Focus       = "LOLBin process events, INetCache drops, suspicious child processes"
    }
    "8" = @{
        Name        = "C2Beacon"
        Description = "C2 beacon detected — outbound connections, DNS, scheduled callback"
        Modules     = "NetworkConnections,EventLogs,ProcessTree,ScheduledTasks,Persistence,BAM"
        Days        = 7
        Focus       = "Periodic outbound, suspicious DNS, process-to-network mapping, beaconing"
    }
    "9" = @{
        Name        = "FullTriage"
        Description = "Full forensic triage — all modules (slowest, most complete)"
        Modules     = "ALL"
        Days        = 7
        Focus       = "Complete artifact coverage across all attack surfaces"
    }
    "0" = @{
        Name        = "Custom"
        Description = "Custom — specify -Modules, -SuspectUser, etc. directly"
        Modules     = "ALL"
        Days        = 7
        Focus       = "Manual configuration"
    }
}

# Interactive picker if no scenario provided
if (-not $Scenario) {
    Write-Host "`n  GREGREP-OVERLORD QUICK LAUNCH" -ForegroundColor Cyan
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Select a scenario matching your alert type:`n"
    
    foreach ($key in $Scenarios.Keys) {
        $sc = $Scenarios[$key]
        Write-Host "  [$key] " -NoNewline -ForegroundColor Yellow
        Write-Host "$($sc.Name)" -NoNewline -ForegroundColor White
        Write-Host " — $($sc.Description)" -ForegroundColor Gray
    }
    
    Write-Host ""
    $choice = Read-Host "  Enter number"
    if (-not $Scenarios.ContainsKey($choice)) {
        Write-Error "Invalid choice: $choice"
        exit 1
    }
    $selected = $Scenarios[$choice]
} else {
    $selected = $Scenarios.Values | Where-Object { $_.Name -eq $Scenario } | Select-Object -First 1
    if (-not $selected) { Write-Error "Unknown scenario: $Scenario"; exit 1 }
}

# Override timeframe if provided
$Days = if ($TimeframeDays -gt 0) { $TimeframeDays } else { $selected.Days }

Write-Host "`n  Launching: " -NoNewline -ForegroundColor Cyan
Write-Host "$($selected.Name)" -ForegroundColor Yellow
Write-Host "  Focus    : $($selected.Focus)" -ForegroundColor Gray
Write-Host "  Modules  : $($selected.Modules)" -ForegroundColor Gray
Write-Host "  Timeframe: Last $Days days`n" -ForegroundColor Gray

# Build argument list
$Args = @(
    "-TimeframeDays", $Days,
    "-Modules", $selected.Modules
)
if ($SuspectUser)    { $Args += @("-SuspectUser",    $SuspectUser) }
if ($SuspectProcess) { $Args += @("-SuspectProcess", $SuspectProcess) }
if ($SuspectIP)      { $Args += @("-SuspectIP",      $SuspectIP) }

# Invoke main orchestrator
$ScriptPath = Join-Path $PSScriptRoot "Invoke-GregrepOverlord.ps1"
if (-not (Test-Path $ScriptPath)) {
    Write-Error "Cannot find Invoke-GregrepOverlord.ps1 at $ScriptPath"
    exit 1
}

& $ScriptPath @Args
