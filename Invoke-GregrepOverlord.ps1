#Requires -Version 5.1
<#
.SYNOPSIS
    Gregrep-Overlord: Forensic Triage Orchestrator for Windows
    
.DESCRIPTION
    A comprehensive incident response triage tool that collects artifacts across
    all major attack surfaces on Windows endpoints and servers. Outputs a
    self-contained HTML report and per-module CSV files for SIEM ingestion or
    analyst review.

    Inspired by EZ Tools (Eric Zimmerman) and KAPE collection logic, but implemented
    entirely in native PowerShell -- no binary dependencies required.

.PARAMETER OutputPath
    Directory to write reports and CSVs. Defaults to .\GregrepOverlord-Output\<hostname>-<datetime>

.PARAMETER TimeframeDays
    How far back to look for artifacts (default: 7 days)

.PARAMETER SuspectUser
    Optional: Focus analysis on a specific user account

.PARAMETER SuspectProcess
    Optional: Focus analysis on a specific process name or path

.PARAMETER SuspectIP
    Optional: Focus network analysis on a specific IP or hostname

.PARAMETER Modules
    Comma-separated list of modules to run. Default: ALL
    Available: EventLogs, BrowserArtifacts, ScheduledTasks, Prefetch, CertUtil,
               Persistence, NetworkConnections, ProcessTree, UserActivity,
               ShadowCopies, WMISubscriptions, PowerShellHistory, RecentFiles,
               LateralMovement, DefenderLogs, RegistryRun, FileSystemAnomalies,
               CredentialAccess, ServicesDrivers, AmCache, ShimCache, BAM

.PARAMETER SkipModules
    Comma-separated list of modules to skip

.EXAMPLE
    # Full triage
    .\Invoke-GregrepOverlord.ps1

.EXAMPLE
    # Alert-focused: suspicious user, last 3 days
    .\Invoke-GregrepOverlord.ps1 -TimeframeDays 3 -SuspectUser "jsmith" -SuspectProcess "powershell.exe"

.EXAMPLE
    # Run only event log and persistence modules
    .\Invoke-GregrepOverlord.ps1 -Modules "EventLogs,Persistence,RegistryRun"

.NOTES
    Author:  Gregrep-Overlord Project
    GitHub:  https://github.com/YOUR_USERNAME/Gregrep-Overlord
    Version: 1.0.0
    Requires: PowerShell 5.1+, Local Admin or SYSTEM privileges
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [int]$TimeframeDays = 7,
    [string]$SuspectUser = "",
    [string]$SuspectProcess = "",
    [string]$SuspectIP = "",
    [string]$Modules = "ALL",
    [string]$SkipModules = ""
)

Set-StrictMode -Version 2
$ErrorActionPreference = "Continue"

# --- BANNER -------------------------------------------------------------------
$Banner = @"

  ||||||+ ||||||+ |||||||+ ||||||+ ||||||+ |||||||+||||||+ 
 ||+====+ ||+==||+||+====+||+====+ ||+==||+||+====+||+==||+
 |||  |||+||||||++|||||+  |||  |||+||||||++|||||+  ||||||++
 |||   |||||+==||+||+==+  |||   |||||+==||+||+==+  ||+===+ 
 +||||||++|||  ||||||||||++||||||++|||  ||||||||||+|||     
  +=====+ +=+  +=++======+ +=====+ +=+  +=++======++=+     
          ||||||+ ||+   ||+|||||||+||||||+ ||+      ||||||+ ||||||+ ||||||+ 
         ||+===||+|||   |||||+====+||+==||+|||     ||+===||+||+==||+||+==||+
         |||   ||||||   ||||||||+  ||||||++|||     |||   |||||||||++|||  |||
         |||   |||+||+ ||++||+==+  ||+==||+|||     |||   |||||+==||+|||  |||
         +||||||++ +||||++ |||||||+|||  ||||||||||++||||||++|||  |||||||||++
          +=====+   +===+  +======++=+  +=++======+ +=====+ +=+  +=++=====+ 
  
  Forensic Triage Orchestrator v1.0.0  |  Windows Engine
  github.com/YOUR_USERNAME/Gregrep-Overlord
"@
Write-Host $Banner -ForegroundColor Cyan

# --- INIT ---------------------------------------------------------------------
$StartTime    = Get-Date
$Hostname     = $env:COMPUTERNAME
$OSVersion    = (Get-CimInstance Win32_OperatingSystem).Caption
$CurrentUser  = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$IsAdmin      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
$TimeframeCut = $StartTime.AddDays(-$TimeframeDays)

if (-not $IsAdmin) {
    Write-Warning "NOT running as Administrator. Some modules will have limited or no output."
    Write-Warning "Re-run as Administrator or SYSTEM for full artifact collection."
}

# Output directory
if (-not $OutputPath) {
    $Stamp      = $StartTime.ToString("yyyyMMdd-HHmmss")
    $OutputPath = ".\GregrepOverlord-Output\$Hostname-$Stamp"
}
$CSVPath = Join-Path $OutputPath "csv"
New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
New-Item -ItemType Directory -Force -Path $CSVPath   | Out-Null

# Module registry
$AllModules = @(
    "EventLogs","BrowserArtifacts","ScheduledTasks","Prefetch","CertUtil",
    "Persistence","NetworkConnections","ProcessTree","UserActivity",
    "ShadowCopies","WMISubscriptions","PowerShellHistory",
    "LateralMovement","DefenderLogs","FileSystemAnomalies",
    "CredentialAccess","ServicesDrivers","AmCache","BAM"
)

$RunModules = if ($Modules -eq "ALL") { $AllModules } else { $Modules -split "," | ForEach-Object { $_.Trim() } }
$SkipList   = if ($SkipModules) { $SkipModules -split "," | ForEach-Object { $_.Trim() } } else { @() }
$RunModules = $RunModules | Where-Object { $_ -notin $SkipList }

# Results accumulator
$Global:OverlordResults = [ordered]@{}
$Global:OverlordFindings = [System.Collections.Generic.List[hashtable]]::new()

# --- HELPERS ------------------------------------------------------------------
function Write-ModuleHeader {
    param([string]$Name, [string]$Description)
    Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline -ForegroundColor DarkGray
    Write-Host "> $Name" -ForegroundColor Yellow -NoNewline
    Write-Host " -- $Description" -ForegroundColor Gray
}

function Save-ModuleCSV {
    param([string]$ModuleName, [array]$Data)
    if ($Data -and $Data.Count -gt 0) {
        $CsvFile = Join-Path $CSVPath "$ModuleName.csv"
        $Data | Export-Csv -Path $CsvFile -NoTypeInformation -Encoding UTF8 -Force
        Write-Host "    [CSV] $($Data.Count) records -> $CsvFile" -ForegroundColor DarkGreen
    }
}

function Add-Finding {
    param([string]$Severity, [string]$Module, [string]$Title, [string]$Detail, [string]$Indicator = "")
    $Global:OverlordFindings.Add(@{
        Severity  = $Severity   # CRITICAL / HIGH / MEDIUM / LOW / INFO
        Module    = $Module
        Title     = $Title
        Detail    = $Detail
        Indicator = $Indicator
        Time      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    })
}

function Safe-Query {
    param([scriptblock]$Block, [string]$ModuleName)
    try { & $Block }
    catch {
        Write-Warning "[$ModuleName] Error: $($_.Exception.Message)"
        return @()
    }
}

function Get-XmlField {
    param([object]$Data, [string[]]$Names)
    try {
        $node = $Data | Where-Object { $_.Name -in $Names } | Select-Object -First 1
        if ($node -eq $null) { return "" }
        $val = $node.'#text'
        if ($val -eq $null) { return [string]$node.InnerText }
        return [string]$val
    } catch { return "" }
}

# --- MODULES ------------------------------------------------------------------

# MODULE 1: EVENT LOGS -- IOC-focused event collection
function Invoke-EventLogs {
    Write-ModuleHeader "EventLogs" "Parsing Security, System, Sysmon, PowerShell, WinRM, Task logs"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Security log -- core auth & process events
    $SecurityEvents = @{
        4624 = "Logon Success"
        4625 = "Logon Failure"
        4634 = "Logoff"
        4648 = "Explicit Credential Logon"
        4672 = "Special Privileges Assigned"
        4698 = "Scheduled Task Created"
        4699 = "Scheduled Task Deleted"
        4700 = "Scheduled Task Enabled"
        4701 = "Scheduled Task Disabled"
        4702 = "Scheduled Task Updated"
        4720 = "User Account Created"
        4722 = "User Account Enabled"
        4724 = "Password Reset Attempt"
        4725 = "User Account Disabled"
        4728 = "Member Added to Security Group"
        4732 = "Member Added to Local Group"
        4738 = "User Account Changed"
        4756 = "Member Added to Universal Group"
        4768 = "Kerberos TGT Requested"
        4769 = "Kerberos Service Ticket Requested"
        4771 = "Kerberos Pre-Auth Failed"
        4776 = "NTLM Auth Attempt"
        4688 = "Process Created"
        4689 = "Process Terminated"
        4663 = "Object Access Attempt"
        4670 = "Object Permissions Changed"
        4657 = "Registry Value Modified"
        4660 = "Object Deleted"
        4946 = "Firewall Rule Added"
        4947 = "Firewall Rule Modified"
        4950 = "Windows Firewall Setting Changed"
        5140 = "Network Share Accessed"
        5145 = "Network Share Object Access Check"
        7045 = "New Service Installed"
        7040 = "Service Start Type Changed"
    }

    foreach ($EvtId in $SecurityEvents.Keys) {
        $Evts = Safe-Query -ModuleName "EventLogs" -Block {
            Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = $EvtId
                StartTime = $TimeframeCut
            } -ErrorAction SilentlyContinue
        }
        foreach ($e in $Evts) {
            $xml  = [xml]$e.ToXml()
            $data = if ($xml.Event.EventData) { $xml.Event.EventData.Data } else { @() }
            $row  = [PSCustomObject]@{
                TimeCreated  = $e.TimeCreated
                EventId      = $e.Id
                Description  = $SecurityEvents[$EvtId]
                SubjectUser  = (Get-XmlField $data @('SubjectUserName'))
                TargetUser   = (Get-XmlField $data @('TargetUserName'))
                ProcessName  = (Get-XmlField $data @('NewProcessName','ProcessName'))
                CommandLine  = (Get-XmlField $data @('CommandLine'))
                LogonType    = (Get-XmlField $data @('LogonType'))
                IpAddress    = (Get-XmlField $data @('IpAddress'))
                WorkStation  = (Get-XmlField $data @('WorkstationName'))
                TaskName     = (Get-XmlField $data @('TaskName'))
                Message      = $e.Message -replace "`n"," " -replace "`r"," "
            }
            # IOC flagging
            if ($EvtId -eq 4688) {
                $cmd = $row.CommandLine
                $suspiciousPatterns = @(
                    'powershell.*-enc','powershell.*bypass','powershell.*hidden',
                    'cmd.*\/c.*http','certutil.*-decode','certutil.*-urlcache',
                    'mshta','wscript','cscript','regsvr32.*scrobj',
                    'rundll32.*javascript','bitsadmin.*transfer',
                    'wmic.*process.*call','schtasks.*\/create',
                    'net.*user.*\/add','net.*localgroup.*administrators',
                    'whoami','nltest','mimikatz','procdump','lsass'
                )
                foreach ($pat in $suspiciousPatterns) {
                    if ($cmd -match $pat) {
                        Add-Finding -Severity "HIGH" -Module "EventLogs" `
                            -Title "Suspicious Process Execution (4688)" `
                            -Detail "Process: $($row.ProcessName) | CMD: $cmd" `
                            -Indicator $pat
                    }
                }
            }
            if ($EvtId -eq 4698) {
                Add-Finding -Severity "MEDIUM" -Module "EventLogs" `
                    -Title "Scheduled Task Created (4698)" `
                    -Detail "Task: $($row.TaskName) by $($row.SubjectUser)" `
                    -Indicator "4698"
            }
            if ($EvtId -in @(4720,4728,4732)) {
                Add-Finding -Severity "HIGH" -Module "EventLogs" `
                    -Title "Account/Group Modification ($EvtId)" `
                    -Detail "$($SecurityEvents[$EvtId]) -- Target: $($row.TargetUser) by $($row.SubjectUser)" `
                    -Indicator "AccountModification"
            }
            if ($SuspectUser -and ($row.SubjectUser -like "*$SuspectUser*" -or $row.TargetUser -like "*$SuspectUser*")) {
                $row | Add-Member -NotePropertyName "FLAGGED_USER" -NotePropertyValue $true -Force
            }
            $results.Add($row)
        }
    }

    # Sysmon events (if available)
    $SysmonEvents = @{
        1  = "Process Create"
        3  = "Network Connection"
        6  = "Driver Loaded"
        7  = "Image Loaded"
        8  = "CreateRemoteThread"
        10 = "ProcessAccess"
        11 = "FileCreate"
        12 = "RegKeyCreate/Delete"
        13 = "RegValueSet"
        15 = "FileCreateStreamHash"
        17 = "PipeCreated"
        22 = "DNS Query"
        23 = "FileDelete"
        25 = "ProcessTampering"
    }
    $SysmonAvail = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
    if ($SysmonAvail) {
        foreach ($SysId in $SysmonEvents.Keys) {
            $SysEvts = Safe-Query -ModuleName "EventLogs-Sysmon" -Block {
                Get-WinEvent -FilterHashtable @{
                    LogName   = 'Microsoft-Windows-Sysmon/Operational'
                    Id        = $SysId
                    StartTime = $TimeframeCut
                } -ErrorAction SilentlyContinue
            }
            foreach ($e in $SysEvts) {
                $xml  = [xml]$e.ToXml()
                $data = if ($xml.Event.EventData) { $xml.Event.EventData.Data } else { @() }
                $row  = [PSCustomObject]@{
                    TimeCreated  = $e.TimeCreated
                    EventId      = "Sysmon-$SysId"
                    Description  = $SysmonEvents[$SysId]
                    SubjectUser  = (Get-XmlField $data @('User'))
                    ProcessName  = (Get-XmlField $data @('Image'))
                    CommandLine  = (Get-XmlField $data @('CommandLine'))
                    TargetImage  = (Get-XmlField $data @('TargetImage','ImageLoaded'))
                    Hashes       = (Get-XmlField $data @('Hashes'))
                    DestIP       = (Get-XmlField $data @('DestinationIp'))
                    DestPort     = (Get-XmlField $data @('DestinationPort'))
                    QueryName    = (Get-XmlField $data @('QueryName'))
                    TargetFile   = (Get-XmlField $data @('TargetFilename'))
                    Message      = $e.Message -replace "`n"," " -replace "`r"," "
                }
                # Sysmon IOC flags
                if ($SysId -eq 8) {
                    Add-Finding -Severity "CRITICAL" -Module "EventLogs-Sysmon" `
                        -Title "CreateRemoteThread (Sysmon 8) -- Possible Code Injection" `
                        -Detail "Source: $($row.ProcessName) -> Target: $($row.TargetImage)" `
                        -Indicator "RemoteThreadInjection"
                }
                if ($SysId -eq 10 -and $row.TargetImage -match "lsass") {
                    Add-Finding -Severity "CRITICAL" -Module "EventLogs-Sysmon" `
                        -Title "LSASS Memory Access (Sysmon 10) -- Credential Dumping Attempt" `
                        -Detail "Source: $($row.ProcessName)" `
                        -Indicator "LSASSDump"
                }
                if ($SysId -eq 3 -and $SuspectIP -and $row.DestIP -like "*$SuspectIP*") {
                    Add-Finding -Severity "HIGH" -Module "EventLogs-Sysmon" `
                        -Title "Network Connection to Suspect IP (Sysmon 3)" `
                        -Detail "$($row.ProcessName) -> $($row.DestIP):$($row.DestPort)" `
                        -Indicator $SuspectIP
                }
                $results.Add($row)
            }
        }
    }

    # PowerShell Script Block Logging (4104)
    $PSLogs = Safe-Query -ModuleName "EventLogs-PS" -Block {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            Id        = @(4103,4104,4105,4106)
            StartTime = $TimeframeCut
        } -ErrorAction SilentlyContinue
    }
    foreach ($e in $PSLogs) {
        $row = [PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventId     = "PSLog-$($e.Id)"
            Description = "PowerShell Script Block"
            Message     = $e.Message -replace "`n"," " -replace "`r"," " | Select-Object -First 1
        }
        $suspicious = @('invoke-mimikatz','invoke-expression','iex\(','downloadstring','downloadfile',
                        'webclient','bypass','reflective','shellcode','virtualalloc',
                        'marshal','loadlibrary','amsiutils','[convert]::from')
        foreach ($pat in $suspicious) {
            if ($e.Message -match $pat) {
                Add-Finding -Severity "CRITICAL" -Module "EventLogs-PS" `
                    -Title "Suspicious PowerShell Script Block (4104)" `
                    -Detail ($e.Message -replace "`n"," " | Select-Object -First 500) `
                    -Indicator $pat
            }
        }
        $results.Add($row)
    }

    # WinRM / Remote Sessions
    $WinRMEvents = Safe-Query -ModuleName "EventLogs-WinRM" -Block {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-WinRM/Operational'
            Id        = @(6,8,15,16,91,168)
            StartTime = $TimeframeCut
        } -ErrorAction SilentlyContinue
    }
    foreach ($e in $WinRMEvents) {
        $row = [PSCustomObject]@{
            TimeCreated = $e.TimeCreated
            EventId     = "WinRM-$($e.Id)"
            Description = "WinRM Remote Session"
            Message     = $e.Message -replace "`n"," " -replace "`r"," "
        }
        Add-Finding -Severity "MEDIUM" -Module "EventLogs-WinRM" `
            -Title "WinRM Session Activity" `
            -Detail $row.Message `
            -Indicator "WinRM"
        $results.Add($row)
    }

    $Global:OverlordResults["EventLogs"] = $results
    Save-ModuleCSV -ModuleName "EventLogs" -Data $results
    Write-Host "    OK $($results.Count) event records collected" -ForegroundColor Green
}

# MODULE 2: BROWSER ARTIFACTS
function Invoke-BrowserArtifacts {
    Write-ModuleHeader "BrowserArtifacts" "Chrome, Edge, Firefox -- history, downloads, extensions"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($Profile in $UserProfiles) {
        if ($SuspectUser -and $Profile.Name -notlike "*$SuspectUser*") { continue }

        $BrowserPaths = @{
            "Chrome"  = @{
                History   = "$($Profile.FullName)\AppData\Local\Google\Chrome\User Data\Default\History"
                Downloads = "$($Profile.FullName)\AppData\Local\Google\Chrome\User Data\Default\History"
                Extensions= "$($Profile.FullName)\AppData\Local\Google\Chrome\User Data\Default\Extensions"
            }
            "Edge"    = @{
                History   = "$($Profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\History"
                Downloads = "$($Profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\History"
                Extensions= "$($Profile.FullName)\AppData\Local\Microsoft\Edge\User Data\Default\Extensions"
            }
            "Firefox" = @{
                History   = "$($Profile.FullName)\AppData\Roaming\Mozilla\Firefox\Profiles"
            }
        }

        foreach ($Browser in $BrowserPaths.Keys) {
            # Chrome/Edge History (SQLite -- copy first to avoid lock)
            $HistPath = $BrowserPaths[$Browser]["History"]
            if ($HistPath -and (Test-Path $HistPath)) {
                try {
                    $TempDb = "$env:TEMP\GO_${Browser}_History_$($Profile.Name).db"
                    Copy-Item $HistPath $TempDb -Force -ErrorAction SilentlyContinue

                    # Use .NET SQLite if available, else parse raw strings
                    $RawContent = [System.IO.File]::ReadAllText($TempDb, [System.Text.Encoding]::Latin1)
                    $UrlPattern = 'https?://[^\x00-\x1f\x7f"'' ]{10,500}'
                    $RegexMatches = [regex]::Matches($RawContent, $UrlPattern)
                    $Seen       = [System.Collections.Generic.HashSet[string]]::new()
                    foreach ($m in $RegexMatches) {
                        $url = $m.Value.TrimEnd('.')
                        if ($Seen.Add($url)) {
                            $row = [PSCustomObject]@{
                                User    = $Profile.Name
                                Browser = $Browser
                                Type    = "History"
                                URL     = $url
                                Source  = $HistPath
                            }
                            # Flag suspicious URLs
                            $suspURL = @('pastebin','paste\.ee','hastebin','temp\.sh','ngrok',
                                         '\.onion','github.*raw','transfer\.sh','anonfiles',
                                         '\.ps1$','\.exe$','\.bat$','\.vbs$','\.hta$')
                            foreach ($pat in $suspURL) {
                                if ($url -match $pat) {
                                    Add-Finding -Severity "HIGH" -Module "BrowserArtifacts" `
                                        -Title "Suspicious Browser URL -- $Browser ($($Profile.Name))" `
                                        -Detail $url -Indicator $pat
                                }
                            }
                            $results.Add($row)
                        }
                    }
                    Remove-Item $TempDb -Force -ErrorAction SilentlyContinue
                } catch {
                    Write-Warning "  [BrowserArtifacts] Could not parse $Browser history for $($Profile.Name): $($_.Exception.Message)"
                }
            }

            # Firefox profiles
            if ($Browser -eq "Firefox" -and (Test-Path $HistPath)) {
                $FFProfiles = Get-ChildItem $HistPath -Directory -ErrorAction SilentlyContinue
                foreach ($FFP in $FFProfiles) {
                    $PlacesDb = Join-Path $FFP.FullName "places.sqlite"
                    if (Test-Path $PlacesDb) {
                        try {
                            $TempDb  = "$env:TEMP\GO_FF_Places_$($Profile.Name).db"
                            Copy-Item $PlacesDb $TempDb -Force -ErrorAction SilentlyContinue
                            $Raw     = [System.IO.File]::ReadAllText($TempDb, [System.Text.Encoding]::Latin1)
                            $Matches = [regex]::Matches($Raw, 'https?://[^\x00-\x1f\x7f"'' ]{10,500}')
                            $Seen    = [System.Collections.Generic.HashSet[string]]::new()
                            foreach ($m in $RegexMatches) {
                                $url = $m.Value.TrimEnd('.')
                                if ($Seen.Add($url)) {
                                    $results.Add([PSCustomObject]@{
                                        User    = $Profile.Name
                                        Browser = "Firefox"
                                        Type    = "History"
                                        URL     = $url
                                        Source  = $PlacesDb
                                    })
                                }
                            }
                            Remove-Item $TempDb -Force -ErrorAction SilentlyContinue
                        } catch { }
                    }
                }
            }

            # Extension inventory (Chrome/Edge)
            $ExtPath = $BrowserPaths[$Browser]["Extensions"]
            if ($ExtPath -and (Test-Path $ExtPath)) {
                $Extensions = Get-ChildItem $ExtPath -Directory -ErrorAction SilentlyContinue
                foreach ($ext in $Extensions) {
                    $ManifestPath = Get-ChildItem $ext.FullName -Recurse -Filter "manifest.json" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($ManifestPath) {
                        try {
                            $manifest = Get-Content $ManifestPath.FullName -Raw | ConvertFrom-Json -ErrorAction SilentlyContinue
                            $row = [PSCustomObject]@{
                                User        = $Profile.Name
                                Browser     = $Browser
                                Type        = "Extension"
                                ExtId       = $ext.Name
                                ExtName     = $manifest.name
                                Version     = $manifest.version
                                Permissions = ($manifest.permissions -join ", ")
                                Source      = $ext.FullName
                            }
                            # Flag overly permissive or suspicious extensions
                            $suspPerms = @('nativeMessaging','<all_urls>','webRequest','proxy','cookies','tabs','history')
                            foreach ($p in $suspPerms) {
                                if ($row.Permissions -match $p) {
                                    Add-Finding -Severity "MEDIUM" -Module "BrowserArtifacts" `
                                        -Title "Browser Extension with $p Permission -- $Browser" `
                                        -Detail "$($row.ExtName) ($($ext.Name)) user:$($Profile.Name)" `
                                        -Indicator "ExtPermission:$p"
                                }
                            }
                            $results.Add($row)
                        } catch { }
                    }
                }
            }
        }
    }

    $Global:OverlordResults["BrowserArtifacts"] = $results
    Save-ModuleCSV -ModuleName "BrowserArtifacts" -Data $results
    Write-Host "    OK $($results.Count) browser records collected" -ForegroundColor Green
}

# MODULE 3: SCHEDULED TASKS
function Invoke-ScheduledTasks {
    Write-ModuleHeader "ScheduledTasks" "Task anomalies, scripting engines, suspicious paths"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $Tasks = Safe-Query -ModuleName "ScheduledTasks" -Block {
        Get-ScheduledTask -ErrorAction SilentlyContinue
    }

    foreach ($Task in $Tasks) {
        $Actions = $Task.Actions
        foreach ($Action in $Actions) {
            $Execute = $Action.Execute
            $Args    = $Action.Arguments
            $row = [PSCustomObject]@{
                TaskName    = $Task.TaskName
                TaskPath    = $Task.TaskPath
                State       = $Task.State
                Author      = $Task.Principal.UserId
                RunLevel    = $Task.Principal.RunLevel
                Execute     = $Execute
                Arguments   = $Args
                Description = $Task.Description
                LastRun     = try { $Task.LastRunTime } catch { "" }
                NextRun     = try { $Task.NextRunTime } catch { "" }
                TriggerType = ($Task.Triggers | Select-Object -ExpandProperty CimClass -ErrorAction SilentlyContinue) -join ";"
                FullCommand = "$Execute $Args"
            }

            $suspPatterns = @(
                'powershell','cmd\.exe','wscript','cscript','mshta','rundll32',
                'regsvr32','bitsadmin','certutil','wmic','msiexec.*http',
                '\\temp\\','\\appdata\\','\\programdata\\','\\public\\',
                '%temp%','%appdata%','%programdata%',
                'http://','https://','\\\\',  # UNC or web
                '\.ps1',  '\.vbs',  '\.js',  '\.hta', '\.bat', '\.cmd'
            )
            $flagged = $false
            foreach ($pat in $suspPatterns) {
                if (($row.PSObject.Properties["FullCommand"] -and $row.FullCommand -match $pat) -or ($row.PSObject.Properties["TaskName"] -and $row.TaskName -match $pat)) {
                    if (-not $flagged) {
                        Add-Finding -Severity "HIGH" -Module "ScheduledTasks" `
                            -Title "Suspicious Scheduled Task: $($Task.TaskName)" `
                            -Detail "Execute: $Execute | Args: $Args" `
                            -Indicator $pat
                        $flagged = $true
                    }
                }
            }

            # Tasks in non-standard paths
            if ($Task.TaskPath -notmatch '\\Microsoft\\') {
                Add-Finding -Severity "MEDIUM" -Module "ScheduledTasks" `
                    -Title "Non-Microsoft Task Path: $($Task.TaskName)" `
                    -Detail "Path: $($Task.TaskPath) | Exec: $Execute" `
                    -Indicator "NonMicrosoftPath"
            }

            $results.Add($row)
        }
    }

    $Global:OverlordResults["ScheduledTasks"] = $results
    Save-ModuleCSV -ModuleName "ScheduledTasks" -Data $results
    Write-Host "    OK $($results.Count) scheduled task records" -ForegroundColor Green
}

# MODULE 4: PREFETCH
function Invoke-Prefetch {
    Write-ModuleHeader "Prefetch" "Executable run evidence from Prefetch files"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $PrefetchPath = "C:\Windows\Prefetch"
    if (-not (Test-Path $PrefetchPath)) {
        Write-Warning "  Prefetch not available (may be disabled or Server OS)"
        return
    }

    $PfFiles = Get-ChildItem $PrefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
    foreach ($pf in $PfFiles) {
        $ExeName = $pf.Name -replace "-[A-F0-9]{8}\.pf$", ""
        $row = [PSCustomObject]@{
            ExecutableName = $ExeName
            PrefetchFile   = $pf.Name
            LastModified   = $pf.LastWriteTime
            CreatedTime    = $pf.CreationTime
            SizeBytes      = $pf.Length
        }

        # Flag suspicious execution locations inferred from name
        $suspNames = @(
            'POWERSHELL','CMD','MSHTA','WSCRIPT','CSCRIPT','RUNDLL32','REGSVR32',
            'CERTUTIL','BITSADMIN','WMIC','MSIEXEC','PSEXEC','MIMIKATZ',
            'PROCDUMP','COBALTSTRIKE','BEACON','FREEWARE','TEMP','CRACK','HACK'
        )
        foreach ($name in $suspNames) {
            if ($ExeName -match $name) {
                Add-Finding -Severity "MEDIUM" -Module "Prefetch" `
                    -Title "Suspicious Prefetch Entry: $ExeName" `
                    -Detail "Last run: $($pf.LastWriteTime) | PF: $($pf.Name)" `
                    -Indicator $name
            }
        }

        # Recently modified prefetch (within timeframe)
        if ($pf.LastWriteTime -gt $TimeframeCut) {
            $row | Add-Member -NotePropertyName "WithinTimeframe" -NotePropertyValue $true -Force
        }

        $results.Add($row)
    }

    $Global:OverlordResults["Prefetch"] = $results
    Save-ModuleCSV -ModuleName "Prefetch" -Data $results
    Write-Host "    OK $($results.Count) prefetch files parsed" -ForegroundColor Green
}

# MODULE 5: CERTUTIL CACHE / LIVING-OFF-THE-LAND ARTIFACTS
function Invoke-CertUtil {
    Write-ModuleHeader "CertUtil" "INetCache drops, certutil decode artifacts, LOLBin artifacts"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($Profile in $UserProfiles) {
        # INetCache -- certutil often drops here
        $INetPaths = @(
            "$($Profile.FullName)\AppData\Local\Microsoft\Windows\INetCache",
            "$($Profile.FullName)\AppData\Local\Microsoft\Windows\Temporary Internet Files"
        )
        foreach ($INetPath in $INetPaths) {
            if (Test-Path $INetPath) {
                $Files = Get-ChildItem $INetPath -Recurse -ErrorAction SilentlyContinue -File |
                    Where-Object { $_.LastWriteTime -gt $TimeframeCut }
                foreach ($f in $Files) {
                    $row = [PSCustomObject]@{
                        User         = $Profile.Name
                        FileName     = $f.Name
                        FullPath     = $f.FullName
                        Extension    = $f.Extension
                        SizeBytes    = $f.Length
                        LastModified = $f.LastWriteTime
                        Created      = $f.CreationTime
                    }
                    $suspExts = @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.hta','.js','.jar','.py','.bin','.tmp')
                    if ($f.Extension -in $suspExts) {
                        Add-Finding -Severity "HIGH" -Module "CertUtil" `
                            -Title "Suspicious File in INetCache: $($f.Name)" `
                            -Detail "User: $($Profile.Name) | Path: $($f.FullName)" `
                            -Indicator "INetCacheDrop"
                    }
                    $results.Add($row)
                }
            }
        }

        # Check temp locations for decoded artifacts
        $TempPaths = @(
            "$($Profile.FullName)\AppData\Local\Temp",
            "C:\Windows\Temp",
            "C:\ProgramData"
        )
        foreach ($TempPath in $TempPaths) {
            if (Test-Path $TempPath) {
                $TempFiles = Get-ChildItem $TempPath -ErrorAction SilentlyContinue -File |
                    Where-Object { $_.LastWriteTime -gt $TimeframeCut -and $_.Extension -in @('.exe','.dll','.ps1','.bat','.vbs','.hta','.js') }
                foreach ($f in $TempFiles) {
                    $row = [PSCustomObject]@{
                        User         = $Profile.Name
                        FileName     = $f.Name
                        FullPath     = $f.FullName
                        Extension    = $f.Extension
                        SizeBytes    = $f.Length
                        LastModified = $f.LastWriteTime
                        Created      = $f.CreationTime
                    }
                    Add-Finding -Severity "HIGH" -Module "CertUtil" `
                        -Title "Executable/Script in Temp: $($f.Name)" `
                        -Detail "User: $($Profile.Name) | Path: $($f.FullName)" `
                        -Indicator "TempDrop"
                    $results.Add($row)
                }
            }
        }
    }

    $Global:OverlordResults["CertUtil"] = $results
    Save-ModuleCSV -ModuleName "CertUtil" -Data $results
    Write-Host "    OK $($results.Count) cache/temp artifacts found" -ForegroundColor Green
}

# MODULE 6: PERSISTENCE MECHANISMS
function Invoke-Persistence {
    Write-ModuleHeader "Persistence" "Startup folders, Run keys, services, DLL hijack paths"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Startup Folders
    $StartupPaths = @(
        "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($p in $UserProfiles) {
        $StartupPaths += "$($p.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    foreach ($sp in $StartupPaths) {
        if (Test-Path $sp) {
            Get-ChildItem $sp -ErrorAction SilentlyContinue | ForEach-Object {
                $row = [PSCustomObject]@{
                    Type     = "StartupFolder"
                    Name     = $_.Name
                    FullPath = $_.FullName
                    Modified = $_.LastWriteTime
                    Source   = $sp
                }
                Add-Finding -Severity "HIGH" -Module "Persistence" `
                    -Title "Item in Startup Folder: $($_.Name)" `
                    -Detail $_.FullName -Indicator "StartupFolder"
                $results.Add($row)
            }
        }
    }

    # Registry Run Keys
    $RunKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\System\CurrentControlSet\Control\Session Manager\BootExecute",
        "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM:\System\CurrentControlSet\Services"
    )
    foreach ($key in $RunKeys) {
        if (Test-Path $key) {
            try {
                $RegVals = Get-ItemProperty $key -ErrorAction SilentlyContinue
                $RegVals.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $row = [PSCustomObject]@{
                        Type     = "RegistryRun"
                        KeyPath  = $key
                        Name     = $_.Name
                        Value    = $_.Value
                        Modified = (Get-Item $key -ErrorAction SilentlyContinue).LastWriteTime
                    }
                    $suspVal = @('powershell','cmd','mshta','wscript','cscript','rundll32',
                                  'regsvr32','\\temp\\','\\appdata\\','http://','https://')
                    foreach ($pat in $suspVal) {
                        if ($_.Value -match $pat) {
                            Add-Finding -Severity "HIGH" -Module "Persistence" `
                                -Title "Suspicious Registry Run Entry: $($_.Name)" `
                                -Detail "Key: $key | Value: $($_.Value)" `
                                -Indicator $pat
                        }
                    }
                    $results.Add($row)
                }
            } catch { }
        }
    }

    # AppInit DLLs (classic DLL hijack persistence)
    $AppInit = Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" `
        -Name AppInit_DLLs -ErrorAction SilentlyContinue
    if ($AppInit -and $AppInit.AppInit_DLLs) {
        Add-Finding -Severity "CRITICAL" -Module "Persistence" `
            -Title "AppInit_DLLs Persistence Detected" `
            -Detail $AppInit.AppInit_DLLs -Indicator "AppInitDLL"
        $results.Add([PSCustomObject]@{
            Type    = "AppInit_DLL"
            KeyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
            Name    = "AppInit_DLLs"
            Value   = $AppInit.AppInit_DLLs
        })
    }

    # COM Hijacking -- UserAssist, InprocServer32 anomalies
    $COMPaths = @("HKCU:\Software\Classes\CLSID","HKCU:\Software\Classes\*\shell")
    foreach ($com in $COMPaths) {
        if (Test-Path $com) {
            Get-ChildItem $com -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $inproc = Get-ItemProperty (Join-Path $_.PSPath "InprocServer32") -ErrorAction SilentlyContinue
                if ($inproc -and $inproc.'(default)') {
                    $dll = $inproc.'(default)'
                    if ($dll -match '\\temp\\|\\appdata\\|\\public\\|\\programdata\\') {
                        Add-Finding -Severity "HIGH" -Module "Persistence" `
                            -Title "COM Hijack: HKCU InprocServer32 in Suspicious Path" `
                            -Detail "CLSID: $($_.PSChildName) | DLL: $dll" `
                            -Indicator "COMHijack"
                        $results.Add([PSCustomObject]@{
                            Type    = "COMHijack"
                            KeyPath = $_.PSPath
                            Name    = "InprocServer32"
                            Value   = $dll
                        })
                    }
                }
            }
        }
    }

    $Global:OverlordResults["Persistence"] = $results
    Save-ModuleCSV -ModuleName "Persistence" -Data $results
    Write-Host "    OK $($results.Count) persistence artifacts found" -ForegroundColor Green
}

# MODULE 7: NETWORK CONNECTIONS
function Invoke-NetworkConnections {
    Write-ModuleHeader "NetworkConnections" "Active TCP/UDP, listening ports, process-to-connection mapping"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $Connections = Safe-Query -ModuleName "NetworkConnections" -Block {
        Get-NetTCPConnection -ErrorAction SilentlyContinue
    }
    $ProcessMap = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $ProcessMap[$_.Id] = $_.Name }

    foreach ($conn in $Connections) {
        $row = [PSCustomObject]@{
            State         = $conn.State
            LocalAddress  = $conn.LocalAddress
            LocalPort     = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort    = $conn.RemotePort
            ProcessId     = $conn.OwningProcess
            ProcessName   = $ProcessMap[$conn.OwningProcess]
            CreationTime  = $conn.CreationTime
        }
        # Flag suspicious remote IPs and ports
        if ($conn.State -eq "Established" -and $conn.RemoteAddress -ne "0.0.0.0" -and $conn.RemoteAddress -ne "127.0.0.1") {
            $suspPorts = @(4444,5555,8080,8443,9001,9002,1337,31337,4899,22,23,3389)
            if ($conn.RemotePort -in $suspPorts) {
                Add-Finding -Severity "HIGH" -Module "NetworkConnections" `
                    -Title "Suspicious Outbound Port: $($conn.RemotePort)" `
                    -Detail "$($row.ProcessName) (PID $($conn.OwningProcess)) -> $($conn.RemoteAddress):$($conn.RemotePort)" `
                    -Indicator "Port:$($conn.RemotePort)"
            }
            if ($SuspectIP -and $conn.RemoteAddress -like "*$SuspectIP*") {
                Add-Finding -Severity "CRITICAL" -Module "NetworkConnections" `
                    -Title "Active Connection to Suspect IP" `
                    -Detail "$($row.ProcessName) (PID $($conn.OwningProcess)) -> $($conn.RemoteAddress):$($conn.RemotePort)" `
                    -Indicator $SuspectIP
            }
        }
        $results.Add($row)
    }

    # DNS Cache
    $DNSCache = Safe-Query -ModuleName "NetworkConnections-DNS" -Block {
        Get-DnsClientCache -ErrorAction SilentlyContinue
    }
    foreach ($dns in $DNSCache) {
        $row = [PSCustomObject]@{
            State         = "DNS"
            LocalAddress  = "DNS-Cache"
            RemoteAddress = $dns.Entry
            RemotePort    = "DNS"
            ProcessName   = "DNS-Cache"
            Data          = $dns.Data
            Type          = $dns.Type
        }
        $suspDomains = @('ngrok','\.tk$','\.pw$','\.top$','\.xyz$','\.ru$','duckdns',
                          'no-ip\.','ddns\.','pastebin','hastebin','rawgit')
        foreach ($pat in $suspDomains) {
            if ($dns.Entry -match $pat) {
                Add-Finding -Severity "HIGH" -Module "NetworkConnections" `
                    -Title "Suspicious DNS Cache Entry" `
                    -Detail $dns.Entry -Indicator $pat
            }
        }
        $results.Add($row)
    }

    $Global:OverlordResults["NetworkConnections"] = $results
    Save-ModuleCSV -ModuleName "NetworkConnections" -Data $results
    Write-Host "    OK $($results.Count) network records collected" -ForegroundColor Green
}

# MODULE 8: PROCESS TREE
function Invoke-ProcessTree {
    Write-ModuleHeader "ProcessTree" "Running processes, parent-child relationships, suspicious paths"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $Processes = Safe-Query -ModuleName "ProcessTree" -Block {
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    }
    $ProcMap = @{}
    foreach ($p in $Processes) { $ProcMap[$p.ProcessId] = $p.Name }

    foreach ($proc in $Processes) {
        $row = [PSCustomObject]@{
            ProcessId    = $proc.ProcessId
            ProcessName  = $proc.Name
            ParentPid    = $proc.ParentProcessId
            ParentName   = $ProcMap[$proc.ParentProcessId]
            ExecutablePath = $proc.ExecutablePath
            CommandLine  = $proc.CommandLine
            Owner        = (Invoke-CimMethod -InputObject $proc -MethodName GetOwner -ErrorAction SilentlyContinue).User
            CreationDate = $proc.CreationDate
        }

        # Parent-child anomalies
        $suspawnPatterns = @(
            @{ Parent = 'winword|excel|powerpnt|outlook'; Child = 'cmd|powershell|wscript|cscript|mshta' },
            @{ Parent = 'explorer'; Child = 'powershell.*-enc|powershell.*hidden' },
            @{ Parent = 'svchost'; Child = 'powershell|cmd|wscript' },
            @{ Parent = 'lsass'; Child = '.*' }
        )
        foreach ($pat in $suspawnPatterns) {
            if ($row.ParentName -match $pat.Parent -and $row.ProcessName -match $pat.Child) {
                Add-Finding -Severity "CRITICAL" -Module "ProcessTree" `
                    -Title "Suspicious Process Spawn: $($row.ParentName) -> $($row.ProcessName)" `
                    -Detail "PID: $($proc.ProcessId) | CMD: $($proc.CommandLine)" `
                    -Indicator "SuspiciousSpawn"
            }
        }

        # Executable from suspicious paths
        if ($proc.ExecutablePath -match '\\temp\\|\\appdata\\|\\public\\|\\programdata\\|\\downloads\\') {
            Add-Finding -Severity "HIGH" -Module "ProcessTree" `
                -Title "Process Running from Suspicious Path" `
                -Detail "$($proc.Name) (PID $($proc.ProcessId)) from $($proc.ExecutablePath)" `
                -Indicator "SuspiciousPath"
        }

        if ($SuspectProcess -and $proc.Name -like "*$SuspectProcess*") {
            Add-Finding -Severity "HIGH" -Module "ProcessTree" `
                -Title "Suspect Process Found: $($proc.Name)" `
                -Detail "PID: $($proc.ProcessId) | CMD: $($proc.CommandLine)" `
                -Indicator $SuspectProcess
        }

        $results.Add($row)
    }

    $Global:OverlordResults["ProcessTree"] = $results
    Save-ModuleCSV -ModuleName "ProcessTree" -Data $results
    Write-Host "    OK $($results.Count) processes analyzed" -ForegroundColor Green
}

# MODULE 9: USER ACTIVITY
function Invoke-UserActivity {
    Write-ModuleHeader "UserActivity" "Recently logged on users, RDP sessions, account anomalies"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Local users and last logon
    $Users = Safe-Query -ModuleName "UserActivity" -Block {
        Get-LocalUser -ErrorAction SilentlyContinue
    }
    foreach ($u in $Users) {
        $row = [PSCustomObject]@{
            Type           = "LocalUser"
            Username       = $u.Name
            Enabled        = $u.Enabled
            LastLogon      = $u.LastLogon
            PasswordLastSet = $u.PasswordLastSet
            PasswordExpires = $u.PasswordExpires
            Description    = $u.Description
        }
        if ($u.Enabled -and -not $u.PasswordExpires -and $u.Name -notmatch 'Administrator|Guest|DefaultAccount|WDAGUtility') {
            Add-Finding -Severity "MEDIUM" -Module "UserActivity" `
                -Title "Local Account with Non-Expiring Password: $($u.Name)" `
                -Detail "Last Logon: $($u.LastLogon)" -Indicator "NoPassExpiry"
        }
        $results.Add($row)
    }

    # Recently accessed files (RecentDocs)
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($Profile in $UserProfiles) {
        $RecentPath = "$($Profile.FullName)\AppData\Roaming\Microsoft\Windows\Recent"
        if (Test-Path $RecentPath) {
            Get-ChildItem $RecentPath -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $TimeframeCut } |
                ForEach-Object {
                    $results.Add([PSCustomObject]@{
                        Type     = "RecentDoc"
                        Username = $Profile.Name
                        FileName = $_.Name
                        FullPath = $_.FullName
                        Accessed = $_.LastWriteTime
                    })
                }
        }

        # Jump lists
        $JumpPath = "$($Profile.FullName)\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"
        if (Test-Path $JumpPath) {
            $JumpCount = (Get-ChildItem $JumpPath -ErrorAction SilentlyContinue).Count
            $results.Add([PSCustomObject]@{
                Type     = "JumpList"
                Username = $Profile.Name
                FileName = "AutomaticDestinations"
                FullPath = $JumpPath
                Accessed = (Get-Item $JumpPath).LastWriteTime
                Count    = $JumpCount
            })
        }
    }

    $Global:OverlordResults["UserActivity"] = $results
    Save-ModuleCSV -ModuleName "UserActivity" -Data $results
    Write-Host "    OK $($results.Count) user activity records" -ForegroundColor Green
}

# MODULE 10: WMI SUBSCRIPTIONS
function Invoke-WMISubscriptions {
    Write-ModuleHeader "WMISubscriptions" "WMI event subscriptions -- common fileless persistence"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $WMIFilters = Safe-Query -ModuleName "WMI" -Block {
        Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    }
    foreach ($f in $WMIFilters) {
        $row = [PSCustomObject]@{
            Type     = "WMI-EventFilter"
            Name     = $f.Name
            Query    = $f.Query
            Language = $f.QueryLanguage
        }
        Add-Finding -Severity "HIGH" -Module "WMISubscriptions" `
            -Title "WMI Event Filter: $($f.Name)" `
            -Detail $f.Query -Indicator "WMIPersistence"
        $results.Add($row)
    }

    $WMIConsumers = Safe-Query -ModuleName "WMI" -Block {
        Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
    }
    foreach ($c in $WMIConsumers) {
        $row = [PSCustomObject]@{
            Type     = "WMI-CommandConsumer"
            Name     = $c.Name
            Command  = $c.CommandLineTemplate
        }
        Add-Finding -Severity "CRITICAL" -Module "WMISubscriptions" `
            -Title "WMI CommandLine Consumer: $($c.Name)" `
            -Detail $c.CommandLineTemplate -Indicator "WMICommandConsumer"
        $results.Add($row)
    }

    $WMIScriptConsumers = Safe-Query -ModuleName "WMI" -Block {
        Get-WMIObject -Namespace root\subscription -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue
    }
    foreach ($c in $WMIScriptConsumers) {
        $row = [PSCustomObject]@{
            Type   = "WMI-ScriptConsumer"
            Name   = $c.Name
            Script = $c.ScriptText
        }
        Add-Finding -Severity "CRITICAL" -Module "WMISubscriptions" `
            -Title "WMI ActiveScript Consumer: $($c.Name)" `
            -Detail ($c.ScriptText | Select-Object -First 200) -Indicator "WMIScriptConsumer"
        $results.Add($row)
    }

    if ($results.Count -eq 0) {
        Write-Host "    OK No WMI subscriptions found (clean)" -ForegroundColor DarkGray
    }

    $Global:OverlordResults["WMISubscriptions"] = $results
    Save-ModuleCSV -ModuleName "WMISubscriptions" -Data $results
    Write-Host "    OK $($results.Count) WMI subscription records" -ForegroundColor Green
}

# MODULE 11: POWERSHELL HISTORY
function Invoke-PowerShellHistory {
    Write-ModuleHeader "PowerShellHistory" "ConsoleHost_history.txt from all user profiles"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($Profile in $UserProfiles) {
        $HistFile = "$($Profile.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $HistFile) {
            $Lines = Get-Content $HistFile -ErrorAction SilentlyContinue
            $LineNum = 0
            foreach ($line in $Lines) {
                $LineNum++
                $row = [PSCustomObject]@{
                    User    = $Profile.Name
                    LineNum = $LineNum
                    Command = $line
                }
                $suspCmds = @(
                    'invoke-expression','iex\s*\(','downloadstring','downloadfile',
                    '-enc\s+[A-Za-z0-9+/=]{20,}','bypass','hidden',
                    'add-mppreference.*exclusion','set-mppreference.*disable',
                    'net\s+user.*\/add','net\s+localgroup',
                    'whoami','nltest','bloodhound','sharphound','rubeus',
                    'mimikatz','sekurlsa','lsadump','dump.*creds'
                )
                foreach ($pat in $suspCmds) {
                    if ($line -match $pat) {
                        Add-Finding -Severity "HIGH" -Module "PowerShellHistory" `
                            -Title "Suspicious PS Command in History -- $($Profile.Name)" `
                            -Detail $line -Indicator $pat
                    }
                }
                $results.Add($row)
            }
        }
    }

    $Global:OverlordResults["PowerShellHistory"] = $results
    Save-ModuleCSV -ModuleName "PowerShellHistory" -Data $results
    Write-Host "    OK $($results.Count) PowerShell history lines" -ForegroundColor Green
}

# MODULE 12: LATERAL MOVEMENT INDICATORS
function Invoke-LateralMovement {
    Write-ModuleHeader "LateralMovement" "Admin shares, PsExec artifacts, RDP, SMB, DCOM"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Admin shares
    $Shares = Safe-Query -ModuleName "LateralMovement" -Block {
        Get-SmbShare -ErrorAction SilentlyContinue
    }
    foreach ($share in $Shares) {
        $row = [PSCustomObject]@{
            Type        = "SMBShare"
            Name        = $share.Name
            Path        = $share.Path
            Description = $share.Description
            ShareType   = $share.ShareType
        }
        if ($share.Name -match '\$' -or $share.Name -in @('ADMIN$','C$','IPC$')) {
            Add-Finding -Severity "INFO" -Module "LateralMovement" `
                -Title "Admin Share Present: $($share.Name)" `
                -Detail "Path: $($share.Path)" -Indicator "AdminShare"
        }
        $results.Add($row)
    }

    # PsExec artifacts (common lateral movement)
    $PsExecPaths = @(
        "C:\Windows\PSEXESVC.exe",
        "C:\Windows\psexec.exe"
    )
    foreach ($p in $PsExecPaths) {
        if (Test-Path $p) {
            $f = Get-Item $p
            Add-Finding -Severity "HIGH" -Module "LateralMovement" `
                -Title "PsExec Binary Present: $($f.Name)" `
                -Detail $f.FullName -Indicator "PsExec"
            $results.Add([PSCustomObject]@{
                Type     = "PsExec"
                Name     = $f.Name
                Path     = $f.FullName
                Modified = $f.LastWriteTime
            })
        }
    }

    # RDP Event log
    $RDPEvents = Safe-Query -ModuleName "LateralMovement-RDP" -Block {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
            Id        = @(21,23,24,25)
            StartTime = $TimeframeCut
        } -ErrorAction SilentlyContinue
    }
    foreach ($e in $RDPEvents) {
        $xml    = [xml]$e.ToXml()
        $data   = $xml.Event.UserData
        $row    = [PSCustomObject]@{
            Type        = "RDP-Session"
            EventId     = $e.Id
            TimeCreated = $e.TimeCreated
            User        = ($data.InnerText -split '\n' | Select-Object -First 1)
            Message     = $e.Message -replace "`n"," "
        }
        Add-Finding -Severity "MEDIUM" -Module "LateralMovement" `
            -Title "RDP Session Event (ID $($e.Id))" `
            -Detail $e.Message -Indicator "RDP"
        $results.Add($row)
    }

    $Global:OverlordResults["LateralMovement"] = $results
    Save-ModuleCSV -ModuleName "LateralMovement" -Data $results
    Write-Host "    OK $($results.Count) lateral movement indicators" -ForegroundColor Green
}

# MODULE 13: DEFENDER / AV LOGS
function Invoke-DefenderLogs {
    Write-ModuleHeader "DefenderLogs" "Windows Defender detections, exclusions, disabled features"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Defender Detection Events
    $DefEvts = Safe-Query -ModuleName "DefenderLogs" -Block {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Windows Defender/Operational'
            Id        = @(1006,1007,1008,1009,1011,1013,1116,1117,1118,1119,5001,5010,5012)
            StartTime = $TimeframeCut
        } -ErrorAction SilentlyContinue
    }
    foreach ($e in $DefEvts) {
        $row = [PSCustomObject]@{
            TimeCreated  = $e.TimeCreated
            EventId      = $e.Id
            Message      = $e.Message -replace "`n"," " -replace "`r"," "
        }
        if ($e.Id -in @(5001,5010,5012)) {
            Add-Finding -Severity "CRITICAL" -Module "DefenderLogs" `
                -Title "Windows Defender Disabled/Modified (Event $($e.Id))" `
                -Detail $e.Message -Indicator "DefenderDisabled"
        }
        if ($e.Id -in @(1116,1117)) {
            Add-Finding -Severity "HIGH" -Module "DefenderLogs" `
                -Title "Malware Detected by Defender (Event $($e.Id))" `
                -Detail ($e.Message -replace "`n"," ") -Indicator "MalwareDetected"
        }
        $results.Add($row)
    }

    # Defender Exclusions
    $DefExclusions = Safe-Query -ModuleName "DefenderLogs-Exclusions" -Block {
        Get-MpPreference -ErrorAction SilentlyContinue
    }
    if ($DefExclusions) {
        $excl = @(
            @{ Type = "ExclusionPath";      Values = $DefExclusions.ExclusionPath },
            @{ Type = "ExclusionExtension"; Values = $DefExclusions.ExclusionExtension },
            @{ Type = "ExclusionProcess";   Values = $DefExclusions.ExclusionProcess }
        )
        foreach ($e in $excl) {
            foreach ($v in $e.Values) {
                if ($v) {
                    Add-Finding -Severity "HIGH" -Module "DefenderLogs" `
                        -Title "Defender Exclusion Present: $($e.Type)" `
                        -Detail $v -Indicator "DefenderExclusion"
                    $results.Add([PSCustomObject]@{
                        TimeCreated = "N/A"
                        EventId     = "Exclusion"
                        Message     = "$($e.Type): $v"
                    })
                }
            }
        }
    }

    $Global:OverlordResults["DefenderLogs"] = $results
    Save-ModuleCSV -ModuleName "DefenderLogs" -Data $results
    Write-Host "    OK $($results.Count) Defender log records" -ForegroundColor Green
}

# MODULE 14: SERVICES & DRIVERS
function Invoke-ServicesDrivers {
    Write-ModuleHeader "ServicesDrivers" "Unsigned, suspicious, and recently installed services/drivers"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $Services = Safe-Query -ModuleName "ServicesDrivers" -Block {
        Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    }
    foreach ($svc in $Services) {
        $row = [PSCustomObject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            State       = $svc.State
            StartMode   = $svc.StartMode
            PathName    = $svc.PathName
            StartUser   = $svc.StartName
        }
        # Suspicious service paths
        if ($svc.PathName -match '\\temp\\|\\appdata\\|\\public\\|\\programdata\\|\\downloads\\') {
            Add-Finding -Severity "HIGH" -Module "ServicesDrivers" `
                -Title "Service Running from Suspicious Path: $($svc.Name)" `
                -Detail $svc.PathName -Indicator "SvcSuspPath"
        }
        # Services running as SYSTEM from user-writable paths
        if ($svc.StartName -eq "LocalSystem" -and $svc.PathName -match '\\users\\') {
            Add-Finding -Severity "CRITICAL" -Module "ServicesDrivers" `
                -Title "SYSTEM Service in User Path: $($svc.Name)" `
                -Detail $svc.PathName -Indicator "SystemSvcUserPath"
        }
        $results.Add($row)
    }

    $Global:OverlordResults["ServicesDrivers"] = $results
    Save-ModuleCSV -ModuleName "ServicesDrivers" -Data $results
    Write-Host "    OK $($results.Count) services analyzed" -ForegroundColor Green
}

# MODULE 15: AMCACHE
function Invoke-AmCache {
    Write-ModuleHeader "AmCache" "AmCache.hve -- application execution history"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $AmCachePath = "C:\Windows\AppCompat\Programs\Amcache.hve"
    if (-not (Test-Path $AmCachePath)) {
        Write-Warning "  AmCache.hve not found or not accessible"
        return
    }

    # Use reg.exe to export -- avoids needing EZ Tools
    $TempReg = "$env:TEMP\GO_AmCache.reg"
    try {
        $regOutput = & reg.exe export "HKLM\SOFTWARE" $TempReg /y 2>&1
    } catch { }

    # Parse via alternate method: copy and read using .NET registry
    try {
        $AmCacheCopy = "$env:TEMP\GO_Amcache.hve"
        Copy-Item $AmCachePath $AmCacheCopy -Force -ErrorAction Stop

        # Load as offline hive
        & reg.exe load "HKLM\GO_AMCACHE" $AmCacheCopy 2>&1 | Out-Null

        $RootPath = "HKLM:\GO_AMCACHE\Root\InventoryApplicationFile"
        if (Test-Path $RootPath) {
            Get-ChildItem $RootPath -ErrorAction SilentlyContinue | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                $row   = [PSCustomObject]@{
                    Name        = $props.Name
                    Publisher   = $props.Publisher
                    Version     = $props.Version
                    InstallDate = $props.InstallDate
                    BinFileVersion = $props.BinFileVersion
                    LinkDate    = $props.LinkDate
                    LowerCaseLongPath = $props.LowerCaseLongPath
                }
                if ($row.LowerCaseLongPath -match '\\temp\\|\\appdata\\|\\public\\|\\downloads\\') {
                    Add-Finding -Severity "MEDIUM" -Module "AmCache" `
                        -Title "AmCache Entry in Suspicious Path" `
                        -Detail $row.LowerCaseLongPath -Indicator "AmCacheSuspPath"
                }
                $results.Add($row)
            }
        }
        & reg.exe unload "HKLM\GO_AMCACHE" 2>&1 | Out-Null
        Remove-Item $AmCacheCopy -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "  [AmCache] Could not load hive: $_"
    }

    $Global:OverlordResults["AmCache"] = $results
    Save-ModuleCSV -ModuleName "AmCache" -Data $results
    Write-Host "    OK $($results.Count) AmCache entries" -ForegroundColor Green
}

# MODULE 16: BAM (Background Activity Moderator)
function Invoke-BAM {
    Write-ModuleHeader "BAM" "Background Activity Moderator -- execution timestamps per user"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $BAMBase = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    if (-not (Test-Path $BAMBase)) {
        $BAMBase = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings"
    }
    if (Test-Path $BAMBase) {
        $SIDs = Get-ChildItem $BAMBase -ErrorAction SilentlyContinue
        foreach ($sid in $SIDs) {
            $entries = Get-ItemProperty $sid.PSPath -ErrorAction SilentlyContinue
            $entries.PSObject.Properties | Where-Object { $_.Name -match '\\' -and $_.Name -notmatch '^PS' } | ForEach-Object {
                $row = [PSCustomObject]@{
                    SID        = $sid.PSChildName
                    Executable = $_.Name
                    LastRun    = if ($_.Value -is [byte[]]) {
                        try { [datetime]::FromFileTime([BitConverter]::ToInt64($_.Value, 0)) } catch { "N/A" }
                    } else { "N/A" }
                }
                if ($row.Executable -match '\\temp\\|\\appdata\\|\\public\\|\\downloads\\') {
                    Add-Finding -Severity "MEDIUM" -Module "BAM" `
                        -Title "BAM: Execution from Suspicious Path" `
                        -Detail $row.Executable -Indicator "BAMSuspPath"
                }
                $results.Add($row)
            }
        }
    }

    $Global:OverlordResults["BAM"] = $results
    Save-ModuleCSV -ModuleName "BAM" -Data $results
    Write-Host "    OK $($results.Count) BAM execution records" -ForegroundColor Green
}

# MODULE 17: CREDENTIAL ACCESS ARTIFACTS
function Invoke-CredentialAccess {
    Write-ModuleHeader "CredentialAccess" "DPAPI, Credential Manager, SAM/NTDS dump indicators"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Credential Manager vaults
    $UserProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($Profile in $UserProfiles) {
        $VaultPath = "$($Profile.FullName)\AppData\Local\Microsoft\Vault"
        if (Test-Path $VaultPath) {
            Get-ChildItem $VaultPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                $results.Add([PSCustomObject]@{
                    User     = $Profile.Name
                    Type     = "CredentialVault"
                    Name     = $_.Name
                    FullPath = $_.FullName
                    Modified = $_.LastWriteTime
                })
            }
        }

        # DPAPI Master Keys -- large number can indicate dump attempt
        $DPAPIPath = "$($Profile.FullName)\AppData\Roaming\Microsoft\Protect"
        if (Test-Path $DPAPIPath) {
            $KeyCount = (@(Get-ChildItem $DPAPIPath -Recurse -ErrorAction SilentlyContinue -File)).Count
            $results.Add([PSCustomObject]@{
                User     = $Profile.Name
                Type     = "DPAPI-MasterKeys"
                Name     = "MasterKeys"
                FullPath = $DPAPIPath
                Count    = $KeyCount
            })
        }
    }

    # Check for SAM backup or shadow copy SAM access indicators
    $SAMBackupIndicators = @("C:\Windows\Repair\SAM","C:\Windows\System32\config\SAM.bak")
    foreach ($sam in $SAMBackupIndicators) {
        if (Test-Path $sam) {
            Add-Finding -Severity "CRITICAL" -Module "CredentialAccess" `
                -Title "SAM Backup File Present" `
                -Detail $sam -Indicator "SAMBackup"
            $results.Add([PSCustomObject]@{
                User     = "SYSTEM"
                Type     = "SAMBackup"
                Name     = $sam
                FullPath = $sam
                Modified = (Get-Item $sam).LastWriteTime
            })
        }
    }

    # LSASS dump file artifacts
    $LsassDumps = @("C:\Windows\Temp","C:\Users\Public","C:\ProgramData") |
        ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue -Filter "*.dmp" } |
        Where-Object { $_.LastWriteTime -gt $TimeframeCut }
    foreach ($dump in $LsassDumps) {
        Add-Finding -Severity "CRITICAL" -Module "CredentialAccess" `
            -Title "Potential LSASS Dump File: $($dump.Name)" `
            -Detail $dump.FullName -Indicator "LSASSDump"
        $results.Add([PSCustomObject]@{
            User     = "Unknown"
            Type     = "DumpFile"
            Name     = $dump.Name
            FullPath = $dump.FullName
            Modified = $dump.LastWriteTime
        })
    }

    $Global:OverlordResults["CredentialAccess"] = $results
    Save-ModuleCSV -ModuleName "CredentialAccess" -Data $results
    Write-Host "    OK $($results.Count) credential access artifacts" -ForegroundColor Green
}

# MODULE 18: FILE SYSTEM ANOMALIES
function Invoke-FileSystemAnomalies {
    Write-ModuleHeader "FileSystemAnomalies" "ADS, renamed PE files, recently dropped executables"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Recently created executables in user-writable paths
    $SearchPaths = @("C:\Users","C:\ProgramData","C:\Windows\Temp","C:\Temp")
    foreach ($sp in $SearchPaths) {
        if (Test-Path $sp) {
            $files = Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue -File |
                Where-Object {
                    $_.LastWriteTime -gt $TimeframeCut -and
                    $_.Extension -in @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.hta','.js','.jar','.py')
                }
            foreach ($f in $files) {
                $row = [PSCustomObject]@{
                    Type     = "RecentExecutable"
                    FileName = $f.Name
                    FullPath = $f.FullName
                    Extension = $f.Extension
                    Size     = $f.Length
                    Created  = $f.CreationTime
                    Modified = $f.LastWriteTime
                }
                Add-Finding -Severity "HIGH" -Module "FileSystemAnomalies" `
                    -Title "Recently Dropped Executable: $($f.Name)" `
                    -Detail $f.FullName -Indicator "RecentDrop"
                $results.Add($row)
            }
        }
    }

    # Check for Alternate Data Streams (ADS)
    $ADSPaths = @("C:\Users","C:\Windows\Temp")
    foreach ($sp in $ADSPaths) {
        if (Test-Path $sp) {
            $ADSFiles = Get-ChildItem $sp -Recurse -ErrorAction SilentlyContinue -File |
                Where-Object { $_.LastWriteTime -gt $TimeframeCut } |
                Select-Object -First 500
            foreach ($f in $ADSFiles) {
                try {
                    $streams = Get-Item $f.FullName -Stream * -ErrorAction SilentlyContinue |
                        Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
                    foreach ($stream in $streams) {
                        Add-Finding -Severity "HIGH" -Module "FileSystemAnomalies" `
                            -Title "Alternate Data Stream Detected" `
                            -Detail "$($f.FullName) | Stream: $($stream.Stream) | Size: $($stream.Length)" `
                            -Indicator "ADS"
                        $results.Add([PSCustomObject]@{
                            Type      = "ADS"
                            FileName  = $f.Name
                            FullPath  = $f.FullName
                            StreamName= $stream.Stream
                            Size      = $stream.Length
                            Modified  = $f.LastWriteTime
                        })
                    }
                } catch { }
            }
        }
    }

    $Global:OverlordResults["FileSystemAnomalies"] = $results
    Save-ModuleCSV -ModuleName "FileSystemAnomalies" -Data $results
    Write-Host "    OK $($results.Count) file system anomalies" -ForegroundColor Green
}

# MODULE 19: SHADOW COPIES
function Invoke-ShadowCopies {
    Write-ModuleHeader "ShadowCopies" "VSS snapshots -- deletion is a ransomware indicator"
    $results = [System.Collections.Generic.List[PSObject]]::new()

    $VSS = Safe-Query -ModuleName "ShadowCopies" -Block {
        Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue
    }
    if ($VSS -and $VSS.Count -gt 0) {
        foreach ($v in $VSS) {
            $results.Add([PSCustomObject]@{
                ID           = $v.ID
                VolumeName   = $v.VolumeName
                DeviceObject = $v.DeviceObject
                InstallDate  = $v.InstallDate
                OriginatingMachine = $v.OriginatingMachine
                State        = $v.State
            })
        }
        Write-Host "    OK $($VSS.Count) shadow copies found" -ForegroundColor Green
    } else {
        Add-Finding -Severity "HIGH" -Module "ShadowCopies" `
            -Title "No VSS Shadow Copies Found" `
            -Detail "All shadow copies may have been deleted -- potential ransomware indicator" `
            -Indicator "VSSDeleted"
        Write-Host "    ! No shadow copies found -- possible deletion" -ForegroundColor Red
    }

    # Check event log for vssadmin delete
    $VSSDeleteEvts = Safe-Query -ModuleName "ShadowCopies" -Block {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4688
            StartTime = $TimeframeCut
        } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'vssadmin.*delete|wmic.*shadowcopy.*delete|wbadmin.*delete' }
    }
    foreach ($e in $VSSDeleteEvts) {
        Add-Finding -Severity "CRITICAL" -Module "ShadowCopies" `
            -Title "VSS Delete Command Detected in Process Events" `
            -Detail ($e.Message -replace "`n"," ") -Indicator "VSSDelete"
        $results.Add([PSCustomObject]@{
            ID          = "Event"
            VolumeName  = "N/A"
            InstallDate = $e.TimeCreated
            State       = "DELETE_CMD: " + ($e.Message -replace "`n"," ")
        })
    }

    $Global:OverlordResults["ShadowCopies"] = $results
    Save-ModuleCSV -ModuleName "ShadowCopies" -Data $results
}

# --- HTML REPORT GENERATOR ----------------------------------------------------
function New-HTMLReport {
    param([string]$ReportPath)

    $EndTime     = Get-Date
    $Duration    = [math]::Round(($EndTime - $StartTime).TotalSeconds, 1)
    $FindingsByS = $Global:OverlordFindings | Group-Object Severity

    $CritCount   = (@($Global:OverlordFindings | Where-Object { $_.Severity -eq "CRITICAL" })).Count
    $HighCount   = (@($Global:OverlordFindings | Where-Object { $_.Severity -eq "HIGH" })).Count
    $MedCount    = (@($Global:OverlordFindings | Where-Object { $_.Severity -eq "MEDIUM" })).Count
    $LowCount    = (@($Global:OverlordFindings | Where-Object { $_.Severity -eq "LOW" })).Count
    $InfoCount   = (@($Global:OverlordFindings | Where-Object { $_.Severity -eq "INFO" })).Count

    $RiskLevel   = if ($CritCount -gt 0) { "CRITICAL" }
                   elseif ($HighCount -gt 0) { "HIGH" }
                   elseif ($MedCount -gt 0) { "MEDIUM" }
                   else { "LOW" }
    $RiskColor   = switch ($RiskLevel) {
        "CRITICAL" { "#ff3b3b" }
        "HIGH"     { "#ff8c00" }
        "MEDIUM"   { "#ffd700" }
        default    { "#00cc66" }
    }

    # Build findings table rows
    $FindingRows = $Global:OverlordFindings | ForEach-Object {
        $sev   = $_.Severity
        $color = switch ($sev) {
            "CRITICAL" { "sev-critical" }
            "HIGH"     { "sev-high" }
            "MEDIUM"   { "sev-medium" }
            "LOW"      { "sev-low" }
            default    { "sev-info" }
        }
        "<tr class='$color'>
            <td><span class='badge badge-$($color)'>$sev</span></td>
            <td>$($_.Module)</td>
            <td>$($_.Title)</td>
            <td class='detail-cell'>$([System.Web.HttpUtility]::HtmlEncode($_.Detail))</td>
            <td>$($_.Time)</td>
        </tr>"
    }
    $FindingRowsHtml = $FindingRows -join "`n"

    # Build module summary cards
    $ModuleCards = $Global:OverlordResults.Keys | ForEach-Object {
        $mod   = $_
        $count = if ($Global:OverlordResults[$mod]) { $Global:OverlordResults[$mod].Count } else { 0 }
        $modFindings = $Global:OverlordFindings | Where-Object { $_.Module -like "*$mod*" }
        $modCrit = (@($modFindings | Where-Object { $_.Severity -eq "CRITICAL" })).Count
        $modHigh = (@($modFindings | Where-Object { $_.Severity -eq "HIGH" })).Count
        $cardClass = if ($modCrit -gt 0) { "card-critical" } elseif ($modHigh -gt 0) { "card-high" } else { "card-ok" }
        "<div class='module-card $cardClass'>
            <div class='card-title'>$mod</div>
            <div class='card-count'>$count records</div>
            $(if ($modCrit -gt 0) { "<span class='badge badge-sev-critical'>$modCrit CRITICAL</span>" })
            $(if ($modHigh -gt 0) { "<span class='badge badge-sev-high'>$modHigh HIGH</span>" })
        </div>"
    }
    $ModuleCardsHtml = $ModuleCards -join "`n"

    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gregrep-Overlord Triage Report -- $Hostname</title>
<style>
  :root {
    --bg: #0d0f14;
    --surface: #151820;
    --surface2: #1c2030;
    --border: #2a2f3e;
    --text: #e0e4f0;
    --text-dim: #7a8099;
    --accent: #4f8ef7;
    --critical: #ff3b3b;
    --high: #ff8c00;
    --medium: #ffd700;
    --low: #00cc66;
    --info: #4f8ef7;
    --font: 'Segoe UI', system-ui, sans-serif;
    --mono: 'Cascadia Code', 'Consolas', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }
  a { color: var(--accent); }

  /* HEADER */
  .header { background: linear-gradient(135deg, #0d0f14 0%, #151c2e 100%); padding: 32px 40px; border-bottom: 1px solid var(--border); }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; }
  .tool-name { font-size: 28px; font-weight: 700; color: var(--accent); letter-spacing: 1px; }
  .tool-sub  { font-size: 13px; color: var(--text-dim); margin-top: 4px; }
  .risk-badge { font-size: 22px; font-weight: 700; padding: 10px 24px; border-radius: 8px; color: #fff; background: $RiskColor; box-shadow: 0 0 20px ${RiskColor}55; }
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-top: 24px; }
  .meta-item { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; }
  .meta-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
  .meta-value { font-size: 15px; font-weight: 600; margin-top: 4px; }

  /* STATS */
  .stats-bar { display: flex; gap: 12px; padding: 20px 40px; background: var(--surface); border-bottom: 1px solid var(--border); flex-wrap: wrap; }
  .stat-box { flex: 1; min-width: 100px; text-align: center; padding: 16px; border-radius: 8px; border: 1px solid var(--border); }
  .stat-box.s-critical { border-color: var(--critical); background: #ff3b3b15; }
  .stat-box.s-high     { border-color: var(--high);     background: #ff8c0015; }
  .stat-box.s-medium   { border-color: var(--medium);   background: #ffd70015; }
  .stat-box.s-low      { border-color: var(--low);      background: #00cc6615; }
  .stat-box.s-info     { border-color: var(--info);     background: #4f8ef715; }
  .stat-num  { font-size: 32px; font-weight: 700; }
  .stat-label{ font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }

  /* CONTENT */
  .content { padding: 32px 40px; }
  h2 { font-size: 18px; font-weight: 600; color: var(--accent); margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  h3 { font-size: 15px; font-weight: 600; color: var(--text); margin: 24px 0 12px; }

  /* MODULES */
  .module-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px; margin-bottom: 32px; }
  .module-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
  .module-card.card-critical { border-color: var(--critical); background: #ff3b3b0d; }
  .module-card.card-high     { border-color: var(--high);     background: #ff8c000d; }
  .module-card.card-ok       { border-color: #2a3a2a;         background: #00cc660d; }
  .card-title { font-weight: 600; font-size: 13px; }
  .card-count { font-size: 12px; color: var(--text-dim); margin: 4px 0; }

  /* BADGES */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; margin: 2px; }
  .badge-sev-critical { background: #ff3b3b30; color: #ff6b6b; border: 1px solid var(--critical); }
  .badge-sev-high     { background: #ff8c0030; color: #ffaa44; border: 1px solid var(--high); }
  .badge-sev-medium   { background: #ffd70030; color: #ffe066; border: 1px solid var(--medium); }
  .badge-sev-low      { background: #00cc6630; color: #33dd88; border: 1px solid var(--low); }
  .badge-sev-info     { background: #4f8ef730; color: #7aaaff; border: 1px solid var(--info); }

  /* FINDINGS TABLE */
  .table-wrap { overflow-x: auto; margin-bottom: 32px; border-radius: 8px; border: 1px solid var(--border); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead { background: var(--surface2); }
  th { padding: 12px 14px; text-align: left; font-weight: 600; color: var(--text-dim); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; border-bottom: 1px solid var(--border); }
  td { padding: 10px 14px; border-bottom: 1px solid #1a1e2a; vertical-align: top; }
  tr:hover td { background: var(--surface2); }
  tr.sev-critical td { border-left: 3px solid var(--critical); }
  tr.sev-high     td { border-left: 3px solid var(--high); }
  tr.sev-medium   td { border-left: 3px solid var(--medium); }
  tr.sev-low      td { border-left: 3px solid var(--low); }
  tr.sev-info     td { border-left: 3px solid var(--info); }
  .detail-cell { font-family: var(--mono); font-size: 12px; max-width: 500px; word-break: break-all; color: var(--text-dim); }

  /* FILTER BAR */
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { padding: 6px 14px; border-radius: 4px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; font-size: 12px; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }
  input[type=text] { padding: 6px 12px; border-radius: 4px; border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 12px; width: 280px; }
  input[type=text]:focus { outline: none; border-color: var(--accent); }

  /* FOOTER */
  .footer { padding: 20px 40px; text-align: center; color: var(--text-dim); font-size: 12px; border-top: 1px solid var(--border); margin-top: 40px; }

  /* PRINT */
  @media print { body { background: #fff; color: #000; } .filter-bar { display: none; } }
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div>
      <div class="tool-name">[SEARCH] GREGREP-OVERLORD</div>
      <div class="tool-sub">Forensic Triage Orchestrator v1.0.0 -- Windows Engine</div>
    </div>
    <div class="risk-badge">RISK: $RiskLevel</div>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">Hostname</div><div class="meta-value">$Hostname</div></div>
    <div class="meta-item"><div class="meta-label">OS</div><div class="meta-value">$OSVersion</div></div>
    <div class="meta-item"><div class="meta-label">Run As</div><div class="meta-value">$CurrentUser</div></div>
    <div class="meta-item"><div class="meta-label">Triage Start</div><div class="meta-value">$($StartTime.ToString("yyyy-MM-dd HH:mm:ss"))</div></div>
    <div class="meta-item"><div class="meta-label">Duration</div><div class="meta-value">${Duration}s</div></div>
    <div class="meta-item"><div class="meta-label">Timeframe</div><div class="meta-value">Last $TimeframeDays days</div></div>
    $(if ($SuspectUser)    { "<div class='meta-item'><div class='meta-label'>Suspect User</div><div class='meta-value' style='color:var(--high)'>$SuspectUser</div></div>" })
    $(if ($SuspectProcess) { "<div class='meta-item'><div class='meta-label'>Suspect Process</div><div class='meta-value' style='color:var(--high)'>$SuspectProcess</div></div>" })
    $(if ($SuspectIP)      { "<div class='meta-item'><div class='meta-label'>Suspect IP</div><div class='meta-value' style='color:var(--high)'>$SuspectIP</div></div>" })
  </div>
</div>

<div class="stats-bar">
  <div class="stat-box s-critical"><div class="stat-num" style="color:var(--critical)">$CritCount</div><div class="stat-label">Critical</div></div>
  <div class="stat-box s-high">    <div class="stat-num" style="color:var(--high)">$HighCount</div>    <div class="stat-label">High</div></div>
  <div class="stat-box s-medium">  <div class="stat-num" style="color:var(--medium)">$MedCount</div>   <div class="stat-label">Medium</div></div>
  <div class="stat-box s-low">     <div class="stat-num" style="color:var(--low)">$LowCount</div>      <div class="stat-label">Low</div></div>
  <div class="stat-box s-info">    <div class="stat-num" style="color:var(--info)">$InfoCount</div>    <div class="stat-label">Info</div></div>
  <div class="stat-box" style="min-width:160px"><div class="stat-num">$($Global:OverlordFindings.Count)</div><div class="stat-label">Total Findings</div></div>
</div>

<div class="content">

<h2>Module Summary</h2>
<div class="module-grid">
$ModuleCardsHtml
</div>

<h2>Findings</h2>
<div class="filter-bar">
  <button class="filter-btn active" onclick="filterSev('ALL')">All</button>
  <button class="filter-btn" onclick="filterSev('CRITICAL')" style="color:var(--critical)">Critical</button>
  <button class="filter-btn" onclick="filterSev('HIGH')"     style="color:var(--high)">High</button>
  <button class="filter-btn" onclick="filterSev('MEDIUM')"   style="color:var(--medium)">Medium</button>
  <button class="filter-btn" onclick="filterSev('LOW')"      style="color:var(--low)">Low</button>
  <button class="filter-btn" onclick="filterSev('INFO')"     style="color:var(--info)">Info</button>
  <input type="text" id="searchBox" placeholder="Search findings..." oninput="searchFindings(this.value)">
</div>

<div class="table-wrap">
<table id="findingsTable">
<thead>
  <tr>
    <th>Severity</th>
    <th>Module</th>
    <th>Finding</th>
    <th>Detail</th>
    <th>Time</th>
  </tr>
</thead>
<tbody id="findingsBody">
$FindingRowsHtml
</tbody>
</table>
</div>

</div>

<div class="footer">
  Generated by Gregrep-Overlord v1.0.0 | $($EndTime.ToString("yyyy-MM-dd HH:mm:ss")) | 
  github.com/YOUR_USERNAME/Gregrep-Overlord
</div>

<script>
function filterSev(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  const rows = document.querySelectorAll('#findingsBody tr');
  rows.forEach(row => {
    if (sev === 'ALL' || row.classList.contains('sev-' + sev.toLowerCase())) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}
function searchFindings(q) {
  const rows = document.querySelectorAll('#findingsBody tr');
  const lq = q.toLowerCase();
  rows.forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(lq) ? '' : 'none';
  });
}
</script>
</body>
</html>
"@

    $HTML | Out-File -FilePath $ReportPath -Encoding UTF8 -Force
}

# --- ORCHESTRATOR -------------------------------------------------------------
Write-Host "`n[CONFIG]" -ForegroundColor Cyan
Write-Host "  Host        : $Hostname ($OSVersion)"
Write-Host "  Run As      : $CurrentUser $(if ($IsAdmin) {'[ADMIN]'} else {'[LIMITED]'})"
Write-Host "  Timeframe   : Last $TimeframeDays days (since $($TimeframeCut.ToString('yyyy-MM-dd')))"
Write-Host "  Output      : $OutputPath"
Write-Host "  Modules     : $($RunModules -join ', ')`n"

# Execute selected modules
$ModuleFunctions = @{
    "EventLogs"           = { Invoke-EventLogs }
    "BrowserArtifacts"    = { Invoke-BrowserArtifacts }
    "ScheduledTasks"      = { Invoke-ScheduledTasks }
    "Prefetch"            = { Invoke-Prefetch }
    "CertUtil"            = { Invoke-CertUtil }
    "Persistence"         = { Invoke-Persistence }
    "NetworkConnections"  = { Invoke-NetworkConnections }
    "ProcessTree"         = { Invoke-ProcessTree }
    "UserActivity"        = { Invoke-UserActivity }
    "WMISubscriptions"    = { Invoke-WMISubscriptions }
    "PowerShellHistory"   = { Invoke-PowerShellHistory }
    "LateralMovement"     = { Invoke-LateralMovement }
    "DefenderLogs"        = { Invoke-DefenderLogs }
    "ServicesDrivers"     = { Invoke-ServicesDrivers }
    "AmCache"             = { Invoke-AmCache }
    "BAM"                 = { Invoke-BAM }
    "CredentialAccess"    = { Invoke-CredentialAccess }
    "FileSystemAnomalies" = { Invoke-FileSystemAnomalies }
    "ShadowCopies"        = { Invoke-ShadowCopies }
}

foreach ($mod in $RunModules) {
    if ($ModuleFunctions.ContainsKey($mod)) {
        & $ModuleFunctions[$mod]
    } else {
        Write-Warning "Unknown module: $mod -- skipping"
    }
}

# Generate reports
Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] > Generating Reports..." -ForegroundColor Yellow
$HTMLReportPath = Join-Path $OutputPath "GregrepOverlord-Report_${Hostname}_$($StartTime.ToString('yyyyMMdd-HHmmss')).html"
New-HTMLReport -ReportPath $HTMLReportPath

# Save findings CSV
$FindingsCSV = Join-Path $CSVPath "FINDINGS_SUMMARY.csv"
$Global:OverlordFindings | ForEach-Object {
    [PSCustomObject]@{
        Severity  = $_.Severity
        Module    = $_.Module
        Title     = $_.Title
        Detail    = $_.Detail
        Indicator = $_.Indicator
        Time      = $_.Time
    }
} | Export-Csv -Path $FindingsCSV -NoTypeInformation -Encoding UTF8

# --- SUMMARY ------------------------------------------------------------------
$EndTime  = Get-Date
$Duration = [math]::Round(($EndTime - $StartTime).TotalSeconds, 1)

Write-Host ("`n" + "-" * 70) -ForegroundColor DarkGray
Write-Host "  GREGREP-OVERLORD COMPLETE" -ForegroundColor Cyan
Write-Host ("-" * 70) -ForegroundColor DarkGray
Write-Host "  Duration    : ${Duration}s"
Write-Host "  Findings    : $($Global:OverlordFindings.Count) total"
Write-Host "  CRITICAL    : $((@($Global:OverlordFindings | Where-Object {$_.Severity -eq 'CRITICAL'})).Count)" -ForegroundColor Red
Write-Host "  HIGH        : $((@($Global:OverlordFindings | Where-Object {$_.Severity -eq 'HIGH'})).Count)" -ForegroundColor DarkYellow
Write-Host "  MEDIUM      : $((@($Global:OverlordFindings | Where-Object {$_.Severity -eq 'MEDIUM'})).Count)" -ForegroundColor Yellow
Write-Host "  HTML Report : $HTMLReportPath" -ForegroundColor Green
Write-Host "  CSV Files   : $CSVPath" -ForegroundColor Green
Write-Host ("-" * 70) -ForegroundColor DarkGray
