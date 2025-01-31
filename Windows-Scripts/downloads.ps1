# Objective: downloads scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

# *-WindowsFeature - Roles and Features on Windows Server 2012 R2 and above
# *-WindowsCapability - Features under Settings > "Optional Features"
# *-WindowsOptionalFeature - Featuers under Control Panel > "Turn Windows features on or off" (apparently this is compatible with Windows Server)

param (
    [string]$Path = $(throw "-Path is required."),
    [bool]$ansibleInstall = $false
)

# somehow this block verifies if the path is legit
$ErrorActionPreference = "Stop"
[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid path" -ForegroundColor white
        break
    }
    $true
})]
$InputPath = $Path
Set-Location -Path $InputPath | Out-Null

# Creating all the directories
$ErrorActionPreference = "Continue"
New-Item -Path $InputPath -Name "scripts" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "installers" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "tools" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "zipped" -ItemType "directory" | Out-Null
$ScriptPath = Join-Path -Path $InputPath -ChildPath "scripts"
$SetupPath = Join-Path -Path $InputPath -ChildPath "installers"
$ToolsPath = Join-Path -Path $InputPath -ChildPath "tools"
$ZippedPath = Join-Path -Path $InputPath -ChildPath "zipped"

New-Item -Path $ScriptPath -Name "conf" -ItemType "directory" | Out-Null
New-Item -Path $ScriptPath -Name "results" -ItemType "directory" | Out-Null
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"
$ResultsPath = Join-Path -Path $ScriptPath -ChildPath "results"

New-Item -Path $ResultsPath -Name "artifacts" -ItemType "directory" | Out-Null
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory" | Out-Null
New-item -Path $ToolsPath -Name "yara" -ItemType "directory" | Out-Null
New-item -Path $ToolsPath -Name "antipwny" -ItemType "directory" | Out-Null
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"
$yaraPath = Join-Path -Path $ToolsPath -ChildPath "yara"
$antipwnyPath = Join-Path -Path $ToolsPath -ChildPath "antipwny"

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Directories created" -ForegroundColor white

# Custom tooling downloads
$ProgressPreference = 'SilentlyContinue'
# Audit script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/audit.ps1", (Join-Path -Path $ScriptPath -ChildPath "audit.ps1"))
# Audit policy file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/auditpol.csv", (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
# Backups script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/backup.ps1", (Join-Path -Path $ScriptPath -ChildPath "backup.ps1"))
# Command runbook
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/command_runbook.txt", (Join-Path -Path $ScriptPath -ChildPath "command_runbook.txt"))  
# Firewall script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/firewall.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
# Inventory script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1", (Join-Path -Path $ScriptPath -ChildPath "inventory.ps1"))
# Logging script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/logging.ps1", (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
# Secure baseline script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/secure.ps1", (Join-Path -Path $ScriptPath -ChildPath "secure.ps1"))
# Wazuh agent config file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/agent_windows.conf", (Join-Path -Path $ConfPath -ChildPath "agent_windows.conf"))
# Yara response script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/yara.bat", (Join-Path -Path $ScriptPath -ChildPath "yara.bat"))
# User Management script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/usermgmt.ps1", (Join-Path -Path $ScriptPath -ChildPath "usermgmt.ps1"))
# SOAR Agent Script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/SOARAgent.ps1", (Join-Path -Path $ScriptPath -ChildPath "soaragent.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] System scripts and config files downloaded" -ForegroundColor white

# Service tooling 
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') { # DC detection
    # RSAT tooling (AD management tools + DNS management)
    Install-WindowsFeature -Name RSAT-AD-Tools,RSAT-DNS-Server,GPMC
    # Domain, Domain Controller, member/client, and Defender GPOs 
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7BEE3B9E95-9783-474A-86A5-907E93E64F57%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7B40E1EAFA-8121-4FFA-B6FE-BC348636AB83%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7B6136C3E1-B316-4C46-9B8B-8C1FC373F73C%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/%7BBEAA6460-782B-4351-B17D-4DC8076633C9%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip"))
    # Reset-KrbtgtKeyInteractive script
    (New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1", (Join-Path -Path $ScriptPath -ChildPath "Reset-KrbtgtKeyInteractive.ps1"))
    # Pingcastle
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip", (Join-Path -Path $InputPath -ChildPath "pc.zip"))
    # Adalanche
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe", (Join-Path -Path $ToolsPath -ChildPath "adalanche.exe"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools downloaded" -ForegroundColor white
    # Pingcastle, GPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pc.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "pc") 
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip") -DestinationPath $ConfPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{BEAA6460-782B-4351-B17D-4DC8076633C9}.zip") -DestinationPath $ConfPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC tools extracted" -ForegroundColor white
} else { # Member server/client tools
    # Local policy file
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/gpos/localpolicy.PolicyRules", (Join-Path -Path $ConfPath -ChildPath "localpolicy.PolicyRules"))
    # LGPO tool
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $InputPath -ChildPath "lg.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO and local policy file downloaded" -ForegroundColor white
    # LGPO extraction
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "lg.zip") -DestinationPath $ToolsPath
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO extracted" -ForegroundColor white
}

# Server Core Tooling
if ((Test-Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion") -and (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" | Select-Object -ExpandProperty "InstallationType") -eq "Server Core") {
    # Explorer++
    (New-Object System.Net.WebClient).DownloadFile("https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-beta-2/explorerpp_x64.zip", (Join-Path -Path $InputPath -ChildPath "epp.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "epp.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "epp")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Explorer++ downloaded and extracted" -ForegroundColor white
    # Server Core App Compatibility FOD
    Add-WindowsCapability -Online -Name ServerCore.AppCompatibility~~~~0.0.1.0 | Out-Null
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Additional MS tools installed" -ForegroundColor white
    # NetworkMiner
    (New-Object System.Net.WebClient).DownloadFile("https://netresec.com/?download=NetworkMiner", (Join-Path -Path $InputPath -ChildPath "nm.zip"))
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "nm.zip") -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "nm")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] NetworkMiner downloaded and extracted" -ForegroundColor white
}

# Third-party tooling for every system
# Get-InjectedThread and Stop-Thread
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Stop-Thread.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Get-InjectedThread and Stop-Thread downloaded" -ForegroundColor white
# PrivEsc checker script
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1", (Join-Path -Path $ScriptPath -ChildPath "PrivescCheck.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] PrivescChecker script downloaded" -ForegroundColor white
# chainsaw + dependency library
$redistpath = Join-Path -Path $SetupPath -ChildPath "vc_redist.64.exe"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip", (Join-Path -Path $InputPath -ChildPath "cs.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://aka.ms/vs/17/release/vc_redist.x64.exe", $redistpath)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chainsaw and C++ redist downloaded" -ForegroundColor white
## silently installing dependency library
& $redistpath /install /passive /norestart
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] C++ redist installed" -ForegroundColor white
# hollows hunter
(New-Object System.Net.WebClient).DownloadFile("https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip", (Join-Path -Path $InputPath -ChildPath "hh64.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter downloaded" -ForegroundColor white
# Basic Sysmon conf file
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", (Join-Path -Path $ConfPath -ChildPath "sysmon.xml"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Sysmon config downloaded" -ForegroundColor white
# Windows Firewall Control + .NET 4.8
$net48path = Join-Path -Path $SetupPath -ChildPath "net_installer.exe"
(New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", (Join-Path -Path $SetupPath -ChildPath "wfcsetup.exe"))
(New-Object System.Net.WebClient).DownloadFile("https://go.microsoft.com/fwlink/?LinkId=2088631", $net48path)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Windows Firewall Control and .NET 4.8 installers downloaded" -ForegroundColor white
## silently installing .NET 4.8 library
& $net48path /passive /norestart
# Wireshark
# (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
(New-Object System.Net.WebClient).DownloadFile("https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe", (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe"))
if(!($ansibleInstall)){
    & (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wireshark downloaded and installed" -ForegroundColor white
} else {
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wireshark downloaded" -ForegroundColor white
}

# Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $InputPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $InputPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $InputPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $InputPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $InputPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $InputPath -ChildPath "tv.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Streams.zip", (Join-Path -Path $InputPath -ChildPath "stm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", (Join-Path -Path $InputPath -ChildPath "sm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/AccessChk.zip", (Join-Path -Path $InputPath -ChildPath "ac.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Strings.zip", (Join-Path -Path $InputPath -ChildPath "str.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools downloaded" -ForegroundColor white
# yara
(New-Object System.Net.WebClient).DownloadFile("https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip", (Join-Path -Path $InputPath -ChildPath "yara.zip"))
## yara rules
(New-Object System.Net.WebClient).DownloadFile("https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Windows.zip", (Join-Path -Path $InputPath -ChildPath "Windows.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Multi.zip", (Join-Path -Path $InputPath -ChildPath "Multi.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] YARA and YARA rules downloaded" -ForegroundColor white

# Notepad++
$npppath = Join-Path -Path $SetupPath -ChildPath "notepadpp_installer.exe"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe", $npppath)
& $npppath /S
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Notepad++ downloaded and installed" -ForegroundColor white

# VSCode
# (New-Object System.Net.WebClient).DownloadFile("https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user", (Join-Path -Path $SetupPath -ChildPath "vscodesetup.exe"))
# Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] VSCode installer downloaded" -ForegroundColor white

# googoo chrome
$chromepath = Join-Path -Path $SetupPath -ChildPath "chromeinstall.exe"
(New-Object System.Net.WebClient).DownloadFile("http://dl.google.com/chrome/install/375.126/chrome_installer.exe", $chromepath)
& $chromepath /silent /install
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Google Chrome downloaded and installed" -ForegroundColor white

# Floss
$flosspath = Join-Path -Path $inputpath -ChildPath "floss.zip"
(New-Object System.Net.WebClient).DownloadFile("https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip", $flosspath)
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Floss downloaded" -ForegroundColor white

# Antipwny (Meterpreter Detection)
(New-Object System.Net.WebClient).DownloadFile("https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe", (Join-Path -Path $antipwnyPath -ChildPath "AntiPwny.exe"))
(New-Object System.Net.WebClient).DownloadFile("https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll", (Join-Path -Path $antipwnyPath -ChildPath "ObjectListView.dll"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Antipwny downloaded" -ForegroundColor white

# Extraction
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "stm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "stm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ac.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ac")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "str.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "str")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools extracted" -ForegroundColor white

Expand-Archive -LiteralPath $flosspath -DestinationPath (Join-Path -Path $ToolsPath -ChildPath "floss.exe")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Floss extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "hh64.zip") -DestinationPath $ToolsPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Hollows Hunter extracted" -ForegroundColor white
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "cs.zip") -DestinationPath $ToolsPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Chainsaw extracted" -ForegroundColor white

Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "yara.zip") -DestinationPath $yaraPath
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "Windows.zip") -DestinationPath $yaraPath
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "Multi.zip") -DestinationPath $yaraPath
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] YARA and YARA rules extracted" -ForegroundColor white

foreach($file in (Get-childItem -Path $InputPath)){
    if($file.name -match ".zip"){
        Move-item -path (Join-Path -path $InputPath -ChildPath $file.name) -Destination $zippedPath
    }
}
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Cleaned up zipped Files" -ForegroundColor white
