# Objective: Download Tools needed for Windows to Ansible Controller Box
# These tools will then be moved to each windows machine during Ansible Execution

# Downloading Scripts

# Download script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/downloads.ps1" -O "downloads.ps1"
# Audit script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/audit.ps1" -O "audit.ps1"
# Audit policy file
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/auditpol.csv" -O "auditpol.csv"
# Backups script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/backup.ps1" -O "backup.ps1"
# Command runbook
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/command_runbook.txt" -O "command_runbook.txt"
# Firewall script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/firewall.ps1" -O "firewall.ps1"
# Inventory script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/inventory.ps1" -O "inventory.ps1"
# Logging script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/logging.ps1" -O "logging.ps1"
# Secure baseline script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/secure.ps1" -O "secure.ps1"
# Yara response script
wget -o /dev/null "https://raw.githubusercontent.com/CCDC-RIT/Logging-Scripts/main/yara.bat" -O "yara.bat"
# User Management script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/usermgmt.ps1" -O "usermgmt.ps1"
# SOAR Agent Script
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/SOARAgent.ps1" -O "soaragent.ps1"

Service tooling 
DC Tooling
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/gpos/%7BEE3B9E95-9783-474A-86A5-907E93E64F57%7D.zip" -O "{EE3B9E95-9783-474A-86A5-907E93E64F57}.zip"
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/gpos/%7B40E1EAFA-8121-4FFA-B6FE-BC348636AB83%7D.zip" -O "{40E1EAFA-8121-4FFA-B6FE-BC348636AB83}.zip"
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/gpos/%7B6136C3E1-B316-4C46-9B8B-8C1FC373F73C%7D.zip" -O "{6136C3E1-B316-4C46-9B8B-8C1FC373F73C}.zip"

# Reset-KrbtgtKeyInteractive script
wget -o /dev/null "https://gist.githubusercontent.com/mubix/fd0c89ec021f70023695/raw/02e3f0df13aa86da41f1587ad798ad3c5e7b3711/Reset-KrbtgtKeyInteractive.ps1" -O "Reset-KrbtgtKeyInteractive.ps1"
# Pingcastle
wget -o /dev/null "https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip" -O "pc.zip"
# Adalanche
wget -o /dev/null "https://github.com/lkarlslund/Adalanche/releases/download/v2024.1.11/adalanche-windows-x64-v2024.1.11.exe" -O "adalanche.exe"
# Member server/client tools
# Local policy file
wget -o /dev/null "https://raw.githubusercontent.com/sandrinus/BlueTeamTools/refs/heads/main/Windows-Scripts/gpos/localpolicy.PolicyRules" -O "localpolicy.PolicyRules"
# LGPO tool
wget -o /dev/null "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip" -O "lg.zip"
# LGPO extraction

# Server Core
wget -o /dev/null "https://github.com/derceg/explorerplusplus/releases/download/version-1.4.0-o /dev/nulleta-2/explorerpp_x64.zip" -O "epp.zip"
wget -o /dev/null "https://netresec.com/?download=NetworkMiner" -O "nm.zip"

# Third-party tooling for every system

# Get-InjectedThread and Stop-Thread
wget -o /dev/null "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1" -O "Get-InjectedThread.ps1"
wget -o /dev/null "https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Stop-Thread.ps1" -O "Stop-Thread.ps1"
# PrivEsc checker script
wget -o /dev/null "https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1" -O "PrivescCheck.ps1"
# chainsaw + dependency library
wget -o /dev/null "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules.zip" -O "cs.zip"
wget -o /dev/null "https://aka.ms/vs/17/release/vc_redist.x64.exe" -O "vc_redist.64.exe"

# hollows hunter
wget -o /dev/null "https://github.com/hasherezade/hollows_hunter/releases/download/v0.3.9/hollows_hunter64.zip" -O "hh64.zip"
# Basic Sysmon conf file
wget -o /dev/null "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -O "sysmon.xml"
# Windows Firewall Control + .NET 4.8
wget -o /dev/null "https://www.binisoft.org/download/wfc6setup.exe" -O "wfcsetup.exe"
wget -o /dev/null "https://go.microsoft.com/fwlink/?LinkId=2088631" -O "net_installer.exe"
# Wireshark
wget -o /dev/null "https://1.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe" -O "wsinstall.exe"
# Sysinternals
wget -o /dev/null "https://download.sysinternals.com/files/Autoruns.zip" -O "ar.zip"
wget -o /dev/null "https://download.sysinternals.com/files/ListDlls.zip" -O "dll.zip"
wget -o /dev/null "https://download.sysinternals.com/files/ProcessExplorer.zip" -O "pe.zip"
wget -o /dev/null "https://download.sysinternals.com/files/ProcessMonitor.zip" -O "pm.zip"
wget -o /dev/null "https://download.sysinternals.com/files/Sigcheck.zip" -O "sc.zip"
wget -o /dev/null "https://download.sysinternals.com/files/TCPView.zip" -O "tv.zip"
wget -o /dev/null "https://download.sysinternals.com/files/Streams.zip" -O "stm.zip"
wget -o /dev/null "https://download.sysinternals.com/files/Sysmon.zip" -O "sm.zip"
wget -o /dev/null "https://download.sysinternals.com/files/AccessChk.zip" -O "ac.zip"
wget -o /dev/null "https://download.sysinternals.com/files/Strings.zip" -O "str.zip"
# yara
wget -o /dev/null "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip" -O "yara.zip"
wget -o /dev/null "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Windows.zip" -O "Windows.zip"
wget -o /dev/null "https://github.com/CCDC-RIT/YaraRules/raw/refs/heads/main/Multi.zip" -O "Multi.zip"
# Notepad++
wget -o /dev/null "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.7.1/npp.8.7.1.Installer.x64.exe" -O "notepadpp_installer.exe"
# googoo chrome
wget -o /dev/null "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -O "chromeinstall.exe"
# Floss
wget -o /dev/null "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip" -O "floss.zip"
# Antipwny (Meterpreter Detection)
wget -o /dev/null "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/AntiPwny.exe" -O "AntiPwny.exe"
wget -o /dev/null "https://github.com/rvazarkar/antipwny/raw/refs/heads/master/exe/x86/ObjectListView.dll" -O "ObjectListView.dll"
