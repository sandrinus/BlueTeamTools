# RIT CCDC Security Orchestration and Automated Response tool

# Built to run on every windows machine in a domain. All alerts are sent to the local machine,
# where the user operating the machine will have the option to take action or not. 


$currentDir = (Get-Location).Path
$auditResultsPath = Join-Path -Path $currentDir -ChildPath "results"

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-output "[INFO] Domain Controller detected"
}

$IIS = $false
if (Get-Service -Name W3SVC 2>$null) {
    $IIS = $true
    Write-output "[INFO] IIS Server detected"
}

$CA = $false
if (Get-Service -Name CertSvc 2>$null) {
    $CA = $true
    Write-output "[INFO] Certificate Authority detected"
}

[System.Collections.ArrayList]$goodLocalUsers = "Administrator","Guest","WDAGUtilityAccount","DefaultAccount","cucumber"
if($DC){
    $goodLocalUsers += "krbtgt"
}
elseif($IIS){
    $goodLocalUsers += "IUSR"
}

function runYaraScan{
    # Scan a directory or file with Yara
    param(
        [string]$file="",
        [string]$directory=""
    )
    $yaraDir = Join-Path -Path $currentDir.Substring(0,$currentDir.IndexOf("\scripts")) -ChildPath "tools\yara64.exe"
    $yaraRules = 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara\rules\compiled.windows'
    $returnValue = ""
    if((Test-Path $yaraDir) -and (Test-Path $yaraRules)){
        if($file -ne ""){
            $returnValue = & $yaraDir --compiled-rules $yaraRules $file
        }
        if($directory -ne ""){
            $returnValue = & $yaraDir --compiled-rules $yaraRules --recursive $directory
            foreach($file in $returnValue){
                $tokens = $file -split " "
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Yara detected malicious File: " -ForegroundColor white -NoNewLine; Write-Host $tokens[1] -ForegroundColor Red -NoNewLine; Write-Host " detected via rule " -ForegroundColor white -NoNewline; Write-Host $tokens[0] -ForegroundColor White
            }
        }
    }

    return $returnValue
}

# This function goes through the current list of local users, and checks against a predetermined list to see if they are potentially malicious or not. 
# User is then given the option to disable the user, do nothing, or add them to the predetermined list if they.
function auditLocalUsers{
    [array]$users = Get-LocalUser
    
    foreach($user in $users){
        if($user.enabled){
            if(!($user.Name -in $goodLocalUsers)){
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Unauthorized Local User " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor Red -NoNewLine; Write-Host " detected" -ForegroundColor white 
                $answer = Read-Host "Take Action? [yes/no/add (adds user to authorized user list)]"
                
                if($answer -ieq "yes"){
                    Disable-LocalUser $user
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Unauthorized Local User " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor Red -NoNewLine; Write-Host " removed" -ForegroundColor white 
                }
                elseif($answer -ieq "add"){
                    $goodLocalUsers.Add($user.Name) | Out-Null
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user -ForegroundColor Green -NoNewLine; Write-Host " is now authorized" -ForegroundColor white 
                }
            }
        }
    }
}

# All of the authorized users for the highly privileged AD groups
[System.Collections.ArrayList]$blackTeam = "black-team","blackteam"
$authorizedPrivilegedGroups = @{"Enterprise Admins" = $blackTeam.clone(); "Schema Admins" = $blackTeam.clone(); "DnsAdmins" = $blackTeam.clone()}

Function auditOverPrivilegedDomainUsers {
    # This function finds all of the members of the Enterprise Admins, Schema Admins, and DNS Admins. 
    # The user operating the Domain controller an then remove users from these accounts as they see
    # fit to follow the principle of least privilege
    $copyOfAuthorizedPrivilegedGroups = $authorizedPrivilegedGroups.clone()

    foreach($group in $authorizedPrivilegedGroups.keys){
        $currentGroupMembers = Get-ADGroupMember -Identity $group
        foreach($user in $currentGroupMembers){
            if(!($user.name -in $authorizedPrivilegedGroups.$group)){
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor red -NoNewLine; Write-Host " is a member of " -ForegroundColor white -NoNewline; Write-Host $group -ForegroundColor White
                $answer = Read-Host "Remove from group? [yes/no/add (adds user to authorized user list)]"

                if($answer -ieq "yes"){
                    Remove-ADGroupMember -Identity $group -Members $user.Name -Confirm:$false
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor red -NoNewLine; Write-Host " removed from " -ForegroundColor white -NoNewline; Write-Host $group -ForegroundColor White 
                }
                elseif($answer -ieq "add"){
                    $copyOfAuthorizedPrivilegedGroups.$group.add($user.Name) | Out-Null
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor Green -NoNewLine; Write-Host " is an authorized member of " -ForegroundColor white -NoNewline; Write-Host $group -ForegroundColor White
                }
            }
        }
    }
    $authorizedPrivilegedGroups = $copyOfAuthorizedPrivilegedGroups.clone()
}

$goodDomainUsers = "blackteam","black-team","krbtgt"

Function auditDomainUsers {
    # Thanks UCI for this idea
    # Credit: https://github.com/UCI-CCDC/CCDC/blob/master/Windows/BackdoorHound.ps1

    $users = Get-ADUser -Filter * -Properties description,company,department

    # Get the average lengths of all 3 properties
    $descriptionTotal = 0
    $companyTotal = 0
    $departmentTotal = 0
    foreach($user in $users){
        $descriptionTotal += $user.description.Length
        $companyTotal += $user.company.Length
        $departmentTotal += $user.department.Length
    }
    $descriptionAverage = $descriptionTotal / $users.Count
    $companyAverage = $companyTotal / $users.Count
    $departmentAverage = $departmentTotal / $users.Count

    # Get the standard deviations of all 3 properties
    $descriptionSumSquaresTotal = 0
    $companySumSquaresTotal = 0
    $departmentSumSquaresTotal = 0
    foreach($user in $users){
        $descriptionSumSquaresTotal += ($user.description.length - $descriptionAverage) * ($user.description.length - $descriptionAverage)
        $companySumSquaresTotal += ($user.company.length - $companyAverage) * ($user.company.length - $companyAverage)
        $departmentSumSquaresTotal += ($user.department.length - $departmentAverage) * ($user.department.length - $departmentAverage)
    }
    $descriptionStDev = $descriptionSumSquaresTotal / ($users.count - 1)
    $companyStDev = $companySumSquaresTotal / ($users.count - 1)
    $departmentStDev = $departmentSumSquaresTotal / ($users.count - 1)

    # 0 = User is not suspicious at all
    # 1 = User has description/company/department that is an outlier, potentially suspicious
    # 2 = Almost all users have a description, and this user does not. Very suspicious
    $isUserSus = 0

    $descriptionLower = $descriptionAverage - (2.5 * $descriptionStDev)
    $descriptionUpper = $descriptionAverage + (2.5 * $descriptionStDev)
    $companyLower = $companyAverage - (2.5 * $companyStDev)
    $companyUpper = $companyAverage + (2.5 * $companyStDev)
    $departmentLower = $departmentAverage - (2.5 * $departmentStDev)
    $departmentUpper = $departmentAVerage + (2.5 * $departmentStDev)

    # The 3 default domain accounts (guest, administrator, and krbtgt) have descriptions with a total length of 149. 
    # If each user has a description, then it should be at least 2 characters even if it is an acryonym
    # If the average description is greater than (155 + # of users - 3  * 2)/# of users 
    # Then it can be assumed that users should have something in the description field, so if it is blank, then this is highly suspicious.

    $haveDescriptions = $false
    $magicNum = ((149 + (($users.count - 3) * 2))/$users.count)
    if($descriptionAverage -ge $magicNum){
        $haveDescriptions = $true
    }

    foreach($user in $users){
        # If any User has a description/company/department that is an outlier (more than 2.5 st. dv's away), send an alert
        if($user.description.length -lt $descriptionLower -or $user.description.length -gt $descriptionUpper){
            $isuserSus = 1
        }
        elseif($user.company.length -lt $companyLower -or $user.company.length -gt $companyUpper){
            $isUserSus = 1
        }
        elseif($user.department.length -lt $departmentLower -or $user.department.length -gt $departmentUpper){
            $isUserSus = 1
        }
        if($haveDescriptions){
            if($user.description.length -eq 0){
                $isUserSus = 2
            }
        }
        $answer = "no"
        if($isUserSus -eq 1){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Potentially malicious Domain User " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor red
            $answer = Read-Host "Deactivate user? [yes/no/add (adds user to authorized user list)]"
        }
        elseif($isUserSus -eq 2){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Highly potentially malicious Domain User " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor red
            $answer = Read-Host "Deactivate user? [yes/no/add (adds user to authorized user list)]"
        }

        if($answer -ieq "yes"){
            Disable-ADAccount -Identity $user.Name
            $disabledUser = get-aduser -identity $user.name
            if(!($disabledUser.enabled)){
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Disabled user " -ForegroundColor White -NoNewline; Write-Host $user.name -ForegroundColor red
            }
        }
        elseif($answer -ieq "add"){
            $goodDomainUsers += $user.name
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] " -ForegroundColor white -NoNewLine; Write-Host $user.Name -ForegroundColor Green -NoNewLine; Write-Host " is now authorized" -ForegroundColor white 
        }

        $isUserSus = 0
    }
}

function checkDLLs{
    $registryAuditPath = Join-Path -Path $auditResultsPath -ChildPath "registryaudit.txt"
    # Get all of content from registryaudit.txt, which holds all of the results of the Dll's that were audited from the audit script 
    [array]$currentDLLs = Get-Content -Path $registryAuditPath
    # Whatever the current key that is being iterated over is
    [string]$currentKey = ""
    # known good dll's
    # TODO: Complete all of these lists
    [array]$goodnetshDLLs = "ifmon.dll","rasmontr.dll","authfwcfg.dll","dhcpmonitor.dll","dot3cfg.dll","fwcfg.dll","hnetmon.dll","nettrace.dll","netiohlp.dll","nshhttp.dll","nshipsec.dll","nshwfp.dll","peerdistsh.dll","rpcnsh.dll","whhelper.dll","wshelper.dll","wwancfg.dll","netprofm.dll","p2pnetsh.dll","wcnetsh.dll","wlancfg.dll"
    [array]$goodAppCertDLLs = ""
    [array]$goodAppInitDLLS = ""
    [array]$goodLsaDLLS = "{msv1_0}",""
    [array]$goodWinlogonDLLs = "explorer.exe","C:\Windows\System32\userinit.exe"
    [array]$goodLocalPortDLLs = "localspl.dll"
    [array]$goodIPPortDLLs = "tcpmon.dll"
    [array]$goodUSBMonitorDLLs = "usbmon.dll"
    [array]$goodWSDPortDLLs = "APMon.dll"
    [hashtable]$hashTable = @{"NetSh" = $goodnetshDLLs; "AppCertDLLs" = $goodAppCertDLLs; "Windows" = $goodAppInitDLLs; "Lsa" = $goodLsaDLLs; "Winlogon" = $goodWinlogonDLLs;"Local Port" = $goodLocalPortDLLs; "IP Port" = $goodIPPortDLLs; "USB Monitor" = $goodUSBMonitorDLLs; "WSD Port" = $goodWSDPortDLLs;}
    # This loop iterates through every line in the file registryaudit.txt. If the line is a registry key, then it updates the currentKey variable
    # If the current key is a key that we have a list of known good dll's for, and the line is a line that contains a dll, the dll on that line
    # is checked against the list of the known good DLL's. If it is not in the list, then an alert is triggered, and the user has the option 
    # to remove the dll. 
    foreach($line in $currentDLLs){
        $tokens = $line.split(" ")
        if($tokens[0] -ieq "key"){
            # If the line is a key, update the current key. 
            $keyTokens = $tokens.split("\")
            $currentKey = $keyTokens[-1]
        }
        elseif((!($line -eq "" -or $tokens[-1] -ieq ":")) -and $currentKey -in $hashTable.Keys){
            if(!($tokens[-1]) -in $hashTable.$currentKey){ 
                Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Potentially Malicious " -ForegroundColor White -NoNewline; Write-Host $currentKey -ForegroundColor White -NoNewline; Write-Host " DLL Found: " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red
                $answer = Read-Host "Take Action? [yes/no]"

                if($answer -ieq "yes"){
                    # Hopefully this works
                    regsvr32 /u $tokens[-1]
                    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Malicious DLL " -ForegroundColor white -NoNewLine; Write-Host $tokens[-1] -ForegroundColor Red -NoNewLine; Write-Host " removed" -ForegroundColor white 
                }
            }
        }
    }
}

Function removeProcessesServices{
    param(
        $ProcessID,
        $Type
    )

    [string]$processName = (Get-Process -Id $ProcessID).ProcessName

    # Get Service name from process
    [string]$query = "ProcessId='" + $ProcessID + "'"
    $serviceInfo = Get-WmiObject Win32_Service -Filter $query
    

    # Get path of process/service from PID
    $path = Get-process -id $ProcessID | select-object -expandproperty path

    # Get the owner of the process
    $processOwner = (get-process -id $ProcessID -IncludeUserName).UserName

    try{
        [array]$processConnections = Get-NetTCPConnection -OwningProcess $ProcessID
    }
    catch{
        [array]$processConnections = @()
    }

    $yaraScanResults = runYaraScan -file $path

    # Inform User of the malicious process/service and ask if program should take action
    
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "WARNING" -ForegroundColor Red -NoNewLine; Write-Host "] Malicious Process found via $($Type)" -ForegroundColor white
    Write-Host "[INFO] Process Name: $($processName)"
    Write-Host "[INFO] PID: $($ProcessID)"
    Write-Host "[INFO] Process Owner: $($processOwner)"
    if($serviceInfo){
        Write-Host "[INFO] Service Name: $($serviceInfo.Name)" -ForegroundColor White
    }
    Write-Host "[INFO] Path: $($path)" -ForegroundColor White
    foreach($connection in $processConnections){
        Write-Host "[INFO] Process Connection from port $($connection.LocalPort) to $($connection.RemoteAddress) on port $($connection.RemotePort)"
    }
    if($yaraScanResults -ne $null){
        Write-Host "[INFO] File matched Yara Rules: $($yaraScanResults)"
    }

    $answer = Read-Host "Take Action? [yes/no]"
    
    if($answer -ieq "yes"){
        Stop-Process -ID $ProcessID -Force
        if($serviceInfo){
            stop-service -Name $serviceInfo.Name -Force
            if($PSVersionTable.PSVersion.Major -ge 6){
                # if powershell is version 6 or up
                remove-service -name $serviceInfo.Name -Force
            }
        }
        Remove-Item -path $path
        if(!(Test-Path -LiteralPath $path)){
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor Green -NoNewLine; Write-Host "] Process/Service " -ForegroundColor white -NoNewLine; 
            Write-Host $process -ForegroundColor Red -NoNewLine; Write-Host " with PID: " -ForegroundColor White -NoNewline; Write-Host $ProcessID -ForegroundColor Red -NoNewline; Write-Host " removed" -ForegroundColor white 
        }
    }
}

Function checkProcessesServices {
    $processAuditPath = Join-Path -Path $auditResultsPath -ChildPath "processaudit.txt"

    # Removing processes deemed to be suspicious by hollows hunter

    # Hopefully there shouldn't be more than 40 suspicious processes found by hollos hunter
    [array]$hollowsHunterProcesses = Get-content $processAuditPath -Tail 40

    # Array for all of the processes removed, just in case we hit them again when
    # iterating through the list and checking the names
    $removedProcesses = New-Object System.Collections.ArrayList

    # Iterate through all of the lines grabbed
    for ($i = 0; $i -lt 40; $i++){
        [array]$tokens = ($hollowsHunterProcesses[$i]).split(" ")
        
        if($tokens[0] -eq "[*]" -and $tokens[2] -eq "suspicious:"){
            # Once the line is found that indicates there are suspicious processes, iterate through the processes
            # Get their PID, and call the removeProcessesServices Function with the PID of the suspicious process.
            for($j = 0; $j -lt $tokens[-1]; $j++){
                [array]$processTokens = ($hollowsHunterProcesses[$i + $j + 2]).split(" ")
                $ProcessID = ($processTokens[2]).trim(",")
                $removedProcesses.add($ProcessID)
                removeProcessesServices -ProcessID $ProcessID -Type "Hollows Hunter"
            }
            break
        }
    }

    # Removing processes found with known bad names

    [array]$knownBadProcessNames = "MeshAgent.exe","tacticalrmm.exe"
    [array]$allProcesses = Get-Process

    foreach($process in $allProcesses){
        if($process.ProcessName -in $knownBadProcessNames -and !($Process.ID -in $removedProcesses)){
            removeProcessesServices -ProcessID $Process.ID -Type "Known Bad Process Name"
            $removedProcesses.add($Process.ID)
        }
    }

    # Check default for meterpreter default port: 4444
    [array]$meterpreterConnections = Get-NetTCPConnection -RemotePort "4444" -ErrorAction "Silentlycontinue"
    
    foreach($connection in $meterpreterConnections){
        removeProcessesServices -ProcessID $connection.OwningProcess -Type "Default Meterpreter Port"
        $removedProcesses.add($connection.OwningProcess)
    }
}

checkProcessesServices
checkDLLs
auditDomainUsers
auditOverPrivilegedDomainUsers
auditLocalUsers
runYaraScan -directory "C:\Users\da1"