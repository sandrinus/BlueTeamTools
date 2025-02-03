#Set-ExecutionPolicy Bypass -Scope Process -Force
#4Logs
$LogFile = "$PSScriptRoot\UserCreationLog.txt"

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected"
}

# Function to write logs
function Write-Log {
    param ([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp - $Message" | Out-File -Append -FilePath $LogFile
}

# Define the password for all users
$SecurePassword = ConvertTo-SecureString "Change.me123!" -AsPlainText -Force

# Define local users
$LocalUsers = @("general", "admiral", "judge", "bodyguard", "cabinetofficial", "treasurer")

# Define local administrators
$LocalAdmins = @("president", "vicepresident", "defenseminister", "secretary")

#Define domain users
$DomainUsers = @("foreignaffairs", "intelofficer", "delegate", "advisor", "lobbyist", "aidworker")

# Define domain users admiins
$DomainUsersAdmins = @("representative", "senator", "attache", "ambassador")

# Define garbage users
$GarbageUsers = @("redteam", "blahblah", "deleteme", "testuser", "randomaccount")


function CreateLocalUser {
    param ($UserName)
    if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $UserName -Password $SecurePassword -FullName $UserName -Description "Practice User"
        Add-LocalGroupMember -Group "Users" -Member $UserName
        Write-Log "Created local user: $UserName"
        Write-Output "Created local user: $UserName"
    } else {
        Write-Output "User $UserName already exists."
    }
}

function CreateLocalAdmin {
    param ($UserName)
    if (-not (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $UserName -Password $SecurePassword -FullName $UserName -Description "Local Admin User"
        Add-LocalGroupMember -Group "Administrators" -Member $UserName
        Write-Log "Created local admin user: $UserName"
        Write-Output "Created local admin user: $UserName"
    } else {
        Write-Output "Admin user $UserName already exists."
    }
}

function CreateDomainUser {
    param ($UserName)
    if (-not (Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $UserName -SamAccountName $UserName -UserPrincipalName "$UserName@domain.local" -AccountPassword $SecurePassword -Enabled $true
        Write-Log "Created domain user: $UserName"
        Write-Output "Created domain user: $UserName"
    } else {
        Write-Output "Domain user $UserName already exists."
    }
}

function CreateDomainAdmin {
    param ($UserName)
    if (-not (Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue)) {
        New-ADUser -Name $UserName -SamAccountName $UserName -UserPrincipalName "$UserName@domain.local" -AccountPassword $SecurePassword -Enabled $true
        Add-ADGroupMember -Identity "Domain Admins" -Members $UserName
        Write-Log "Created domain admin user: $UserName"
        Write-Output "Created domain admin user: $UserName"
    } else {
        Write-Output "Domain admin user $UserName already exists."
    }
}

Write-Log "Starting user creation process..."

foreach ($User in $LocalUsers) {
    CreateLocalUser -UserName $User
}
foreach ($Admin in $LocalAdmins) {
    if ($Admin -ne "president") {
        CreateLocalAdmin -UserName $Admin
    }
}
foreach ($User in $DomainUsers) {
    CreateDomainUser -UserName $User
}
foreach ($User in $DomainUsersAdmins) {
    CreateDomainAdmin -UserName $User
}
#garbage
foreach ($User in $GarbageUsers) {
    CreateLocalUser -UserName $User
    CreateDomainUser -UserName $User
}


Write-Log "User creation process completed."
Write-Output "User creation script completed. Log saved at: $LogFile"