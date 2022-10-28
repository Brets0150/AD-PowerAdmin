#Requires -RunAsAdministrator
<#
.SYNOPSIS
	A collection of functions to help manage, and harden Windows Active Directory.

.VERSION
    0.5.0

.DESCRIPTION
    This is a collection of functions to help manage, and harden Windows Active Directory. This tool is

.EXAMPLE
	PS> Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
	PS> Invoke-WebRequest https://github.com/Brets0150/CG_BlueTeamTools/blob/main/AD-PowerAdmin.ps1 -O ./AD-PowerAdmin.ps1
	PS> ./AD-PowerAdmin.ps1

.LINK
	https://github.com/Brets0150/CG_BlueTeamTools/blob/main/AD-PowerAdmin.ps1

.NOTES
	Author: Bret.s AKA: CyberGladius / License: MIT
#>

#=======================================================================================
# Global Variables and Settings.
[CmdletBinding(DefaultParametersetName='None')]
Param (
    [Parameter(ParameterSetName='Unattend',Mandatory=$true)][switch]$Unattended,
    [Parameter(ParameterSetName='Unattend',Mandatory=$true)]
    [ValidateSet("Test","Daily","krbtgt-RotateKey","PwUserFollowup")][string]$JobName,
    [Parameter(ParameterSetName='Unattend',Mandatory=$false)][string]$JobVar1
)

# Get this files full path and name and put it in a variable.
[string]$global:ThisScript = ([io.fileinfo]$MyInvocation.MyCommand.Definition).FullName

# Parse the $global:ThisScript variable to get the directory path without the script name.
[string]$global:ThisScriptDir = $global:ThisScript.Split("\\")[0..($global:ThisScript.Split("\\").Count - 2)] -join "\\"

# Rename the terminal window, cuz it looks cool. =P
$host.UI.RawUI.WindowTitle = "AD PowerAdmin - CyberGladius.com"

#=======================================================================================
# Base checks.

# Check if the script is running with PowerShell version 5 or higher.
# If not, throw an error and exit.
if ($host.Version.Major -lt 5){
    Write-Output "This script requires PowerShell 5 or higher."
    exit 1
}

# check if $global:ThisScript is empty or null, if yes, display an error message and end the script.
if ($null -eq $global:ThisScript -or $global:ThisScript -eq "") {
    Write-Host "Error: Could not determine the path to this script. Please ensure that the script is being run from a PowerShell prompt (i.e. not from a script or batch file)." -ForegroundColor Red
    exit 1
}

# Check if $global:ThisScript is a real file, if not, display an error message and end the script.
if (!(Test-Path -Path $global:ThisScript)) {
    Write-Host "Error: Could not determine the path to this script. Please ensure that the script is being run from a PowerShell prompt (i.e. not from a script or batch file)." -ForegroundColor Red
    exit 1
}

# Check if this script can reach the "AD-PowerAdmin_settings.ps1" file. If not, display an error message and end the script.
if (!(Test-Path -Path "$global:ThisScriptDir\\AD-PowerAdmin_settings.ps1")) {
    Write-Host "Error: Could not find the AD-PowerAdmin_setting.ps1 file. Please ensure that the script is being run from a PowerShell prompt (i.e. not from a script or batch file).
    The AD-PowerAdmin_settings.ps1 file needs to be located in the same directory as the main AD-PowerAdmin.ps1 file." -ForegroundColor Red
    exit 1
}

# Try to Import the variables from the AD-PowerAdmin_settings.ps1 file.
try {
    Import-Module "$global:ThisScriptDir\\AD-PowerAdmin_settings.ps1" -Force
} catch {
    Write-Host "Error: Could not import the variables from the AD-PowerAdmin_settings.ps1 file.
    Please ensure that the script is being run from a PowerShell prompt (i.e. not from a script or batch file).
    The AD-PowerAdmin_settings.ps1 file needs to be located in the same directory as the main AD-PowerAdmin.ps1 file." -ForegroundColor Red
    exit 1
}

#=======================================================================================
# Functions

# Funcation to build a list of AD Users with Adinistrative Rights, including the Domain Admin and Enterprise Admins.
Function Get-ADAdmins() {
    [PSCustomObject]$ADAdmins = @()


    <# High Value Target Groups
    Domain administrators
    Enterprise administrators
    Schema administrators
    Backup operators
    Account operators
    Server operators
    #>

    # Append $ADAdmins with members of the Domain Admins
    $ADAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive

    # Append $ADAdmins with members of the Enterprise Admins
    $ADAdmins += Get-ADGroupMember -Identity "Enterprise Admins" -Recursive

    # Append $ADAdmins with members of the Builtin Administrators group
    $ADAdmins += Get-ADGroupMember -Identity "Administrators" -Recursive

    # Remove duplicates from $ADAdmins
    $ADAdmins = $ADAdmins | Select-Object -Unique

    # Return the list of AD Admins
    return $ADAdmins
}
# End of Get-ADAdmins function

# Fuction to takes a list of AD Users and gets their account details.
Function Get-ADAdminAudit() {
    # Loop through each AD Admin User
    Get-ADAdmins | ForEach-Object {
        # Get the AD User's details
        Get-ADUser -Identity $_.DistinguishedName -Properties Name, SamAccountName, DistinguishedName, LastLogonDate
    } | Format-List -Property Name, SamAccountName, DistinguishedName, LastLogonDate
}
# End of Get-ADAdminAudit function

# Take a link and download the file to the current directory.
Function Get-DownloadFile {

    Param(
        [Parameter(Mandatory=$True,Position=1)][string]$URL,
        [Parameter(Mandatory=$False,Position=2)][string]$OutFileName
    )

    # Enable Tls12
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # If $OutFileName not given, Get the file name from the link
    if ($OutFileName -eq $null) {
        $OutFileName = $env:temp+'\'+$URL.Split('/').Last()
    }

    # Download the file
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $URL -OutFile $OutFileName

        # Confrim the file was downloaded.
        if (Test-Path -Path $OutFileName) {
            Write-Host "File downloaded successfully." -ForegroundColor Green
        }
        else {
            Write-Host "File download failed." -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Host "Error: Could not download the file." -ForegroundColor Red
        exit 1
    }

    # Return the file name
    return $OutFileName
}
# End of Get-DownloadFile function

# Function that will create a scheduled task that runs a command at a specified time.
# Example: New-ScheduledTask -ActionString "Taskmgr.exe" -ActionArguments "/q" -ScheduleRunTime "09:00" -Recurring Once -TaskName "Test" -TaskDiscription "Just a Test"
Function New-ScheduledTask {

    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$ActionString,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$ActionArguments,
        [Parameter(Mandatory=$True,Position=3)]
        [string]$ScheduleRunTime,
        [Parameter(Mandatory=$True,Position=4)][ValidateSet("Daliy","Weekly","Monthly","Once")]
        [string]$Recurring,
        [Parameter(Mandatory=$True,Position=5)]
        [string]$TaskName,
        [Parameter(Mandatory=$True,Position=6)]
        [string]$TaskDiscription
    )

    # Get the current user's name
    [string]$UserName = "$env:UserDomain\$env:UserName"

    # Create $trigger based on $Recurring
    if ($Recurring -eq "Daliy") {
        $Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Weekly") {
        $Trigger = New-ScheduledTaskTrigger -WeeksInterval 1 -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Monthly") {
        $Trigger = New-ScheduledTaskTrigger -MonthsInterval 1 -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Once") {
        $Trigger = New-ScheduledTaskTrigger -Once -At $ScheduleRunTime
    }

    try {
        $Action    = (New-ScheduledTaskAction -Execute $ActionString -Argument $ActionArguments)
        $Principal = New-ScheduledTaskPrincipal -UserId $UserName -RunLevel Highest
        $Settings  = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
        Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description $TaskDiscription
    }
    catch {
        Write-Host "Unable to create schedule task."
        Write-Output $_
        return $false
    }

    return $true
}
#End of New-ScheduledTask function

# Function to get the number of days since a users last password update. Returns -1 if the user has never changed their password. otherwise returns the number of days since the last password change.
Function Get-ADUserPasswordAge {
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$UserName
    )
    # Get the user's password last set date
    [int]$DayOfYearPasswordLastSet = (Get-ADUser -Identity $UserName -Properties PasswordLastSet).PasswordLastSet.DayOfYear
    # Get the number of days since the user last changed their password
    [int]$DaysSincePasswordChange = (Get-Date).DayOfYear - $DayOfYearPasswordLastSet
    # Return the number of days since the user last changed their password
    return $DaysSincePasswordChange
}
# End of Get-ADUserPasswordAge function

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function Test-PasswordIsComplex() {

    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [String]$StringToTest
    )

	Process {
		$criteriaMet = 0

		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($StringToTest -cmatch '[A-Z]') {$criteriaMet++}

		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($StringToTest -cmatch '[a-z]') {$criteriaMet++}

		# Numeric Characters (0 through 9)
		If ($StringToTest -match '\d') {$criteriaMet++}

		# Special Chracters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($StringToTest -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}

		# Check If It Matches Default Windows Complexity Requirements
		If ($criteriaMet -lt 3) {Return $false}
		If ($StringToTest.Length -lt 8) {Return $false}
		Return $true
	}
}
# End of Test-PasswordIsComplex function

# Function to create a random 64 character long password and return it.
Function New-RandomPassword {
    param(
        [Parameter(Mandatory=$False,Position=1)]
        [int]$PasswordNrChars = 64
    )

	Process {
		$Iterations = 0
        Do {
			If ($Iterations -ge 20) {
				EXIT
			}
			$Iterations++
			$pwdBytes = @()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
                $pwdBytes += $byte[0]
			}
			While ($pwdBytes.Count -lt $PasswordNrChars)
				$NewPassword = ([char[]]$pwdBytes) -join ''
			}
        Until (Test-PasswordIsComplex $NewPassword)
        Return $NewPassword
	}
}
# End of New-RandomPassword function

# Function to update the KRBTGT password in the Active Directory Domain.
Function Update-KRBTGTPassword {

    Param(
        [Parameter(Mandatory=$False,Position=1)]
        [bool]$OverridePwd
    )

    # If [bool]$OverridePwd is unset, empty, or null, set it to $false.
    If ($null -eq $OverridePwd -or $OverridePwd -eq $false -or $OverridePwd -eq "") {
        $OverridePwd = $false
    }

    # Get the current domain
    [string]$Domain = (Get-ADDomain).NetbiosName

    # if the current running user is a member of the Domain Admins group.
    if ( $null -eq ((Get-ADGroupMember -Identity "Domain Admins") | Where-Object {$_.SamAccountName -eq $env:UserName}) ) {
        # If the current user is not a member of the Domain Admins group, then exit the script.
        Write-Host "You are not a member of the Domain Admins group. Please contact your Domain Administrator."
        return
    }

    # Try to connect to the Active Directory Domain, if fails, display error message and return the main menu.
    try {
        $ADTest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Domain")
    } catch {
        Write-Host "Unable to connect to the Active Directory Domain. Please check the Domain Name and try again."
        Write-Host "$ADTest"
        Write-Host "$_"
        return
    }

    # Get KRBTGT AD Object with all properties and attributes, store in $KRBTGTObject.
    $KRBTGTObject = Get-ADUser -Filter {sAMAccountName -eq 'krbtgt'} -Properties *

    # Get a Intiger of days between the current date and the PasswordLastSet of the KRBTGT AD Object.
    [int]$KRBTGTLastUpdateDays = (Get-Date).DayOfYear - $KRBTGTObject.PasswordLastSet.DayOfYear

    # Check if the current KRBTGT password last update time is less than 90 days.
    if ( ($KRBTGTLastUpdateDays -lt $global:krbtgtPwUpdateInterval) -and ($OverridePwd -eq $false) ) {
        # If the current KRBTGT password last update time is less than 90 days, then exit the script.
        Write-Host "The current KRBTGT password last update time is less than $global:krbtgtPwUpdateInterval days."
        Write-Host "Days since last update: $KRBTGTLastUpdateDays"
    }

    # If the current KRBTGT password last update time is greater than 90 days, then update the krbtgt user password.
    if ( ($KRBTGTLastUpdateDays -gt $global:krbtgtPwUpdateInterval) -or $OverridePwd ) {

        try {
            [int]$PassLength = 64

            # Generate A New Password With The Specified Length (Text)
            [string]$NewKRBTGTPassword = (New-RandomPassword $PassLength).ToString()

            # Convert the NewKRBTGTPassword to SecureString
            $NewKRBTGTPasswordSecure = ConvertTo-SecureString -String $NewKRBTGTPassword -AsPlainText -Force

            # Update the krbtgt user password with a random password genorated by the New-RandomPassword function.
            Set-ADAccountPassword -Identity $KRBTGTObject.DistinguishedName -Reset -NewPassword $NewKRBTGTPasswordSecure

            # Update the KRBTGT object variable.
            $KRBTGTObject = Get-ADUser -Filter {sAMAccountName -eq 'krbtgt'} -Properties *

            # check if the password was updated successfully by checking if the PasswordLastSet equal to the current date and time.
            if ( $KRBTGTObject.PasswordLastSet.DayOfYear -eq (Get-Date).DayOfYear ) {
                # If the password was updated successfully, then display a success message.
                Write-Host "The KRBTGT password was updated successfully." -ForegroundColor Green

                # If $OverridePwd is not true, then add the scheduled task to update the KRBTGT password.
                If ($OverridePwd -eq $false) {
                    # Get the time it will be 10 hours and 10 minutes from the current time.
                    $NextUpdateTime = (Get-Date).AddHours(10).AddMinutes(10)

                    [string]$ThisScriptsFullName = $global:ThisScript

                    # Create a schedule task to run the Update-KRBTGTPassword function X number of hours after first password update.
                    New-ScheduledTask -ActionString "$ThisScriptsFullName" -ActionArguments '-Unattended $true -JobName "krbtgt-RotateKey"' -ScheduleRunTime $NextUpdateTime `
                    -Recurring Once -TaskName "KRBTGT-Final-Update" -TaskDiscription "KRBTGT second password update, to run once."

                    # Check if the scheduled task named "KRBTGT-Final-Update" was created successfully.
                    if ($null -eq (Get-ScheduledTask -TaskName "KRBTGT-Final-Update")) {
                        # If the scheduled task was not created successfully, then display an error message.
                        Write-Host "The KRBTGT password update task was not created successfully." -ForegroundColor Red
                        return
                    }
                }
                # If $OverridePwd is true, check if the scheduled task named "KRBTGT-Final-Update" exists, if it does unregister it.
                If ($OverridePwd -eq $true) {
                    # Check if the scheduled task named "KRBTGT-Final-Update" exists.
                    if ($null -ne (Get-ScheduledTask -TaskName "KRBTGT-Final-Update")) {
                        # If the scheduled task named "KRBTGT-Final-Update" exists, then unregister it.
                        Unregister-ScheduledTask -TaskName "KRBTGT-Final-Update" -Confirm:$false
                    }
                }
            } else {
                # If the password was not updated successfully, then display an error message.
                Write-Host "The KRBTGT password was not updated successfully." -ForeGroundColor Red
                return
            }
        }
        catch {
            Write-Host "Unable to update the KRBTGT password. Please check the Domain Name and try again."
            Write-Output $_
            return
        }
    }
}
# End of Update-KRBTGTPassword function

# Function to seartch AD for Computer Objects that have been inactive for more than X days.
# Example: Search-InactiveComputers -SearchOUbase 'OU=Desktops,DC=EXAMPLE,DC=COM' -DisabledOULocal 'OU=Disabled.Desktop,OU=Desktops,DC=EXAMPLE,DC=COM' -InactiveDays 90 -ReportOnly $false
Function Search-InactiveComputers {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SearchOUbase,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$DisabledOULocal,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=4)]
        [bool]$ReportOnly
    )

    # $time variable converts $DaysInactive to LastLogonTimeStamp property format for the -Filter switch to work
    $InactiveDate = (Get-Date).Adddays(-($InactiveDays))

    # Check if the OU specified in the $SearchOUbase parameter exists in the Active Directory Domain.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $SearchOUbase} -Properties * ) ) {
        # If the OU specified in the $SearchOUbase parameter does not exist in the Active Directory Domain, then display an error message.
        Write-Host "Error: The Computer OU specified in the SearchOUbase parameter does not exist in the Active Directory Domain." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }

    # Check if the OU specified in the $DisabledOULocal parameter exists in the Active Directory Domain.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $DisabledOULocal} -Properties * ) ) {
        # If the OU specified in the $DisabledOULocal parameter does not exist in the Active Directory Domain, then display an error message.
        Write-Host "Error: The Computer OU specified in the DisabledOULocal parameter does not exist in the Active Directory Domain." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }

    # Search for Computers that have been inactive for more than X days.
    $InactiveComputerObjects = Get-ADComputer -SearchBase $SearchOUbase -Filter {LastLogonTimeStamp -lt $InactiveDate -and Enabled -eq $true} `
    -ResultPageSize 2000 -resultSetSize $null -Properties Name, OperatingSystem, SamAccountName, DistinguishedName, LastLogonDate

    # Check if $InactiveComputerObjects is empty. If it is, then no computers are inactive.
    if ($null -ne $InactiveComputerObjects) {

        # If $ReportOnly is true, then display the inactive computer objects and exit the function.
        if ($ReportOnly) {
            # Display the inactive computer objects.
            Write-Host "Inactive Computer Objects:" -ForegroundColor Yellow
            $InactiveComputerObjects | Select-Object Name, OperatingSystem, SamAccountName, DistinguishedName, LastLogonDate | Format-Table -AutoSize
            return
        }

        #For each inactive computer, Disable the Computer AD object, update the discription, and move the computer to the Disabled.Desktop OU.
        $InactiveComputerObjects | ForEach-Object {
            # Current Computer Object.
            $CurrentComputerObject = $_
            # Get the old(currently) set computer discription.
            $ComputerOldDescription = (Get-ADComputer -Identity $CurrentComputerObject -Prop Description).Description

            #Get the old OU location of the computer.
            $ComputerOldOU = $CurrentComputerObject.DistinguishedName

            # Get all groups the computer is a member of.
            $ComputersGroupMemberships = Get-ADPrincipalGroupMembership $CurrentComputerObject.DistinguishedName

            # Foreach group, remove the computer from the group.
            $ComputersGroupMemberships | ForEach-Object {
                # If $_.DistinguishedName not equal to "Domain Computers", then remove the computer from the group.
                if ($_.name -ne 'Domain Computers') {
                    Remove-ADPrincipalGroupMembership -Identity $CurrentComputerObject -MemberOf $_.DistinguishedName -Confirm:$False
                }
            }

            # Disable the computer in AD.
            Disable-ADAccount $CurrentComputerObject

            # Update the computer description.
            Set-ADComputer $CurrentComputerObject -Description "$ComputerOldDescription -- Account disabled $(Get-Date -format "yyyy-MM-dd") by AD-PowerAdmin. :: OLD-OU: $ComputerOldOU"

            # Move the computer to the Disabled.Desktop OU.
            Move-ADObject $CurrentComputerObject -targetpath $DisabledOULocal
        }
    }

    # Check if $InactiveComputerObjects is empty. If it is, Output that no computers are inactive.
    if ($null -eq $InactiveComputerObjects) {
        Write-Host "No inactive computers were found." -ForegroundColor Green
    }

}
# End of Search-InactiveComputers function

# Function take in array of hashtables, for each hashtable, run the Search-InactiveComputers function.
# Example: Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays 90
Function Search-MultipleInactiveComputers {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [hashtable[]]$InactiveComputersLocations,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=3)]
        [bool]$ReportOnly
    )

    # Foreach hashtable in the $InactiveComputersLocations array, run the Search-InactiveComputers function.
    $InactiveComputersLocations| ForEach-Object {
        Search-InactiveComputers -SearchOUbase $_.SearchOUbase -DisabledOULocal $_.DisabledOULocal -InactiveDays $InactiveDays -ReportOnly $ReportOnly
    }
}
# End of Search-MultipleInactiveComputers function

# function to only search for inactive User accounts and display there SamName and last login date.
# Example: Search-InactiveUsers -InactiveDays 90 -DisplayOnly
Function Search-InactiveUsers {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SearchOUbase,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$DisabledOULocal,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=4)]
        [bool]$ReportOnly
    )

    # $time variable converts $DaysInactive to LastLogonTimeStamp property format for the -Filter switch to work
    $InactiveDate = (Get-Date).Adddays(-($InactiveDays))

    # Check if the $DisabledOULocal is a valid OU. If not, then exit the function.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $DisabledOULocal} -Properties * ) ) {
        Write-Host "Error: The User OU specified in the DisabledOULocal($DisabledOULocal) does not exist in the AD." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }

    # Check if the SearchOUbase is a valid OU. If not, then exit the function.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $SearchOUbase} -Properties * ) ) {
        Write-Host "Warning: The given SearchOUbase($SearchOUbase) does not exist or is not set. Scanning entire AD..." -ForegroundColor Yellow
        $InactiveUserObjects = Get-ADUser -Filter {LastLogonTimeStamp -lt $InactiveDate -and Enabled -eq $true} -Properties Name, SamAccountName, DistinguishedName, LastLogonDate
    } else {
        # Search for Users that have been inactive for more than X days.
        $InactiveUserObjects = Get-ADUser -Filter {LastLogonTimeStamp -lt $InactiveDate -and Enabled -eq $true} -SearchBase $SearchOUbase -Properties Name, SamAccountName, DistinguishedName, LastLogonDate
    }

    # Check if $InactiveUserObjects is empty. If it is, then no users are inactive.
    if ($null -ne $InactiveUserObjects) {
        # If $DisplayOnly is true, then display the SamName and last login date of the inactive users.
        if ($ReportOnly -eq $true) {
            Write-Host '-- Inactive User Accounts --'
            # For each inactive user, display the SamName and last login date.
            $InactiveUserObjects | ForEach-Object {
                # Display the SamName and last login date.
                Write-Host SamName: $_.SamAccountName `-`- Last Login: $_.LastLogonDate `-`- Distinguished Name: $_.DistinguishedName
            }
            Write-Host '--------------------------'
            return
        }

        # If $ReportOnly is false, then disable the inactive users.
        if ($ReportOnly -eq $false) {
            # For each inactive user, Disable the User AD object, update the discription, and move the user to the Disabled.Users OU.
            $InactiveUserObjects | ForEach-Object {
                # Current User Object.
                $CurrentUserObject = $_
                # Get the old(currently) set user discription.
                $UserOldDescription = (Get-ADUser -Identity $CurrentUserObject -Prop Description).Description
                # Get the old OU location of the user.
                $UserOldOU = $CurrentUserObject.DistinguishedName
                # Get all groups the user is a member of.
                $UsersGroupMemberships = Get-ADPrincipalGroupMembership $CurrentUserObject.DistinguishedName
                # Foreach group, remove the user from the group.
                $UsersGroupMemberships | ForEach-Object {
                    # If $_.DistinguishedName not equal to "Domain Users" and not equal to "Administrators, then remove the user from the group.
                    if ($_.name -ne 'Domain Users' -and $_.name -ne 'Administrators') {
                        Remove-ADPrincipalGroupMembership -Identity $CurrentUserObject -MemberOf $_.DistinguishedName -Confirm:$False
                    }
                }
                # Disable the user account.
                Disable-ADAccount -Identity $CurrentUserObject -Confirm:$False
                # Update the user discription.
                Set-ADUser -Identity $CurrentUserObject -Description "$UserOldDescription -- Account disabled $(Get-Date -format 'yyyy-MM-dd') by AD-PowerAdmin. :: OLD-OU: $UserOldOU" -Confirm:$False
                # Move the user to the Disabled Users OU.
                Move-ADObject -Identity $CurrentUserObject -TargetPath $DisabledOULocal -Confirm:$False
                # Output the Samname of the user that was disabled.
                Write-Host "Disabled User: $CurrentUserObject.SamAccountName" -ForegroundColor Green
            }
        }
    }

    # Check if $InactiveUserObjects is empty. If it is, Output that no users are inactive.
    if ($null -eq $InactiveUserObjects) {
        Write-Host "No inactive users were found in $SearchOUbase" -ForegroundColor Green
    }

}
# End of Search-InactiveUsers function

# Function take in array of hashtables, for each hashtable, run the Search-InactiveComputers function.
# Example: Search-MultipleInactiveComputers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays 90
Function Search-MultipleInactiveUsers {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [hashtable[]]$InactiveUsersLocations,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=3)]
        [bool]$ReportOnly
    )

    # Foreach hashtable in the $InactiveUsersLocations array, run the Search-InactiveComputers function.
    $InactiveUsersLocations | ForEach-Object {
        #If $_.SearchOUbase is empty, then SearchOUbase equals $null.
        if ($_.SearchOUbase -eq '') {
            Search-InactiveUsers -SearchOUbase 'NA' -DisabledOULocal $_.DisabledOULocal -InactiveDays $InactiveDays -ReportOnly $ReportOnly
        } else {
            Search-InactiveUsers -SearchOUbase $_.SearchOUbase -DisabledOULocal $_.DisabledOULocal -InactiveDays $InactiveDays -ReportOnly $ReportOnly
        }
    }
}
# End of Search-MultipleInactiveUsers function

# Function to install the DSInternals PowerShell module.
# DSInternals is used to audit users passwords and other security attributes.
# The module is well-vetted by Microsoft and is safe to use.
# PowerShell Gallery: https://www.powershellgallery.com/packages/DSInternals/4.7
Function Install-DSInternals {
    # Check if the DSInternals PowerShell module is installed. If not, then install it.
    if ( $null -eq (Get-Module -ListAvailable -Name DSInternals) ) {
        # Install the DSInternals PowerShell module.
        Install-Module -Name DSInternals -Force -ErrorAction SilentlyContinue
    }
    # Checkc if the DSInternals PowerShell module is installed. Try again to install it.
    if ( $null -eq (Get-Module -ListAvailable -Name DSInternals) ) {
        Write-Host "Warning: The DSInternals PowerShell module failed to install. Trying another method...." -ForegroundColor Yellow
        # TLS 1.2 must be enabled on older versions of Windows.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        # Download the NuGet package manager binary.
        Install-PackageProvider -Name NuGet -Force
        # Register the PowerShell Gallery as package repository if it is missing for any reason.
        if($null -eq (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default }
        # Download the DSInternals PowerShell module.
        Install-Module -Name DSInternals -Force
    }

    # confrim that the DSInternals PowerShell module is installed. If not, then output an error and exit the script.
    if ( $null -eq (Get-Module -ListAvailable -Name DSInternals) ) {
        Write-Host "Error: The DSInternals PowerShell module is not installed. Please install it and try again." -ForegroundColor Red
        Exit 1
    }

    # If the DSInternals PowerShell module is installed, then import it.
    Import-Module DSInternals
}
# End of Install-DSInternals function

# Funcation to user the DSInternals PowerShell module and the Test-PasswordQuality to check all users password quality in active directory.
Function Get-PasswordAudit {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$false,Position=1)]
        [string]$SearchOUbase,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$NtlmHashDataFile,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$WeakPassDictFile
    )

    # Check if the DSInternals PowerShell module is installed. If not, then install it.
    Install-DSInternals

    # If $SearchOUbase is not empty, then filter $AllAdAccountData to only include users in the $SearchOUbase OU.
    if ($SearchOUbase -ne '') {
    # Check if the provided OU exists. If not, then output an error and exit the script.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $SearchOUbase} -ErrorAction SilentlyContinue) ) {
        Write-Host "Error: The OU $SearchOUbase does not exist." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }
    # Use Get-ADReplAccount from DSInternals PowerShell module to get all users in active directory. This function work with AD replication(DCSync) data.
    $AllAdAccountData = Get-ADReplAccount -All -Server $env:COMPUTERNAME | Where-Object { $_.DistinguishedName -like "*$SearchOUbase*" }
    }

    # If $SearchOUbase is empty, then dont filter Get-ADReplAccount.
    if ($SearchOUbase -eq '') {
    # Output that no OU was provided, so all users will be checked.
    Write-Host "No OU was provided, so all users will be checked." -ForegroundColor Yellow
    # Use Get-ADReplAccount from DSInternals PowerShell module to get all users in active directory. This function work with AD replication(DCSync) data.
    $AllAdAccountData = Get-ADReplAccount -All -Server $env:COMPUTERNAME
    }

    # Confrim  $AllAdAccountData is not empty. If it is, then output an error and exit the function.
    if ($null -eq $AllAdAccountData) {
    Write-Host "Error: No users were found in active directory." -ForegroundColor Red
    return
    }

    # Build the base of the Test-PasswordQuality command.
    $TestPasswordParam = @{}

    # If $NtlmHashDataFile is not empty, then use the $NtlmHashDataFile file to check the password quality. Append the $NtlmHashDataFile to the $TestPasswordQualityCommand.
    if ($NtlmHashDataFile -ne '') {
    # Test if the $NtlmHashDataFile file exists. If not, then output an warning and do not use the $NtlmHashDataFile file.
    if (Test-Path $NtlmHashDataFile) {
        $TestPasswordParam.WeakPasswordHashesSortedFile = $NtlmHashDataFile
    } else {
        Write-Host "Warning: The $NtlmHashDataFile file does not exist. The $NtlmHashDataFile file will not be used." -ForegroundColor Yellow
    }
    }

    # If $WeakPassDictFile is not empty, then use the $WeakPassDictFile file to check the password quality. Append the $WeakPassDictFile to the $TestPasswordQualityCommand.
    if ($WeakPassDictFile -ne '') {
    # Test if the $WeakPassDictFile file exists. If not, then output an warning and do not use the $WeakPassDictFile file.
    if (Test-Path $WeakPassDictFile) {
        $TestPasswordParam.WeakPasswordsFile = $WeakPassDictFile
    } else {
        Write-Host "Warning: The $WeakPassDictFile file does not exist. The $WeakPassDictFile file will not be used." -ForegroundColor Yellow
    }
    }

    # Pipe the $AllAdAccountData to the $TestPasswordQualityCommand.
    [object]$ADPasswordTestData = $AllAdAccountData | Test-PasswordQuality @TestPasswordParam

    # Confirl the $ADPasswordTestData is not empty. If it is, then output an error and exit the function.
    if ($null -eq $ADPasswordTestData) {
    Write-Host "Error: No users were found in active directory." -ForegroundColor Red
    return
    }

    # If the $ADPasswordTestData is not empty, then return the $ADPasswordTestData.
    return $ADPasswordTestData
}
# End of Get-PasswordAudit function

# Funcation to user the DSInternals PowerShell module and the Test-PasswordQuality to check all users password quality in active directory.
Function Get-PasswordAuditAdminReport {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AdPwTestData
    )

    # If the $AdPwTestData is empty, then use the Get-PasswordAudit function to get the $AdPwTestData.
    if ($null -eq $AdPwTestData) {
        [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile
    }
    # Convert the $ADPasswordTestData to an output string.
    $ADPasswordTestDataString = $AdPwTestData | Out-String

    # Output the $ADPasswordTestDataString to the screen.
    Write-Host $ADPasswordTestDataString -ForegroundColor Green

    #try to email the $global:AdminReportEmail with the Subject "ADPowerAdmin Password Audit Report" and the email Body will contains $AdPwTestData data.
    try {
        Send-Email -ToEmail "$global:ReportAdminEmailTo" -FromEmail "$global:ReportsEmailFrom" -Subject "ADPowerAdmin Password Audit Report" -Body $ADPasswordTestDataString
    } catch {
        # If the email fails, then output an error and exit the function.
        Write-Host "Error: The Admin Report email failed to send to $global:ReportAdminEmailTo." -ForegroundColor Red
        write-host "    Please check the 'AD-PowerAdmin_settings.ps1' file and make sure the email settings are correct." -ForegroundColor Red
        # if debug is enabled, then output the error.
        if ($global:Debug) {
            Write-Host "Debug: $_" -ForegroundColor Red
        }
        return
    }
}
# End of Get-PasswordAuditAdminReport function

# Function to process users with breached or weak passwords.
Function Invoke-WeakPwdProcess {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AdPwTestData
    )
    # If the $AdPwTestData is empty, then use the Get-PasswordAudit function to get the $AdPwTestData.
    if ($null -eq $AdPwTestData) {
        [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile
    }

    # Filter the $ADPasswordTestData to only include users with a breached password.
    $BreachedUsers = $AdPwTestData | Select-Object WeakPassword | Select-Object -ExpandProperty *

    # If the $BreachedUsers is not empty, then email the user with the breached password with the Subject "ADPowerAdmin: Password Breached or Weak - ACTION REQUIRED" and the email Body will tell the User to change their password in 72-hour.
    if ($null -ne $BreachedUsers) {
        # Loop through each user in $BreachedUsers.
        foreach ($User in $BreachedUsers) {

            # Split the $User to get the user name only.
            $UserOnly  = $User.Split('\')[1]

            # Check is a schedule task with the TaskName of "PWFollowUp-$UserOnly" exists for the user. If it does, then skip the user.
            if (Get-ScheduledTask -TaskName "PWFollowUp-$UserOnly" -ErrorAction SilentlyContinue) {
                continue
            }
            # Get the email addrerss of the user from active directory.
            $UserData  = Get-ADUser -Identity $UserOnly -Properties *
            $UserEmail = $UserData | Select-Object -ExpandProperty EmailAddress
            $UserName  = $UserData | Select-Object -ExpandProperty DisplayName
            $Subject   = $global:PwAuditAlertEmailSubject
            # Message to send to the user.
            $Message = "Hello $UserName,`r`n"
            $Message += $global:PwAuditAlertEmailMessage

            # If the $global:PwAuditAlertEmailCCAdmins is true, then add the $global:ReportAdminEmailTo to the CC list.
            if ($global:PwAuditAlertEmailCCAdmins) {
                $CC = $global:ReportAdminEmailTo
            } else {
                $CC = $null
            }

            #try to email the $User.
            try {
                Send-Email -ToEmail "$global:ReportAdminEmailTo" -FromEmail "$global:ReportsEmailFrom" -CcEmail $CC -Subject "$Subject" -Body "$Message"
            } catch {
                # If the email fails, then output an error and exit the function.
                Write-Host "Error: A breached user email failed to send to $UserEmail" -ForegroundColor Red
                write-host "    Please check the 'AD-PowerAdmin_settings.ps1' file and make sure the email settings are correct." -ForegroundColor Red
                # if debug is enabled, then output the error.
                if ($global:Debug) {
                    Write-Host "Debug: $_" -ForegroundColor Red
                }
                return
            }

            [string]$TaskName = "PWFollowUp-$UserOnly"
            [string]$TaskDiscription = "Follow up check to confirm the password has been changed for $UserOnly"
            # Set the scheduled task to run in $global:PwAuditPwChangeGracePeriod days.
            $PwFollowUpTime = (Get-Date).AddDays($global:PwAuditPwChangeGracePeriod)

            [string]$ThisScriptsFullName = $global:ThisScript

            # Try to schedule a task to change the password of the user in $global:PwAuditPwChangeGracePeriod.
            try {
                <# Create a New-ScheduledTask.
                    The action will be to run the $ThisScriptsFullName with the -ActionArguments "-Unattended -JobName 'PwUserFollowup' -JobVar1 '$UserOnly'"
                    The -ScheduleRunTime at $PwFollowUpTime.
                    The run task once.
                    The create with the TaskName with the value of $TaskName.
                    The create with the TaskDiscription with the value of $TaskDiscription.
                    Do not output anything to the console.
                #>
                New-ScheduledTask -ActionString "$ThisScriptsFullName" -ActionArguments "-Unattended -JobName 'PwUserFollowup' -JobVar1 '$UserOnly'" -ScheduleRunTime $PwFollowUpTime -Recurring Once -TaskName $TaskName -TaskDiscription $TaskDiscription | Out-Null

            } catch {
                # If the task fails, then output an error and exit the function.
                Write-Host "Error: A task failed to schedule to change the password of $UserOnly." -ForegroundColor Red
                # if debug is enabled, then output the error.
                if ($global:Debug) {
                    Write-Host "Debug: $_" -ForegroundColor Red
                }
                return
            } finally {
                Write-Host "Scheduled follow up check for the password of $UserOnly, at $PwFollowUpTime" -ForegroundColor Green
            }
        }
    }
}
# End of Invoke-WeakPwdProcess function

# A function that will take in a username, check if that user has updated their password in the days value in $global:PwAuditPwChangeGracePeriod.
# If the user has not updated their password in the days value in $global:PwAuditPwChangeGracePeriod, then enable the user attribue "User must change password at next logon" fro the users AD account.
function Test-UserUpdatedPassword {
    param (
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Username,
        [Parameter(Mandatory=$true,Position=2)]
        [int]$UpdateGracePeriod
    )
    # Confrim the username give is not empty.
    if ($Username -eq '' -or $Username -eq $null) {
        Write-Host "Error: The username is empty." -ForegroundColor Red
        return
    }
    # Confirm the user account exists in active directory.
    if (-not (Get-ADUser -Identity $Username -ErrorAction SilentlyContinue)) {
        Write-Host "Error: The user account $Username does not exist in active directory." -ForegroundColor Red
        return
    }
    # Use the Get-ADUserPasswordAge function to get the password age of the user.
    $PasswordAge = Get-ADUserPasswordAge -Username $Username
    # Check if the $PasswordAge is greater than the $global:PwAuditPwChangeGracePeriod. If it is, then enable the user attribue "User must change password at next logon" fro the users AD account.
    if ($PasswordAge -gt $UpdateGracePeriod) {
        # Enable the user attribue "User must change password at next logon" fro the users AD account.
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
        # Output the user name and the date the user will be required to change their password.
    }
}
# End of the Test-UserUpdatedPassword function.

# A Function that takes in "TO" and "FROM" email addresses and a subject line and sends an email with the contents of the $ReportData variable.
Function Send-Email {
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ToEmail,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$FromEmail,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$CcEmail,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$Subject,
        [Parameter(Mandatory=$true,Position=4)]
        [string]$Body,
        [Parameter(Mandatory=$false,Position=5)]
        [string]$SmtpServer,
        [Parameter(Mandatory=$false,Position=6)]
        [string]$SmtpPort,
        [Parameter(Mandatory=$false,Position=7)]
        [string]$SmtpUser,
        [Parameter(Mandatory=$false,Position=8)]
        [string]$SmtpPass,
        [Parameter(Mandatory=$false,Position=9)]
        [bool]$DebugEmail
    )

    # Build the email sending variables.
    $EmailServerParam = @{}

    # If $SMTPServer is not empty, then use the $global:SmtpServer variable. If the $global:SmtpServer is empty, then display an error and exit the function.
    if ($SmtpServer -ne '') {
        $EmailServerParam.SmtpServer = $SmtpServer
    } elseif ($global:SmtpServer -ne '') {
        $EmailServerParam.SmtpServer = $global:SMTPServer
    } else {
        Write-Host "Error: The SMTP Server is not set. Please set the SMTP Server in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # If $SMTPPort is not empty, then use the $global:SmtpPort variable. If the $global:SmtpPort is empty, then display an warning and continue.
    if ($SmtpPort -ne '') {
        $EmailServerParam.Port = $SmtpPort
    } elseif ($global:SmtpPort -ne '') {
        $EmailServerParam.Port = $global:SMTPPort
    } else {
        $EmailServerParam.Port = "587"
    }
    # Build the email sending variables.
    $Message = New-Object Net.Mail.MailMessage;
    $Message.From = $FromEmail;
    $Message.To.Add($ToEmail);
    $Message.Subject = "$Subject";
    $Message.Body = "$Body";

    # If $CcEmail is not empty or null, then add the $CcEmail to the email.
    if ($CcEmail -ne '' -and $CcEmail -ne $null) {
        $Message.CC.Add($CcEmail);
    }

    $Smtp = New-Object Net.Mail.SmtpClient($EmailServerParam.SmtpServer, $EmailServerParam.Port);
    # SSL is always used.
    $Smtp.EnableSSL = $true;

    # If $SMTPUser and $SMTPPass is not empty or null, then use the $global:SMTPUser and $global:SMTPPassword variables. If the $global:SMTPUser or $global:SMTPPassword is empty, then display an warning and continue.
    # If either is not empty, then use the $global:SMTPUser and $global:SMTPPassword to build $Smtp.Credentials object variable.
    if (($SmtpUser -ne '') -and ($SmtpPass -ne '')) {
        $Smtp.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPass);
    }
    if (($global:SMTPUser -ne '') -and ($global:SMTPPassword -ne '')) {
        $Smtp.Credentials = New-Object System.Net.NetworkCredential($global:SMTPUser, $global:SMTPPassword);
    }

    # Try to send the email.
    try {
        $Smtp.send($Message);
    } catch {
        # If the email fails, then output an error and exit the function.
        Write-Host "Error: The email failed to send to $ToEmail " -ForegroundColor Red
        Write-Host "    Please check the 'AD-PowerAdmin_settings.ps1' file and make sure the email settings are correct." -ForegroundColor Red
        # If $global:Debug is true, then output the full error message.
        if (($global:Debug) -or ($DebugEmail)) {
            Write-Host $_.Exception -ForegroundColor Red
        }
        return
    }
    # Close the SMTP connection.
    $Message.Dispose();
    $Smtp.Dispose();
    # Start a sleep timer for 1 second.
    Start-Sleep -Seconds 1
}
# End of the Send-Email function.

# A To ask a user for the variable for the Send-Email function. With the gathered information, the function will send an email to the user.
Function Send-EmailTest {
    $Subject = "ADPowerAdmin: Test Email"
    $Body = "This is a test email from the ADPowerAdmin script. If you are reading this, then the email was sent successfully."
    Write-Host "You can leave any of the following fields blank and the script will use the default settings from the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
    # Ask the user for the email address to send the test email to.
    $ToEmail = Read-Host "Enter the email address to send the test email to"
    # Ask the user for the email address to send the test email from.
    $FromEmail = Read-Host "Enter the email address to send the test email from"
    # Ask the user for the SMTP Server to send the test email from.
    $SmtpServer = Read-Host "Enter the SMTP Server to send the test email"
    # Ask the user for the SMTP Port to send the test email from.
    $SmtpPort = Read-Host "Enter the SMTP Port to send the test email"
    # Ask the user for the SMTP User to send the test email from.
    $SmtpUser = Read-Host "Enter the SMTP User to send the test email"
    # Ask the user for the SMTP Password to send the test email from.
    $SmtpPass = Read-Host "Enter the SMTP Password to send the test email"

    $SendTestEmailParam = @{}

    # If $SMTPServer is not empty, then use the $global:SmtpServer variable for $SMTPServer. If the $global:SmtpServer is empty, then display an error and exit the function.
    # If $SMTPServer is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpServer -ne '') {
        $SendTestEmailParam.SmtpServer = "$SmtpServer"
    } elseif ($global:SmtpServer -ne '') {
        $SendTestEmailParam.SmtpServer = "$global:SMTPServer"
    } else {
        Write-Host "Error: The SMTP Server is not set. Please set the SMTP Server in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # If $SMTPPort is not empty, then use the $global:SmtpPort variable for $SMTPPort. If the $global:SmtpServer is empty, then display a warning and continue.
    # If $SMTPPort is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpPort -ne '') {
        $SendTestEmailParam.SmtpPort = "$SmtpPort"
    } elseif ($global:SmtpPort -ne '') {
        $SendTestEmailParam.SmtpPort = "$global:SMTPPort"
    } else {
        Write-Host "Warning: The SMTP Port is not set. Please Check the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
        Write-Host "Trying to send email with default SMTP Port." -ForegroundColor Yellow
    }

    # If $SmtpUser is not empty, then use the $global:SmtpPort variable for $SmtpUser. If the $global:SmtpServer is empty, then display a warning and continue.
    # If $SmtpUser is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpUser -ne '') {
        $SendTestEmailParam.SmtpUser = "$SmtpUser"
    } elseif ($global:SMTPUsername -ne '') {
        $SendTestEmailParam.SmtpUser = "$global:SMTPUsername"
    } else {
        Write-Host "Warning: The SMTP User is not set. Please Check the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
        Write-Host "Trying to send email without SMTP User." -ForegroundColor Yellow
    }

    # If $SmtpPass is not empty, then use the $global:SmtpPort variable for $SmtpPass. If the $global:SmtpServer is empty, then display a warning and continue.
    # If $SmtpPass is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpPass -ne '') {
        $SendTestEmailParam.SmtpPass = "$SmtpPass"
    } elseif ($global:SMTPPassword -ne '') {
        $SendTestEmailParam.SmtpPass = "$global:SMTPPassword"
    } else {
        Write-Host "Warning: The SMTP Password is not set. Please Check the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
        Write-Host "Trying to send email without SMTP Password." -ForegroundColor Yellow
    }

    # If $ToEmail is not empty, then use the $global:ToEmail variable for $ToEmail. If the $global:ToEmail is empty, then display an error and exit the function.
    # If $ToEmail is not empty add it to the $SendTestEmailParam variable.
    if ($ToEmail -ne '') {
        $SendTestEmailParam.ToEmail = "$ToEmail"
    } elseif ($global:ToEmail -ne '') {
        $SendTestEmailParam.ToEmail = "$global:ToEmail"
    } else {
        Write-Host "Error: The To Email is not set. Please set the To Email in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # If $FromEmail is not empty, then use the $global:FromEmail variable for $FromEmail. If the $global:FromEmail is empty, then display an error and exit the function.
    # If $FromEmail is not empty add it to the $SendTestEmailParam variable.
    if ($FromEmail -ne '') {
        $SendTestEmailParam.FromEmail = "$FromEmail"
    } elseif ($global:FromEmail -ne '') {
        $SendTestEmailParam.FromEmail = "$global:FromEmail"
    } else {
        Write-Host "Error: The From Email is not set. Please set the From Email in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # Enabele debugging.
    $SendTestEmailParam.DebugEmail = $true

    # Try to send the email.
    Send-Email -ToEmail "$ToEmail" -FromEmail "$FromEmail" -Subject "$Subject" -Body "$Body" @SendTestEmailParam
    return
}
# End of the Send-EmailTest function.

# A function to install the AD-PowerAdmin script to run daily as a scheduled task.
function Install-ADPowerAdmin {

    # Check if the AD-PowerAdmin_Daily schedule task already exists.
    if (Get-ScheduledTask -TaskName "AD-PowerAdmin_Daily" -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin schedule task already exists, then ask the user if they want to overwrite the existing schedule task.
        Write-Host "The AD-PowerAdmin schedule task already exists." -ForegroundColor Yellow
        $OverwriteScheduleTask = Read-Host "Do you want to overwrite the existing schedule task? (Y/N)"
        # If the user does not want to overwrite the existing schedule task, then exit the function.
        if ($OverwriteScheduleTask -ne 'Y') {
            Write-Host "The AD-PowerAdmin schedule task was not overwritten." -ForegroundColor Yellow
            return
        }
    }

    [string] $TaskName = "AD-PowerAdmin_Daily"
    # Set ScheduleRunTime to be tomorrow at 9:00 AM.
    [datetime]$ScheduleRunTime = (Get-Date).AddDays(1).Date + "09:00:00"
    [string]$TaskDiscription = "AD-PowerAdmin Daily Tasks"
    [string]$ThisScriptsFullName = $global:ThisScript

    # Try to set up a new schedule task to run the AD-PowerAdmin script daily.
    try {
        # Create a new schedule task to run the AD-PowerAdmin script daily.
        New-ScheduledTask -ActionString "$ThisScriptsFullName" -ActionArguments "-Unattended -JobName 'Daily'" -ScheduleRunTime $ScheduleRunTime -Recurring Once -TaskName $TaskName -TaskDiscription $TaskDiscription | Out-Null
    } catch {
        # If the schedule task was not created successfully, then display an error message to the user.
        Write-Host "Error: The AD-PowerAdmin schedule task was not created successfully." -ForegroundColor Red
    } finally {
        # If the schedule task was created successfully, then display a message to the user.
        Write-Host "The AD-PowerAdmin schedule task was created successfully." -ForegroundColor Green
    }
}


# Function that runs a collection of function that nned to be performed daily on Active Directory.
function Start-DailyADTasks {

    # Check if the $global:KerberosKRBTGTAudit is set to $true. If it is, then run the Update-KRBTGTPassword function.
    if ($global:KerberosKRBTGTAudit -eq $true) {
        # Run the function to update the KRBTGT password.
        Update-KRBTGTPassword -OverridePwd $false
    }

    # Check if the $global:InactiveComputerAudit is set to $true. If it is, then run the Search-MultipleInactiveComputers function.
    if ($global:InactiveComputerAudit -eq $true) {
        # Run the function to search for inactive computers.
        Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $global:InactiveDays -ReportOnly $false
    }

    # Check if the $global:InactiveUserAudit is set to $true. If it is, then run the Search-MultipleInactiveUsers function.
    if ($global:InactiveUserAudit -eq $true) {
        # Run the function to search for inactive users.
        Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $false
    }

    # Check if the $global:WeakPasswordAudit is set to $true. If it is, then run weak password process.
    if ($global:WeakPasswordAudit -eq $true) {
        # Set the $AdPwdAuditData variable to the output of the Get-ADPasswordAudit function.
        $AdPwdAuditData = Get-ADPasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile
        # With the $AdPwdAuditData variable, run the Invoke-WeakPwdProcess function.
        Invoke-WeakPwdProcess -AdPwTestData $AdPwdAuditData
        # If it is the first day of the month, then run Get-PasswordAuditAdminReport.
        if ((Get-Date).Day -eq 1) {
            Get-PasswordAuditAdminReport -AdPwTestData $AdPwdAuditData
        }
    }
}
# End of the Start-DailyADTasks function.

# Function that will output this scripts logo.
function Show-Logo {
    Write-Host '
    ______      __                 ________          ___
   / ____/_  __/ /_  ___  _____   / ____/ /___ _____/ (_)_  _______
  / /   / / / / __ \/ _ \/ ___/  / / __/ / __ `/ __  / / / / / ___/
 / /___/ /_/ / /_/ /  __/ /     / /_/ / / /_/ / /_/ / / /_/ (__  )
 \____/\__, /_.___/\___/_/      \____/_/\__,_/\__,_/_/\__,_/____/
      /____/   Presents
    ___    ____        ____                          ___       __          _
   /   |  / __ \      / __ \____ _      _____  _____/   | ____/ /___ ___  (_)___
  / /| | / / / /_____/ /_/ / __ \ | /| / / _ \/ ___/ /| |/ __  / __ `__ \/ / __ \
 / ___ |/ /_/ /_____/ ____/ /_/ / |/ |/ /  __/ /  / ___ / /_/ / / / / / / / / / /
/_/  |_/_____/     /_/    \____/|__/|__/\___/_/  /_/  |_\__,_/_/ /_/ /_/_/_/ /_/
'
}
# End of the Show-Logo function.

# Function to display the main menu options for AD-PowerAdmin
function Show-Menu {
    Clear-Host
    Show-Logo
    Write-Host "================ AD-PowerAdmin Tools ================"
    Write-Host "1: Press '1' Audit AD Admin account Report."
    Write-Host "2: Press '2' Run a security audit."
    Write-Host "3: Press '3' Force KRBTGT password Update."
    Write-Host "4: Press '4' Search for inactive computers report only."
    Write-Host "5: Press '5' Search for inactive computers and disable them."
    Write-Host "6: Press '6' Search for inactive users accounts."
    Write-Host "7: Press '7' Search for inactive users accounts and disable them."
    Write-Host "8: Press '8' Run a password audit WITHOUT sending emails to users or scheduling a forced password changes."
    Write-Host "9: Press '9' Run a password audit AND send emails to users and schedule forced password changes."
    Write-Host "D: Press 'D' Run all daily tasks."
    Write-Host "I: Press 'I' To install this script as a scheduled task to run the daily test, checks, and clean-up."
    Write-Host "E: Press 'E' To send a test email."
    Write-Host "H: Press 'H' To show the help menu."
    Write-Host "Q: Press 'Q' to quit."
}
# End of the Show-Menu function.

# Function Help Menu
function Show-Help {
    Clear-Host
    Show-Logo
    Write-Host "
    =========== AD-PowerAdmin General Notes =============
    AD-PowerAdmin is a collection of scripts to make Active Directory more secure. There are two main ways to use this script;
    A one-time run and audit OR, a scheduled task to automate tests and clean-ups.

    ================ AD-PowerAdmin Tools ================

    === Audit AD Admin account Report. ===
        This option will generate a report of all accounts with Domain Administrator rights or Enterprise Administrator rights.

    === Force KRBTGT password Update. ===
        This option will update the KRBTGT password for all domain controllers.
        During normal operation, the KRBTGT password needs to be updated every 90 days, twice.
        Every 90 days, update the KRBTGT password, wait 10 hours, then update it again.
        Alternativly, use this scripts '-Daliy' option to automate this process.

        See my blog post for more details: https://cybergladius.com/ad-hardening-against-kerberos-golden-ticket-attack/

    === Search for inactive computers. ===
        Search for computers that have been inactive for more than X days; default is 90 days. This will disable the computer,
        strip all group membership, and move it to the Disabled.Desktop OU. This can be run manually or automated
        via the 'Daliy' option.

        See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

        !!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

    ===   Search for inactive Users   ===
        Search for User that have been inactive for more than X days; default is 90 days. This will disable the user,
        strip all group membership, and move it to the Disabled.Users OU. This can be run manually or automated
        via the 'Daliy' option.

        See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

        !!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

    ===    Password Audit for User    ===
        The Password Audid checks for the following.
            - Weak or breached passwords.
            - Goups of User accounts that all have the same password.
            - User accounts will never expire.
            - Administrative accounts are allowed to be delegated to a service account.

        If you want to test for known breached passwords, you will need to download the breached password list
        from https://haveibeenpwned.com/Passwords. The file is a 7z compressed file. You will need to extract
        the file and save it to the same directory as the AD-PowerAdmin.ps1 script. The file name should be
        'pwned-passwords-ntlm-ordered-by-hash-v8.txt' and the file size should be 28.5GB. The file is updated every
        12 months. You will need to download the new file and replace the old file when it is updated.

        If you want to test for weak passwords, you will need to download or build a list of weak passwords.
        The file should be a text file with one password per line. Consider all the bad passwords you have seen in
        the past within your company and add them to the list. This will help prevent users from using these very
        bad passwords. Every company is guilty of using bad passwords with the company name in it, or the name of
        the CEO, or the name of the company mascot, etc.
        Example: '<CompanyName>2022!', '<CompanyInitials>2022!', '<CompanyHqCityName>@<YearEstablished>', etc.
        The file name should be 'weak-passwords.txt' and reside in the same directory as the AD-PowerAdmin.ps1 script.

        Users will be notified via email if their password is weak or breached. User accounts with a weak or breached
        password will have X days to change their password, default is 3 days. If the user does not change their
        password within X days, the user account will have the 'User must change password at next logon' option enabled.

        On the first day of the month, the script will send an email to the admin account with a report of all the audit results.

        !!!   NOTES   !!!
            - You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.
            - The follow up process to ensure users change their password is done via a scheduled task.
            - The process by which the password data is pulled is done via a DCSync. This can trigger an alert in your SIEM.
                A DCSync, is not an attack, it is a normal process, but attackers are known to use DCSync to get password hashes.

    =====================================================
    "
}
# End of the Show-Help function.

#=======================================================================================
# Main

#Check Unattended Mode is true, if true, then run the script without prompting the user.
if ($Unattended) {
    # Check is a JobName was passed, if not, display error messga can exit.
    if ($JobName -eq $null) {
        Write-Host "Error: No JobName was passed to the script. Unattended mode can only be used with a JobName."
        Exit 1
    }

    # if JobName is "krbtgt-RotateKey", then run the krbtgt-RotateKey functions.
    # Note: this is used by the scheduled task. Do not use this manually.
    if ($JobName -eq "krbtgt-RotateKey") {
        # Update the KRBTGT password in the Active Directory Domain.
        Update-KRBTGTPassword -OverridePwd $true
    }

    # if JobName is "Daliy", then run the Start-DailyADTacks functions.
    if ($JobName -eq "Daily") {
        # Run the function to update the KRBTGT password.
        Start-DailyADTasks
    }

    # If the jobname is "BreachedUserFollowup" then run the Test-UserUpdatedPassword function.
    if ($JobName -eq "PwUserFollowup") {
        # Confirm that $JobVar1 is not null.
        if ($JobVar1 -eq $null) {
            Write-Host "Error: JobVar1 must contain the username of the user to check the password for. Unattended PwUserFollowup mode can only be used with a JobVar1." -ForegroundColor Red
            Exit 1
        }
        # Run the function to test if the user has updated their password.
        Test-UserUpdatedPassword -UserName "$JobVar1" -UpdateGracePeriod $global:PwAuditPwChangeGracePeriod
        # Unregister the scheduled task with the name "PwUserFollowup-$JobVar1
        Unregister-ScheduledTask -TaskName "PwUserFollowup-$JobVar1" -Confirm:$false
    }

    # If the jobname is "BreachedUserFollowup" then run the Test-UserUpdatedPassword function.
    if ($JobName -eq "Test") {
        # Run the function to test if the user has updated their password.
        Write-Host "Test"
    }

    # Exit the script
    Exit 0
}

# Display the main menu and wait for the user to select an option.
do {
    Show-Menu
    $Selection = Read-Host "Please make a selection"
    switch ($selection) {
    '1' {
        # Audit AD Admin account Report.
        Get-ADAdminAudit
    }

    '2' {
        # Run a security audit.
        Write-Host "Hello World!"
    }

    '3' {
        # Force KRBTGT password Update.
        Update-KRBTGTPassword -OverridePwd $false
    }

    '4' {
        # Run the function to search for inactive computers.
        Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $global:InactiveDays -ReportOnly $true
    }

    '5' {
        # Run the function to search for inactive computers and disable them.
        Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $global:InactiveDays -ReportOnly $false
    }

    '6' {
        # Search for inactive users accounts.
        Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $true
    }

    '7' {
        # Search for inactive users accounts and disable them.
        Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $false
    }

    '8' {
        # Run a password audit with NO Breached or weak password checks.
        Get-PasswordAuditAdminReport
    }

    '9' {
        # Run a password audit with Breached or weak password checks, emails, and scheduled tasks.
        # Set the $AdPwdAuditData variable to the output of the Get-ADPasswordAudit function.
        $AdPwdAuditData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile
        Get-PasswordAuditAdminReport -AdPwTestData $AdPwdAuditData
        # With the $AdPwdAuditData variable, run the Invoke-WeakPwdProcess function.
        Invoke-WeakPwdProcess -AdPwTestData $AdPwdAuditData
    }

    'd' {
        # Run daily tasks.
        Start-DailyADTasks
    }

    'i' {
        # Install the scheduled tasks for the daily tasks.
        Install-DailyADTasks
    }

    'e' {
        # Send a test email.
        Send-EmailTest
    }

    't' {
        Write-Host $global:ThisScript
    }

    'h' {
        Show-Help
    }

    }
    pause
} until ($Selection -eq 'q')

# End of script.
Exit 0