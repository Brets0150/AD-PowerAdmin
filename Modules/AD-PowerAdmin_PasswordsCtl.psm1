Function Initialize-Module {
        <#
    .SYNOPSIS
    Initialize-Module

    .DESCRIPTION
    Initialize-Module

    .EXAMPLE
    Initialize-Module

    .NOTES
    Initialize-Module is called by AD-PowerAdmin_Main.ps1 to initialize the module.

    #>
    # Append $global:Menu with the menu items to be displayed.
    $global:Menu += @{
        'Update-KRBTGTPassword' = @{
            Title    = 'Update KRBTGT Password'
            Label    = 'Update the KRBTGT password in the Active Directory Domain if the password is older than the preset.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Update-KRBTGTPassword'
            Command  = 'Update-KRBTGTPassword'
        }
        'Update-KRBTGTPasswordForce' = @{
            Title    = 'Update KRBTGT Password - Force'
            Label    = 'Force a password change to the KRBTGT account. The password will be updated now and a scheduled task will be created to update the password again in 10 hours.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Update-KRBTGTPassword'
            Command  = 'Update-KRBTGTPassword -OverridePwd $true'
        }
        'Get-PasswordAuditAdminReport' = @{
            Title    = 'Password Audit Report'
            Label    = 'Get a report of all users with breached or weak passwords.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Get-PasswordAuditAdminReport'
            Command  = 'Get-PasswordAuditAdminReport'
        }
        'Get-PasswordAuditAdminReportAndEmail' = @{
            Title    = 'Password Audit Report & Email'
            Label    = 'Get a report of all users with breached or weak passwords and email the report to the administrator.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Get-PasswordAuditAdminReport'
            Command  = 'Get-PasswordAuditAdminReport -EmailReport'
        }
    }

    # Append the $global:UnattendedJobs with the jobs to be run unattended from this module.
    $global:UnattendedJobs += @{
        # if JobName is 'krbtgt-RotateKey', then run the krbtgt-RotateKey functions.
        # Note: this is used by the scheduled task. Do not use this manually.
        'krbtgt-RotateKey' = @{
            Title    = 'Update KRBTGT Password'
            Label    = 'Update the KRBTGT password in the Active Directory Domain.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Update-KRBTGTPassword'
            Daily    = $false
            Command  = 'Update-KRBTGTPassword -OverridePwd $true'
        }
        'Test-krbtgtPwdAge' = @{
            Title    = 'Update KRBTGT Password'
            Label    = 'Update the KRBTGT password in the Active Directory Domain.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Update-KRBTGTPassword'
            Daily    = $true
            Command  = 'Update-KRBTGTPassword -OverridePwd $false'
        }
        'PwUserFollowup' = @{
            Title    = 'Password UserFollowup'
            Label    = 'Update the KRBTGT password in the Active Directory Domain.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Test-PwUserFollowup'
            Daily    = $false
            Command  = 'Test-PwUserFollowup -JobVar1 $JobVar1'
        }
        'Start-MonthlyPasswordAudit' = @{
            Title    = 'Password Audit Report & Email'
            Label    = 'Runs daliy, if 1st-DOM, Password Audit Report & Email'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Start-MonthlyPasswordAudit'
            Daily    = $true
            Command  = 'Start-MonthlyPasswordAudit'
        }
    }
}

Initialize-Module

Function Get-ADUserPasswordAge {
    <#
    .SYNOPSIS
    Function to get the number of days since a users last password update.

    .DESCRIPTION
    Function to get the number of days since a users last password update.

    .PARAMETER UserName
    The username of the user to check the password age.

    .EXAMPLE
    Get-ADUserPasswordAge -UserName "JohnDoe"

    .NOTES

    #>

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
# End of Get-ADUserPasswordAge function
}

Function Test-PasswordIsComplex {
    <#
    .SYNOPSIS
    FUNCTION: Confirm Generated Password Meets Complexity Requirements
    Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements

    .DESCRIPTION
    FUNCTION: Confirm Generated Password Meets Complexity Requirements
    Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements

    .PARAMETER StringToTest
    The string to test if it meets the complexity requirements.

    .EXAMPLE
    Test-PasswordIsComplex -StringToTest "Password123!"

    .NOTES

    #>

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
# End of Test-PasswordIsComplex function
}

Function New-RandomPassword {
    <#
    .SYNOPSIS
    Function to create a random 64 character long password and return it.

    .DESCRIPTION
    Function to create a random 64 character long password and return it.

    .EXAMPLE
    $NewPassword = New-RandomPassword

    .INPUTS
    None

    .OUTPUTS
    System.String

    .NOTES

    #>

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
# End of New-RandomPassword function
}

Function Update-KRBTGTPassword {
    <#
    .SYNOPSIS
    Update the KRBTGT password in the Active Directory Domain.

    .DESCRIPTION
    === KRBTGT password Check ===
    This option will check the KRBTGT AD Account password age. If the password age is greater than 90 days, then the password will be updated.
    If the password age is less than 90 days, then the password will not be updated, unless the force switch is used.
    During normal operation, the KRBTGT password needs to be updated every 90 days, twice.
    Every 90 days, update the KRBTGT password, wait 10 hours, then update it again.
    Alternativly, use this scripts '-Daliy' option to automate this process.

    See my blog post for more details: https://cybergladius.com/ad-hardening-against-kerberos-golden-ticket-attack/

    The menu options are:
        1. Update the KRBTGT password in the Active Directory Domain if the password
            is older than the preset number of days(set in the AD-PowerAdmin_settings.ps1).
            A scheduled task will be created to update the password again in 10 hours.
        NOTE: This option will not create a scheduled task if AD-PowerAdmin is running not installed!

        2. Force a password change to the KRBTGT account now. There will be NO scheduled task
            created to update the password again in 10 hours.
            If you have a breach, run this option twise to invalidate all current tickets.
            You may see a few things temporarily break, but ligitamate users and computers
            will be able to re-authenticate.

    .PARAMETER OverridePwd
    # If the OverridePwd switch is used, then the KRBTGT password will be updated even if the current password last update time is less than 90 days.

    .EXAMPLE
    Update-KRBTGTPassword

    .NOTES

    #>

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
                    New-ScheduledTask -ActionString 'PowerShell' -ActionArguments "$ThisScriptsFullName -Unattended $true -JobName `"krbtgt-RotateKey`"" -ScheduleRunTime $NextUpdateTime `
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
                    if ($null -ne (Get-ScheduledTask -TaskName "KRBTGT-Final-Update" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
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
# End of Update-KRBTGTPassword function
}

Function Get-PasswordAudit {
    <#
    .SYNOPSIS
    Funcation to user the DSInternals PowerShell module and the Test-PasswordQuality to check all users password quality in active directory.

    .DESCRIPTION
    Funcation to user the DSInternals PowerShell module and the Test-PasswordQuality to check all users password quality in active directory.

    .PARAMETER SearchOUbase
    The OU to search for users in active directory. If this parameter is not used, then all users in active directory will be checked.

    .PARAMETER NtlmHashDataFile
    The file to use to check the password quality. This file should be a sorted list of NTLM hashes. If this parameter is not used, then the NtlmHashDataFile in the AD-PowerAdmin_settings.ps1 file will be used.

    .PARAMETER WeakPassDictFile
    The file to use to check the password quality. This file should be a list of weak passwords. If this parameter is not used, then the WeakPassDictFile in the AD-PowerAdmin_settings.ps1 file will be used.

    .EXAMPLE
    [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile

    .NOTES

    #>

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
# End of Get-PasswordAudit function
}

Function Get-PasswordAuditAdminReport {
    <#
    .SYNOPSIS
    Funcation to user the DSInternals PowerShell module and the Test-PasswordQuality to check all users password quality in active directory.

    .DESCRIPTION
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

        On the first day of the month, the script will send an email to the admin account with a report of all
        the audit results.

        !!!   NOTES   !!!
            - You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.
            - The follow up process to ensure users change their password is done via a scheduled task.
            - The process by which the password data is pulled is done via a DCSync. This can trigger
                an alert in your SIEM.
                A DCSync, is not an attack, it is a normal process, but attackers are known to
                use DCSync to get password hashes.

            - If non-user accounts have the warrning 'These administrative accounts are allowed to be
                delegated to a service' then itmay be a false positive. See my post here
                for more details: https://cybergladius.social/@CyberGladius/109649278142902592

    .PARAMETER AdPwTestData
    The $AdPwTestData object to use to create the report. If this parameter is not used, then the Get-PasswordAudit function will be used to get the $AdPwTestData.

    .PARAMETER EmailReport
    If the $EmailReport switch is used, then send the $ADPasswordTestDataString to the $global:PasswordQualityTestEmailTo email address.

    .EXAMPLE
    Get-PasswordAuditAdminReport -EmailReport

    .NOTES

    #>
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AdPwTestData,
        [Parameter(Mandatory=$false,Position=1)]
        [switch]$EmailReport
    )

    # If the $AdPwTestData is empty, then use the Get-PasswordAudit function to get the $AdPwTestData.
    if ($null -eq $AdPwTestData) {
        [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile
    }
    # Convert the $ADPasswordTestData to an output string.
    $ADPasswordTestDataString = $AdPwTestData | Out-String

    # Output the $ADPasswordTestDataString to the screen.
    Write-Host $ADPasswordTestDataString -ForegroundColor Green

    # If the $EmailReport switch is used, then send the $ADPasswordTestDataString to the $global:PasswordQualityTestEmailTo email address.
    if ($EmailReport) {
        # Confirm the $global:ReportAdminEmailTo is not empty. If it is, then output an error and exit the function.
        if ($null -eq $global:ReportAdminEmailTo) {
            Write-Host "Error: The '`$global:ReportAdminEmailTo' variable is empty. Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
            return
        }
        # Confirm the "$global:ReportsEmailFrom" is not empty. If it is, then output an error and exit the function.
        if ($null -eq $global:ReportsEmailFrom) {
            Write-Host "Error: The '`$global:ReportsEmailFrom' variable is empty. Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
            return
        }
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
}

Function Invoke-WeakPwdProcess {
    <#
    .SYNOPSIS
    Function to process users with breached or weak passwords.

    .DESCRIPTION
    Function to process users with breached or weak passwords.

    .PARAMETER AdPwTestData
    The $AdPwTestData object to use to create the report. If this parameter is not used, then the Get-PasswordAudit function will be used to get the $AdPwTestData.

    .EXAMPLE
    Invoke-WeakPwdProcess

    .NOTES

    #>

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
                Send-Email -ToEmail "$UserEmail" -FromEmail "$global:ReportsEmailFrom" -CcEmail $CC -Subject "$Subject" -Body "$Message"
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
                New-ScheduledTask -ActionString 'PowerShell' -ActionArguments "$ThisScriptsFullName -Unattended -JobName `'PwUserFollowup`' -JobVar1 `'$UserOnly`'" -ScheduleRunTime $PwFollowUpTime -Recurring Once -TaskName $TaskName -TaskDiscription $TaskDiscription | Out-Null

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
# End of Invoke-WeakPwdProcess function
}

function Test-UserUpdatedPassword {
    <#
    .SYNOPSIS
    A function that will take in a username, check if that user has updated their password in the days value in $global:PwAuditPwChangeGracePeriod.
    If the user has not updated their password in the days value in $global:PwAuditPwChangeGracePeriod, then enable the user attribue "User must change password at next logon" for the users AD account.

    .DESCRIPTION
    A function that will take in a username, check if that user has updated their password in the days value in $global:PwAuditPwChangeGracePeriod.
    If the user has not updated their password in the days value in $global:PwAuditPwChangeGracePeriod, then enable the user attribue "User must change password at next logon" for the users AD account.

    .PARAMETER Username
    The username of the user to check if they have updated their password.

    .PARAMETER UpdateGracePeriod
    The number of days the user has to update their password.

    .EXAMPLE
    Test-UserUpdatedPassword -Username "JohnDoe" -UpdateGracePeriod 3

    .NOTES

    #>

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
    # Check if the $PasswordAge is greater than the $global:PwAuditPwChangeGracePeriod. If it is, then enable the user attribue "User must change password at next logon" for the users AD account.
    if ($PasswordAge -gt $UpdateGracePeriod) {
        # Enable the user attribue "User must change password at next logon" fro the users AD account.
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
        # Output the user name and the date the user will be required to change their password.
    }
# End of the Test-UserUpdatedPassword function.
}

function Test-PwUserFollowup {
    <#
    .SYNOPSIS
    A function that will take in a username, check if that user has updated their password in the days value in $global:PwAuditPwChangeGracePeriod.
    If the user has not updated their password in the days value in $global:PwAuditPwChangeGracePeriod, then enable the user attribue "User must change password at next logon" for the users AD account.

    .DESCRIPTION
    A function that will take in a username, check if that user has updated their password in the days value in $global:PwAuditPwChangeGracePeriod.
    If the user has not updated their password in the days value in $global:PwAuditPwChangeGracePeriod, then enable the user attribue "User must change password at next logon" for the users AD account.

    .PARAMETER Username
    The username of the user to check if they have updated their password.

    .PARAMETER UpdateGracePeriod
    The number of days the user has to update their password.

    .EXAMPLE
    Test-UserUpdatedPassword -Username "JohnDoe" -UpdateGracePeriod 3

    .NOTES

    #>
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$JobVar1
    )

    # Confirm that $JobVar1 is not null.
    if ($JobVar1 -eq $null) {
        Write-Host "Error: JobVar1 must contain the username of the user to check the password for. Unattended PwUserFollowup mode can only be used with a JobVar1." -ForegroundColor Red
        Exit 1
    }
    # Run the function to test if the user has updated their password.
    Test-UserUpdatedPassword -UserName "$JobVar1" -UpdateGracePeriod $global:PwAuditPwChangeGracePeriod
    # Unregister the scheduled task with the name "PwUserFollowup-$JobVar1
    Unregister-ScheduledTask -TaskName "PwFollowUp-$JobVar1" -Confirm:$false
# End of the Test-PwUserFollowup function.
}

function Start-MonthlyPasswordAudit {
    <#
    .SYNOPSIS
    Daily password audit process.

    .DESCRIPTION
        Test the users passwords in active directory for weak passwords and breached passwords.
        If a user account has a weak or breached password, then email the user and tell them to change their password.
        if the user does not change their password in X days, then enable the "User must change password at next logon" option for the user account.
        A scheduled task will be created to check if the user updates their password in X days.

        If it is the first day of the month, then run Get-PasswordAuditAdminReport and email the report to the admin account.

        all the settings for this function are in the AD-PowerAdmin_settings.ps1 file.

    .EXAMPLE
    Start-MonthlyPasswordAudit

    .NOTES

    #>

    # Check if the $global:WeakPasswordAudit is set to $true. If it is, then run weak password process.
    if ($global:WeakPasswordAudit -eq $true) {
        # Set the $AdPwdAuditData variable to the output of the Get-ADPasswordAudit function.
        $AdPwdAuditData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile
        # With the $AdPwdAuditData variable, run the Invoke-WeakPwdProcess function.
        Invoke-WeakPwdProcess -AdPwTestData $AdPwdAuditData
        # If it is the first day of the month, then run Get-PasswordAuditAdminReport.
        if ((Get-Date).Day -eq 1) {
            Get-PasswordAuditAdminReport -AdPwTestData $AdPwdAuditData -EmailReport
        }
    }
# End of the Start-MonthlyPasswordAudit function.
}