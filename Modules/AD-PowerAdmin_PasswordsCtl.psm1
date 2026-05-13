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
    # Remove stale entries if module is reloaded.
    $global:Menu.Remove('PasswordsCtlMenu')
    $global:Menu.Remove('PasswordNotRequiredMenu')
    $global:SubMenus.Remove('PasswordsCtlMenu')
    $global:SubMenus.Remove('PasswordNotRequiredMenu')

    # Unload $global:UnattendedJobs keys, so they can be reloaded.
    $global:UnattendedJobs.Remove('krbtgt-RotateKey')
    $global:UnattendedJobs.Remove('Test-krbtgtPwdAge')
    $global:UnattendedJobs.Remove('PwUserFollowup')
    $global:UnattendedJobs.Remove('Start-MonthlyPasswordAudit')
    $global:UnattendedJobs.Remove('Start-DailyPasswordNotRequiredAudit')
    $global:UnattendedJobs.Remove('Start-DailyAsRepRoastingAudit')

    # Register the sub-menu items.
    $global:SubMenus += @{
        'PasswordsCtlMenu' = @{
            Title = "Password Management"
            Items = @{
                'UpdateKRBTGTPassword' = @{
                    Title   = 'Update KRBTGT Password'
                    Label   = 'Update the KRBTGT password in the Active Directory Domain if the password is older than the preset.'
                    Command = 'Update-KRBTGTPassword'
                }
                'UpdateKRBTGTPasswordForce' = @{
                    Title   = 'Update KRBTGT Password - Force'
                    Label   = 'Force a password change to the KRBTGT account. The password will be updated now and a scheduled task will be created to update the password again in 10 hours.'
                    Command = 'Update-KRBTGTPassword -OverridePwd $true'
                }
                'GetPasswordAuditAdminReport' = @{
                    Title   = 'Password Audit Report'
                    Label   = 'Get a report of all users with breached or weak passwords.'
                    Command = 'Get-PasswordAuditAdminReport'
                }
                'GetPasswordAuditAdminReportAndEmail' = @{
                    Title   = 'Password Audit Report and Email'
                    Label   = 'Get a report of all users with breached or weak passwords and email the report to the administrator.'
                    Command = 'Get-PasswordAuditAdminReport -EmailReport'
                }
                'GetPasswordNotRequiredAudit' = @{
                    Title   = 'PasswordNotRequired Audit'
                    Label   = 'Find all user and computer accounts with PasswordNotRequired (PASSWD_NOTREQD) set and produce a risk-rated report.'
                    Command = 'Get-PasswordNotRequiredAudit'
                }
                'StartPasswordNotRequiredRemediation' = @{
                    Title   = 'PasswordNotRequired Remediation'
                    Label   = 'Review PasswordNotRequired findings and interactively clear the flag from affected user accounts after explicit confirmation.'
                    Command = 'Start-PasswordNotRequiredRemediation'
                }
                'GetAsRepRoastingAudit' = @{
                    Title   = 'AS-REP Roasting Audit'
                    Label   = 'Find all user accounts with Kerberos preauthentication disabled (DoesNotRequirePreAuth) and produce a risk-rated report.'
                    Command = 'Get-AsRepRoastingAudit'
                }
                'StartAsRepRoastingRemediation' = @{
                    Title   = 'AS-REP Roasting Remediation'
                    Label   = 'Review AS-REP Roastable findings and interactively re-enable preauthentication on affected user accounts after explicit confirmation.'
                    Command = 'Start-AsRepRoastingRemediation'
                }
            }
        }
    }

    # Register a single main menu entry that opens the sub-menu.
    $global:Menu += @{
        'PasswordsCtlMenu' = @{
            Title    = 'Password Management'
            Label    = 'Manage KRBTGT password rotation, breached and weak password audits, and PasswordNotRequired (PASSWD_NOTREQD) account detection and remediation.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Enter-SubMenu'
            Command  = "Enter-SubMenu 'PasswordsCtlMenu'"
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
        'Start-DailyPasswordNotRequiredAudit' = @{
            Title    = 'Daily PasswordNotRequired Audit'
            Label    = 'Daily check for accounts with PasswordNotRequired set. Emails admin if critical or high risk accounts are found.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Start-DailyPasswordNotRequiredAudit'
            Daily    = $true
            Command  = 'Start-DailyPasswordNotRequiredAudit'
        }
        'Start-DailyAsRepRoastingAudit' = @{
            Title    = 'Daily AS-REP Roasting Audit'
            Label    = 'Daily check for user accounts with Kerberos preauthentication disabled. Emails admin if critical or high risk accounts are found.'
            Module   = 'AD-PowerAdmin_PasswordsCtl'
            Function = 'Start-DailyAsRepRoastingAudit'
            Daily    = $true
            Command  = 'Start-DailyAsRepRoastingAudit'
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

Function Test-NtlmHashesInDirectory {
    <#
    .SYNOPSIS
        Check AD account NTLM hashes against the HIBP range-file directory.

    .DESCRIPTION
        Groups the supplied AD accounts by their 5-character NTLM hash prefix, then reads the
        corresponding range file (PREFIX.txt) from $HashDirectory once per prefix. Each range
        file contains SUFFIX:count lines; if an account's hash suffix appears in the file the
        account is considered breached. Returns the SamAccountName of each breached account.

        This function is called automatically by Get-PasswordAudit when $global:NtlmHashDataDir
        is configured. It is an alternative to the DSInternals -WeakPasswordHashesSortedFile
        check which requires a single sorted flat file.

    .PARAMETER AdAccounts
        Objects returned by Get-ADReplAccount. Must include SamAccountName and NTHash (byte[16]).

    .PARAMETER HashDirectory
        Path to the directory containing HIBP NTLM range files in PREFIX.txt format.

    .OUTPUTS
        [string[]] SamAccountName of each account whose NTLM hash was found in the directory.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [object[]]$AdAccounts,
        [Parameter(Mandatory=$true)]
        [string]$HashDirectory
    )

    if (-not (Test-Path $HashDirectory -PathType Container)) {
        Write-Host "Warning: HIBP hash directory not found: $HashDirectory" -ForegroundColor Yellow
        return @()
    }

    [System.Collections.Generic.List[string]]$Breached = [System.Collections.Generic.List[string]]::new()

    # Group accounts by 5-char prefix so each range file is read at most once.
    [hashtable]$PrefixGroups = @{}
    foreach ($Account in $AdAccounts) {
        if ($null -eq $Account.NTHash -or $Account.NTHash.Length -ne 16) { continue }
        [string]$FullHash = [System.BitConverter]::ToString($Account.NTHash).Replace('-', '').ToUpper()
        [string]$Prefix   = $FullHash.Substring(0, 5)
        [string]$Suffix   = $FullHash.Substring(5)
        if (-not $PrefixGroups.ContainsKey($Prefix)) {
            $PrefixGroups[$Prefix] = [System.Collections.Generic.List[object]]::new()
        }
        $PrefixGroups[$Prefix].Add([PSCustomObject]@{ Sam = $Account.SamAccountName; Suffix = $Suffix })
    }

    foreach ($Prefix in $PrefixGroups.Keys) {
        [string]$RangeFile = Join-Path $HashDirectory "$Prefix.txt"
        if (-not (Test-Path $RangeFile)) { continue }

        [hashtable]$FileSuffixes = @{}
        foreach ($Line in (Get-Content $RangeFile)) {
            [string[]]$Parts = $Line.Split(':')
            if ($Parts.Length -ge 1 -and $Parts[0].Length -gt 0) {
                $FileSuffixes[$Parts[0]] = $true
            }
        }

        foreach ($Entry in $PrefixGroups[$Prefix]) {
            if ($FileSuffixes.ContainsKey($Entry.Suffix)) {
                $Breached.Add($Entry.Sam)
            }
        }
    }

    return , $Breached.ToArray()
# End of Test-NtlmHashesInDirectory function
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

    .PARAMETER NtlmHashDataDir
    Path to the HIBP NTLM range-file directory for directory-mode breach detection. When provided
    and the directory exists, Test-NtlmHashesInDirectory is called after Test-PasswordQuality and
    the results are merged into the returned result's WeakPasswordHashes property.

    .PARAMETER WeakPassDictFile
    The file to use to check the password quality. This file should be a list of weak passwords. If this parameter is not used, then the WeakPassDictFile in the AD-PowerAdmin_settings.ps1 file will be used.

    .EXAMPLE
    [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile -NtlmHashDataDir $global:NtlmHashDataDir

    .NOTES

    #>

    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$false,Position=1)]
        [string]$SearchOUbase,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$NtlmHashDataFile,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$WeakPassDictFile,
        [Parameter(Mandatory=$false,Position=4)]
        [string]$NtlmHashDataDir
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

    # Directory-mode HIBP check: look up each account's NT hash in the range-file directory and
    # merge breached accounts into WeakPasswordHashes so they appear in the report and trigger
    # the notification workflow in Invoke-WeakPwdProcess.
    if ($NtlmHashDataDir -ne '' -and $null -ne $NtlmHashDataDir -and (Test-Path $NtlmHashDataDir -PathType Container)) {
        Write-Host "Checking HIBP hash directory for breached passwords..." -ForegroundColor Yellow
        [string[]]$DirectoryBreached = Test-NtlmHashesInDirectory -AdAccounts $AllAdAccountData -HashDirectory $NtlmHashDataDir
        if ($DirectoryBreached.Count -gt 0) {
            # WeakPasswordHashes is only initialized by DSInternals when -WeakPasswordHashesSortedFile
            # is passed to Test-PasswordQuality. In directory mode no hash file is passed, so the
            # property is null. Initialize it via reflection before calling .Add().
            if ($null -eq $ADPasswordTestData.WeakPasswordHashes) {
                try {
                    [System.Reflection.BindingFlags]$RFlags = 'Public,NonPublic,Instance'
                    $WHProp = $ADPasswordTestData.GetType().GetProperty('WeakPasswordHashes', $RFlags)
                    if ($WHProp) {
                        $WHProp.SetValue($ADPasswordTestData, [System.Collections.Generic.SortedSet[string]]::new())
                    }
                } catch { }
            }

            [string]$DomainName = $env:USERDOMAIN
            if ($null -ne $ADPasswordTestData.WeakPasswordHashes) {
                foreach ($Sam in $DirectoryBreached) {
                    $ADPasswordTestData.WeakPasswordHashes.Add("$DomainName\$Sam") | Out-Null
                }
                Write-Host "Found $($DirectoryBreached.Count) breached account(s) via HIBP directory lookup." -ForegroundColor Yellow
            } else {
                Write-Host "Warning: WeakPasswordHashes unavailable; merging HIBP results into WeakPassword." -ForegroundColor Yellow
                foreach ($Sam in $DirectoryBreached) {
                    $ADPasswordTestData.WeakPassword.Add("$DomainName\$Sam") | Out-Null
                }
                Write-Host "Found $($DirectoryBreached.Count) breached account(s) via HIBP directory lookup." -ForegroundColor Yellow
            }
        }
    }

    # Release the large account data set before returning. Get-ADReplAccount can load
    # gigabytes of NT hash and attribute data into memory. Without an explicit free, this
    # data stays resident while the caller attempts an SMTP TLS handshake, which causes
    # the handshake to fail under memory pressure ("Server does not support secure connections").
    $AllAdAccountData = $null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

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
        [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile -NtlmHashDataDir $global:NtlmHashDataDir
    }
    # Convert the $ADPasswordTestData to an output string.
    $ADPasswordTestDataString = $AdPwTestData | Out-String

    # Output the $ADPasswordTestDataString to the screen.
    Write-Host $ADPasswordTestDataString -ForegroundColor Green

    # If the $EmailReport switch is used, then send the $ADPasswordTestDataString to the $global:PasswordQualityTestEmailTo email address.
    if ($EmailReport) {
        # Confirm the $global:ADAdminEmail is not empty. If it is, then output an error and exit the function.
        if ($null -eq $global:ADAdminEmail) {
            Write-Host "Error: The '`$global:ADAdminEmail' variable is empty. Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
            return
        }
        # Confirm the "$global:FromEmail" is not empty. If it is, then output an error and exit the function.
        if ($null -eq $global:FromEmail) {
            Write-Host "Error: The '`$global:FromEmail' variable is empty. Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
            return
        }
        #try to email the $global:ADAdminEmail with the Subject "ADPowerAdmin Password Audit Report" and the email Body will contains $AdPwTestData data.
        try {
            Send-Email -ToEmail "$global:ADAdminEmail" -FromEmail "$global:FromEmail" -Subject "ADPowerAdmin Password Audit Report" -Body $ADPasswordTestDataString
        } catch {
            # If the email fails, then output an error and exit the function.
            Write-Host "Error: The Admin Report email failed to send to $global:ADAdminEmail." -ForegroundColor Red
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

    # Check if this is a Unattended job and $global:KerberosKRBTGTAudit is not true. If it is, then exit the function.
    If ($global:Unattended -and $global:KerberosKRBTGTAudit -eq $false) {
        return
    }

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
    [int]$KRBTGTLastUpdateDays = $( $(Get-Date) - $KRBTGTObject.PasswordLastSet ).Days

    # Check if the current KRBTGT password last update time is less than 90 days.
    if ( ( $($KRBTGTLastUpdateDays) -lt $global:krbtgtPwUpdateInterval ) -and ($OverridePwd -eq $false) ) {
        # If the current KRBTGT password last update time is less than 90 days, then exit the script.
        Write-Host "The current KRBTGT password last update time is less than $global:krbtgtPwUpdateInterval days."
        Write-Host "Days since last update: $($KRBTGTLastUpdateDays.ToString())"
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
                    New-ScheduledTask -ActionString 'PowerShell' -ActionArguments "$ThisScriptsFullName -Unattended -JobName `"krbtgt-RotateKey`"" -ScheduleRunTime $NextUpdateTime `
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
        [object]$AdPwTestData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile -NtlmHashDataDir $global:NtlmHashDataDir
    }

    # Combine dictionary-matched (WeakPassword) and HIBP hash-matched (WeakPasswordHashes) accounts.
    # Using a List to deduplicate accounts that appear in both sets.
    [System.Collections.Generic.List[string]]$BreachedUsers = [System.Collections.Generic.List[string]]::new()
    if ($null -ne $AdPwTestData.WeakPassword) {
        foreach ($Entry in $AdPwTestData.WeakPassword) { $BreachedUsers.Add($Entry) }
    }
    if ($null -ne $AdPwTestData.WeakPasswordHashes) {
        foreach ($Entry in $AdPwTestData.WeakPasswordHashes) {
            if (-not $BreachedUsers.Contains($Entry)) { $BreachedUsers.Add($Entry) }
        }
    }

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

            # If the $global:PwAuditAlertEmailCCAdmins is true, then add the $global:ADAdminEmail to the CC list.
            if ($global:PwAuditAlertEmailCCAdmins) {
                $CC = $global:ADAdminEmail
            } else {
                $CC = $null
            }

            #try to email the $User.
            try {
                Send-Email -ToEmail "$UserEmail" -FromEmail "$global:FromEmail" -CcEmail $CC -Subject "$Subject" -Body "$Message"
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
        $AdPwdAuditData = Get-PasswordAudit -SearchOUbase $global:PasswordQualityTestSearchOUbase -WeakPassDictFile $global:WeakPassDictFile -NtlmHashDataFile $global:NtlmHashDataFile -NtlmHashDataDir $global:NtlmHashDataDir
        # With the $AdPwdAuditData variable, run the Invoke-WeakPwdProcess function.
        Invoke-WeakPwdProcess -AdPwTestData $AdPwdAuditData
        # If it is the first day of the month, then run Get-PasswordAuditAdminReport.
        if ((Get-Date).Day -eq 1) {
            Get-PasswordAuditAdminReport -AdPwTestData $AdPwdAuditData -EmailReport
        }
    }
# End of the Start-MonthlyPasswordAudit function.
}

function Get-PrivilegedAccountNames {
    # Returns a HashSet of DistinguishedNames for members of all high-privilege AD groups.
    # Private helper used by Get-PasswordNotRequiredAccounts to assign risk levels.

    [string[]]$PrivGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Backup Operators",
        "Account Operators",
        "Server Operators",
        "Domain Controllers",
        "Print Operators",
        "Replicator",
        "Enterprise Key Admins",
        "Key Admins",
        "DNSAdmins",
        "Group Policy Creator Owners"
    )

    $Members = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($Group in $PrivGroups) {
        try {
            $GroupMembers = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue
            foreach ($Member in $GroupMembers) {
                $Members.Add($Member.DistinguishedName) | Out-Null
            }
        } catch { }
    }

    return , $Members
# End of Get-PrivilegedAccountNames function
}

Function Get-PasswordNotRequiredAccounts {
    <#
    .SYNOPSIS
    Collect all AD accounts with PasswordNotRequired (PASSWD_NOTREQD) set.

    .DESCRIPTION
    Queries Active Directory for all user accounts and computer accounts with the
    PasswordNotRequired flag enabled. Each finding is cross-referenced against
    high-privilege group membership and assigned a risk level.

    Risk levels:
        Critical -- Enabled user account in a high-privilege group.
        High     -- Enabled standard user account.
        Medium   -- Disabled user that is privileged or logged in within the past 90 days.
        Low      -- Disabled stale user with no known privilege.
        Review   -- Computer account with PASSWD_NOTREQD set.

    PasswordNotRequired=True does not confirm the account has a blank password. It means
    the account is permitted to bypass normal password requirements and should be treated
    as a misconfiguration requiring remediation regardless.

    .OUTPUTS
    [PSCustomObject[]] Array with fields: ObjectType, SamAccountName, UserPrincipalName,
    Enabled, PasswordNotRequired, PasswordLastSet, LastLogonDate, DistinguishedName,
    PrivilegedGroupMember, MemberOf, RiskLevel, RecommendedAction.

    .EXAMPLE
    $Findings = Get-PasswordNotRequiredAccounts

    .NOTES
    Requires only the ActiveDirectory PowerShell module. Does not require DSInternals.
    #>

    $PrivilegedDNs     = Get-PrivilegedAccountNames
    $RecentLoginCutoff = (Get-Date).AddDays(-90)
    $Results           = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- User accounts ---
    $Users = Get-ADUser -Filter { PasswordNotRequired -eq $true } `
        -Properties PasswordNotRequired, Enabled, SamAccountName, UserPrincipalName, `
                    DistinguishedName, MemberOf, PasswordLastSet, LastLogonDate `
        -ErrorAction SilentlyContinue

    foreach ($User in @($Users)) {
        [bool]$IsPrivileged      = $PrivilegedDNs.Contains($User.DistinguishedName)
        [bool]$WasRecentlyActive = ($null -ne $User.LastLogonDate -and $User.LastLogonDate -gt $RecentLoginCutoff)

        if ($User.Enabled -and $IsPrivileged) {
            $RiskLevel         = 'Critical'
            $RecommendedAction = 'Clear PasswordNotRequired immediately. Verify no blank password. Review privileged group membership.'
        } elseif ($User.Enabled) {
            $RiskLevel         = 'High'
            $RecommendedAction = 'Clear PasswordNotRequired. Verify the account is in use and its password meets policy.'
        } elseif (-not $User.Enabled -and ($IsPrivileged -or $WasRecentlyActive)) {
            $RiskLevel         = 'Medium'
            $RecommendedAction = 'Clear PasswordNotRequired. Review account necessity and any privileged group membership.'
        } else {
            $RiskLevel         = 'Low'
            $RecommendedAction = 'Clear PasswordNotRequired. Consider removing this stale disabled account entirely.'
        }

        [string]$MemberOfNames = ($User.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=', '' }) -join '; '

        $Results.Add([PSCustomObject]@{
            ObjectType            = 'User'
            SamAccountName        = $User.SamAccountName
            UserPrincipalName     = $User.UserPrincipalName
            Enabled               = $User.Enabled
            PasswordNotRequired   = $true
            PasswordLastSet       = $User.PasswordLastSet
            LastLogonDate         = $User.LastLogonDate
            DistinguishedName     = $User.DistinguishedName
            PrivilegedGroupMember = $IsPrivileged
            MemberOf              = $MemberOfNames
            RiskLevel             = $RiskLevel
            RecommendedAction     = $RecommendedAction
        })
    }

    # --- Computer accounts ---
    $Computers = Get-ADComputer `
        -LDAPFilter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))" `
        -Properties Enabled, PasswordLastSet, LastLogonDate `
        -ErrorAction SilentlyContinue

    foreach ($Computer in @($Computers)) {
        $Results.Add([PSCustomObject]@{
            ObjectType            = 'Computer'
            SamAccountName        = $Computer.Name
            UserPrincipalName     = ''
            Enabled               = $Computer.Enabled
            PasswordNotRequired   = $true
            PasswordLastSet       = $Computer.PasswordLastSet
            LastLogonDate         = $Computer.LastLogonDate
            DistinguishedName     = $Computer.DistinguishedName
            PrivilegedGroupMember = $false
            MemberOf              = ''
            RiskLevel             = 'Review'
            RecommendedAction     = 'Investigate whether PASSWD_NOTREQD is intentional. Clear if not required.'
        })
    }

    return , $Results.ToArray()
# End of Get-PasswordNotRequiredAccounts function
}

function Show-PasswordNotRequiredFindings {
    <#
    .SYNOPSIS
    Display risk-rated PasswordNotRequired findings to the console.

    .DESCRIPTION
    Shared display helper used by Get-PasswordNotRequiredAudit and
    Start-PasswordNotRequiredRemediation. Writes output to the console without
    prompting for export.

    .PARAMETER Findings
    Array of PSCustomObjects returned by Get-PasswordNotRequiredAccounts.

    .EXAMPLE
    Show-PasswordNotRequiredFindings -Findings $Findings

    .NOTES
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject[]]$Findings
    )

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        Write-Host "  [OK] No accounts found with PasswordNotRequired set." -ForegroundColor Green
        return
    }

    [int]$CriticalCount = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    [int]$HighCount     = @($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
    [int]$MediumCount   = @($Findings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    [int]$LowCount      = @($Findings | Where-Object { $_.RiskLevel -eq 'Low' }).Count
    [int]$ReviewCount   = @($Findings | Where-Object { $_.RiskLevel -eq 'Review' }).Count

    Write-Host ""
    Write-Host "  PasswordNotRequired / PASSWD_NOTREQD Audit" -ForegroundColor White
    Write-Host "  ===========================================" -ForegroundColor White
    Write-Host "  Summary: Critical=$CriticalCount  High=$HighCount  Medium=$MediumCount  Low=$LowCount  Review=$ReviewCount" -ForegroundColor Yellow
    Write-Host ""

    foreach ($Level in @('Critical', 'High', 'Medium', 'Low', 'Review')) {
        [array]$Group = @($Findings | Where-Object { $_.RiskLevel -eq $Level })
        if ($Group.Count -eq 0) { continue }

        [string]$Color = switch ($Level) {
            'Critical' { 'Red' }
            'High'     { 'Red' }
            'Medium'   { 'Yellow' }
            'Low'      { 'Yellow' }
            'Review'   { 'Cyan' }
            default    { 'White' }
        }

        Write-Host "  --- [$Level] ($($Group.Count) account(s)) ---" -ForegroundColor $Color
        foreach ($Finding in $Group) {
            Write-Host "    Type      : $($Finding.ObjectType)"            -ForegroundColor $Color
            Write-Host "    Account   : $($Finding.SamAccountName)"        -ForegroundColor $Color
            Write-Host "    Enabled   : $($Finding.Enabled)"               -ForegroundColor $Color
            Write-Host "    Privileged: $($Finding.PrivilegedGroupMember)" -ForegroundColor $Color
            Write-Host "    PwLastSet : $($Finding.PasswordLastSet)"       -ForegroundColor $Color
            Write-Host "    LastLogon : $($Finding.LastLogonDate)"         -ForegroundColor $Color
            Write-Host "    DN        : $($Finding.DistinguishedName)"     -ForegroundColor $Color
            Write-Host "    Action    : $($Finding.RecommendedAction)"     -ForegroundColor $Color
            Write-Host ""
        }
    }

    Write-Host "  NOTE: PasswordNotRequired=True does not confirm a blank password." -ForegroundColor Yellow
    Write-Host "        To verify actual blank passwords, run Password Audit in this menu." -ForegroundColor Yellow
    Write-Host ""
# End of Show-PasswordNotRequiredFindings function
}

Function Get-PasswordNotRequiredAudit {
    <#
    .SYNOPSIS
    Audit Active Directory for accounts with PasswordNotRequired set.

    .DESCRIPTION
    Searches all user and computer accounts in the domain for the PasswordNotRequired
    (PASSWD_NOTREQD) flag. Assigns a risk level to each finding based on account state and
    privilege level, displays the results, and offers CSV export to Reports/.

    .EXAMPLE
    Get-PasswordNotRequiredAudit

    .NOTES
    Run from the Password Management sub-menu for interactive use.
    For automated daily monitoring use Start-DailyPasswordNotRequiredAudit.
    #>

    [PSCustomObject[]]$Findings = Get-PasswordNotRequiredAccounts

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        Write-Host "  [OK] No accounts found with PasswordNotRequired set. Domain is clean." -ForegroundColor Green
        return
    }

    Show-PasswordNotRequiredFindings -Findings $Findings

    Export-AdPowerAdminData -Data $Findings -ReportName "AD-PasswordNotRequired-Findings"
# End of Get-PasswordNotRequiredAudit function
}

Function Start-PasswordNotRequiredRemediation {
    <#
    .SYNOPSIS
    Interactively remove the PasswordNotRequired flag from affected AD user accounts.

    .DESCRIPTION
    Retrieves all accounts with PasswordNotRequired set, displays the full risk-rated
    report, then requires explicit confirmation before clearing the flag from user accounts.
    Computer accounts are listed separately with manual remediation guidance.

    Safe by design:
    - Displays the full audit report before any modification.
    - Requires typing YES (exact) to proceed. Any other input cancels with no changes.
    - Logs every operation (success and failure) and exports the log to Reports/.
    - Does not automatically modify computer accounts.
    - Does not reset passwords; clearing the flag alone is sufficient to enforce policy.

    .EXAMPLE
    Start-PasswordNotRequiredRemediation

    .NOTES
    After remediation, verify affected accounts have passwords that meet policy.
    For accounts that had a blank password, use Set-ADAccountPassword to assign a
    strong password and enable ChangePasswordAtLogon.
    #>

    [PSCustomObject[]]$Findings = Get-PasswordNotRequiredAccounts

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        Write-Host "  [OK] No accounts found with PasswordNotRequired set. No remediation needed." -ForegroundColor Green
        return
    }

    Show-PasswordNotRequiredFindings -Findings $Findings

    [array]$UserFindings     = @($Findings | Where-Object { $_.ObjectType -eq 'User' })
    [array]$ComputerFindings = @($Findings | Where-Object { $_.ObjectType -eq 'Computer' })

    # --- User account remediation ---
    if ($UserFindings.Count -gt 0) {
        Write-Host "  REMEDIATION: $($UserFindings.Count) user account(s) eligible to have PasswordNotRequired cleared." -ForegroundColor Yellow
        Write-Host "  This clears the flag only. Passwords are not changed by this operation." -ForegroundColor Yellow
        [string]$Confirm = Read-Host "  Type YES to proceed. Any other input cancels (default: No)"

        if ($Confirm -eq 'YES') {
            $RemediationLog = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($Finding in $UserFindings) {
                try {
                    Set-ADUser -Identity $Finding.DistinguishedName -PasswordNotRequired $false -ErrorAction Stop
                    Write-Host "  [OK] Cleared PasswordNotRequired: $($Finding.SamAccountName)" -ForegroundColor Green
                    $RemediationLog.Add([PSCustomObject]@{
                        Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        SamAccountName = $Finding.SamAccountName
                        RiskLevel      = $Finding.RiskLevel
                        Enabled        = $Finding.Enabled
                        Action         = 'PasswordNotRequired cleared'
                        Result         = 'Success'
                    })
                } catch {
                    Write-Host "  [FAIL] Could not clear PasswordNotRequired: $($Finding.SamAccountName) -- $_" -ForegroundColor Red
                    $RemediationLog.Add([PSCustomObject]@{
                        Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                        SamAccountName = $Finding.SamAccountName
                        RiskLevel      = $Finding.RiskLevel
                        Enabled        = $Finding.Enabled
                        Action         = 'PasswordNotRequired clear attempted'
                        Result         = "Failed: $_"
                    })
                }
            }

            Export-AdPowerAdminData -Data $RemediationLog -ReportName "AD-PasswordNotRequired-RemediationLog"
        } else {
            Write-Host "  Remediation cancelled. No changes were made." -ForegroundColor Yellow
        }
    }

    # --- Computer account guidance ---
    if ($ComputerFindings.Count -gt 0) {
        Write-Host ""
        Write-Host "  COMPUTER ACCOUNTS: Manual review required before remediation." -ForegroundColor Yellow
        Write-Host "  $($ComputerFindings.Count) computer account(s) found with PASSWD_NOTREQD set." -ForegroundColor Yellow
        Write-Host "  Verify each account before clearing the flag." -ForegroundColor Yellow
        Write-Host "  To clear the flag from a specific computer account:" -ForegroundColor Cyan
        Write-Host "    Set-ADAccountControl -Identity <computername> -PasswordNotRequired `$false" -ForegroundColor Cyan
        Write-Host ""
    }
# End of Start-PasswordNotRequiredRemediation function
}

Function Start-DailyPasswordNotRequiredAudit {
    <#
    .SYNOPSIS
    Daily unattended audit for accounts with PasswordNotRequired set.

    .DESCRIPTION
    Runs as part of the daily unattended job schedule. Checks the domain for accounts with
    PasswordNotRequired set. Exports a dated CSV to Reports/ and emails the administrator
    if any Critical or High risk accounts are found.

    Controlled by the $global:PasswordNotRequiredAudit feature flag in
    AD-PowerAdmin_settings.ps1. Set to $false to disable without removing functionality.

    .EXAMPLE
    Start-DailyPasswordNotRequiredAudit

    .NOTES
    Invoked automatically by the AD-PowerAdmin scheduler when Daily = $true jobs run.
    #>

    if ($global:PasswordNotRequiredAudit -ne $true) { return }

    [PSCustomObject[]]$Findings = Get-PasswordNotRequiredAccounts

    # Export a dated CSV on every run regardless of findings count.
    [string]$DateStamp  = (Get-Date).ToString('yyyy-MM-dd')
    [string]$ReportFile = "$global:ReportsPath\AD-PasswordNotRequired-Daily-$DateStamp.csv"

    if ($null -ne $Findings -and $Findings.Count -gt 0) {
        try {
            $Findings | Export-Csv -Path $ReportFile -NoTypeInformation -Force
        } catch {
            if ($global:Debug) { Write-Host "Debug: Failed to write PasswordNotRequired daily CSV: $_" -ForegroundColor Red }
        }
    }

    # Only send an alert email for Critical and High findings.
    [array]$AlertFindings = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' -or $_.RiskLevel -eq 'High' })

    if ($AlertFindings.Count -eq 0) { return }

    [int]$CriticalCount = @($AlertFindings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    [int]$HighCount     = @($AlertFindings | Where-Object { $_.RiskLevel -eq 'High' }).Count

    [string]$Body  = "AD-PowerAdmin Daily PasswordNotRequired Audit`r`n"
    [string]$Body += "Date: $(Get-Date)`r`n"
    [string]$Body += "----------------------------------------------`r`n`r`n"
    [string]$Body += "ALERT: $($AlertFindings.Count) account(s) with PasswordNotRequired flag detected.`r`n"
    [string]$Body += "  Critical: $CriticalCount`r`n"
    [string]$Body += "  High    : $HighCount`r`n`r`n"
    [string]$Body += "These accounts bypass password policy and may authenticate without a password.`r`n"
    [string]$Body += "Use 'PasswordNotRequired Audit' in the Password Management menu to remediate.`r`n`r`n"
    [string]$Body += "Affected Accounts:`r`n"

    foreach ($Finding in ($AlertFindings | Sort-Object RiskLevel, SamAccountName)) {
        [string]$Body += "  [$($Finding.RiskLevel)] $($Finding.SamAccountName)"
        [string]$Body += " (Enabled: $($Finding.Enabled), Privileged: $($Finding.PrivilegedGroupMember))`r`n"
    }

    [string]$Body += "`r`nFull report: $ReportFile`r`n"

    if ($null -eq $global:ADAdminEmail -or $global:ADAdminEmail -eq '') { return }

    try {
        Send-Email -ToEmail "$global:ADAdminEmail" `
            -FromEmail "$global:FromEmail" `
            -Subject "AD-PowerAdmin: PasswordNotRequired Accounts Detected - ACTION REQUIRED" `
            -Body $Body
    } catch {
        if ($global:Debug) {
            Write-Host "Debug: Failed to send PasswordNotRequired alert email: $_" -ForegroundColor Red
        }
    }
# End of Start-DailyPasswordNotRequiredAudit function
}

function Get-AsRepRoastableAccounts {
    <#
    .SYNOPSIS
    Collect all AD user accounts with Kerberos preauthentication disabled.

    .DESCRIPTION
    Queries Active Directory for all user accounts where DoesNotRequirePreAuth is
    set to true. Each finding is cross-referenced against high-privilege group
    membership and assigned a risk level.

    Risk levels:
        Critical -- Enabled account that is a member of a privileged group.
        High     -- Enabled account with a ServicePrincipalName set or AdminCount=1.
        Medium   -- Enabled account with no special indicators.
        Low      -- Disabled account.

    An account with preauthentication disabled does not require a valid password
    to request a Kerberos AS-REP ticket. An attacker can request that ticket
    offline and attempt to crack the account key it is encrypted with.

    .OUTPUTS
    [PSCustomObject[]] Array with fields: SamAccountName, UserPrincipalName,
    Enabled, DoesNotRequirePreAuth, PasswordLastSet, LastLogonDate, AdminCount,
    ServicePrincipalName, DistinguishedName, PrivilegedGroupMember, MemberOf,
    RiskLevel, RecommendedAction.

    .EXAMPLE
    $Findings = Get-AsRepRoastableAccounts

    .NOTES
    Requires only the ActiveDirectory PowerShell module.
    Called by all AS-REP Roasting audit and remediation functions.
    #>

    $PrivilegedDNs = Get-PrivilegedAccountNames
    $Results       = [System.Collections.Generic.List[PSCustomObject]]::new()

    $Users = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
        -Properties DoesNotRequirePreAuth, Enabled, SamAccountName, UserPrincipalName, `
                    DistinguishedName, MemberOf, PasswordLastSet, LastLogonDate, `
                    AdminCount, ServicePrincipalName `
        -ErrorAction SilentlyContinue

    foreach ($User in @($Users)) {
        [bool]$IsPrivileged = $PrivilegedDNs.Contains($User.DistinguishedName)
        [bool]$HasSPN       = ($null -ne $User.ServicePrincipalName -and $User.ServicePrincipalName.Count -gt 0)
        [bool]$IsAdminCount = ($User.AdminCount -eq 1)

        if ($User.Enabled -and $IsPrivileged) {
            $RiskLevel         = 'Critical'
            $RecommendedAction = 'Re-enable preauthentication immediately. Reset account password. Review privileged group membership.'
        } elseif ($User.Enabled -and ($HasSPN -or $IsAdminCount)) {
            $RiskLevel         = 'High'
            $RecommendedAction = 'Re-enable preauthentication. Reset account password. Review SPN configuration and AdminCount flag.'
        } elseif ($User.Enabled) {
            $RiskLevel         = 'Medium'
            $RecommendedAction = 'Re-enable preauthentication. Reset account password to invalidate any captured AS-REP hashes.'
        } else {
            $RiskLevel         = 'Low'
            $RecommendedAction = 'Re-enable preauthentication. Consider disabling or removing this stale account.'
        }

        [string]$MemberOfNames = ($User.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=', '' }) -join '; '
        [string]$SPNList       = if ($HasSPN) { $User.ServicePrincipalName -join '; ' } else { '' }

        $Results.Add([PSCustomObject]@{
            SamAccountName        = $User.SamAccountName
            UserPrincipalName     = $User.UserPrincipalName
            Enabled               = $User.Enabled
            DoesNotRequirePreAuth = $true
            PasswordLastSet       = $User.PasswordLastSet
            LastLogonDate         = $User.LastLogonDate
            AdminCount            = $User.AdminCount
            ServicePrincipalName  = $SPNList
            DistinguishedName     = $User.DistinguishedName
            PrivilegedGroupMember = $IsPrivileged
            MemberOf              = $MemberOfNames
            RiskLevel             = $RiskLevel
            RecommendedAction     = $RecommendedAction
        })
    }

    return , $Results.ToArray()
# End of Get-AsRepRoastableAccounts function
}

function Show-AsRepRoastingFindings {
    <#
    .SYNOPSIS
    Display risk-rated AS-REP Roastable findings to the console.

    .DESCRIPTION
    Shared display helper used by Get-AsRepRoastingAudit and
    Start-AsRepRoastingRemediation. Writes output to the console without
    prompting for export.

    .PARAMETER Findings
    Array of PSCustomObjects returned by Get-AsRepRoastableAccounts.

    .EXAMPLE
    Show-AsRepRoastingFindings -Findings $Findings

    .NOTES
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject[]]$Findings
    )

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        Write-Host "  [OK] No accounts found with Kerberos preauthentication disabled." -ForegroundColor Green
        return
    }

    [int]$CriticalCount = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    [int]$HighCount     = @($Findings | Where-Object { $_.RiskLevel -eq 'High' }).Count
    [int]$MediumCount   = @($Findings | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    [int]$LowCount      = @($Findings | Where-Object { $_.RiskLevel -eq 'Low' }).Count

    Write-Host ""
    Write-Host "  AS-REP Roasting Audit (DoesNotRequirePreAuth)" -ForegroundColor White
    Write-Host "  ==============================================" -ForegroundColor White
    Write-Host "  Summary: Critical=$CriticalCount  High=$HighCount  Medium=$MediumCount  Low=$LowCount" -ForegroundColor Yellow
    Write-Host ""

    foreach ($Level in @('Critical', 'High', 'Medium', 'Low')) {
        [array]$Group = @($Findings | Where-Object { $_.RiskLevel -eq $Level })
        if ($Group.Count -eq 0) { continue }

        [string]$Color = switch ($Level) {
            'Critical' { 'Red' }
            'High'     { 'Red' }
            'Medium'   { 'Yellow' }
            'Low'      { 'Yellow' }
            default    { 'White' }
        }

        Write-Host "  --- [$Level] ($($Group.Count) account(s)) ---" -ForegroundColor $Color
        foreach ($Finding in $Group) {
            Write-Host "    Account   : $($Finding.SamAccountName)"        -ForegroundColor $Color
            Write-Host "    Enabled   : $($Finding.Enabled)"               -ForegroundColor $Color
            Write-Host "    Privileged: $($Finding.PrivilegedGroupMember)" -ForegroundColor $Color
            Write-Host "    HasSPN    : $(if ($Finding.ServicePrincipalName -ne '') { 'True' } else { 'False' })" -ForegroundColor $Color
            Write-Host "    PwLastSet : $($Finding.PasswordLastSet)"       -ForegroundColor $Color
            Write-Host "    LastLogon : $($Finding.LastLogonDate)"         -ForegroundColor $Color
            Write-Host "    DN        : $($Finding.DistinguishedName)"     -ForegroundColor $Color
            Write-Host "    Action    : $($Finding.RecommendedAction)"     -ForegroundColor $Color
            Write-Host ""
        }
    }

    Write-Host "  IMPORTANT: Re-enabling preauthentication does not invalidate previously" -ForegroundColor Yellow
    Write-Host "             captured AS-REP hashes. Reset passwords for all affected accounts." -ForegroundColor Yellow
    Write-Host ""
# End of Show-AsRepRoastingFindings function
}

Function Get-AsRepRoastingAudit {
    <#
    .SYNOPSIS
    Audit Active Directory for accounts with Kerberos preauthentication disabled.

    .DESCRIPTION
    Searches all user accounts in the domain for DoesNotRequirePreAuth set to true.
    Assigns a risk level to each finding based on account state and privilege level,
    displays the results, and offers CSV export to Reports/.

    .EXAMPLE
    Get-AsRepRoastingAudit

    .NOTES
    Run from the Password Management sub-menu for interactive use.
    For automated daily monitoring use Start-DailyAsRepRoastingAudit.
    #>

    [PSCustomObject[]]$Findings = Get-AsRepRoastableAccounts

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        Write-Host "  [OK] No accounts found with Kerberos preauthentication disabled. Domain is clean." -ForegroundColor Green
        return
    }

    Show-AsRepRoastingFindings -Findings $Findings

    Export-AdPowerAdminData -Data $Findings -ReportName "AD-AsRepRoasting-Findings"
# End of Get-AsRepRoastingAudit function
}

Function Start-AsRepRoastingRemediation {
    <#
    .SYNOPSIS
    Interactively re-enable Kerberos preauthentication on affected AD user accounts.

    .DESCRIPTION
    Retrieves all accounts with DoesNotRequirePreAuth set, displays the full risk-rated
    report, then requires explicit confirmation before re-enabling preauthentication.

    Safe by design:
    - Displays the full audit report before any modification.
    - Requires typing YES (exact) to proceed. Any other input cancels with no changes.
    - Logs every operation (success and failure) and exports the log to Reports/.
    - Does not automatically reset passwords. Passwords MUST be manually reset after
      remediation to invalidate any AS-REP hashes already captured by an attacker.
    - Only clears DoesNotRequirePreAuth; no other account attributes are modified.

    .EXAMPLE
    Start-AsRepRoastingRemediation

    .NOTES
    After remediation, manually reset the password for every remediated account.
    Re-enabling preauthentication does not invalidate hashes captured before the change.
    #>

    [PSCustomObject[]]$Findings = Get-AsRepRoastableAccounts

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        Write-Host "  [OK] No accounts found with Kerberos preauthentication disabled. No remediation needed." -ForegroundColor Green
        return
    }

    Show-AsRepRoastingFindings -Findings $Findings

    Write-Host "  REMEDIATION: $($Findings.Count) account(s) eligible to have preauthentication re-enabled." -ForegroundColor Yellow
    Write-Host "  This sets DoesNotRequirePreAuth to false only. Passwords are NOT changed by this operation." -ForegroundColor Yellow
    Write-Host "  You MUST manually reset passwords for all remediated accounts after this step." -ForegroundColor Yellow
    [string]$Confirm = Read-Host "  Type YES to proceed. Any other input cancels (default: No)"

    if ($Confirm -eq 'YES') {
        $RemediationLog = [System.Collections.Generic.List[PSCustomObject]]::new()

        foreach ($Finding in $Findings) {
            try {
                Set-ADAccountControl -Identity $Finding.DistinguishedName -DoesNotRequirePreAuth $false -ErrorAction Stop
                Write-Host "  [OK] Re-enabled preauthentication: $($Finding.SamAccountName)" -ForegroundColor Green
                $RemediationLog.Add([PSCustomObject]@{
                    Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    SamAccountName = $Finding.SamAccountName
                    RiskLevel      = $Finding.RiskLevel
                    Enabled        = $Finding.Enabled
                    Action         = 'DoesNotRequirePreAuth cleared'
                    Result         = 'Success'
                })
            } catch {
                Write-Host "  [FAIL] Could not re-enable preauthentication: $($Finding.SamAccountName) -- $_" -ForegroundColor Red
                $RemediationLog.Add([PSCustomObject]@{
                    Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
                    SamAccountName = $Finding.SamAccountName
                    RiskLevel      = $Finding.RiskLevel
                    Enabled        = $Finding.Enabled
                    Action         = 'DoesNotRequirePreAuth clear attempted'
                    Result         = "Failed: $_"
                })
            }
        }

        Export-AdPowerAdminData -Data $RemediationLog -ReportName "AD-AsRepRoasting-RemediationLog"

        Write-Host ""
        Write-Host "  ACTION REQUIRED: Reset passwords for all remediated accounts." -ForegroundColor Red
        Write-Host "  Re-enabling preauthentication does not invalidate captured AS-REP hashes." -ForegroundColor Red
        Write-Host "  Use Set-ADAccountPassword to assign a new strong password for each account." -ForegroundColor Red
        Write-Host ""
    } else {
        Write-Host "  Remediation cancelled. No changes were made." -ForegroundColor Yellow
    }
# End of Start-AsRepRoastingRemediation function
}

Function Start-DailyAsRepRoastingAudit {
    <#
    .SYNOPSIS
    Daily unattended audit for accounts with Kerberos preauthentication disabled.

    .DESCRIPTION
    Runs as part of the daily unattended job schedule. Checks the domain for user
    accounts with DoesNotRequirePreAuth set. Exports a dated CSV to Reports/ and
    emails the administrator if any Critical or High risk accounts are found.

    Controlled by the $global:AsRepRoastingAudit feature flag in
    AD-PowerAdmin_settings.ps1. Set to $false to disable without removing functionality.

    .EXAMPLE
    Start-DailyAsRepRoastingAudit

    .NOTES
    Invoked automatically by the AD-PowerAdmin scheduler when Daily = $true jobs run.
    #>

    if ($global:AsRepRoastingAudit -ne $true) { return }

    [PSCustomObject[]]$Findings = Get-AsRepRoastableAccounts

    # Export a dated CSV on every run regardless of findings count.
    [string]$DateStamp  = (Get-Date).ToString('yyyy-MM-dd')
    [string]$ReportFile = "$global:ReportsPath\AD-AsRepRoasting-Daily-$DateStamp.csv"

    if ($null -ne $Findings -and $Findings.Count -gt 0) {
        try {
            $Findings | Export-Csv -Path $ReportFile -NoTypeInformation -Force
        } catch {
            if ($global:Debug) { Write-Host "Debug: Failed to write AS-REP Roasting daily CSV: $_" -ForegroundColor Red }
        }
    }

    # Only send an alert email for Critical and High findings.
    [array]$AlertFindings = @($Findings | Where-Object { $_.RiskLevel -eq 'Critical' -or $_.RiskLevel -eq 'High' })

    if ($AlertFindings.Count -eq 0) { return }

    [int]$CriticalCount = @($AlertFindings | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    [int]$HighCount     = @($AlertFindings | Where-Object { $_.RiskLevel -eq 'High' }).Count

    [string]$Body  = "AD-PowerAdmin Daily AS-REP Roasting Audit`r`n"
    [string]$Body += "Date: $(Get-Date)`r`n"
    [string]$Body += "----------------------------------------------`r`n`r`n"
    [string]$Body += "ALERT: $($AlertFindings.Count) account(s) with Kerberos preauthentication disabled.`r`n"
    [string]$Body += "  Critical: $CriticalCount`r`n"
    [string]$Body += "  High    : $HighCount`r`n`r`n"
    [string]$Body += "Accounts with preauthentication disabled are vulnerable to AS-REP Roasting.`r`n"
    [string]$Body += "An attacker can request AS-REP tickets offline and crack the encrypted response`r`n"
    [string]$Body += "without providing a password or interacting with the target account.`r`n`r`n"
    [string]$Body += "Use 'AS-REP Roasting Audit' in the Password Management menu to remediate.`r`n"
    [string]$Body += "After remediation, reset passwords for all affected accounts.`r`n`r`n"
    [string]$Body += "Affected Accounts:`r`n"

    foreach ($Finding in ($AlertFindings | Sort-Object RiskLevel, SamAccountName)) {
        [string]$Body += "  [$($Finding.RiskLevel)] $($Finding.SamAccountName)"
        [string]$Body += " (Enabled: $($Finding.Enabled), Privileged: $($Finding.PrivilegedGroupMember))`r`n"
    }

    [string]$Body += "`r`nFull report: $ReportFile`r`n"

    if ($null -eq $global:ADAdminEmail -or $global:ADAdminEmail -eq '') { return }

    try {
        Send-Email -ToEmail "$global:ADAdminEmail" `
            -FromEmail "$global:FromEmail" `
            -Subject "AD-PowerAdmin: AS-REP Roastable Accounts Detected - ACTION REQUIRED" `
            -Body $Body
    } catch {
        if ($global:Debug) {
            Write-Host "Debug: Failed to send AS-REP Roasting alert email: $_" -ForegroundColor Red
        }
    }
# End of Start-DailyAsRepRoastingAudit function
}