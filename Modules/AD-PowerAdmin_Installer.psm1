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
        'Install-ADPowerAdmin' = @{
            Title    = "Install AD-PowerAdmin"
            Label    = "Install AD-PowereAdmin to run daily tasts as a scheduled task."
            Module   = "AD-PowerAdmin_Installer"
            Function = "Install-ADPowerAdmin"
            Command  = "Install-ADPowerAdmin"
        }
        'Test-ADPowerAdminInstall' = @{
            Title    = "Test AD-PowerAdmin Install"
            Label    = "Test if the AD-PowerAdmin script is installed correctly."
            Module   = "AD-PowerAdmin_Installer"
            Function = "Test-ADPowerAdminInstall"
            Command  = "Test-ADPowerAdminInstall"
        }
        'Remove-ADPowerAdmin' = @{
            Title    = "Uninstall AD-PowerAdmin"
            Label    = "Remove the AD-PowerAdmin script and all related objects."
            Module   = "AD-PowerAdmin_Installer"
            Function = "Remove-ADPowerAdmin"
            Command  = "Remove-ADPowerAdmin"
        }
    }
}

Initialize-Module

Function Install-DSInternals {
    <#
    .SYNOPSIS
    Function to check if the DSInternals PowerShell module is installed. If not, then install it, if the install fails, error and exit the script.

    .DESCRIPTION
    Function to check if the DSInternals PowerShell module is installed. If not, then install it, if the install fails, error and exit the script.
    DSInternals is used to audit users passwords and other security attributes.
    The module is well-vetted by Microsoft and is safe to use.
    PowerShell Gallery: https://www.powershellgallery.com/packages/DSInternals/4.7
    GitHub: https://github.com/MichaelGrafnetter/DSInternals

    .EXAMPLE
    Install-DSInternals

    .NOTES

    #>

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

    # Try to import the DSInternals PowerShell module. If the import fails, then output an error and exit the script.
    try {
        Import-Module -Name DSInternals -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Error: The DSInternals PowerShell module failed to import." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }

# End of Install-DSInternals function
}

function Install-ADPowerAdmin {
    <#
    .SYNOPSIS
    A function to install the AD-PowerAdmin script to run daily as a scheduled task.

    .DESCRIPTION
    Install the AD-PowerAdmin script to run daily tasks as a scheduled task.

    Note: The function that make up the install process check if there objectives are already completed before
        they try to complete them. For example, the function to create the AD-PowerAdmin home directory
        will check if the home directory already exists before it tries to create it.
        This allows the install script to be run multiple times without causing any issues.

    The install will:
    - Create the AD-PowerAdmin home directory as defined in the AD-PowerAdmin_settings.ps1 file.
        Set the owner of the AD-PowerAdmin home directory to the Domain Administrators group
        and remove all other permissions. Set the system audit policy and the AD-PowerAdmin
        home directory audit policy to "Everyone" for "Success" and "Failure". These audit
        settings means that any interaction with the AD-PowerAdmin home directory will be
        logged in the security event log.

    - Check if the AD-PowerAdmin script is already running from the defined install
        directory(set in the AD-PowerAdmin_settings.ps1 file). If AD-PowerAdmin is
        running in a folder other then the defined install
        directory(set in the AD-PowerAdmin_settings.ps1 file), then copy the AD-PowerAdmin
        script to the install directory.

    - Install the DSInternals PowerShell module.

    - Create the AD-PowerAdmin sMSA account; needed for the unattended Scheduled Task.
        Create a new standalone Managed Service Account (sMSA) for the AD-PowerAdmin schedule task.
        The sMSA account will be the name defined in the AD-PowerAdmin_settings.ps1($global:MsaAccountName) file.
        The sMSA account will be created in the "domain.com/Managed Service Accounts" container,
            and will be a member of the "Domain Admins" group.
        The sMSA will be created with a random password and change ever 30-days.

    - Modify the existing "Domian Controllers Policy" GPO to give the sMSA account the "Log on as a service" right.
        I know this sounds odd. Read the comments in the Set-ADPowerAdminGPO function for more information.

    - Create a AD-PowerAdmin Schduled daily task.
        The task will be named "AD-PowerAdmin_Daily".
        The task will run the AD-PowerAdmin script daily at 9:00 AM.
        The task will run the AD-PowerAdmin script with the "-Unattended" and "-JobName 'Daily'" parameters.

    .EXAMPLE
    Install-ADPowerAdmin

    .NOTES

    #>

    # Create the AD-PowerAdmin home directory.
    New-ADPowerAdminHomeFolder

    # Check if the AD-PowerAdmin script is already installed.
    # If AD-PowerAdmin is running in a folder other then the defined install directory(set in the AD-PowerAdmin_settings.ps1 file), then copy the AD-PowerAdmin script to the install directory.
    Copy-AdPowerAdmin

    # Create a ADPowerAdmMSA account with domain admin rights.
    New-ADPowerAdminSmsaAccount

    # Create a new GPO to give the sMSA account the "Log on as a service" right.
    Set-ADPowerAdminGPO -Install

    # Create a new scheduled task to run the AD-PowerAdmin script daily.
    New-ADPowerAdminScheduledTask -ScriptsFullFullPathForScheduleTask "$global:IntallDirectory\$global:ThisScriptsName"

    # Install the DSInternals PowerShell module.
    Install-DSInternals

    # Test the AD-PowerAdmin install.
    Write-Host "Testing the AD-PowerAdmin install." -ForegroundColor White
    Write-host "----------------------------------------" -ForegroundColor White
    Test-ADPowerAdminInstall
    Write-host "----------------------------------------" -ForegroundColor White
    Write-Host "The AD-PowerAdmin install is complete." -ForegroundColor Green

# End of the Install-ADPowerAdmin function.
}

function New-ADPowerAdminSmsaAccount {
    <#
    .SYNOPSIS
    function to create a AD-PowerAdmin sMSA account.

    .DESCRIPTION
    Create the AD-PowerAdmin sMSA account; needed for the unattended Scheduled Task.
        Create a new standalone Managed Service Account (sMSA) for the AD-PowerAdmin schedule task.
        The sMSA account will be the name defined in the AD-PowerAdmin_settings.ps1($global:MsaAccountName) file.
        The sMSA account will be created in the "domain.com/Managed Service Accounts" container,
            and will be a member of the "Domain Admins" group.
        The sMSA will be created with a random password and change ever 30-days.

    .EXAMPLE
    New-ADPowerAdminSmsaAccount

    .NOTES

    #>

    [string]$MsaAccountDescription = "AD-PowerAdmin sMSA Account"
    # Check if the AD-PowerAdmin_MSA account already exists.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'"
    # Check if the "$global:MsaAccountName" sMSA account already exists. If it does not exist, then create the sMSA account.
    if ($null -eq $MsaIdentity) {

        # Check if the defined sMSA account name "$global:MsaAccountName" is longer than 14 characters.
        if ($global:MsaAccountName.Length -gt 14) {
            Write-Host "Error: The sMSA account name '$global:MsaAccountName' is longer than 14 characters." -ForegroundColor Red
            Write-Host "Error: The sMSA account name must be 14 characters or less." -ForegroundColor Red
            return
        }

        # Try to run the New-ADServiceAccount command. If the command fails, then display an error and exit the function.
        try {
            New-ADServiceAccount -SamAccountName "$global:MsaAccountName" -Name "$global:MsaAccountName" -Description "$MsaAccountDescription" -RestrictToSingleComputer -Enabled $true
        } catch {
            Write-Host "Error: The AD-PowerAdmin sMSA account was not created." -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
        $AdServerIdentity = Get-ADComputer -identity "$env:COMPUTERNAME"
        $MsaIdentity      = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -Properties * -ErrorAction SilentlyContinue
        Add-ADComputerServiceAccount -Identity $AdServerIdentity -ServiceAccount $MsaIdentity.sAMAccountName
        Install-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
        # Test that the sMSA account was created and this compluter is a member of the sMSA group.
        if ($null -eq $MsaIdentity) {
            Write-Host "Error: The AD-PowerAdmin sMSA account was not created." -ForegroundColor Red
            return
        }
        # Test that the sMSA account was created and this compluter is a member of the sMSA group.
        $TestAdServiceAccount = Test-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
        if (-Not $TestAdServiceAccount) {
            Write-Host "Error: The AD-PowerAdmin sMSA group was not created." -ForegroundColor Red
            return
        }
        # Add the sMSA account to the "Domain Admins" group.
        Add-ADGroupMember -Identity "Domain Admins" -Members $MsaIdentity.SamAccountName
    } else {
        # If the sMSA account already exists, then display a warning and continue.
        Write-Host "The sMSA account '$global:MsaAccountName' already exists." -ForegroundColor Yellow
    }
# End of the New-ADPowerAdminSmsaAccount function.
}

function New-ADPowerAdminScheduledTask {
    <#
    .SYNOPSIS
    function to create a AD-PowerAdmin Schduled daily task.

    .DESCRIPTION
    function to create a AD-PowerAdmin Schduled daily task.
    The task will be named "AD-PowerAdmin_Daily".
    The task will run the AD-PowerAdmin script daily at 9:00 AM.
    The task will run the AD-PowerAdmin script with the "-Unattended" and "-JobName 'Daily'" parameters.

    .EXAMPLE
    New-ADPowerAdminScheduledTask

    .NOTES

    #>

    param (
        [Parameter(Mandatory=$false, Position=1)]
        [string]$ScriptsFullFullPathForScheduleTask = "$global:ThisScript"
    )

    # ---------- Create the AD-PowerAdmin schedule task ----------
    [string]$TaskName = "AD-PowerAdmin_Daily"
    # Set ScheduleRunTime to be tomorrow at 9:00 AM.
    [datetime]$ScheduleRunTime = (Get-Date).AddDays(1).Date + "09:00:00"
    [string]$TaskDiscription = "AD-PowerAdmin Daily Tasks"
    [string]$ThisScriptsFullName = "$ScriptsFullFullPathForScheduleTask"
    # Check if the AD-PowerAdmin_Daily schedule task already exists.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin schedule task already exists, then ask the user if they want to overwrite the existing schedule task.
        Write-Host "The AD-PowerAdmin schedule task already exists." -ForegroundColor Yellow
        $OverwriteScheduleTask = Read-Host "Do you want to overwrite the existing schedule task? (Y/N)"
        # If the user does not want to overwrite the existing schedule task, then exit the function.
        if ($OverwriteScheduleTask -ne 'Y' -or $OverwriteScheduleTask -ne 'y') {
            Write-Host "The AD-PowerAdmin schedule task was not overwritten." -ForegroundColor Yellow
            return
        }
        # If the user wants to overwrite the existing schedule task, then delete the existing schedule task.
        Write-Host "Deleting the existing AD-PowerAdmin schedule task." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
    }
    # Try to set up a new schedule task to run the AD-PowerAdmin script daily.
    try {
        # Create a new schedule task to run the AD-PowerAdmin script daily.
        New-ScheduledTask -ActionString 'PowerShell.exe' -ActionArguments "$ThisScriptsFullName -Unattended -JobName 'Daily'" -ScheduleRunTime $ScheduleRunTime -Recurring "Daliy" -TaskName $TaskName -TaskDiscription $TaskDiscription
    } catch {
        # If the schedule task was not created successfully, then display an error message to the user.
        Write-Host "Error: The AD-PowerAdmin schedule task failed to be created." -ForegroundColor Red
        return
    }
# End of the New-ADPowerAdminScheduledTask function.
}

function New-ADPowerAdminHomeFolder {
    <#
    .SYNOPSIS
    A function to set up the AD-PowerAdmin script home directory.

    .DESCRIPTION
    - Create the AD-PowerAdmin home directory.
    - The home directory will be named "AD-PowerAdmin".
    - The home directory will be created in the "C:\Scripts" directory.
    - Set the owner of the AD-PowerAdmin home directory to the Domain Administrators group.
    - Set the system audit policy and the AD-PowerAdmin home directory to audit policy to "Everyone" for "Success" and "Failure".

    .EXAMPLE
    Install-ADPowerAdmin

    .NOTES

    #>

    # Check if the AD-PowerAdmin home directory exists at C:\Scripts\AD-PowerAdmin, if not then create it and all parent directories.
    if (-Not (Test-Path -Path "$global:InstallDirectory")) {
        New-Item -Path "$global:InstallDirectory" -ItemType Directory -Force | Out-Null
    }

    # Set the owner of the AD-PowerAdmin home directory to the Domain Administrators group.
    $InstallDirACL = Get-Acl -Path "$global:InstallDirectory"
    # Set the owner of the AD-PowerAdmin home directory to the Domain Admins group.
    $DomainAdminsGroup = New-Object System.Security.Principal.NTAccount("Domain Admins")
    $InstallDirACL.SetOwner($DomainAdminsGroup)
    $InstallDirACL.SetAccessRuleProtection($true, $false)
    $InstallDirRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DomainAdminsGroup, "FullControl", "Allow")
    $InstallDirACL.AddAccessRule($InstallDirRule)
    Set-Acl -Path "$global:InstallDirectory" -AclObject $InstallDirACL

    # # Enable folder-level auditing
    Enable-AuditLogging -FolderPath "$global:InstallDirectory" -Principal "Everyone" -AuditSuccess $true -AuditFailure $true -Policy "File System" -AuditFlags "Success,Failure"
# End of the Install-ADPowerAdminHomeFolder function.
}

function Enable-AuditLogging {
    <#
    .SYNOPSIS
    A function to enable audit logging on a folder.

    .DESCRIPTION
    Enable audit logging on the system usign the "auditpol" cmdlet. Then enable audit logging on the given folder.

    .EXAMPLE
    Enable-AuditLogging -FolderPath "C:\Scripts\AD-PowerAdmin" -AuditSuccess $true -AuditFailure $true -Policy "File System" -AuditFlags "Success,Failure"

    .NOTES

    #>

    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$FolderPath,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Principal = "Everyone",
        [bool]$AuditSuccess = $true,
        [Parameter(Mandatory=$false, Position=3)]
        [bool]$AuditFailure = $true,
        [Parameter(Mandatory=$true, Position=4)]
        [string]$Policy,
        [Parameter(Mandatory=$false, Position=5)]
        [string]$AuditFlags = "Success,Failure"
    )

    # Enable the audit policy for the given folder.
    [string]$AuditFlagsSuccess = "disable"
    [string]$AuditFlagsFailure = "disable"

    if ($AuditSuccess) {
        $AuditFlagsSuccess = "enable"
    }

    if ($AuditFailure) {
        $AuditFlagsFailure = "enable"
    }

    # File system auditing needs to be enabled before we can set the audit policy on objects)files and folders).
    # The cmdlet "auditpol" requires admin rights to run.
    # The cmdlet command being run by PowerShell is "auditpol /set /subcategory:"File System" /success:enable /failure:enable"
    Start-Process -FilePath auditpol -ArgumentList "/set /subcategory:`"$Policy`" /success:$AuditFlagsSuccess /failure:$AuditFlagsFailure" -Verb RunAs -Wait

    # Enable folder-level auditing on the given folder.

    # Get the current audit settings for the folder.
    $FolderACL = Get-Acl -Path $FolderPath

    # Create an array of audit rules to apply to the folder.
    $AuditSettings = @{
        # FileSystemRights = "CreateFiles", "Delete", "WriteData"
        FileSystemRights = "ExecuteFile", "DeleteSubdirectoriesAndFiles", "Write", "Delete", "ChangePermissions", "TakeOwnership"
    }

    # For each audit rule, create a new audit rule object and add it to the folder's ACL.
    foreach ($FileSystemRight in $AuditSettings["FileSystemRights"]) {
        $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($Principal, $FileSystemRight, "ContainerInherit,ObjectInherit", "None", "$AuditFlags")
        $FolderACL.AddAuditRule($AuditRule)
    }

    # Try to apply the audit settings and ACL rules to the folder.
    try {
        Set-Acl -Path $FolderPath -AclObject $FolderACL
    } catch {
        Write-Host "Error: The audit settings failed to be applied to the folder '$FolderPath'." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        break
    }
# End of the Enable-AuditLogging function.
}

function Copy-AdPowerAdmin {
    <#
    .SYNOPSIS
    A function to copy the AD-PowerAdmin script to the install directory.

    .DESCRIPTION
    Check if the AD-PowerAdmin script is running from the AD-PowerAdmin home directory, defined in the AD-PowerAdmin_settings.ps1 file.
    If the AD-PowerAdmin script is not running from the AD-PowerAdmin home directory, then check if the file contents of the current running directory match the AD-PowerAdmin home directory.
    If it does not match, then copy the AD-PowerAdmin current directory contents to the AD-PowerAdmin home directory.
    Confirm that the files in the current running directory match the AD-PowerAdmin home directory. If you are already running from the AD-PowerAdmin home directory, then the currect directory contents will match the AD-PowerAdmin home directory.

    .EXAMPLE
    Copy-AdPowerAdmin

    .NOTES
    I was going to have this function return a $true or $false value to indicate if the AD-PowerAdmin home directory was copied successfully.
    But, I decided I did not want to have another if statment in the Install-ADPowerAdmin function to check the return value.

    #>

    # Set deafult output to $false.
    [bool]$InstallStatus = $false

    # ---------- Move the AD-PowerAdmin home directory ----------
    # Check if this script is running from the AD-PowerAdmin home directory.
    if ($global:InstallDirectory -ne $global:ThisScriptDir) {

        # Check if the two directory contents match each other before we try to copy the data.
        $DirCompare = Compare-Object -ReferenceObject (Get-ChildItem -Path "$global:ThisScriptDir" -Exclude ".git") -DifferenceObject (Get-ChildItem -Path "$global:InstallDirectory" -Exclude ".git") -Property Name -PassThru

        # If the two directory contents already match, then exit the function.
        if ( $null -eq $DirCompare ) {
            Write-Host 'AD-PowerAdmin is not running from the directory set in the AD-PowerAdmin_setttings.ps1($global:InstallDirectory)
             config file, but the current running scripts directorys files match the install directorys files.' -ForegroundColor Yellow
            return
        }

        # If this script is running from the AD-PowerAdmin home directory, then move the AD-PowerAdmin home directory.
        Write-Host "Copy the AD-PowerAdmin files to the configured new home directory." -ForegroundColor Yellow
        Copy-Item -Path "$global:ThisScriptDir/*" -Destination "$global:InstallDirectory" -Force -Recurse
        Clear-Variable -Name $DirCompare -ErrorAction SilentlyContinue
    }

    # Check if the two directory contents match each other.
    $DirCompare = Compare-Object -ReferenceObject (Get-ChildItem -Path "$global:ThisScriptDir" -Exclude ".git") -DifferenceObject (Get-ChildItem -Path "$global:InstallDirectory" -Exclude ".git") -Property Name -PassThru

    # Check the $InstallStatus variable for any differences.
    if ( $null -ne $DirCompare ) {
        Write-Host "Error: The AD-PowerAdmin home directory was not copied successfully." -ForegroundColor Red
        return
    }

    if ( $null -eq $DirCompare ) {
        Write-Host "The AD-PowerAdmin currect directory matches the  set home directory." -ForegroundColor Green
    }

    # If the function has not returned yet, then the AD-PowerAdmin home directory was copied successfully.
    $InstallStatus = $true
    # Return the install status.
    # $InstallStatus
# End of the Copy-AdPowerAdmin function.
}

Function Set-ADPowerAdminGPO {
    <#
    .SYNOPSIS
    A Function that will update the "Default Domain Controllers Policy" GPO to give the AD-PowerAdmin sMSA account the "Log on as a service" right.

    .DESCRIPTION
    - A-PowerAdmin requires the "Log on as a service" right to run rights for the AD-PowerAdmin sMSA account. Without this right, the AD-PowerAdmin script will not run because Windows is dumb.
        If you want more information on this issue, please see the following links: https://cybergladius.com/secure-windows-scheduled-tasks-with-managed-service-accounts/

        To complicate the issue, the "Log on as a service" GPO setting cannot be applied via PowerShell. This makes it impossible for me to create a new GPO with the "Log on as a service" right.
        So, the workaround I came up with is to edit the "Default Domain Controllers Policy" GPO to add the "Log on as a service" right to the AD-PowerAdmin sMSA account.
        Now, you may be asking, "isn't editing the "Log on as a service" setting a security issue?" Yes, but not really. Since we use an sMSA account, the password is random and changes every 30 days.
        In addition, only this domain controller can read the password for the sMSA account. So, if an attacker could read the AD-PowerAdmin sMSA account password, they would have already compromised the domain controller.
        So it's a moot point.

        - Open the "Default Domain Controllers Policy" GPO.
        - Check if the GPO contains the "Log on as a service" right configured for the AD-PowerAdmin sMSA account.
        - if the GPO does not contain the "Log on as a service" right configured for the AD-PowerAdmin sMSA account, then add it.
        - Force the server is update its GPO settings.

    .EXAMPLE
    Set-ADPowerAdminGPO -Install
    Set-ADPowerAdminGPO -Uninstall
    Set-ADPowerAdminGPO -Test

    .NOTES
    The GPO will be created with a random password and change ever 30-days.

    #>

    param (
        [Parameter(Mandatory=$false, Position=1)]
        [switch]$Install,
        [Parameter(Mandatory=$false, Position=2)]
        [switch]$Uninstall,
        [Parameter(Mandatory=$false, Position=3)]
        [switch]$Test
    )

    # Check if the Install, Uninstall, or Test switch is set. If more than one switch is set, then display an error and exit the function.
    if (($Install -and $Uninstall) -or ($Install -and $Test) -or ($Uninstall -and $Test)) {
        Write-Host "Error: Only one of the following switches can be set: -Install, -Uninstall, or -Test." -ForegroundColor Red
        return
    }

    # Check if the Install, Uninstall, or Test switch is set. If none of the switches are set, then display an error and exit the function.
    if (-Not ($Install -or $Uninstall -or $Test)) {
        Write-Host "Error: One of the following switches must be set: -Install, -Uninstall, or -Test." -ForegroundColor Red
        return
    }

    # Get domain controller to run all commands against
    [object]$DomainContollerServer = Get-ADDomainController
    # Get the Active Directory root DNS domain name.
    [object]$DnsRootDomainName = Get-ADDomain -Identity $DomainContollerServer.Domain | Select-Object -Property DNSRoot
    # \\localhost\SYSVOL\domain.loc\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
    [string]$GpoCfgFile = "\\$($DnsRootDomainName.DNSRoot)\SYSVOL\$($DnsRootDomainName.DNSRoot)\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    # Get content of the $GpoCfgFile. Maintain the line breaks.
    [string]$GpoCfgFileContent = Get-Content -Path $GpoCfgFile -Raw
    $SID = Get-ADServiceAccount -Identity "$global:MsaAccountName`$" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue

    #Check it $GpoCfgFile exists.
    if (-Not (Test-Path -Path "$GpoCfgFile")) {
        Write-Host "Error: The GPO configuration file '$GpoCfgFile' does not exist." -ForegroundColor Red
        break
    }

    # If Install or Uninstall switch is set, then check if the $GpoCfgFileContent contains the "SeServiceLogonRight" line.
    if ($Install -or $Uninstall) {
        # Check if the $GpoCfgFileContent contains the "SeServiceLogonRight" line.
        if ($GpoCfgFileContent -notmatch "SeServiceLogonRight") {
            Write-Host "Warrning: The GPO configuration file '$GpoCfgFile' does not contain the 'SeServiceLogonRight' line." -ForegroundColor Yellow
        }
        # Check if the $SID is null.
        if ($null -eq $SID) {
            Write-Host "Error: The SID for the sMSA account '$global:MsaAccountName' was not found." -ForegroundColor Red
            break
        }
    }

    # If the Install switch is set, then add the $global:MsaAccountName to the "SeServiceLogonRight" line.
    if ($Install) {

        # Check if the $GpoCfgFileContent contains $global:MsaAccountName or $SID.Value is already in the "SeServiceLogonRight" line.
        if (($GpoCfgFileContent -match "$global:MsaAccountName") -or ($GpoCfgFileContent -match "$($SID.Value)")) {
            Write-Host "The GPO configuration file '$GpoCfgFile' already contains the '$global:MsaAccountName' or '$($SID.Value)' line." -ForegroundColor Yellow
            return
        }

        # For each line of a file, check if the line contains the "SeServiceLogonRight" line.
        # If the line contains the "SeServiceLogonRight" line, then add the $global:MsaAccountName to the line.
        # If the line does not contain the "SeServiceLogonRight" line, then add the line to the $GpoCfgFileContentNew variable.
        [string]$GpoCfgFileContentNew = ""
        foreach ($Line in $GpoCfgFileContent.Split("`n")) {
            if ($Line -match "SeServiceLogonRight") {
                # Track if the SeServiceLogonRight line is found.
                [bool]$SeServiceLogonRightLineFound = $true
                # Remove the line break from the end of the line.
                $Line = $Line.TrimEnd()
                $Line = $Line + ",*$($SID.Value)"
            }
            $GpoCfgFileContentNew = $GpoCfgFileContentNew + $Line + "`n"
        }
        # Check if the SeServiceLogonRight line was found. If it was not found then add a new line containing'SeServiceLogonRight = "*$($SID.Value)"' agfter the line that starts with 'SeBatchLogonRight'.
        if (-Not $SeServiceLogonRightLineFound) {
            [string]$GpoCfgFileContentNew = ""
            foreach ($Line in $GpoCfgFileContent.Split("`n")) {
                if ($Line -match "SeBatchLogonRight") {
                    $Line = $Line + "`n" + "SeServiceLogonRight = *$($SID.Value)"
                }
                $GpoCfgFileContentNew = $GpoCfgFileContentNew + $Line + "`n"
            }
        }
    }

    # If the Uninstall switch is set, then remove the $global:MsaAccountName from the "SeServiceLogonRight" line.
    if ($Uninstall) {
        # For each line of a file, check if the line contains the "SeServiceLogonRight" line.
        # If the line contains the "SeServiceLogonRight" line, then remove the $global:MsaAccountName from the line but keeping everything else intact.
        # If the line does not contain the "SeServiceLogonRight" line, then add the line to the $GpoCfgFileContentNew variable.
        [string]$GpoCfgFileContentNew = ""
        foreach ($Line in $GpoCfgFileContent.Split("`n")) {
            if ($Line -match "SeServiceLogonRight") {
                # Remove the line break from the end of the line.
                $Line = $Line.TrimEnd()
                $Line = $Line -replace ",\*$($SID.Value)", ""
                $Line = $Line -replace ",$global:MsaAccountName", ""
            }
            $GpoCfgFileContentNew = $GpoCfgFileContentNew + $Line + "`n"
        }
        Write-host "The '$global:MsaAccountName' account has been removed from the  GPO configuration file." -ForegroundColor Yellow
    }

    # If the Test switch is set, then remove the $global:MsaAccountName from the "SeServiceLogonRight" line.
    if ($Test) {
        # Get the "SeServiceLogonRight" line from the $GpoCfgFileContent, and test that line contains the $global:MsaAccountName or $SID.Value.
        [string]$SeServiceLogonRightLine = $GpoCfgFileContent | Select-String -Pattern "SeServiceLogonRight"
        if (($SeServiceLogonRightLine -match "$global:MsaAccountName") -or ($SeServiceLogonRightLine -match "$($SID.Value)")) {
            $true
            return
        }
        $false
    }

    # If Install or Uninstall switch is set, then write the $GpoCfgFileContentNew to the $GpoCfgFile.
    if ($Install -or $Uninstall) {
        # Write-Output $GpoCfgFile
        $GpoCfgFileContentNew | Out-File "$GpoCfgFile" -Encoding unicode -Force -NoNewline
        # Confirm that the $GpoCfgFile matches the $GpoCfgFileContentNew.
        [string]$GpoCfgFileContentNewTest = Get-Content -Path $GpoCfgFile -Raw
        if ($GpoCfgFileContentNewTest -ne $GpoCfgFileContentNew) {
            Write-Host '----------------------------------------' -ForegroundColor Yellow
            $GpoCfgFileContentNew
            Write-Host '----------------------------------------' -ForegroundColor Yellow
            $GpoCfgFileContentNewTest
            Write-Host '----------------------------------------' -ForegroundColor Yellow
            Write-Host "Error: The GPO configuration file '$GpoCfgFile' was not updated." -ForegroundColor Red
            Exit 1
        }
        # Create a object variable that contains the "Default Domain Controllers Policy" GPO.
        [object]$DefaultDomainControllersPolicy = Get-GPO -Guid '6AC1786C-016F-11D2-945F-00C04fB984F9'
        #Force AD to process new GPO
        $DefaultDomainControllersPolicy | Set-GPRegistryValue -Key HKLM\SOFTWARE -ValueName "Default" -Value "" -Type String -Server $DomainContollerServer | Out-Null
        $DefaultDomainControllersPolicy | Remove-GPRegistryValue -Key HKLM\SOFTWARE -ValueName "Default" -Server $DomainContollerServer | Out-Null
        Invoke-GPUpdate -Force
    }
# End of the New-ADPowerAdminGPO function.
}

function Test-ADPowerAdminInstall {
    <#
    .SYNOPSIS
    A function to test if the AD-PowerAdmin script is installed.

    .DESCRIPTION
    Test if the AD-PowerAdmin script is installed.

    .EXAMPLE
    Test-ADPowerAdminInstall

    .NOTES

    #>

    [bool]$TestAdPowerAdminInstallGood = $true
    # Check is the $global:MsaAccountName sMSA account exists.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'"

    # Check if the "$global:MsaAccountName" sMSA account already exists. If it does not exist, then create the sMSA account.
    if ($null -eq $MsaIdentity) {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' does not exist." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' exists." -ForegroundColor Green
    }

    # Check if the $global:MsaAccountName sMSA account is a member of the "Domain Admins" group.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -Properties * -ErrorAction SilentlyContinue
    if ($null -eq $MsaIdentity) {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' is not a member of the 'Domain Admins' group." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' is a member of the 'Domain Admins' group." -ForegroundColor Green
    }

    # Check if the AD-PowerAdmin GPO settings are correct.
    if (Set-ADPowerAdminGPO -Test) {
        Write-Host "The AD-PowerAdmin_GPO GPO exists." -ForegroundColor Green
    } else {
        Write-Host "The AD-PowerAdmin_GPO GPO does not exist." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    }

    # Check if the AD-PowerAdmin_Daily schedule task exists.
    $TaskIdentity = Get-ScheduledTask -TaskName "AD-PowerAdmin_Daily" -ErrorAction SilentlyContinue
    if ($null -eq $TaskIdentity) {
        Write-Host "The AD-PowerAdmin_Daily schedule task does not exist." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin_Daily schedule task exists." -ForegroundColor Green
    }

    # Check if the AD-PowerAdmin_Daily schedule task is enabled.
    $TaskIdentity = Get-ScheduledTask -TaskName "AD-PowerAdmin_Daily" -ErrorAction SilentlyContinue
    if ($null -eq $TaskIdentity) {
        Write-Host "The AD-PowerAdmin_Daily schedule task is not enabled." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin_Daily schedule task is enabled." -ForegroundColor Green
    }

    # Check if the Audit Policy is set correctly.
    if (-Not (Test-SystemAuditPolicy -Policy "File System" -AuditSuccess $true -AuditFailure $true)) {
        Write-Host "The system Audit Policy is set incorrectly" -ForegroundColor Red
        Write-Host "The Audit Policy maybe getting reset by a GPO?" -ForegroundColor Yellow
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The system Audit Policy is set correctly" -ForegroundColor Green
    }

    # Check if the Install folder ACL are set correctly.
    if ((Test-FolderAuditPolicy -FolderPath "$global:InstallDirectory" -Principal "Everyone" -AuditFlags "Success,Failure")) {
        Write-Host "The Install folder Audit Policies are set correctly" -ForegroundColor Green
    } else {
        Write-Host "The Install folder Audit Policies are incorrect" -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    }

# End of the Test-ADPowerAdminInstall function.
}

function Test-SystemAuditPolicy {
    <#
    .SYNOPSIS
    A function to test if the audit policy is set correctly.

    .DESCRIPTION
    Test if the system audit policy is set correctly based on given parameters. Return true or false.

    .EXAMPLE
    Test-SystemAuditPolicy -Policy "File System" -AuditSuccess $true -AuditFailure $true

    .NOTES

    #>

    param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Policy,
        [Parameter(Mandatory=$false, Position=2)]
        [bool]$AuditSuccess = $true,
        [Parameter(Mandatory=$false, Position=3)]
        [bool]$AuditFailure = $true

    )

    # Set the default output to $false.
    $AuditPoliciesCorrect = $false

    # Check the $AuditFlags parameter for Success and/or Failure. If the AuditFlag contains Success then set the Success flag to "enable". If the AuditFlag contains Failure then set the Failure flag to "enable".
    if ($AuditSuccess -and $AuditFailure){
        $AuditPolicyCorrectOutput = "Success and Failure"
    }

    if ($AuditSuccess -and $AuditFailure -eq $false) {
        $AuditPolicyCorrectOutput = "Success"
    }

    if ($AuditFailure -and $AuditSuccess -eq $false) {
        $AuditPolicyCorrectOutput = "Failure"
    }

    # Get all audit policies
    $AllAuditPolicies = (auditpol.exe /get /category:* /r | ConvertFrom-Csv)

    # If $SinglePolicyToCheck is not set, then error and exit the function.
    if ('' -eq $Policy) {
        Write-Host "Error: The Policy parameter is not set." -ForegroundColor Red
        return
    }

    # Filter the audit policies to only the policy that we want to check.
    $AllAuditPolicies = $AllAuditPolicies | Where-Object { $_.Subcategory -eq $Policy }

    # String compare the audit policy to the expected output.
    [string]$AuditSetting = $AllAuditPolicies.{Inclusion Setting}
    if ($AuditSetting -eq $AuditPolicyCorrectOutput) {
        $AuditPoliciesCorrect = $true
    }

    # Return the audit policy results.
    $AuditPoliciesCorrect
# End of the Test-AuditSettings function.
}

function Test-FolderAuditPolicy {
    <#
    .SYNOPSIS
    A function to test if the audit policy is set correctly on a folder.

    .DESCRIPTION
    Test if the audit policy is set correctly on a folder based on given parameters. Return true or false.

    .EXAMPLE
    Test-FolderAuditPolicy -FolderPath "C:\Scripts\AD-PowerAdmin" -Principal "Everyone" -AuditFlags "Success,Failure"

    .NOTES

    #>

    param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$FolderPath,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$Principal = "Everyone",
        [Parameter(Mandatory=$false, Position=3)]
        [string]$auditFlags = "Success,Failure"
    )
    # Set default output to $false.
    $AuditPoliciesCorrect = $false

    # Check if the folder path is provided
    if (-not $FolderPath) {
        Write-Host "Please provide a folder path."
        return
    }

    # Check if the folder exists
    if (-not (Test-Path -Path $FolderPath -PathType Container)) {
        Write-Host "The specified folder does not exist." -ForegroundColor Red
        return
    }

    try {
        # Get the current audit settings for the folder
        $CurrentAuditSettings = (Get-Acl -Path "$FolderPath" -Audit).GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        # Define the expected audit settings
        $ExpectedAuditSettings = @{
            FileSystemRights = "ExecuteFile, DeleteSubdirectoriesAndFiles, Write, Delete, ChangePermissions, TakeOwnership"
        }

        # Check if the expected audit settings match the current audit settings.
        if ($CurrentAuditSettings.FileSystemRights -eq $ExpectedAuditSettings.FileSystemRights) {
            $AuditPoliciesCorrect = $true
        }
    } catch {
        Write-Host "Error: $_"
    }
    $AuditPoliciesCorrect
# End of the Test-FolderAuditPolicy function.
}

function Remove-AdPowerAdmin {
    <#
    .SYNOPSIS
    A function to remove the AD-PowerAdmin script.

    .DESCRIPTION
    This function does a partial uninstall of the AD-PowerAdmin script.
    - Remove the AD-PowerAdmin schedule task.
    - Remove the sMSA account.
    - Remove the sMSA account from the "login as a service" setting in the "Default Domain Controllers Policy" GPO.
    - Remove the AD-PowerAdmin home directory.
    !NOTE!: YES, this will delete the AD-PowerAdmin script and all of its files! But you will be asked to confirm this action.

    What is not removed:
    - The system audit policy is not changed.
    - DSInternals is not removed.

    .EXAMPLE
    Remove-AdPowerAdmin

    .NOTES

    #>

    # ---------- Remove the AD-PowerAdmin schedule task ----------
    [string]$TaskName = "AD-PowerAdmin_Daily"
    # Check if the AD-PowerAdmin_Daily schedule task exists.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin schedule task exists, then delete the existing schedule task.
        Write-Host "Deleting the existing AD-PowerAdmin schedule task." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
    }

    # ---------- Remove the AD-PowerAdmin_GPO GPO ----------
    Set-ADPowerAdminGPO -Uninstall

    # ---------- Remove the AD-PowerAdmin sMSA account ----------
    # Check if the AD-PowerAdmin_MSA account exists.
    if (Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin_MSA account exists, then delete the existing sMSA account.
        Write-Host "Deleting the existing AD-PowerAdmin_MSA account." -ForegroundColor Yellow
        Remove-ADServiceAccount -Identity "$global:MsaAccountName" -Confirm:$false
    }

    # Ask the user if they want to delete the AD-PowerAdmin home directory.
    $DeleteHomeDirectory = Read-Host "Do you want to delete the AD-PowerAdmin home directory? (Y/N)"
    # If the user does not want to delete the AD-PowerAdmin home directory, then exit the function.
    if ($DeleteHomeDirectory -ne 'Y' -or $DeleteHomeDirectory -ne 'y') {
        # Check if the AD-PowerAdmin home directory exists at C:\Scripts\AD-PowerAdmin, if it exists then delete it.
        if (Test-Path -Path "$global:InstallDirectory") {
            Write-Host "Deleting the existing AD-PowerAdmin home directory." -ForegroundColor Yellow
            Remove-Item -Path "$global:InstallDirectory" -Recurse -Force
        }
    }
# End of the Remove-AdPowerAdmin function.
}