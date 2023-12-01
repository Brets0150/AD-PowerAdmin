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
            Module   = "AD-PowerAdmin_Installer.psm1"
            Function = "Install-ADPowerAdmin"
            Command  = "Install-ADPowerAdmin"
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

function New-ADPowerAdminSmsaAccount {
    <#
    .SYNOPSIS
    function to create a AD-PowerAdmin sMSA account.

    .DESCRIPTION
    ---------Create the AD-PowerAdmin sMSA account needed for the Scheduled Task----------------
        Create a new Managed Service Account (MSA) for the AD-PowerAdmin schedule task. The MSA will be named "AD-PowerAdmin_MSA".
        The MSA will be created in the "Users" container and will be a member of the "Domain Admins" group.
        The MSA will be created with a random password and change ever 30-days.

    .EXAMPLE
    New-ADPowerAdminSmsaAccount

    .NOTES

    #>

    [string]$MsaAccountDescription = "AD-PowerAdmin sMSA Account"
    # Check if the AD-PowerAdmin_MSA account already exists.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'"
    # Check if the "$global:MsaAccountName" sMSA account already exists. If it does not exist, then create the sMSA account.
    if ($null -eq $MsaIdentity) {
        # Try to run the New-ADServiceAccount command. If the command fails, then display an error and exit the function.
        try {
            New-ADServiceAccount -SamAccountName "$global:MsaAccountName" -Name "$global:MsaAccountName" -Description "$MsaAccountDescription" -RestrictToSingleComputer -Enabled $true
        } catch {
            Write-Host "Error: The AD-PowerAdmin sMSA account was not created." -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            break
        }
        $AdServerIdentity = Get-ADComputer -identity "$env:COMPUTERNAME"
        $MsaIdentity      = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -Properties * -ErrorAction SilentlyContinue
        Add-ADComputerServiceAccount -Identity $AdServerIdentity -ServiceAccount $MsaIdentity.sAMAccountName
        Install-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
        # Test that the sMSA account was created and this compluter is a member of the sMSA group.
        if ($null -eq $MsaIdentity) {
            Write-Host "Error: The AD-PowerAdmin sMSA account was not created." -ForegroundColor Red
            break
        }
        # Test that the sMSA account was created and this compluter is a member of the sMSA group.
        $TestAdServiceAccount = Test-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
        if (-Not $TestAdServiceAccount) {
            Write-Host "Error: The AD-PowerAdmin sMSA group was not created." -ForegroundColor Red
            break
        }
        # Add the sMSA account to the "Domain Admins" group.
        Add-ADGroupMember -Identity "Domain Admins" -Members $MsaIdentity.SamAccountName
    } else {
        # If the sMSA account already exists, then display a warning and continue.
        Write-Host "The sMSA account '$global:MsaAccountName' already exists." -ForegroundColor Yellow
    }
# End of the New-ADPowerAdminSmsaAccount function.
}

Function New-ADPowerAdminGPO {
    <#
    .SYNOPSIS
    A Function that will create a new GPO to give the AD-PowerAdmin sMSA account the "Log on as a service" right.

    .DESCRIPTION
    - A Function that will create a new GPO to give the AD-PowerAdmin sMSA account the "Log on as a service" right.
        The GPO will be named "AD-PowerAdmin_GPO".
        The GPO will be linked to the "Domain Controllers" OU.
        The GPO will be created with a random password and change ever 30-days.

    .EXAMPLE
    New-ADPowerAdminGPO

    .NOTES
    The GPO will be created with a random password and change ever 30-days.

    #>

    # Get domain controller to run all commands against
    [object]$DomainContollerServer = Get-ADDomainController
    # Get the Active Directory root DNS domain name.
    [object]$DnsRootDomainName = Get-ADDomain -Identity $DomainContollerServer.Domain | Select-Object -Property DNSRoot
    # \\localhost\SYSVOL\domain.loc\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
    [string]$GpoCfgFile = "\\$($DnsRootDomainName.DNSRoot)\SYSVOL\$($DnsRootDomainName.DNSRoot)\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    # Check it $GpoCfgFile exists.
    if (-Not (Test-Path -Path "$GpoCfgFile")) {
        Write-Host "Error: The GPO configuration file '$GpoCfgFile' does not exist." -ForegroundColor Red
        break
    }
    # Get content of the $GpoCfgFile. Maintain the line breaks.
    [string]$GpoCfgFileContent = Get-Content -Path $GpoCfgFile -Raw
    # Check if the $GpoCfgFileContent contains the "SeServiceLogonRight" line.
    if ($GpoCfgFileContent -notmatch "SeServiceLogonRight") {
        Write-Host "Warrning: The GPO configuration file '$GpoCfgFile' does not contain the 'SeServiceLogonRight' line." -ForegroundColor Yellow
    }
    $SID = Get-ADServiceAccount -Identity "$global:MsaAccountName`$" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue
    # Check if the $SID is null.
    if ($null -eq $SID) {
        Write-Host "Error: The SID for the sMSA account '$global:MsaAccountName' was not found." -ForegroundColor Red
        break
    }
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
# End of the New-ADPowerAdminGPO function.
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

    # ---------- Create the AD-PowerAdmin schedule task ----------
    [string]$TaskName = "AD-PowerAdmin_Daily"
    # Set ScheduleRunTime to be tomorrow at 9:00 AM.
    [datetime]$ScheduleRunTime = (Get-Date).AddDays(1).Date + "09:00:00"
    [string]$TaskDiscription = "AD-PowerAdmin Daily Tasks"
    [string]$ThisScriptsFullName = "$global:ThisScript"
    # Check if the AD-PowerAdmin_Daily schedule task already exists.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin schedule task already exists, then ask the user if they want to overwrite the existing schedule task.
        Write-Host "The AD-PowerAdmin schedule task already exists." -ForegroundColor Yellow
        $OverwriteScheduleTask = Read-Host "Do you want to overwrite the existing schedule task? (Y/N)"
        # If the user does not want to overwrite the existing schedule task, then exit the function.
        if ($OverwriteScheduleTask -ne 'Y') {
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

function Install-ADPowerAdmin {
    <#
    .SYNOPSIS
    A function to install the AD-PowerAdmin script to run daily as a scheduled task.

    .DESCRIPTION
    Install the AD-PowerAdmin script to run daily tasks as a scheduled task.

    The install will:
    - Create the AD-PowerAdmin sMSA account needed for the Scheduled Task
        Create a new Managed Service Account (MSA) for the AD-PowerAdmin schedule task. The MSA will be named "AD-PowerAdmin_MSA".
        The MSA will be created in the "Users" container and will be a member of the "Domain Admins" group.
        The MSA will be created with a random password and change ever 30-days.

    - Create a new GPO to give the AD-PowerAdmin sMSA account the "Log on as a service" right.
        The GPO will be named "AD-PowerAdmin_GPO".
        The GPO will be linked to the "Domain Controllers" OU.
        The GPO will be created with a random password and change ever 30-days.

    - Create a AD-PowerAdmin Schduled daily task.
        The task will be named "AD-PowerAdmin_Daily".
        The task will run the AD-PowerAdmin script daily at 9:00 AM.
        The task will run the AD-PowerAdmin script with the "-Unattended" and "-JobName 'Daily'" parameters.

    .EXAMPLE
    Install-ADPowerAdmin

    .NOTES

    #>
    # Create a ADPowerAdmMSA account with domain admin rights.
    New-ADPowerAdminSmsaAccount
    # Create a new GPO to give the sMSA account the "Log on as a service" right.
    New-ADPowerAdminGPO
    # Create a new scheduled task to run the AD-PowerAdmin script daily.
    New-ADPowerAdminScheduledTask
    # Install the DSInternals PowerShell module.
    Install-DSInternals
# End of the Install-ADPowerAdmin function.
}