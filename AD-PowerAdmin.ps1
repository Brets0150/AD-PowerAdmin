#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    A collection of functions to help manage, and harden Windows Active Directory.

.DESCRIPTION
    AD-PowerAdmin is a tool to help Active Directory administrators secure and manage their AD.
    Automating security checks ranging from User and Computer cleanup, password audits,
    security misconfiguration audits, and much more. The core philosophy is to automate daily testing
    of AD security and email when there is an issue. This tool focuses on common weaknesses,
    and attack-vectors adversaries use and defends against them.

.EXAMPLE
    PS> git clone https://github.com/Brets0150/AD-PowerAdmin.git
    PS> cd AD-PowerAdmin
    # Edit the config file "AD-PowerAdmin_settings.ps1" to your liking.
    PS> .\AD-PowerAdmin.ps1

.LINK
    https://github.com/Brets0150/AD-PowerAdmin

.NOTES
    Author: Bret.s AKA: CyberGladius / License: MIT

    AD-PowerAdmin Change Log:
        - v1.0.2 Alpha - 11/21/23: Total rewrite of the script. The script is now modular and can be expanded easily.
            - All original funcions migrated to the new framework.
            - Way too many changes to list here.
            - Still Alpha, but getting close to Beta.
        - v1.0.3 Alpha - 1/2/2024:
            - Changed the debug logging managent process. I needed a way to save the console output from sub-functions for reports, so I had to change the way debug logging was handled, which lead debugging being its own funciton.
            - Updated PowerShell version check to to be acurate when using PowerShell Remote(WinRM).
        - 1.0.3 Beta - 1/23/2024:
            - Moving to Beta, with soft deploy to production.
#>

#=======================================================================================
# Global Variables and Settings.
[CmdletBinding(DefaultParametersetName='None')]
Param (
    [Parameter(ParameterSetName='Unattend',Mandatory=$true)][switch]$Unattended,
    [Parameter(ParameterSetName='Unattend',Mandatory=$true)][string]$JobName,
    [Parameter(ParameterSetName='Unattend',Mandatory=$false)][string]$JobVar1
)

# Get this files full path and name(C:\Scripts\AD-PowerAdmin\AD-PowerAdmin.ps1) and put it in a variable.
[string]$global:ThisScript = ([io.fileinfo]$MyInvocation.MyCommand.Definition).FullName

# Parse the $global:ThisScript variable to get the directory path without the script name(C:\Scripts\AD-PowerAdmin).
[string]$global:ThisScriptDir = $global:ThisScript.Split("\\")[0..($global:ThisScript.Split("\\").Count - 2)] -join "\\"

# Get this scripts name(AD-PowerAdmin.ps1) and put it in a variable.
[string]$global:ThisScriptsName = $global:ThisScript.Split("\\")[-1]

# Set Module path
[string]$global:ModulesPath = "$global:ThisScriptDir\\Modules"

# Rename the terminal window, cuz it looks cool. =P
$host.UI.RawUI.WindowTitle = "AD-PowerAdmin - CyberGladius.com"

# Version of this script.
[string]$global:Version = "1.0.3 Beta"

# Max character length of the menu options.
[int]$global:OptionsMaxTextLength = 82

# Set the Menu variable to be used later.
[PSCustomObject]$global:Menu = @{}

# Set the $global:UnattendedJobs variable to be used later.
[PSCustomObject]$global:UnattendedJobs = @{}

#=======================================================================================
# Start Local Functions Section

function Show-Logo {
    <#
    .SYNOPSIS
    Function that will output this scripts logo or the main menu.
    #>
    Write-Host "
====================================================================================
      ______      __                 ________          ___
     / ____/_  __/ /_  ___  _____   / ____/ /___ _____/ (_)_  _______
    / /   / / / / __ \/ _ \/ ___/  / / __/ / __ ``/ __  / / / / / ___/
   / /___/ /_/ / /_/ /  __/ /     / /_/ / / /_/ / /_/ / / /_/ (__  )
   \____/\__, /_.___/\___/_/      \____/_/\__,_/\__,_/_/\__,_/____/
        /____/   Presents
      ___    ____        ____                          ___       __          _
     /   |  / __ \      / __ \____ _      _____  _____/   | ____/ /___ ___  (_)___
    / /| | / / / /_____/ /_/ / __ \ | /| / / _ \/ ___/ /| |/ __  / __ ``__ \/ / __ \
   / ___ |/ /_/ /_____/ ____/ /_/ / |/ |/ /  __/ /  / ___ / /_/ / / / / / / / / / /
  /_/  |_/_____/     /_/    \____/|__/|__/\___/_/  /_/  |_\__,_/_/ /_/ /_/_/_/ /_/
  Version: $global:Version
====================================================================================

" -ForegroundColor Cyan
}

function Initialize-Debug {
    <#
    .SYNOPSIS
    Function that will check the $global:Debug variable, if set to true start a transcript for the whole session.
    This function is called at the beginning of the begining of the script and the Enter-MainMenu function. Some other
        function need to call a start-transcript; breaking the main transcript. This function will check if a transcript
        is already running, if not, restart the debug transcript.
    #>

    # Check if a transcript is already running.
    try {
        Get-Transcript | Out-Null
        $TranscriptRunning = $true
    } catch {
        $TranscriptRunning = $false
    }

    # If the transcript is not running, check if it should be running, if so, start it.
    if (!$TranscriptRunning) {
        # No transcript is currently running.
        if ($global:Debug) {
            Start-Transcript -Path "$global:ThisScriptDir\\AD-PowerAdmin_Debug.log" -Append -Force | Out-Null
        }
    }

    return
# End of Initialize-Debug function.
}

function Initialize-AllModules {
    # Try to import the models from the Modules folder and catch any errors.
    try {
        # We only want to import the module manifests. This ensures the modules are loaded in the correct order and only things we want are loaded.
        # Do not change this to import the modules directly(".psm1"). Don't be lazy, write the module manifest.
        Get-ChildItem -Path $global:ModulesPath -Filter *.psd1 | ForEach-Object {Import-Module "$global:ModulesPath\\$($_.Name)" -Force -Verbose}
        clear-host
    } catch {
        Write-Host "Error: Could not import the modules from the Modules folder.
        Please ensure that the script is being run from a PowerShell prompt (i.e. not from a script or batch file).
        The Modules folder needs to be located in the same directory as the main AD-PowerAdmin.ps1 file, in the `"Modules`" folder" -ForegroundColor Red
        exit 1
    }
}

function Initialize-ADPowerAdmin {
    <#

    .SYNOPSIS
    This function will check if all the base requirements are met to run this script.
        This code is pretty straight forward.

    #>

    # Check if the script is running with PowerShell version 5 or higher.
    # If not, throw an error and exit.
    if ($PSVersionTable.PSVersion.Major -lt 5){
        Write-Output "This script requires PowerShell 5 or higher."
        Write-Output "Your PowerShell version is $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor).$($PSVersionTable.PSVersion.Build).$($PSVersionTable.PSVersion.Revision)"
        Write-Output "Your '`$PSVersionTable Results:'"
        $PSVersionTable
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

    # If debug, $global:Debug, is true, Start-Transcript will be called.
    Initialize-Debug

    # Import all the modules from the Modules folder.
    Initialize-AllModules

# End of Initialize-ADPowerAdmin function.
}

function Start-Automation {
    <#

    .SYNOPSIS
    Function that will build the main menu from the $global:Menu variable defined in each module. The $global:Menu variable is populated by the Initialize-Module function in each module.
    The user will select a action from the menu and the function that is associated with the action will be run.

    .DESCRIPTION
    This function will build the main menu from the $global:Menu variable defined in each module. The $global:Menu variable is populated by the Initialize-Module function in each module.
    The user will select a action from the menu and the function that is associated with the action will be run.

    .PARAMETER Unattended
    This is a switch parameter that is used to run the script in unattended mode.
    When this parameter is used, the script will not display the main menu and will run the function that is associated with the $JobName parameter.

    .PARAMETER JobName
    This is a string parameter that is used to run the script in unattended mode.
    The JobName parameter is used to select the function/Command that will be run when the script is run in unattended mode.
    Unattended jobs are configured in the Initialize-Module function in each module.

    .PARAMETER JobVar1
    This is a string parameter that is passed to the function that is associated with the $JobName parameter.

    .EXAMPLE
    PS> Start-Automation -Unattended -JobName "Test" -JobVar1 "Test"

    .Notes

    #>

    [CmdletBinding(DefaultParametersetName='None')]
    Param (
        [Parameter(ParameterSetName='Unattend',Mandatory=$true)][switch]$Unattended,
        [Parameter(ParameterSetName='Unattend',Mandatory=$true)][string]$JobName,
        [Parameter(ParameterSetName='Unattend',Mandatory=$false)][string]$JobVar1
    )

    # Check is a JobName was passed, if not, display error messga can exit.
    if ($JobName -eq $null) {
        Write-Host "Error: No JobName was passed to the script. Unattended mode can only be used with a JobName."
        Exit 1
    }

    # Foreach value in the $global:UnattendedJobs variable, build a new PowerShell object and add the value to the object.
    # The $global:UnattendedJobs variable is populated by the Initialize-Module function in each module.
    [array]$UnattendedJobObjects = @()
    foreach ($UnattendedJob in $global:UnattendedJobs.GetEnumerator()) {
        # Create a new object to store the menu item.
        [object]$UnattendedJobObject = New-Object -TypeName PSObject
        # Add the menu index value to the object.
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "JobName" -Value $UnattendedJob.Name
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "Title" -Value $UnattendedJob.Value.Title
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "Label" -Value $UnattendedJob.Value.Label
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "Module" -Value $UnattendedJob.Value.Module
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "Function" -Value $UnattendedJob.Value.Function
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "Daily" -Value $UnattendedJob.Value.Daily
        $UnattendedJobObject | Add-Member -MemberType NoteProperty -Name "Command" -Value $UnattendedJob.Value.Command
        # Add the object to the $MenuObjects variable.
        $UnattendedJobObjects += $UnattendedJobObject
    }

    # if JobName is "Daily", then run the Start-DailyADTacks functions.
    if ($JobName -eq "Daily") {
        # Foreach item in the $global:UnattendedJobs variable, if the item has a Daily value of $true, run the Command that is associated with the item.
        $UnattendedJobObjects | ForEach-Object {
            if ($_.Daily -eq $true) {
                # Run the function that is associated with the $MenuObjects.MenuIndex; $MenuObjects.FunctionName.
                Invoke-Expression $_.Command
            }
        }
        return
    }

    # Foreach JobName in the $UnattendedJobsObject, if the JobName matches the $JobName variable, run the Command that is associated with the JobName.
    $UnattendedJobObjects | ForEach-Object {
        if ($_.JobName -eq $JobName) {
            Write-Host "Running $($_.Title) - $($_.Label)" -ForegroundColor Green

            # If the $JobVar1 variable is not null, add it to the Command.
            if ($null -ne $JobVar1) {
                $_.Command = "$($_.Command) -JobVar1 `"$JobVar1`""
            }
            # Run the function that is associated with the $MenuObjects.MenuIndex; $MenuObjects.FunctionName.
            Invoke-Expression $_.Command -ErrorAction:SilentlyContinue
        }
    }
# End of Start-Automation function.
}

function Enter-MainMenu {
    <#
    .SYNOPSIS
    Function that will build the main menu from the $global:Menu variable defined in each module. The $global:Menu variable is populated by the Initialize-Module function in each module.
    The user will select a action from the menu and the function that is associated with the action will be run.

    .DESCRIPTION
    This function will build the main menu from the $global:Menu variable defined in each module. The $global:Menu variable is populated by the Initialize-Module function in each module.
    The user will select a action from the menu and the function that is associated with the action will be run.

    .EXAMPLE
    Enter-MainMenu

    .Notes

    #>

    # Confirm debug is running if enabled. Some function need to call a start-transcript; breaking the main transcript.
    #  This function will check if a transcript is already running, if not, restart the debug transcript.
    Initialize-Debug

    # Call the Show-Logo function to display the logo.
    Clear-Host
    Show-Logo

    [array]$MenuObjects = @()
    [int]$MenuIndex = 0
    # Track the max length of the menu options to make the menu look nice.
    [int]$OptionsMaxTextLength = 0

    # Build a user select menu from the $global:Menu variable. Foreach item in the $global:Menu variable, create a number for the user to select, next to the number display the "FunctionName" ' -- ' "Label".
    # The $global:Menu variable is populated by the Initialize-Module function in each module.
    foreach ( $MenuItem in $( $global:Menu.GetEnumerator() | Sort-Object {$_.Value.Title} ) ) {
        # Increment the menu number counter by 1.
        $MenuIndex++
        # Create a new object to store the menu item.
        [object]$MenuItemObject = New-Object -TypeName PSObject
        # Add the menu index value to the object.
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "MenuIndex" -Value $MenuIndex
        # Add the menu item to the object.
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "Function" -Value $MenuItem.Value.Function
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "Title" -Value $MenuItem.Value.Title
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "Module" -Value $MenuItem.Value.Module
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "Label" -Value $MenuItem.Value.Label
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "Command" -Value $MenuItem.Value.Command

        # Get the length of Title and the MenuIndex combined.
        [int]$TitleLength = $MenuItemObject.Title.Length + $MenuItemObject.MenuIndex.ToString().Length
        $MenuItemObject | Add-Member -MemberType NoteProperty -Name "TitleLength" -Value $TitleLength

        # If it is longer than the $OptionsTextLength variable, set the $OptionsTextLength variable to the new length.
        if ($TitleLength -gt $OptionsMaxTextLength) {
            $OptionsMaxTextLength = ($MenuItemObject.Title.Length + $MenuItemObject.MenuIndex.ToString().Length)
        }

        # Add the object to the $MenuObjects variable.
        $MenuObjects += $MenuItemObject
    }
    # Set the $MaxLabelLength variable to the $global:OptionsMaxTextLength - $OptionsMaxTextLength to make the menu look nice.
    $MaxLabelLength = $global:OptionsMaxTextLength - $OptionsMaxTextLength

    # Foreach item in the $global:MenuObjects variable, increment the $MenuNumber counter by 1 and output the $MenuNumber $_.Values.FunctionName $_.Values.Label
    $MenuObjects | ForEach-Object {

        # Compute the $_.TitleLength - $OptionsMaxTextLength and add that many spaces to the end of the $_.Title.
        [int]$SpacesToAdd = $OptionsMaxTextLength - $_.TitleLength
        [string]$Spaces = " " * $SpacesToAdd
        $_.Title = "$($_.Title)$Spaces"

        # While the lenght of $_.Label if longer than 46 characters, divide the string at the closest space to the 46th character and add a newline and add $OptionsMaxTextLength spaces.
        # Repeat until the string is less than 46 characters.
        while ($_.Label.Length -gt $MaxLabelLength) {
            [int]$SpaceIndex = $_.Label.Substring(0,$MaxLabelLength).LastIndexOf(" ")
            [int]$SpacesToAdd = $OptionsMaxTextLength + 3
            [string]$Spaces = " " * $SpacesToAdd
            # Count the number of characters in the substring.
            [int]$SubstringLength = $_.Label.Substring(0,$SpaceIndex).Length
            [string]$NewLabel += "$($_.Label.Substring(0,$SpaceIndex))`n$Spaces"
            # Remove the substring from the label.
            $_.Label = $_.Label.Remove(0,$SubstringLength)
        }
        # If the length of the $_.Label is less than 46 characters, then $NewLabel = $_.Label.
        if ($_.Label.Length -lt $MaxLabelLength) {
            $NewLabel += $_.Label
        }

        # Output the $MenuNumber $_.Values.FunctionName $_.Values.Label
        Write-Host "$($_.MenuIndex). $($_.Title)" -ForegroundColor Green -NoNewline;
        Write-Host " -$NewLabel"
        $NewLabel = $null
    }

    Write-Host ""
    Write-Host "=================================================================================="
    Write-Host "h. Help"
    Write-Host "q. Quit"
    Write-Host "=================================================================================="
    Write-Host ""

    # Ask the user to input a number from the menu. The selected number will be stored in the $MenuChoice variable.
    [string]$MenuChoice = Read-Host "Input the job # you want to run"

    # The $MenuChoice variable needs to equal a $MenuObjects.MenuIndex value. If the $MenuChoice variable does not equal a $MenuObjects.MenuIndex value, display an error message and exit the script.
    # If the $MenuChoice variable does equal a $MenuObjects.MenuIndex value, run the function that is associated with the $MenuObjects.MenuIndex; $MenuObjects.FunctionName.
    [Int32]$OutNumber = $null
    if ([Int32]::TryParse($MenuChoice,[ref]$OutNumber)) {
        #
        if ($MenuChoice -in $MenuObjects.MenuIndex) {
            Write-Host "==================================================================================" -ForegroundColor Green
            # Get the $MenuObjects.FunctionName value that matches the $MenuChoice variable.
            $SelectedOption = $MenuObjects | Where-Object {$_.MenuIndex -eq $MenuChoice} | Select-Object -ExpandProperty Command
            # Run the function that is associated with the $MenuObjects.MenuIndex; $MenuObjects.FunctionName.
            Invoke-Expression "$SelectedOption"
            Write-Host "==================================================================================" -ForegroundColor Green
        }

        # If the $MenuChoise is a number but not one in the $MenuObjects.MenuIndex then display an error message.
        if ($MenuChoice -notin $MenuObjects.MenuIndex) {
            # Display an error message and exit the script.
            Write-Host "Error: Invalid selection. Please select a number from the menu." -ForegroundColor Red
        }
    }

    # If the $MenuChoise is "q" then exit the script.
    if ($MenuChoice -eq "q") {
        Write-Host "Exiting..." -ForegroundColor Yellow
        return
    }

    # If the $MenuChoise is "h" ask the user to input a number from the menu. The selected number will be stored in the $MenuChoice variable, then get that functions .DISCRIPTION and output it to the screen.
    if ($MenuChoice -eq "h") {
        # Ask the user to input a number from the menu. The selected number will be stored in the $MenuChoice variable.
        [string]$MenuChoice = Read-Host "Job # you want help with"
        $SelectedFunction = $MenuObjects | Where-Object {$_.MenuIndex -eq $MenuChoice} | Select-Object -ExpandProperty Function
        $Help = Get-Help -Name $SelectedFunction -Full
        $Help.DESCRIPTION
    }

    Pause
    Enter-MainMenu
}

# End Local Functions Section
#=======================================================================================
# Main Script Section
#=======================================================================================

# Initialize the script.
Initialize-ADPowerAdmin

# Run the Start-Automation function if the script is running in unattended mode.
if ($Unattended) {
    Start-Automation -Unattended -JobName $JobName -JobVar1 $JobVar1
}

# If the script is not running in unattended mode, run the Enter-MainMenu function.
if (!$Unattended) {
    Enter-MainMenu
}

# If debug, $global:Debug, is true, Stop-Transcript will be called.
if ($global:Debug) {
    Stop-Transcript -ErrorAction:SilentlyContinue | Out-Null
}

# End of Script
#=======================================================================================
exit 0