#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory
# NOTE: If launched under PowerShell 5, modules that require PowerShell 7 are automatically excluded.

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
        - 1.2.0 Production - 9/18/2024:
            - Added new versioning method to include module versions.
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

# Set the reports folder path.
[string]$global:ReportsPath = "$global:ThisScriptDir\\Reports"

# Rename the terminal window, cuz it looks cool. =P
$host.UI.RawUI.WindowTitle = "AD-PowerAdmin - CyberGladius.com"

# Version of this script.
[System.Version]$global:Version = "1.2.0"

# Max character length of the menu options.
[int]$global:OptionsMaxTextLength = 82

# Set the Menu variable to be used later.
[PSCustomObject]$global:Menu = @{}

# Set the $global:UnattendedJobs variable to be used later.
[PSCustomObject]$global:UnattendedJobs = @{}

# Registry of submenus contributed by modules. Modules register here in Initialize-Module;
# Enter-SubMenu dispatches from this table. Same self-registration pattern as $global:Menu.
[hashtable]$global:SubMenus = @{}

# Modules present in the Modules folder but skipped at load time due to a PS version
# requirement that exceeds the current session. Populated by Get-IncompatibleModules.
[array]$global:IncompatibleModules = @()

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
    / /   / / / / __ \/ _ \/ ___/  / / __/ / __ |  __  / / / / / ___/
   / /___/ /_/ / /_/ /  __/ /     / /_/ / / /_/ / /_/ / / /_/ (__  )
   \____/\__, /_.___/\___/_/      \____/_/\__,_/\__,_/_/\__,_/____/
        /____/   Presents
      ___    ____        ____                          ___       __          _
     /   |  / __ \      / __ \____ _      _____  _____/   | ____/ /___ ___  (_)___
    / /| | / / / /_____/ /_/ / __ \ | /| / / _ \/ ___/ /| |/ __  / __ -__ \/ / __ \
   / ___ |/ /_/ /_____/ ____/ /_/ / |/ |/ /  __/ /  / ___ / /_/ / / / / / / / / / /
  /_/  |_/_____/     /_/    \____/|__/|__/\___/_/  /_/  |_\__,_/_/ /_/ /_/_/_/ /_/
  Version: $(Get-ADPAVersion)
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
    # Get-Transcript is absent from some Server 2016 PS 5.1 builds, so wrap it. When
    # present it returns $null (PS 5.1) or empty string (PS 7) when no transcript is
    # active -- it does NOT throw, so IsNullOrWhiteSpace is the correct test.
    $TranscriptRunning = $false
    try {
        $TranscriptRunning = -not [string]::IsNullOrWhiteSpace((Get-Transcript -ErrorAction Stop))
    } catch { }

    # If the transcript is not running, check if it should be running, if so, start it.
    if (!$TranscriptRunning) {
        # No transcript is currently running.
        if ($global:Debug) {
            Start-Transcript -Path "$global:ReportsPath\\AD-PowerAdmin_Debug.log" -Append -Force | Out-Null
        }
    }

    return
# End of Initialize-Debug function.
}

function Initialize-UnattendedLog {
    <#
    .SYNOPSIS
    Ensures the dedicated unattended-task log transcript is running.
    Idempotent: if the unattended log is already the active transcript, does nothing.
    If a different transcript is running (e.g., the debug log), stops it quietly and
    starts the unattended log. If no transcript is running, starts the unattended log.
    No-op when $global:UnattendedLog is $false.
    #>
    if (-not $global:UnattendedLog) { return }

    $currentTranscript = $null
    try {
        $currentTranscript = Get-Transcript
    } catch { }

    # If the unattended log is already the active transcript, nothing to do.
    if ($currentTranscript -and ($currentTranscript -like "*AD-PowerAdmin_Unattended.log")) {
        return
    }

    # Stop any other running transcript (e.g., the debug log). Suppress the
    # return-value string so it is not buffered into the new transcript.
    if ($currentTranscript) {
        Stop-AllTranscripts | Out-Null
    }

    # Start the dedicated unattended log.
    Start-Transcript -Path "$global:ReportsPath\AD-PowerAdmin_Unattended.log" -Append -Force | Out-Null
# End of Initialize-UnattendedLog function.
}

Function Get-ADPAVersion {
    <#
    .SYNOPSIS
        Function that will output the version of this script.

    .Discrption
        This funciton will take Count all the module .psd1 files in the Modules folder, get each modules version(ModuleVersion), add those version numbers up into a X.X, then add X.X to this scripts version numbers last two digits.

    .EXAMPLE
        PS> Get-ADPAVersion
    #>
    # Parameters, A flag can be passed which will output the loaded modules, their versions and Channel.
    [CmdletBinding()]
    Param (
        [switch]$Detailed
    )

    $Modules = Get-ChildItem -Path $global:ModulesPath -Filter *.psd1
    [float]$Version = 0
    Get-Content -Path $Modules.FullName | Select-String -Pattern "ModuleVersion" | ForEach-Object {
        $Version += ($_.ToString()).Split('=')[1].Trim().Trim("'")
    }
    $CumulativeModuleVersion = [System.Version]$Version
    [System.Version]$OverallVersion = "$($global:Version.Major).$($global:Version.Minor + $CumulativeModuleVersion.Major).$($global:Version.Build + $CumulativeModuleVersion.Minor)"

    # Initialize the OverallChannel variable with a default value
    $OverallChannel = "Unknown"

    # Check the file contect for the "Channel" line, and use the lowest channel as the overall channel. Alpha < Beta < Production.
    Get-Content -Path $Modules.FullName | Select-String -Pattern "Channel" | Select-String -Pattern "=" | ForEach-Object {
        $ChannelLine = $_
        if ($ChannelLine) {
            $Channel = ($ChannelLine.ToString()).Split('=')[1].Trim().Trim("'")
            if ($Channel -eq "Alpha") {
                $OverallChannel = "Alpha"
            }
            if ($Channel -eq "Beta" -and $OverallChannel -ne "Alpha") {
                $OverallChannel = "Beta"
            }
            if ($Channel -eq "Production" -and $OverallChannel -ne "Alpha" -and $OverallChannel -ne "Beta") {
                $OverallChannel = "Production"
            }
        }
    }

    if ($Detailed) {
        Write-Host "AD-PowerAdmin Version: $($OverallVersion) - $($OverallChannel)" -ForegroundColor Green
        Write-Host "Modules Version: $($CumulativeModuleVersion) - $($OverallChannel)" -ForegroundColor Green
        Write-Host "Modules Loaded: $($Modules.Count)" -ForegroundColor Green
        # Create a custom PSObject to store the module name, version, and channel.
        $ModulesDetails = @()

        $Modules | ForEach-Object {
            $ModuleVersion = (Get-Content -Path $_.FullName | Select-String -Pattern "ModuleVersion" | Select-String -Pattern "=" ).ToString().Split('=')[1].Trim().Trim("'")
            $ChannelLine = Get-Content -Path $_.FullName | Select-String -Pattern "Channel" | Select-String -Pattern "="
            if ($ChannelLine) {
                $ModuleChannel = $ChannelLine.ToString().Split('=')[1].Trim().Trim("'")
            } else {
                $ModuleChannel = "Unknown"
            }
            # Add the module name, version, and channel to the $ModulesDetails array.
            $ModulesDetails += [PSCustomObject]@{
                Name = $_.Name
                Version = $ModuleVersion
                Channel = $ModuleChannel
            }
        }
        $ModulesDetails | Format-Table -AutoSize
    }

    return $OverallVersion, $OverallChannel
}

Function Show-Diagnostics {
    <#
    .SYNOPSIS
    Function that will output diagnostic information about the script and its environment.

    .DESCRIPTION
    This function will gather and display information about the script's environment, including
    the PowerShell version, the operating system, and any relevant environment variables.

    .EXAMPLE
    Show-Diagnostics

    .NOTES

    #>

    Write-Host "AD-PowerAdmin Diagnostics" -ForegroundColor Cyan
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "AD-PowerAdmin Script Version: $($global:Version)" -ForegroundColor White
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor White
    Write-Host "Operating System: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor White
    Write-Host "Current User: $($env:USERNAME)" -ForegroundColor White
    Write-Host "Script Directory: $($PSScriptRoot)" -ForegroundColor White
    Write-Host "Modules Path: $($global:ModulesPath)" -ForegroundColor White
    Write-Host "----------------------------------------" -ForegroundColor Cyan
    Write-Host "Loaded Modules:" -ForegroundColor Cyan
    Get-ADPAVersion -Detailed

    return
}

Function Show-Credits {
    <#
    .SYNOPSIS
    Display third-party tool and code attribution for AD-PowerAdmin.

    .DESCRIPTION
    Lists every external tool, module, or code extract that AD-PowerAdmin depends on
    or embeds, along with the author's name and project URL.

    .EXAMPLE
    Show-Credits
    #>

    Write-Host ""
    Write-Host "AD-PowerAdmin -- Third-Party Credits" -ForegroundColor Cyan
    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "AD-PowerAdmin is made possible in part by the following third-party works." -ForegroundColor White
    Write-Host "Thank you to the authors for their contributions to the community." -ForegroundColor White
    Write-Host ""

    Write-Host "DSInternals" -ForegroundColor Green
    Write-Host "  Author : Michal Grafnetter" -ForegroundColor White
    Write-Host "  Purpose: Password quality auditing, KRBTGT key rotation, and AD replication" -ForegroundColor White
    Write-Host "           data extraction used by the Password Management module." -ForegroundColor White
    Write-Host "  URL    : https://github.com/MichaelGrafnetter/DSInternals" -ForegroundColor White
    Write-Host ""

    Write-Host "Have I Been Pwned (HIBP) Pwned Passwords API" -ForegroundColor Green
    Write-Host "  Author : Troy Hunt" -ForegroundColor White
    Write-Host "  Purpose: Breach password detection via NTLM hash range lookups." -ForegroundColor White
    Write-Host "           Used by the HIBP Password Manager module to flag compromised" -ForegroundColor White
    Write-Host "           AD passwords against the HIBP breach database." -ForegroundColor White
    Write-Host "  URL    : https://haveibeenpwned.com" -ForegroundColor White
    Write-Host ""

    Write-Host "Weak Passwords List" -ForegroundColor Green
    Write-Host "  Source : weakpasswords.net" -ForegroundColor White
    Write-Host "  Purpose: Plain-text dictionary of commonly used weak passwords." -ForegroundColor White
    Write-Host "           Used alongside HIBP data to identify trivially guessable" -ForegroundColor White
    Write-Host "           AD account passwords during password audits." -ForegroundColor White
    Write-Host "  URL    : https://weakpasswords.net" -ForegroundColor White
    Write-Host ""

    Write-Host "Calendar GUI Widget (Calendar v1.0.0)" -ForegroundColor Green
    Write-Host "  Source : PowerShell Gallery" -ForegroundColor White
    Write-Host "  Purpose: Interactive date-picker widget embedded in the Utils module" -ForegroundColor White
    Write-Host "           and used for scheduling and date-input functions." -ForegroundColor White
    Write-Host "  URL    : https://www.powershellgallery.com/packages/Calendar/1.0.0" -ForegroundColor White
    Write-Host ""

    Write-Host "PoShEvents (v0.2.1)" -ForegroundColor Green
    Write-Host "  Author : Jason Walker" -ForegroundColor White
    Write-Host "  Purpose: Logon failure reason mapping for Windows Security Event ID 4625." -ForegroundColor White
    Write-Host "           Code extracted and adapted for use in the Log Manager module." -ForegroundColor White
    Write-Host "  URL    : https://www.powershellgallery.com/packages/PoShEvents/0.2.1" -ForegroundColor White
    Write-Host ""

    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host ""

    return
}

function Stop-AllTranscripts {
    <#
    .SYNOPSIS
    Function that will stop all transcripts that are currently running.
    Yes, this is a bit of a hack, but it works. There is not a way to query the current transcript sessions,
        so we are forced to use a while loop to stop all transcripts. Auful, I know. I am open to suggestions on how to do this better.
    #>

    # Check if a transcript is already running.
    try {
        while ($true) {
            Stop-Transcript -ErrorAction Stop
        }
    } catch {
        # Do nothing.
        return
    }
}

function Stop-ADPowerAdmin {
    <#
    .SYNOPSIS
    Cleanly terminates the entire AD-PowerAdmin application from any menu depth.
    #>
    Write-Host "Exiting AD-PowerAdmin..." -ForegroundColor Yellow
    Stop-AllTranscripts
    exit 0
}

function Get-IncompatibleModules {
    <#
    .SYNOPSIS
        Scans the Modules folder and identifies modules whose minimum required PowerShell
        version exceeds the version of the current session.

    .DESCRIPTION
        Reads each .psd1 manifest in $global:ModulesPath via Import-PowerShellDataFile,
        extracts the PowerShellVersion field, and compares it against the running
        $PSVersionTable.PSVersion. The result is stored in $global:IncompatibleModules
        so other functions can reference it without re-scanning. When $global:Debug is
        enabled the findings are also written to the active debug transcript.
        This function does not import, alter, or remove any module.

    .OUTPUTS
        [PSCustomObject[]] Each object has:
            Name            - BaseName of the incompatible .psd1 file
            RequiredVersion - [System.Version] declared in the manifest
            CurrentVersion  - [System.Version] of the running PS session

    .EXAMPLE
        Get-IncompatibleModules
        $global:IncompatibleModules | ForEach-Object { Write-Host $_.Name }
    #>

    [array]$incompatible = @()
    [System.Version]$currentVersion = $PSVersionTable.PSVersion

    Get-ChildItem -Path $global:ModulesPath -Filter '*.psd1' | ForEach-Object {
        try {
            $manifest = Import-PowerShellDataFile -Path $_.FullName -ErrorAction Stop
            if ($manifest.PowerShellVersion) {
                [System.Version]$required = $manifest.PowerShellVersion
                if ($currentVersion -lt $required) {
                    $incompatible += [PSCustomObject]@{
                        Name            = $_.BaseName
                        RequiredVersion = $required
                        CurrentVersion  = $currentVersion
                    }
                }
            }
        } catch {
            # Manifest unreadable; treat as compatible and let Import-Module surface any error.
        }
    }

    # Persist result globally so Enter-MainMenu can display the banner without re-scanning.
    $global:IncompatibleModules = $incompatible

    # Debug transcript output. Initialize-Debug is called before Initialize-AllModules,
    # so the transcript is already active when this runs. Output is conditional on the
    # debug flag to avoid polluting the console in non-debug runs.
    if ($global:Debug) {
        if ($incompatible.Count -gt 0) {
            Write-Host "DEBUG: Module compatibility scan (PS $currentVersion) - $($incompatible.Count) module(s) skipped:" -ForegroundColor DarkYellow
            $incompatible | ForEach-Object {
                Write-Host "  DEBUG: '$($_.Name)' requires PS $($_.RequiredVersion) - not loaded in this session." -ForegroundColor DarkYellow
            }
        } else {
            Write-Host "DEBUG: Module compatibility scan (PS $currentVersion) - all modules compatible." -ForegroundColor DarkGray
        }
    }

    return $incompatible
}

function Initialize-AllModules {
    # Detect incompatible modules before loading anything. Results are stored in
    # $global:IncompatibleModules and optionally written to the debug transcript.
    Get-IncompatibleModules | Out-Null
    [array]$incompatibleNames = $global:IncompatibleModules | Select-Object -ExpandProperty Name

    # Try to import the models from the Modules folder and catch any errors.
    try {
        # We only want to import the module manifests. This ensures the modules are loaded in the correct order and only things we want are loaded.
        # Do not change this to import the modules directly(".psm1"). Don't be lazy, write the module manifest.
        Get-ChildItem -Path $global:ModulesPath -Filter *.psd1 | ForEach-Object {
            if ($incompatibleNames -contains $_.BaseName) { return }
            Import-Module "$global:ModulesPath\\$($_.Name)" -Force -Verbose
        }
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

    Stop-AllTranscripts

    # Check if the Reports folder exists, if not, create it.
    if (!(Test-Path -Path $global:ReportsPath)) {
        New-Item -Path $global:ReportsPath -ItemType Directory -Force | Out-Null
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

    # Task Scheduler passes -File script arguments as raw Windows command-line tokens.
    # Single quotes are NOT stripped by Windows argument parsing (only double quotes are),
    # so a task configured with -JobName 'HoneypotHourlyMonitor' will deliver the value
    # with literal single-quote characters. Strip any surrounding quotes before matching.
    $JobName = $JobName.Trim("'").Trim('"')

    # Start the dedicated unattended log (always on when $global:UnattendedLog is $true).
    # Falls back to the debug transcript when $global:UnattendedLog is $false.
    Initialize-UnattendedLog
    Initialize-Debug

    # Write a timestamped boundary marker so individual runs are identifiable in the log.
    Write-Host "=== Unattended Run Start: $JobName | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="

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
        Initialize-UnattendedLog
        Initialize-Debug
        Write-Host "=== Unattended Run End: $JobName | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
        Stop-AllTranscripts | Out-Null
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
            Invoke-Expression $_.Command
        }
    }

    Initialize-UnattendedLog
    Initialize-Debug
    Write-Host "=== Unattended Run End: $JobName | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
    Stop-AllTranscripts | Out-Null
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
    try { Clear-Host } catch { Write-Host ([char]27 + "[2J" + [char]27 + "[H") -NoNewline }
    Show-Logo

    # Yellow banner listing any modules that were skipped due to PS version mismatch.
    # $global:IncompatibleModules is populated by Get-IncompatibleModules during
    # Initialize-AllModules, so no re-scan is needed here.
    if ($global:IncompatibleModules.Count -gt 0) {
        Write-Host ""
        Write-Host "[!] Running under PowerShell $($PSVersionTable.PSVersion.Major). The following modules require a newer version and are not available:" -ForegroundColor Yellow
        $global:IncompatibleModules | ForEach-Object {
            Write-Host "    - $($_.Name)  (requires PS $($_.RequiredVersion))" -ForegroundColor Yellow
        }
        Write-Host "    Launch a PowerShell 7 console and run AD-PowerAdmin directly to use these modules." -ForegroundColor Yellow
        Write-Host ""
    }

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
    Write-Host "c. Credits"
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

    # If the $MenuChoice is "qq" then terminate the entire application immediately.
    if ($MenuChoice -eq "qq") {
        Stop-ADPowerAdmin
    }

    # If the $MenuChoise is "h" ask the user to input a number from the menu. The selected number will be stored in the $MenuChoice variable, then get that functions .DISCRIPTION and output it to the screen.
    if ($MenuChoice -eq "h") {
        # Ask the user to input a number from the menu. The selected number will be stored in the $MenuChoice variable.
        [string]$MenuChoice = Read-Host "Job # you want help with"
        $SelectedFunction = $MenuObjects | Where-Object {$_.MenuIndex -eq $MenuChoice} | Select-Object -ExpandProperty Function
        $Help = Get-Help -Name $SelectedFunction -Full
        $Help.DESCRIPTION
    }

        # If the user inputs 'd' then run the Show-Diagnostics function.
    if ($MenuChoice -eq "d") {
        Show-Diagnostics
    }

    # If the user inputs 'c' then display the credits screen.
    if ($MenuChoice -eq "c") {
        Show-Credits
    }

    Pause
    Enter-MainMenu
}

function Enter-SubMenu {
    <#
    .SYNOPSIS
        Display and dispatch a module-defined submenu.

    .DESCRIPTION
        Reads the submenu registered under $SubMenuKey in $global:SubMenus and presents
        it with the same numbering, label formatting, and Invoke-Expression dispatch used
        by Enter-MainMenu. Loops until the user presses Q to return to the caller.

        Modules register submenus in Initialize-Module:
            $global:SubMenus += @{
                'MyKey' = @{
                    Title = "My Submenu"
                    Items = @{
                        'Item1' = @{ Title = "Do Thing"; Label = "Description."; Command = "My-Function" }
                    }
                }
            }
        Then point the main menu entry at: Command = "Enter-SubMenu 'MyKey'"

    .PARAMETER SubMenuKey
        Key in $global:SubMenus that identifies which submenu to display.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$SubMenuKey
    )

    $SubMenuDef = $global:SubMenus[$SubMenuKey]
    if (-not $SubMenuDef) {
        Write-Host "Error: Submenu '$SubMenuKey' is not registered in `$global:SubMenus." -ForegroundColor Red
        return
    }

    while ($true) {
        try { Clear-Host } catch { Write-Host ([char]27 + "[2J" + [char]27 + "[H") -NoNewline }
        Show-Logo

        Write-Host "  === $($SubMenuDef.Title) ===" -ForegroundColor Cyan
        Write-Host ""

        # Number the items alphabetically by Title, same approach as Enter-MainMenu.
        [int]$idx = 1
        [array]$SubMenuObjects = $SubMenuDef.Items.GetEnumerator() |
            Sort-Object { $_.Value.Title } |
            ForEach-Object {
                [PSCustomObject]@{
                    Index   = $idx++
                    Title   = $_.Value.Title
                    Label   = $_.Value.Label
                    Command = $_.Value.Command
                }
            }

        # Find the widest (title + index digits) combination so every title can be
        # padded to the same column width, matching how Enter-MainMenu aligns labels.
        [int]$SubMaxTitleLen = 0
        $SubMenuObjects | ForEach-Object {
            [int]$Combined = $_.Title.Length + $_.Index.ToString().Length
            if ($Combined -gt $SubMaxTitleLen) { $SubMaxTitleLen = $Combined }
        }
        [int]$SubMaxLabelLength = $global:OptionsMaxTextLength - $SubMaxTitleLen

        $SubMenuObjects | ForEach-Object {
            # Pad each title so labels start at the same column regardless of title length.
            [int]$TitlePad = $SubMaxTitleLen - ($_.Title.Length + $_.Index.ToString().Length)
            [string]$PaddedTitle = $_.Title + (' ' * $TitlePad)

            # Word-wrap the label at word boundaries, same approach as Enter-MainMenu.
            [string]$RemainingLabel = $_.Label
            [string]$NewLabel = ""
            [string]$IndentSpaces = " " * ($SubMaxTitleLen + 3)

            while ($RemainingLabel.Length -gt $SubMaxLabelLength) {
                [int]$BreakAt = $RemainingLabel.Substring(0, $SubMaxLabelLength).LastIndexOf(" ")
                if ($BreakAt -le 0) { $BreakAt = $SubMaxLabelLength }
                $NewLabel += "$($RemainingLabel.Substring(0, $BreakAt))`n$IndentSpaces"
                $RemainingLabel = $RemainingLabel.Substring($BreakAt).TrimStart()
            }
            $NewLabel += $RemainingLabel

            Write-Host "$($_.Index). $PaddedTitle" -ForegroundColor Green -NoNewline
            Write-Host " -$NewLabel"
            $NewLabel = $null
        }

        Write-Host ""
        Write-Host "=================================================================================="
        if ($null -ne $SubMenuDef.HelpCommand) { Write-Host "h. Help / Deployment Guide" }
        Write-Host "q. Back to Main Menu"
        Write-Host "qq. Quit Application"
        Write-Host "=================================================================================="
        Write-Host ""

        [string]$Choice = Read-Host "Input the option # you want to run"

        if ($Choice -eq 'q' -or $Choice -eq 'Q') { return }
        if ($Choice -eq 'qq' -or $Choice -eq 'QQ') { Stop-ADPowerAdmin }

        [Int32]$OutNum = 0
        if ($Choice -eq 'h' -or $Choice -eq 'H') {
            if ($null -ne $SubMenuDef.HelpCommand) {
                Write-Host "==================================================================================" -ForegroundColor Green
                Invoke-Expression $SubMenuDef.HelpCommand
                Write-Host "==================================================================================" -ForegroundColor Green
            } else {
                Write-Host "No help is available for this menu." -ForegroundColor Yellow
            }
        } elseif ([Int32]::TryParse($Choice, [ref]$OutNum)) {
            $Selected = $SubMenuObjects | Where-Object { $_.Index -eq $OutNum }
            if ($Selected) {
                Write-Host "==================================================================================" -ForegroundColor Green
                Invoke-Expression "$($Selected.Command)"
                Write-Host "==================================================================================" -ForegroundColor Green
            } else {
                Write-Host "Error: Invalid selection. Please select a number from the menu." -ForegroundColor Red
            }
        } else {
            Write-Host "Error: Invalid input. Please enter a number, H, or Q." -ForegroundColor Red
        }

        Pause
    }
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