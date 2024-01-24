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

    # Any function you want to use in the "Command" property must be exported by adding the function to the "FunctionsToExport" property in the module manifest(the .psd1 file).
    # The main script cannot see any functions in the module unless they are exported in the module manifest(the .psd1 file).

    # Append $global:Menu with the menu items to be displayed.
    $global:Menu += @{
        'Get-Example1' = @{ # Must be a unique name. You have have multiple menu items that run the same "command", but they must have unique names.
            Title    = "Example 1 Title" # This is the title that will be displayed in the menu. PLEASE keep this short, like 20 characters or less.
            Label    = "Run Example 1 Command Label" # This is the label that will be displayed in the menu. Try keep this short, like 150-250 characters or less.
            Module   = "AD-PowerAdmin_Example" # This is the name of the module in which the function resides. Not really used(for now), but it is here for reference and in case it is needed in the future.
            Function = "Get-Example1" # This is the name of function that will be run. Not realy used(for now), but is here for reference and incase it is needed in the future.
            Command  = "Get-Example1" # This is the command(a function from this module) that will be run.
        }
        'Get-Example2' = @{
            Title    = "Example 2 Title"
            Label    = "Run Example 2 Command Label"
            Module   = "AD-PowerAdmin_Example"
            Function = 'Get-Example2'
            Command  = 'Get-Example2 -Parameter "This is a test"'
        }
    }
    # Append the $global:UnattendedJobs with the jobs to be run unattended from this module.
    $global:UnattendedJobs += @{

        # Single unattended job. This job can be run from a scheduled task, or from the command line.
        # An example of when to use this is found in the weak password test. The weak password test runs as a daily job and checks for weak passwords.
        #   If a weak password is found, then a single unattended job is created to follow up and check if the user updated their password.
        #   That single unattended job is run from a scheduled task, and looks like this: Powershell.exe .\AD-PowerAdmin.ps1 -Unattended -JobName PwUserFollowup -JobVar1 $JobVar1
        #   The $JobVar1 variable is passed to the job, and is used to pass the user's samAccountName to the job.

        'SingleUnattendedJob' = @{ # This is the name of the job. It is used to identify the job in the database. This is the value to use with the -JobName parameter.
            Title    = 'Single Unattended Job' # A title for the job. Not used right now, but will be in the future.
            Label    = 'Run from a schduled task by "Powershell.exe .\AD-PowerAdmin.ps1 -Unattended -JobName SingleUnattendedJob -JobVar1 "This is a test"; could also be run from the command line.' # A discription of the job.
            Module   = 'AD-PowerAdmin_Example' # This is the name of the module in which the function resides. Not really used(for now), but it is here for reference and in case it is needed in the future.
            Function = 'Start-ExampleJob' # This is the name of function that will be run. Not realy used(for now), but is here for reference and incase it is needed in the future.
            Daily    = $false # Do not run this as part of the daliy task jobs. If this is set to $true, then AD-PowerAdmin will run this job daily, if AD-PowerAdmin is installed.
            Command  = "Start-ExampleJob -JobVar1 $($JobVar1)" # This is the command that will be run. The $JobVar1 variable is passed to the function.
        }

        # This is an example of a daily job. AD-PowerAdmin, when installed, has a scheduled task that runs daily and triggers any "command" in $global:UnattendedJobs that has the "Daily" property set to $true.
        # Any daily jobs should not require a -JobVar1 parameter. If a -JobVar1 parameter is required, then the job should be run manually, or have a scheduled task created for it.
        'DailyUnattendedJob' = @{
            Title    = 'Daily Unattended Job'
            Label    = 'AD-PowerAdmin will run this job daily, if AD-PowerAdmin is installed. Run from a daily schduled task by "Powershell.exe .\AD-PowerAdmin.ps1 -Unattended -JobName Daily'
            Module   = 'AD-PowerAdmin_Example'
            Function = 'Get-Example1'
            Daily    = $true
            Command  = 'Get-Example1'
        }
    }
}

# Call the Initialize-Module function. This needs to run to load all the data we need from the module.
Initialize-Module

Function Get-Example1 {
    <#
    .SYNOPSIS
    Funcation to get example 1.

    .DESCRIPTION
    === Example 1. ===
        This option will get example 1.
        This entired description will be displayed in the help menu.

    .EXAMPLE
    Get-Example1

    .INPUTS
    Get-Example1 does not take pipeline input.

    .OUTPUTS
    The output is a string of example 1.

    .NOTES

    #>

    # Get example 1.
    Write-Host "Example 1"
# End of Get-ADAdmins function
}

Function Get-Example2 {
    <#
    .SYNOPSIS
    Funcation to get example 2.

    .DESCRIPTION
    === Example 2. ===
        This option will get example 2
        This entired description will be displayed in the help menu.

    .EXAMPLE
    Get-Example2

    .INPUTS
    Get-Example2 does not take pipeline input.

    .OUTPUTS
    The output is a string of example 2.

    .NOTES

    #>
    # Parameter help description
    Param(
    [Parameter(Mandatory=$true,Position=1)]
    [string]$Parameter
    )
    # Trim the parameter.
    $Parameter = $Parameter.Trim()
    # Get example 2.
    Write-Host "Example 2: $Parameter"
# End of Get-ADAdmins function
}

Function Start-ExampleJob {
    <#
    .SYNOPSIS
    Funcation to run job

    .DESCRIPTION
    same

    .EXAMPLE
    Start-ExampleJob

    .INPUTS
    Start-ExampleJob  does not take pipeline input.

    .OUTPUTS
    The output is a string of the results of "Get-Example1"

    .NOTES

    #>
    # Parameter help description
    Param(
    [Parameter(Mandatory=$true,Position=1)]
    [string]$JobVar1
    )

    Write-Host $JobVar1
    Get-Example2 -Parameter $JobVar1
# End of Get-ADAdmins function
}