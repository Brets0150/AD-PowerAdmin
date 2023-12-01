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
        'Get-Example1' = @{
            Title    = "Example 1 Title"
            Label    = "Run Example 1 Command Label"
            Module   = "AD-PowerAdmin_Example"
            Function = "Get-Example1"
            Command  = "Get-Example1"
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
        # if JobName is 'krbtgt-RotateKey', then run the krbtgt-RotateKey functions.
        # Note: this is used by the scheduled task. Do not use this manually.
        'ManualUnattendedJob' = @{
            Title    = 'Manual Unattended Job'
            Label    = 'Run from a schduled task by "Powershell.exe .\AD-PowerAdmin.ps1 -Unattended -JobName ManualUnattendedJob -JobVar1 "This is a test"'
            Module   = 'AD-PowerAdmin_Example'
            Function = 'Start-ExampleJob'
            Daily    = $false
            Command  = 'Start-ExampleJob'
        }
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
# End of Get-ADAdmins function
}