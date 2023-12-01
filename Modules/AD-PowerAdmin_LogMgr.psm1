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
        'Get-ADUserLockouts' = @{
            Title    = "Account Lockouts Search"
            Label    = "Search Event Log for Account Lockouts"
            Module   = "AD-PowerAdmin_LogMgr"
            Function = "Get-ADUserLockouts"
            Command  = "Get-ADUserLockouts"
        }
    }
}

# Initialize-Module

Function Get-ADUserLockouts {
    <#
    .SYNOPSIS
    Function to search Event logs on a Domain Controller for account lockouts in the last 7 days.

    .DESCRIPTION
    Function to search Event logs on a Domain Controller for account lockouts in the last 7 days.

    .EXAMPLE
    Example: Get-ADUserLockouts

    .INPUTS
    Get-ADUserLockouts does not take pipeline input.

    .OUTPUTS
    The output is a list of AD User accounts that have been locked out in the last 7 days.

    .NOTES
    This needs a rewitte.

    #>
    [CmdletBinding( DefaultParameterSetName = 'All')]
    param (
        [Parameter(ValueFromPipeline = $true,ParameterSetName = 'ByUser')]
        [Microsoft.ActiveDirectory.Management.ADUser]$Identity,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    Begin{
        $filterHt = @{
            LogName = 'Security'
            ID = 4740
        }
        if ($PSBoundParameters.ContainsKey('StartTime')){
            $filterHt['StartTime'] = $StartTime
        }
        if ($PSBoundParameters.ContainsKey('EndTime')){
            $filterHt['EndTime'] = $EndTime
        }
        $PDCEmulator = (Get-ADDomain).PDCEmulator
        # Query the event log just once instead of for each user if using the pipeline
        $events = Get-WinEvent -ComputerName $PDCEmulator -FilterHashtable $filterHt
    }
    Process {
        if ($PSCmdlet.ParameterSetName -eq 'ByUser'){
            $user = Get-ADUser $Identity
            # Filter the events
            $output = $events | Where-Object {$_.Properties[0].Value -eq $user.SamAccountName}
        } else {
            $output = $events
        }
        foreach ($event in $output){
            [pscustomobject]@{
                UserName = $event.Properties[0].Value
                CallerComputer = $event.Properties[1].Value
                TimeStamp = $event.TimeCreated
            }
        }
    }
    End{}
# End of the Search-EventLogForAccountLockouts function.
}
