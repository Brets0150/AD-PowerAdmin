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
        'Unregister-AdUser' = @{ # Must be a unique name. You have have multiple menu items that run the same "command", but they must have unique names.
            Title    = "Decommision AD User" # This is the title that will be displayed in the menu. PLEASE keep this short, like 20 characters or less.
            Label    = "Decommision an AD User account; remove all group assosations, rotate password, and Disable the account" # This is the label that will be displayed in the menu. Try keep this short, like 150-250 characters or less.
            Module   = "AD-PowerAdmin_Mgr" # This is the name of the module in which the function resides. Not really used(for now), but it is here for reference and in case it is needed in the future.
            Function = "Unregister-AdUser" # This is the name of function that will be run. Not realy used(for now), but is here for reference and incase it is needed in the future.
            Command  = "Unregister-AdUser" # This is the command(a function from this module) that will be run.
        }
    }
}

# Call the Initialize-Module function. This needs to run to load all the data we need from the module.
Initialize-Module

Function Test-MgrPreFlight {
    <#
    .SYNOPSIS
        Validates that a caller-supplied list of global variables are present and non-empty.

    .DESCRIPTION
        Accepts an array of global variable names (without the '$global:' prefix).
        For each name, retrieves the variable from global scope and checks that it is
        not null, not an empty string, and not an empty collection. Any that fail are
        collected and reported together. When $global:Debug is enabled, a DEBUG line
        is also written to the active transcript.

        Each function in this module declares its own required globals and passes them
        here, so the check list grows naturally as the module expands.

    .PARAMETER RequiredGlobals
        One or more global variable names to validate, without the '$global:' prefix.

    .OUTPUTS
        [bool] $true when every named global is present and non-empty; $false otherwise.

    .EXAMPLE
        if (-not (Test-MgrPreFlight -RequiredGlobals @('InactiveUsersLocations', 'ADAdminEmail'))) { return }
    #>

    param(
        [Parameter(Mandatory=$true)]
        [string[]]$RequiredGlobals
    )

    [array]$missing = @()

    foreach ($varName in $RequiredGlobals) {
        $value = Get-Variable -Name $varName -Scope Global -ValueOnly -ErrorAction SilentlyContinue

        $isEmpty = if ($null -eq $value) {
            $true
        } elseif ($value -is [string]) {
            [string]::IsNullOrWhiteSpace($value)
        } else {
            @($value).Count -eq 0
        }

        if ($isEmpty) { $missing += "`$global:$varName" }
    }

    if ($missing.Count -gt 0) {
        Write-Host "Error: AD-PowerAdmin_Mgr cannot run - required settings are missing or empty:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "  Missing: $_" -ForegroundColor Red }
        Write-Host "Update the missing values in 'AD-PowerAdmin_settings.ps1' and try again." -ForegroundColor Yellow
        if ($global:Debug) {
            Write-Host "DEBUG: Test-MgrPreFlight failed. Missing: $($missing -join ', ')" -ForegroundColor DarkYellow
        }
        return $false
    }

    return $true
}

Function Unregister-AdUser {
    <#
    .SYNOPSIS
        The Unregister-AdUser function is used to decommission an AD user account.

    .DESCRIPTION
        The Unregister-AdUser function is used to decommission an AD user account.
        1. If a SamAccountName is not provided, the user will be prompted to enter one. Search for an account with a like name and for each account found, the user will be prompted to select the account to decommission.
        2. The user will be prompted to confirm the account to decommission.
        3. Remove all group assosations the account has, except for the Domain Users group.
        4. Rotate the password using the New-RandomPassword function.
        5. Disable the account.
        6. Get the User Account objects current description then append the User Account objects description with the date and time the account was decommisioned.
        7. Move the account to the Decommissioned OU.

    .EXAMPLE
        Unregister-AdUser

    .EXAMPLE
        Unregister-AdUser -AdUserToDisable $(Search-SingleAdObject)

    .NOTES

    #>

    # Set the function Parameters
    param(
        [Parameter(Mandatory=$False,Position=1)]
        [System.Object]$AdUserToDisable
    )

    if (-not (Test-MgrPreFlight -RequiredGlobals @('InactiveUsersLocations'))) { return }

    # Check if $AdUserSamAccountName is provided. If not, prompt the user to enter one.
    if (-not $AdUserToDisable) {
        [System.Object]$AdUserToDisable = Search-SingleAdObject
    }
    $AdUserToDisable = Get-ADUser -Identity $($AdUserToDisable).samAccountName -Properties "*"

    # Prompt the user to confirm the account to decommission.
    [string]$Prompt = "Are you sure you want to update the AD User `"$($($AdUserToDisable).DistinguishedName)`" with a new random pasword, remove all groups, disable and move the AD object to the disabled OU? (y/N)"
    $Confirm = Read-Host -Prompt $Prompt

    # If the user don't confirm, exit the function.
    if ($Confirm -ne "Y" -and $Confirm -ne "y") {
        Write-Host "Failed to confirm the account to decommission. Exiting the function."  -ForegroundColor Red
        return
    }

    # If the user confirms, remove all group assosations the account has, except for the Domain Users group.
    if ($Confirm -eq "Y" -or $Confirm -eq "y") {
        # Capture group membership objects before removal so they can be preserved in the description.
        # Keeping the full ADGroup objects lets us use DistinguishedName for removal (unambiguous)
        # while using Name only for the human-readable description string.
        [array]$FormerGroupObjects = $AdUserToDisable | Get-ADPrincipalGroupMembership |
            Where-Object { $_.Name -ne "Domain Users" }
        [string]$FormerGroupsString = ($FormerGroupObjects | Select-Object -ExpandProperty Name) -join '; '

        # Remove group memberships using DistinguishedName to avoid name-vs-SamAccountName mismatches.
        $FormerGroupObjects | ForEach-Object {
            Remove-ADGroupMember -Identity $_.DistinguishedName -Members $AdUserToDisable.SamAccountName -Confirm:$false
        }
        # Rotate the password using the New-RandomPassword function.
        Set-ADAccountPassword -Identity $AdUserToDisable -NewPassword $(ConvertTo-SecureString -String "$(New-RandomPassword).ToString()" -AsPlainText -Force)
        # Disable the account.
        Disable-ADAccount -Identity $AdUserToDisable

        # Get the User Account objects current description then append the User Account objects description with the date and time the account was decommisioned.
        $AdUserToDisableDescription = $AdUserToDisable.Description
        $AdUserToDisableDescription += " -- Decommissioned on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Manually by $($env:USERNAME) with AD-PowerAdmin."
        $AdUserToDisableDescription += " -- Former groups: $FormerGroupsString"
        # Set the User Account objects description to the new description.
        Set-ADUser -Identity $AdUserToDisable -Description $AdUserToDisableDescription

        # Confirm the "$($global:InactiveUsersLocations).DisabledOULocal" OU exist in AD.
        if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$($global:InactiveUsersLocations).DisabledOULocal'")) {
            Write-Host "The OU $($($global:InactiveUsersLocations).DisabledOULocal) does not exist in AD." -ForegroundColor Red
            Write-Host "Update the global:InactiveUsersLocations setting in 'AD-PowerAdmin_settings.ps1"  -ForegroundColor Red
            Write-Host "Leaving Disabled user account in the current OU."  -ForegroundColor Yellow
            return
        }
        # Move the account to the Decommissioned OU.
        Move-ADObject -Identity $AdUserToDisable -TargetPath "$($global:InactiveUsersLocations).DisabledOULocal"
    }
# End of Get-ADAdmins function
}