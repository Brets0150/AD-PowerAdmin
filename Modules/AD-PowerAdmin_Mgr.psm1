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
    $global:Menu.Remove('Unregister-AdUser')
    $global:Menu.Remove('MgrMenu')
    $global:SubMenus.Remove('MgrMenu')

    # Register the sub-menu items.
    $global:SubMenus += @{
        'MgrMenu' = @{
            Title = "AD Management"
            Items = @{
                'DecommissionAdUser' = @{
                    Title   = "Decommission AD User"
                    Label   = "Decommission an AD user account: remove all group memberships, rotate the password, disable the account, and move it to the disabled OU."
                    Command = "Unregister-AdUser"
                }
                'SetMachineAccountQuota' = @{
                    Title   = "Set MAQ to Zero"
                    Label   = "Set ms-DS-MachineAccountQuota to 0 to prevent non-administrator users from creating computer accounts in the domain. Eliminates the Machine Account Quota vulnerability."
                    Command = "Set-MachineAccountQuota"
                }
                'SetAdAccountRandomPassword' = @{
                    Title   = "Set Random Password"
                    Label   = "Assign a cryptographically random 64-character password to an AD user account. Intended for disabled, unused, or non-interactive accounts that must have a password set but should never be used for interactive login."
                    Command = "Set-AdAccountRandomPassword"
                }
            }
        }
    }

    # Register a single main menu entry that opens the sub-menu.
    $global:Menu += @{
        'MgrMenu' = @{
            Title    = "AD Management"
            Label    = "Manage AD user accounts and domain security settings, including user decommissioning and Machine Account Quota remediation."
            Module   = "AD-PowerAdmin_Mgr"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'MgrMenu'"
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
# End of Unregister-AdUser function
}

Function Set-MachineAccountQuota {
    <#
    .SYNOPSIS
    Sets the Machine Account Quota (ms-DS-MachineAccountQuota) to 0 to prevent non-admin users from creating computer accounts.

    .DESCRIPTION
    === Machine Account Quota Remediation. ===
        The ms-DS-MachineAccountQuota domain attribute controls how many computer accounts
        an ordinary authenticated user can create. The default value of 10 is a well-known
        attack enabler: a low-privileged user can create a computer account and use it in
        Kerberos abuse, NTLM relay, or Resource-Based Constrained Delegation attack chains.

        This function:
        1. Reads the current ms-DS-MachineAccountQuota value via Get-ADObject so the
           attribute is always retrieved from LDAP regardless of the typed wrapper.
        2. Reports the current value and exits cleanly if it is already 0.
        3. Prompts the user to confirm the change before modifying anything.
        4. Sets ms-DS-MachineAccountQuota to 0 using Set-ADDomain -Replace.
        5. Re-reads the attribute from LDAP to verify the change was applied.

        Setting this value to 0 does NOT prevent administrators from joining machines to
        the domain. It only removes the default quota granted to ordinary users. Delegation
        of computer-join rights should be handled explicitly via AD delegation.

        Reference: AD-PowerAdmin.wiki/Vulnerabilities/ad_machine_account_quota_audit.md

    .EXAMPLE
    Set-MachineAccountQuota

    .INPUTS
    Set-MachineAccountQuota does not take pipeline input.

    .OUTPUTS
    None. All results are written to the console via Write-Host.

    .NOTES
    Requires Domain Admin or equivalent write access to the domain NC head object.

    ms-DS-MachineAccountQuota is not in the fixed property set returned by Get-ADDomain.
    This function uses Get-ADObject -Properties to read and verify the attribute directly
    from LDAP, consistent with the Get-MachineAccountQuotaAudit audit function.

    #>

    # Read the current value via Get-ADObject so the attribute is always retrieved from LDAP.
    $DomainDN = $null
    try { $DomainDN = (Get-ADDomain).DistinguishedName } catch {}

    if ($null -eq $DomainDN) {
        Write-Host "[FAIL] Unable to retrieve the domain Distinguished Name via Get-ADDomain." -ForegroundColor Red
        return
    }

    $DomainObject = Get-ADObject -Identity $DomainDN -Properties 'ms-DS-MachineAccountQuota' -ErrorAction SilentlyContinue
    $MAQRaw = $DomainObject.'ms-DS-MachineAccountQuota'

    if ($null -eq $MAQRaw) {
        Write-Host "[FAIL] Could not read ms-DS-MachineAccountQuota from the domain object ($DomainDN)." -ForegroundColor Red
        Write-Host "       Verify that you have read access to the domain NC head object." -ForegroundColor Yellow
        return
    }

    [int]$CurrentMAQ = [int]$MAQRaw

    if ($CurrentMAQ -eq 0) {
        Write-Host "[OK] ms-DS-MachineAccountQuota is already 0. No action required." -ForegroundColor Green
        return
    }

    # Report the current value and explain the risk before prompting.
    Write-Host ""
    Write-Host "Current ms-DS-MachineAccountQuota value: $CurrentMAQ" -ForegroundColor Yellow
    Write-Host "Any authenticated domain user can currently create up to $CurrentMAQ computer accounts." -ForegroundColor Yellow
    Write-Host "Setting this to 0 prevents non-admin users from creating computer accounts." -ForegroundColor Yellow
    Write-Host "Administrators and explicitly delegated accounts are not affected by this change." -ForegroundColor Yellow
    Write-Host ""

    [string]$Confirm = Read-Host "Set ms-DS-MachineAccountQuota to 0 on '$DomainDN'? (y/N)"
    if ($Confirm -ne "y" -and $Confirm -ne "Y") {
        Write-Host "Operation cancelled. No changes were made." -ForegroundColor Yellow
        return
    }

    # Apply the change.
    try {
        Set-ADDomain -Identity $DomainDN -Replace @{'ms-DS-MachineAccountQuota' = 0}
    } catch {
        Write-Host "[FAIL] Set-ADDomain failed: $_" -ForegroundColor Red
        Write-Host "       Verify that you have Domain Admin or equivalent write rights." -ForegroundColor Yellow
        return
    }

    # Verify the change was applied by re-reading from LDAP.
    $VerifyObject = Get-ADObject -Identity $DomainDN -Properties 'ms-DS-MachineAccountQuota' -ErrorAction SilentlyContinue
    [int]$VerifiedMAQ = [int]$VerifyObject.'ms-DS-MachineAccountQuota'

    if ($VerifiedMAQ -eq 0) {
        Write-Host "[OK] ms-DS-MachineAccountQuota is now 0. Non-admin users can no longer create computer accounts." -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Verification failed. ms-DS-MachineAccountQuota reads $VerifiedMAQ after the change attempt." -ForegroundColor Red
        Write-Host "       Review the domain object manually and check replication status." -ForegroundColor Yellow
    }
# End of Set-MachineAccountQuota function
}