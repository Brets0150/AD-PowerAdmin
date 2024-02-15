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
    # Unload $global:Menu keys, so they can be reloaded.
    $global:Menu.Remove('Get-ADAdminAudit')
    $global:Menu.Remove('Get-ADUserAudit')
    $global:Menu.Remove('Search-InactiveComputers')
    $global:Menu.Remove('Search-InactiveComputersAndDisable')
    $global:Menu.Remove('Search-InactiveUsers')
    $global:Menu.Remove('Search-InactiveUsersAndDisable')
    $global:Menu.Remove('Search-AD')
    $global:Menu.Remove('Test-ADSecurityBestPractices')
    $global:Menu.Remove('Test-Test')

    # Unload $global:UnattendedJobs keys, so they can be reloaded.
    $global:UnattendedJobs.Remove('Start-DailyInactiveUserAudit')
    $global:UnattendedJobs.Remove('Start-DailyInactiveComputerAudit')

    # Append $global:Menu with the menu items to be displayed.
    $global:Menu += @{
        'Get-ADAdminAudit' = @{
            Title    = "AD Admins Report"
            Label    = "Searches AD for accounts in high privileged AD groups and create a report that can be exported to a CSV file."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Get-ADAdminAudit"
            Command  = "Get-ADAdminAudit"
        }
        'Get-ADUserAudit' = @{
            Title    = "AD Users Report"
            Label    = "Searches AD for all AD Users and their last login and password last set date, then export the results to a CSV file."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Get-ADUserAudit"
            Command  = "Get-ADUserAudit"
        }
        'Search-InactiveComputers' = @{
            Title    = "Search Inactive Computers"
            Label    = "Search for inactive computers report only."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Search-MultipleInactiveComputers"
            Command  = 'Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $($global:InactiveDays) -ReportOnly $true'
        }
        'Search-InactiveComputersAndDisable' = @{
            Title    = "Disable Inactive Computers"
            Label    = "Search for inactive computers and disable them."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Search-MultipleInactiveComputers"
            Command  = 'Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $global:InactiveDays -ReportOnly $false'
        }
        'Search-InactiveUsers' = @{
            Title    = "Search Inactive Users"
            Label    = "Search for inactive users report only."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Search-MultipleInactiveUsers"
            Command  = 'Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $true'
        }
        'Search-InactiveUsersAndDisable' = @{
            Title    = "Disable Inactive Users"
            Label    = "Search for inactive users and disable them."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Search-MultipleInactiveUsers"
            Command  = 'Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $false'
        }
        'Search-AD' = @{
            Title    = "Search AD"
            Label    = "Search AD for a User, Computer, or all Objects."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Search-AD"
            Command  = 'Search-AD -TextResults $true'
        }
        'Test-ADSecurityBestPractices' = @{
            Title    = "AD Security Check"
            Label    = "Test AD Security Best Practices."
            Module   = "AD-PowerAdmin_Audits"
            Function = "Test-ADSecurityBestPractices"
            Command  = 'Test-ADSecurityBestPractices'
        }
    }

    # Append the $global:UnattendedJobs with the jobs to be run unattended from this module.
    $global:UnattendedJobs += @{
        # if JobName is 'krbtgt-RotateKey', then run the krbtgt-RotateKey functions.
        # Note: this is used by the scheduled task. Do not use this manually.
        'Start-DailyInactiveUserAudit' = @{
            Title    = 'Inactive User Audit'
            Label    = 'Search and disable inactive users.'
            Module   = 'AD-PowerAdmin_Audits'
            Function = 'Start-DailyInactiveUserAudit'
            Daily    = $true
            Command  = 'Start-DailyInactiveUserAudit'
        }
        'Start-DailyInactiveComputerAudit' = @{
            Title    = 'Inactive Computer Audit'
            Label    = 'Search and disable inactive Computers.'
            Module   = 'AD-PowerAdmin_Audits'
            Function = 'Start-DailyInactiveComputerAudit'
            Daily    = $true
            Command  = 'Start-DailyInactiveComputerAudit'
        }
    }
}

Initialize-Module

Function Get-ADAdmins {
    <#
    .SYNOPSIS
    Funcation to build a list of AD Users with Adinistrative Rights, including the Domain Admin and Enterprise Admins.

    .DESCRIPTION
    === Audit AD Admin account Report. ===
        This option will generate a report of all accounts with Domain Administrator rights or Enterprise Administrator rights.
        Microsoft states the following groups should be treated as high-value targets:
            Domain Admins
            Enterprise Admins
            Administrators
            Schema Admins
            Backup Operators
            Account Operators
            Server Operators
            Domain Controllers
            Print Operators
            Replicator
            Enterprise Key Admins
            Key Admins

        So any user in any of these groups will be reported on.

    .EXAMPLE
    $ADAdmins = Get-ADAdmins

    .INPUTS
    Get-ADAdmins does not take pipeline input.

    .OUTPUTS
    The output is a list of AD Users who are members of the High Value Target Groups.

    .NOTES

    #>

    [PSCustomObject]$ADAdmins = @()

    # Append $ADAdmins with members of the Domain Admins
    $ADAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Enterprise Admins
    $ADAdmins += Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin Administrators group
    $ADAdmins += Get-ADGroupMember -Identity "Administrators" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Schema administrators" group
    $ADAdmins += Get-ADGroupMember -Identity "Schema Admins" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Backup operators" group
    $ADAdmins += Get-ADGroupMember -Identity "Backup Operators" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Account operators" group
    $ADAdmins += Get-ADGroupMember -Identity "Account Operators" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Server operators" group
    $ADAdmins += Get-ADGroupMember -Identity "Server Operators" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Domain controllers" group
    $ADAdmins += Get-ADGroupMember -Identity "Domain Controllers" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Print operators" group
    $ADAdmins += Get-ADGroupMember -Identity "Print Operators" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Replicator" group
    $ADAdmins += Get-ADGroupMember -Identity "Replicator" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "Enterprise key admins" group
    $ADAdmins += Get-ADGroupMember -Identity "Enterprise Key Admins" -Recursive -ErrorAction:SilentlyContinue
    # Append $ADAdmins with members of the Builtin "key admins" group
    $ADAdmins += Get-ADGroupMember -Identity "Key Admins" -Recursive -ErrorAction:SilentlyContinue

    # Remove duplicates from $ADAdmins
    $ADAdmins = $ADAdmins | Select-Object -Unique

    # Return the list of AD Admins
    return $ADAdmins
# End of Get-ADAdmins function
}

Function Get-ADAdminAudit {
    <#
    .SYNOPSIS
    Fuction to takes a list of AD Users and gets their account details.

    .DESCRIPTION
    === AD Admin Account Report. ===
        This option will generate a report of all AD Users, Computers, and Group Managed Service Accounts with high risk permissions.
        The report can help you identify accounts that may be at risk, or a high value target for an Attacker.
        This report can be exported to a CSV file.

        Microsoft states the following groups should be treated as high-value targets:
            Domain Admins
            Enterprise Admins
            Administrators
            Schema Admins
            Backup Operators
            Account Operators
            Server Operators
            Domain Controllers
            Print Operators
            Replicator
            Enterprise Key Admins
            Key Admins

        So any user in any of these groups will be reported on.

    .EXAMPLE
    Get-ADAdminAudit

    .INPUTS
    Get-ADAdminAudit does not take pipeline input.

    .OUTPUTS
    The output is a list of AD Users, Computers, and Group Managed Service Accounts with high risk permissions.

    .NOTES

    #>

    # Loop through each AD Admin User
    $AdminData = Get-ADAdmins | ForEach-Object {
        # Test if $_ is a AD User, Computer, or Group Managed Service Account.
        if ($_.ObjectClass -eq "user") {
            # Get the AD User's details
            Get-ADUser -Identity $_.DistinguishedName -Properties Name, SamAccountName, DistinguishedName, ObjectClass, LastLogonDate, Enabled -ErrorAction:SilentlyContinue
        } elseif ($_.ObjectClass -eq "computer") {
            # Get the AD Computer's details
            Get-ADComputer -Identity $_.DistinguishedName -Properties Name, SamAccountName, DistinguishedName, ObjectClass, LastLogonDate, Enabled -ErrorAction:SilentlyContinue
        } elseif ($_.ObjectClass -like '*ManagedServiceAccount') {
            # Get the AD Group Managed Service Account's details
            Get-ADServiceAccount -Identity $_.DistinguishedName -Properties Name, SamAccountName, DistinguishedName, ObjectClass, LastLogonDate, Enabled -ErrorAction:SilentlyContinue
        }
    }
    # Sort the results by the Name property and remove duplicates.
    $AdminData = $AdminData | Sort-Object -Property Name | Select-Object -Unique | Format-List -Property Name, SamAccountName, DistinguishedName, ObjectClass, LastLogonDate, Enabled

    # Ask the user if they want to export the results to a CSV file.
    Export-AdPowerAdminData -Data $AdminData -ReportName "AD-AdminAudit"

    # Return the list of AD Admins
    return $AdminData
# End of Get-ADAdminAudit function
}

Function Get-ADUserAudit {
    <#
    .SYNOPSIS
    Fuction to get all Active Directory Users and their last login and password last set date, then export the results to a CSV file.

    .DESCRIPTION
    === AD User Account Report. ===
        This option will generate a report of all AD Users and their last login and password last set date.
        The report can help you identify accounts that have not been used in a long time and accounts that have not had their password changed in a long time.
        This report can be exported to a CSV file.

    .EXAMPLE
    Get-ADUserAudit

    .INPUTS
    Get-ADUserAudit does not take pipeline input.

    .OUTPUTS
    The output is a list of AD Users and their last login and password last set date.

    .NOTES

    #>

    # Get all AD Users and their last login and password last set date.
    $ADUsers = Get-ADUser -Filter * -Properties Name, SamAccountName, DistinguishedName, LastLogonDate, PasswordLastSet -ErrorAction:SilentlyContinue
    # Ask the user if they want to export the results to a CSV file.
    $ExportResults = Read-Host "Would you like to export the results to a CSV file? (Y/N)"
    # If the user enters "Y" or "y", then export the results to a CSV file.
    if ($ExportResults -eq "Y" -or $ExportResults -eq "y") {
        # Get the current datetime and put it in a variable.
        [string]$CurrentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
        # Export the results to a CSV file.
        $ADUsers | Export-Csv -Path "$global:ReportsPath\\AD-UserAudit_$CurrentDateTime.csv" -NoTypeInformation
        # Display a message to the user that the results were exported to a CSV file.
        Write-Host "The results were exported to a CSV file located in the same directory as this script." -ForegroundColor Green
    } else {
        # If the user enters anything other than "Y" or "y", then display a message to the user that the results were not exported to a CSV file.
        $ADUsers | Format-List -Property Name, SamAccountName, DistinguishedName, LastLogonDate, PasswordLastSet
    }
}

Function Get-ADComputerInDefaultFolder {
    <#
    .SYNOPSIS
    Function that will check is there are any AD COmputer objects in the default Computer folder.

    .DESCRIPTION
    === AD Computer in default folder. ===
        This option will check if there are any AD Computer objects in the default Computer folder.
        If there are any AD Computer objects in the default Computer folder, then they will be displayed.

        AD Objects should not be kept in the default folder. They should be sorted into OUs to ensure they are getting all the corrent GPOs applied.
        This function will help you audit your AD to ensure all AD Computer objects are in the correct OU.

    .EXAMPLE
    Search-ADComputerInDefaultFolder

    .INPUTS
    Search-ADComputerInDefaultFolder does not take pipeline input.

    .OUTPUTS
    The output is a list of AD Computer objects in the default Computer folder.

    .NOTES
    Needs to be tested. Not done.

    #>

    $Count = 0

    # Get a list of all AD Computers
    $ADComputers = Get-ADComputer -Filter * -SearchBase "CN=Computers,$($(Get-ADDomain).DistinguishedName)" -Properties Name, SamAccountName, DistinguishedName, ObjectClass -ErrorAction:SilentlyContinue

    # Loop through each AD Computer
    $ADComputers | ForEach-Object {
        # If the AD Computer is in the default "Computers" folder, then it is not in the default "Computers" folder.
        if ($_.DistinguishedName -like "CN=$($_.Name),CN=Computers,$($(Get-ADDomain).DistinguishedName)") {
            # If the AD Computer is in the default "Computers" folder, then it is not in the default "Computers" folder.
            Write-Host "AD Computer '$($_.Name)' is in the default 'Computers' folder" -ForegroundColor Red
            $Count++
        }
    }

    # If $Count is 0, then no AD Computers were found in the default "Computers" folder.
    if ($Count -eq 0) {
        Write-Host "No AD Computers were found in the default 'Computers' folder." -ForegroundColor Green
    }
 # End of Search-ADComputerInDefaultFolder function
}

Function Get-ADUserMemberOf {
    <#
    .SYNOPSIS
    Function to get all groups a user is a member of, including nested groups.

    .DESCRIPTION
    Get a list of the unique groups a user is a member of, including nested groups.

    .EXAMPLE
    #The user to check.
    $User = "CN=James Bond,OU=Techs,OU=US,OU=Network,OU=Users,DC=example,DC=com";

    #Get all groups.
    $Groups = Get-ADUserMemberOf -DistinguishedName (Get-ADUser -Identity $User).DistinguishedName;

    #Output all groups.
    $Groups | Select-Object Name | Sort-Object -Property Name;

    .NOTES
    This function is used by the Search-DcSyncRisk function.

    #>

    Param(
        [string]$DistinguishedName,
        [array]$Groups = @()
    )

    #Get the AD object, and get group membership.
    $ADObject = Get-ADObject -Filter "DistinguishedName -eq '$DistinguishedName'" -Properties memberOf, DistinguishedName;

    # If object does not exist, display an error message, and exit the function.
    if ($null -eq $ADObject) {
        Write-Host "Error: The object specified in the DistinguishedName parameter does not exist in the Active Directory Domain." -ForegroundColor Red
        return
    }

    #If object exists.
    If($ADObject)
    {
        #Enummurate through each of the groups.
        Foreach($GroupDistinguishedName in $ADObject.memberOf)
        {
            #Get member of groups from the enummerated group.
            $CurrentGroup = Get-ADObject -Filter "DistinguishedName -eq '$GroupDistinguishedName'" -Properties memberOf, DistinguishedName;

            #Check if the group is already in the array.
            If(($Groups | Where-Object {$_.DistinguishedName -eq $GroupDistinguishedName}).Count -eq 0)
            {
                # Add group to array.
                $Groups +=  $CurrentGroup;

                #Get recursive groups.
                $Groups = Get-ADUserMemberOf -DistinguishedName $GroupDistinguishedName -Groups $Groups;
            }
        }
    }

    # Filter $Groups to be unique and sorted by name.
    $Groups = $Groups | Select-Object -Unique | Select-Object Name | Sort-Object -Property Name;
    #Return groups.
    Return $Groups;
# End of Get-ADUserNestedGroups function
}

Function Search-ADUserNonDefaultPrimaryGroup {
    <#
    .SYNOPSIS
    Function to test for Users with non-default Primary Group IDs

    .DESCRIPTION
    === AD User with non-default Primary Group ID. ===
        This option will check if there are any AD User objects with a non-default Primary Group ID.
        If there are any AD User objects with a non-default Primary Group ID, then they will be displayed.

        AD Users should have a Primary Group ID of 513, which is the "Domain Users" group.
        Using a non-default Primary Group ID is a method of hiding a users membership in a group.
        Attackers may use this method to hide an account they are using as a backdoor.

    .EXAMPLE
    Search-ADUserNonDefaultPrimaryGroup

    .INPUTS
    Search-ADUserNonDefaultPrimaryGroup does not take pipeline input.

    .OUTPUTS
    The output is a list of AD User objects with a non-default Primary Group ID.

    .NOTES

    #>

    # Set a count to 0
    $Count = 0
    # Get a list of all AD Users
    $ADUsers = Get-ADUser -Filter * -Properties Name, SamAccountName, DistinguishedName, PrimaryGroupID -ErrorAction:SilentlyContinue
    # Loop through each AD User
    ForEach ($ADUser in $ADUsers) {
        # If the PrimaryGroupID is not 513, then the user is not in the default "Domain Users" group.
        if ($ADUser.PrimaryGroupID -ne 513) {

            # If the user account has the guest $ADUser.DistinguishedName, and is in the 514 group, and has the $_.Name of guest, then skip the user.
            if ($ADUser.DistinguishedName -eq "CN=Guest,CN=Users,$($(Get-ADDomain).DistinguishedName)" -And $ADUser.PrimaryGroupID -eq 514 -And $ADUser.Name -eq "Guest") { continue }

            # Write the AD User's details to the console
            Write-Host "User: $($ADUser.Name) ($($ADUser.SamAccountName)) DistinguishedName: $($ADUser.DistinguishedName) IN PrimaryGroupID: $($ADUser.PrimaryGroupID)" -ForegroundColor Red

            $Count++
        }
    }
    # If $Count is 0, then no AD Users were found with a non-default Primary Group ID.
    if ($Count -eq 0) {
        Write-Host "No AD Users were found with a non-default Primary Group ID." -ForegroundColor Green
    }

 # End of Search-ADUserNonDefaultPrimaryGroup function
}

Function Search-InactiveComputers {
    <#
    .SYNOPSIS
    Function to seartch AD for Computer Objects that have been inactive for more than X days.

    .DESCRIPTION
    === Search for inactive computers. ===
        Search for computers that have been inactive for more than X days; default is 90 days. This can also disable the computer,
        strip all group membership, and move it to the Disabled.Desktop OU. This can be run manually or automated
        via the 'Daliy' option.

        The "SearchOUbase" parameter is the OU to search for inactive computers. "SearchOUbase" must be defined in the 'AD-PowerAdmin_settings.ps1' file.
        The "DisabledOULocal" parameter is the OU to move the inactive computers to. "DisabledOULocal" must be defined in the 'AD-PowerAdmin_settings.ps1' file.

        See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

        !!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

    .EXAMPLE
    Example: Search-InactiveComputers -SearchOUbase 'OU=Desktops,DC=EXAMPLE,DC=COM' -DisabledOULocal 'OU=Disabled.Desktop,OU=Desktops,DC=EXAMPLE,DC=COM' -InactiveDays 90 -ReportOnly $false

    .INPUTS
    Search-InactiveComputers does not take pipeline input.

    .OUTPUTS
    The output is a list of inactive computer accounts.

    .NOTES
    The Search-InactiveComputers function will only disable, strip all group membership, and move the computer to the Disabled.Desktop OU if the $ReportOnly variable is set to false.

    #>

    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SearchOUbase,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$DisabledOULocal,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=4)]
        [bool]$ReportOnly
    )

    # $time variable converts $DaysInactive to LastLogonTimeStamp property format for the -Filter switch to work
    $InactiveDate = (Get-Date).Adddays(-($InactiveDays))

    # Check if the OU specified in the $SearchOUbase parameter exists in the Active Directory Domain.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $SearchOUbase} -Properties * ) ) {
        # If the OU specified in the $SearchOUbase parameter does not exist in the Active Directory Domain, then display an error message.
        Write-Host "Error: The Computer OU specified in the SearchOUbase parameter does not exist in the Active Directory Domain." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }

    # Check if the OU specified in the $DisabledOULocal parameter exists in the Active Directory Domain.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $DisabledOULocal} -Properties * ) ) {
        # If the OU specified in the $DisabledOULocal parameter does not exist in the Active Directory Domain, then display an error message.
        Write-Host "Error: The Computer OU specified in the DisabledOULocal parameter does not exist in the Active Directory Domain." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }

    # Search for Computers that have been inactive for more than X days.
    $InactiveComputerObjects = Get-ADComputer -SearchBase $SearchOUbase -Filter {LastLogonTimeStamp -lt $InactiveDate -and Enabled -eq $true} `
    -ResultPageSize 2000 -resultSetSize $null -Properties Name, OperatingSystem, SamAccountName, DistinguishedName, LastLogonDate

    # Check if $InactiveComputerObjects is empty. If it is, then no computers are inactive.
    if ($null -ne $InactiveComputerObjects) {

        # If $ReportOnly is true, then display the inactive computer objects and exit the function.
        if ($ReportOnly) {
            # Display the inactive computer objects.
            Write-Host "Inactive Computer Objects in: $SearchOUbase" -ForegroundColor Red
            $InactiveComputerObjects | Select-Object Name, OperatingSystem, DistinguishedName, LastLogonDate | Format-Table -AutoSize
            return
        }

        #For each inactive computer, Disable the Computer AD object, update the discription, and move the computer to the Disabled.Desktop OU.
        $InactiveComputerObjects | ForEach-Object {
            # Current Computer Object.
            $CurrentComputerObject = $_
            # Get the old(currently) set computer discription.
            $ComputerOldDescription = (Get-ADComputer -Identity $CurrentComputerObject -Prop Description).Description

            #Get the old OU location of the computer.
            $ComputerOldOU = $CurrentComputerObject.DistinguishedName

            # Get all groups the computer is a member of.
            $ComputersGroupMemberships = Get-ADPrincipalGroupMembership $CurrentComputerObject.DistinguishedName

            # Foreach group, remove the computer from the group.
            $ComputersGroupMemberships | ForEach-Object {
                # If $_.DistinguishedName not equal to "Domain Computers", then remove the computer from the group.
                if ($_.name -ne 'Domain Computers') {
                    Remove-ADPrincipalGroupMembership -Identity $CurrentComputerObject -MemberOf $_.DistinguishedName -Confirm:$False
                }
            }

            # Disable the computer in AD.
            Disable-ADAccount $CurrentComputerObject

            # Update the computer description.
            Set-ADComputer $CurrentComputerObject -Description "$ComputerOldDescription -- Account disabled $(Get-Date -format "yyyy-MM-dd") by AD-PowerAdmin. :: OLD-OU: $ComputerOldOU"

            # Move the computer to the Disabled.Desktop OU.
            Move-ADObject $CurrentComputerObject -targetpath $DisabledOULocal

            # Output the Samname of the user that was disabled.
            Write-Host "Disabled Computer: $CurrentComputerObject.SamAccountName" -ForegroundColor Green
        }
    }

    # Check if $InactiveComputerObjects is empty. If it is, Output that no computers are inactive.
    if ($null -eq $InactiveComputerObjects) {
        Write-Host "No inactive computers were found in the `"$SearchOUbase`" search path." -ForegroundColor Green
    } else {
        # Output the number of inactive computers found.
        Write-Host "Found $($InactiveComputerObjects.Count) inactive computers in the `"$SearchOUbase`" search path." -ForegroundColor Red 
    }
# End of Search-InactiveComputers function
}

Function Search-MultipleInactiveComputers {
    <#
    .SYNOPSIS
    Function take in array of hashtables, for each hashtable, run the Search-InactiveComputers function.

    .DESCRIPTION
    === Search for inactive computers. ===
        Search for computers that have been inactive for more than X days; default is 90 days. This can also disable the computer,
        strip all group membership, and move it to the Disabled.Desktop OU. This can be run manually or automated
        via the 'Daliy' option.

        The "SearchOUbase" parameter is the OU to search for inactive computers. "SearchOUbase" must be defined in the 'AD-PowerAdmin_settings.ps1' file.
        The "DisabledOULocal" parameter is the OU to move the inactive computers to. "DisabledOULocal" must be defined in the 'AD-PowerAdmin_settings.ps1' file.

        See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

        !!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

    .EXAMPLE
    Example: Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays 90

    .INPUTS
    Search-InactiveComputers does not take pipeline input.

    .OUTPUTS
    The output is a list of inactive computer accounts.

    .NOTES

    #>

    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [hashtable[]]$InactiveComputersLocations,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=3)]
        [bool]$ReportOnly
    )

    # Foreach hashtable in the $InactiveComputersLocations array, run the Search-InactiveComputers function.
    $InactiveComputersLocations | ForEach-Object {
        Search-InactiveComputers -SearchOUbase $_.SearchOUbase -DisabledOULocal $_.DisabledOULocal -InactiveDays $InactiveDays -ReportOnly $ReportOnly
    }
#End of Search-MultipleInactiveComputers function
}

Function Search-InactiveUsers {
    <#
    .SYNOPSIS
    Function to only search for inactive User accounts and display there SamName and last login date.

    .DESCRIPTION
    ===   Search for inactive Users   ===
    Search for User that have been inactive for more than X days; default is 90 days. This can disable the user,
    strip all group membership, and move it to the Disabled.Users OU. This can be run manually or automated
    via the 'Daliy' option.

    The "SearchBase" parameter is the OU to search for inactive users. "SearchBase" must be defined in the 'AD-PowerAdmin_settings.ps1' file.
    The "DisabledOULocal" parameter is the OU to move the inactive users to. "DisabledOULocal" must be defined in the 'AD-PowerAdmin_settings.ps1' file.

    See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

    !!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

    .EXAMPLE
    Example: Search-InactiveUsers -SearchOUbase 'OU=Users,DC=EXAMPLE,DC=COM' -DisabledOULocal 'OU=Disabled.Users,OU=Users,DC=EXAMPLE,DC=COM' -InactiveDays 90 -ReportOnly $false

    .INPUTS
    Search-InactiveUsers does not take pipeline input.

    .OUTPUTS
    The output is a list of inactive user accounts.

    .NOTES
    Discovered accounts will only be disabled, permission stripped, and moved to the Disabled.Users OU if the $ReportOnly variable is set to false.

    #>

    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SearchOUbase,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$DisabledOULocal,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=4)]
        [bool]$ReportOnly
    )

    # $time variable converts $DaysInactive to LastLogonTimeStamp property format for the -Filter switch to work
    $InactiveDate = (Get-Date).Adddays(-($InactiveDays))

    # Check if the $DisabledOULocal is a valid OU. If not, then exit the function.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $DisabledOULocal} -Properties * ) ) {
        Write-Host "Error: The User OU specified in the DisabledOULocal($DisabledOULocal) does not exist in the AD." -ForegroundColor Red
        Write-Host "       Please update your 'AD-PowerAdmin_settings.ps1' file with the details that match your environment." -ForegroundColor Red
        return
    }

    # Check if the SearchOUbase is a valid OU. If not, then exit the function.
    if ( $null -eq (Get-ADOrganizationalUnit -Filter {distinguishedName -eq $SearchOUbase} -Properties * ) ) {
        Write-Host "Warning: The given SearchOUbase($SearchOUbase) does not exist or is not set. Scanning entire AD..." -ForegroundColor Yellow
        $InactiveUserObjects = Get-ADUser -Filter {LastLogonTimeStamp -lt $InactiveDate -and Enabled -eq $true} -Properties Name, SamAccountName, DistinguishedName, LastLogonDate
    } else {
        # Search for Users that have been inactive for more than X days.
        $InactiveUserObjects = Get-ADUser -Filter {LastLogonTimeStamp -lt $InactiveDate -and Enabled -eq $true} -SearchBase $SearchOUbase -Properties Name, SamAccountName, DistinguishedName, LastLogonDate
    }

    # Check if $InactiveUserObjects is empty. If it is, then no users are inactive.
    if ($null -ne $InactiveUserObjects) {
        # If $DisplayOnly is true, then display the SamName and last login date of the inactive users.
        if ($ReportOnly -eq $true) {
            Write-Host "Inactive User Accounts in: `'$SearchOUbase`'" -ForegroundColor Yellow
            # For each inactive user, display the SamName and last login date.
            $InactiveUserObjects | ForEach-Object {
                # Display the SamName and last login date.
                Write-Host SamName: $_.SamAccountName `-`- Last Login: $_.LastLogonDate `-`- Distinguished Name: `'$_.DistinguishedName`'
            }
            return
        }

        # If $ReportOnly is false, then disable the inactive users.
        if ($ReportOnly -eq $false) {
            # For each inactive user, Disable the User AD object, update the discription, and move the user to the Disabled.Users OU.
            $InactiveUserObjects | ForEach-Object {
                # Current User Object.
                $CurrentUserObject = $_
                # Get the old(currently) set user discription.
                $UserOldDescription = (Get-ADUser -Identity $CurrentUserObject -Prop Description).Description
                # Get the old OU location of the user.
                $UserOldOU = $CurrentUserObject.DistinguishedName
                # Get all groups the user is a member of.
                $UsersGroupMemberships = Get-ADPrincipalGroupMembership $CurrentUserObject.DistinguishedName
                # Foreach group, remove the user from the group.
                $UsersGroupMemberships | ForEach-Object {
                    # If $_.DistinguishedName not equal to "Domain Users" and not equal to "Administrators, then remove the user from the group.
                    if ($_.name -ne 'Domain Users' -and $_.name -ne 'Administrators') {
                        Remove-ADPrincipalGroupMembership -Identity $CurrentUserObject -MemberOf $_.DistinguishedName -Confirm:$False
                    }
                }
                # Disable the user account.
                Disable-ADAccount -Identity $CurrentUserObject -Confirm:$False
                # Update the user discription.
                Set-ADUser -Identity $CurrentUserObject -Description "$UserOldDescription -- Account disabled $(Get-Date -format 'yyyy-MM-dd') by AD-PowerAdmin. :: OLD-OU: $UserOldOU" -Confirm:$False
                # Move the user to the Disabled Users OU.
                Move-ADObject -Identity $CurrentUserObject -TargetPath $DisabledOULocal -Confirm:$False
                # Output the Samname of the user that was disabled.
                Write-Host "Disabled User: $CurrentUserObject.SamAccountName" -ForegroundColor Green
            }
        }
    }

    # Check if $InactiveUserObjects is empty. If it is, Output that no users are inactive.
    if ($null -eq $InactiveUserObjects) {
        Write-Host "No inactive users were found in $SearchOUbase" -ForegroundColor Green
    }
# End of Search-InactiveUsers function
}

Function Search-MultipleInactiveUsers {
    <#
    .SYNOPSIS
    Function take in array of hashtables, for each hashtable, run the Search-InactiveComputers function.

    .DESCRIPTION
    ===   Search for inactive Users   ===
    Search for User that have been inactive for more than X days; default is 90 days. This can disable the user,
    strip all group membership, and move it to the Disabled.Users OU. This can be run manually or automated
    via the 'Daliy' option.

    The "SearchBase" parameter is the OU to search for inactive users. "SearchBase" must be defined in the 'AD-PowerAdmin_settings.ps1' file.
    The "DisabledOULocal" parameter is the OU to move the inactive users to. "DisabledOULocal" must be defined in the 'AD-PowerAdmin_settings.ps1' file.

    See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

    !!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

    .EXAMPLE
    Example: Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays 90 -ReportOnly $false

    .INPUTS
    Search-MultipleInactiveComputers does not take pipeline input.

    .OUTPUTS
    The output is a list of inactive user accounts.

    .NOTES
    Discovered accounts will only be disabled, permission stripped, and moved to the Disabled.Users OU if the $ReportOnly variable is set to false.

    #>
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [hashtable[]]$InactiveUsersLocations,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$InactiveDays,
        [Parameter(Mandatory=$true,Position=3)]
        [bool]$ReportOnly
    )

    # Foreach hashtable in the $InactiveUsersLocations array, run the Search-InactiveComputers function.
    $InactiveUsersLocations | ForEach-Object {
        #If $_.SearchOUbase is empty, then SearchOUbase equals $null.
        if ($_.SearchOUbase -eq '') {
            Search-InactiveUsers -SearchOUbase 'NA' -DisabledOULocal $_.DisabledOULocal -InactiveDays $InactiveDays -ReportOnly $ReportOnly
        } else {
            Search-InactiveUsers -SearchOUbase $_.SearchOUbase -DisabledOULocal $_.DisabledOULocal -InactiveDays $InactiveDays -ReportOnly $ReportOnly
        }
    }
# End of Search-MultipleInactiveUsers function
}

function Search-DisabledADAccountWithGroupMembership {
    <#
    .SYNOPSIS
    This function will search all of AD for accounts that are disabled and still have membership in groups other than the "Domain Users" group.

    .DESCRIPTION
    This function will search all of AD for accounts that are disabled and still have membership in groups other than the "Domain Users" group.

    .EXAMPLE
    Search-DisabledADAccountWithGroupMembership

    .INPUTS
    Search-DisabledADAccountWithGroupMembership does not take pipeline input.

    .OUTPUTS
    The output is a list of disabled AD accounts that are a member of any group other than the "Domain Users" group.

    .NOTES

    #>

    # Search for all disabled AD accounts.
    [Object]$SearchResults = Get-AdUser -Filter "Enabled -eq 'False'" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName
    # Check if the $SearchResults variable is empty.
    if ($null -eq $SearchResults) {
        Write-Host "Error: No disabled AD accounts were found." -ForegroundColor Yellow
        return
    }

    # Loop through each disabled AD account.
    foreach ($DisabledADAccount in $SearchResults) {

        # Get the disabled AD account's groups.
        [Object]$DisabledADAccountGroupMemberships = Get-ADPrincipalGroupMembership -Identity $DisabledADAccount.DistinguishedName

        # Create a list variable to store the disabled AD account's groups.
        [Object]$DisabledADAccountGroupsList = @()
        # Loop through each disabled AD account's group and add it to the $DisabledADAccountGroupsList variable if it is not the "Domain Users" group.
        foreach ($DisabledADAccountGroup in $DisabledADAccountGroupMemberships) {

            # If the disabled AD account is Guest, and the group is the "Guests", or Domain Guests group, then continue to the next group.
            if ($DisabledADAccount.Name -eq 'Guest' -and ($DisabledADAccountGroup.Name -eq 'Guests' -or $DisabledADAccountGroup.Name -eq 'Domain Guests')) { continue }

            # If the disabled AD account is krbtgt, and the group is the "Denied RODC Password Replication Group" group, then continue to the next group.
            if ($DisabledADAccount.Name -eq 'krbtgt' -and $DisabledADAccountGroup.Name -eq 'Denied RODC Password Replication Group') { continue }

            # If the disabled AD account is DefaultAccount, and the group is the "System Managed Accounts Group" group, then continue to the next group.
            if ($DisabledADAccount.Name -eq 'DefaultAccount' -and $DisabledADAccountGroup.Name -eq 'System Managed Accounts Group') { continue }

            # For all other groups that are not the "Domain Users" group, add the group to the $DisabledADAccountGroupsList variable.
            if ($DisabledADAccountGroup.Name -ne 'Domain Users') {
                $DisabledADAccountGroupsList += $DisabledADAccountGroup.Name
            }
        }

        # If the $DisabledADAccountGroupsList is not empty, then display the disabled AD account's groups to the user.
        if ($DisabledADAccountGroupsList -ne '') {
            # Display the disabled AD account's groups to the user.
            Write-Host "The disabled AD account '$($DisabledADAccount.Name)' is a member of the following groups:" -ForegroundColor Red
            $DisabledADAccountGroupsList | Format-List
        }
    }
    return
# End of the Search-DisabledADAccount function.
}

function Search-ADUserAdminCountHighPrivilegedGroups {
    <#
    .SYNOPSIS
    Function to search for AD User accounts with attributes "adminCount" = 1, and check if they are a member of any high privileged groups.

    .DESCRIPTION
    Function that will use Search-ADUserAdminCount to search for all AD User accounts with attributes "adminCount" = 1 and then check if the user is a member of any high privileged groups.
    High privileged groups include Domain Admins, Enterprise Admins, Administrators, Schema Adminsm, Backup Operators, Account Operators, Server Operators,
       Domain Controllers, Print Operators, Replicator, Enterprise Key Admins, and Key Admins.

    .EXAMPLE
    Search-ADUserAdminCountHighPrivilegedGroups

    .INPUTS
    Search-ADUserAdminCountHighPrivilegedGroups does not take pipeline input.

    .OUTPUTS
    None.

    .NOTES

    #>

    $Count = 0

    # Search for all AD User accounts with attributes "adminCount" = 1.
    [Object]$ADUsersWAdmCount = Get-AdUser -Filter "adminCount -eq 1" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName
    # Check if the $SearchResults variable is empty.
    if ($null -eq $ADUsersWAdmCount) {
        continue
    }
    # Create an array of all high privileged groups.
    [array]$HighPrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins", "Backup Operators", "Account Operators", "Server Operators", "Domain Controllers", "Print Operators", "Replicator", "Enterprise Key Admins", "Key Admins")

    # Get all members of the high privileged groups.
    [Object]$HighPrivilegedGroupsMembers = $HighPrivilegedGroups | ForEach-Object {
        Get-ADGroupMember -Identity $_
    }
    # Check if the user is a member of any high privileged groups.
    ForEach ($ADUser in $ADUsersWAdmCount) {
        # Test if the current user is a member of any high privileged groups. If the user is a member of any high privileged groups, then continue to the next user.
        if ($HighPrivilegedGroupsMembers.distinguishedName -contains $ADUser.distinguishedName ) { continue }
        # If the current user name is krbtgt, then continue to the next user.
        if ($ADUser.Name -eq 'krbtgt') { continue }
        # If the loop has not been continued, then the user is not a member of any high privileged groups.
        # The user account attributes "adminCount" = 1 should be cleared.
        # Ask the user if they want to clear the user account attributes "adminCount" = 1.
        Write-Host "The user '$($ADUser.Name)' ('$($ADUser.DistinguishedName)') has attributes 'adminCount' = 1 but is not a member of any high privileged groups." -ForegroundColor Yellow
        [string]$ClearAdminCount = Read-Host "Do you want to clear the user account attributes 'adminCount' = 1? (default=Y, Y/n)"
        # Check if the user wants to clear the user account attributes "adminCount" = 1. If yes, then set the user account attributes "adminCount" = <not set>.
        if ($ClearAdminCount -eq 'Y' -or $ClearAdminCount -eq 'y' -or $ClearAdminCount -eq '') {
            Set-ADUser -Identity $ADUser.DistinguishedName -Clear adminCount
            Write-Host "The user account attributes 'adminCount' = 1 for the user '$($ADUser.Name)' has been cleared." -ForegroundColor Green
        }
        # Increment the $Count variable by 1.
        $Count++
    }
    # If $Count is 0, then no AD Users were found with attributes "adminCount" = 1.
    if ($Count -eq 0) {
        Write-Host "No AD Users were found with attributes 'adminCount' = 1." -ForegroundColor Green
    }
# End of the Search-ADUserAdminCountHighPrivilegedGroups function.
}

function Search-DefaultDomainPolicy {
    <#
    .SYNOPSIS
    # Function to search the Default Domain Policy for a given GPO setting.

    .DESCRIPTION
    Function to search the Default Domain Policy for a given GPO setting.

    .EXAMPLE
    Search-DefaultDomainPolicy

    .INPUTS
    Search-DefaultDomainPolicy does not take pipeline input.

    .OUTPUTS
    The output is a list of GPO settings that match the given GPO setting.

    .NOTES

    #>

    # Ask the user for the GPO setting to search for.
    [string]$GPOSetting = Read-Host "Enter the GPO setting to search for:"
    # Confirm the GPO setting given string is not empty.
    if ($GPOSetting -eq '') {
        Write-Host "Error: The GPO setting given was empty." -ForegroundColor Red
        return
    }
    # Search for the given GPO setting in the Default Domain Policy.
    [Object]$SearchResults = Get-GPRegistryValue -Name $GPOSetting -All -ErrorAction SilentlyContinue
    # Check if the $SearchResults variable is empty.
    if ($null -eq $SearchResults) {
        Write-Host "Error: The GPO setting '$GPOSetting' was not found in the Default Domain Policy." -ForegroundColor Red
        return
    }
    # Display the search results to the user.
    Write-Host "The following GPO settings were found to match in the Default Domain Policy:" -ForegroundColor Yellow
    $SearchResults | Format-List
    return
}

function Search-DisabledObjects {
    <#
    .SYNOPSIS
    A Function that seaches the designated Disabled object OUs from the settings file, and ensure all objects within the folder are disabled. If they are not disabled, then disable them.

    .DESCRIPTION
    A Function that seaches the designated Disabled object OUs from the settings file, and ensure all objects within the folder are disabled. If they are not disabled, then disable them.

    .EXAMPLE
    Search-DisabledObjects

    .INPUTS
    Search-DisabledObjects does not take pipeline input.

    .OUTPUTS
    The output is a list of all objects that were disabled.

    .NOTES

    #>

    # Create a variable to store the number of objects that were disabled.
    [int]$DisabledObjectsCount = 0
    # Loop through each Disabled object OU.
    foreach ($DisabledObjectOU in $global:DisabledObjectOUs) {
        # Search for all objects in the Disabled object OU that are not disabled.
        [Object]$SearchResults = Get-ADObject -Filter "Enabled -eq 'True'" -SearchBase $DisabledObjectOU -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName
        # Check if the $SearchResults variable is empty.
        if ($null -eq $SearchResults) {
            Write-Host "No objects were found in the Disabled object OU '$DisabledObjectOU'." -ForegroundColor Yellow
            continue
        }
        # Loop through each object in the Disabled object OU that is not disabled.
        foreach ($Object in $SearchResults) {
            # Disable the object.
            Disable-ADAccount -Identity $Object.DistinguishedName
            # Increment the $DisabledObjectsCount variable by 1.
            $DisabledObjectsCount++
        }
    }
    # Display the number of objects that were disabled.
    Write-Host "The number of objects that were disabled: $DisabledObjectsCount" -ForegroundColor Yellow
    return
}

function Search-AD {
    <#
    .SYNOPSIS
    Function to search for a given User in Active Directory.

    .DESCRIPTION
    Search AD for a given User, Computer, or Object(everything) based on the object name. The user will be asked if they want to
    search for a User, Computer, or Object. The user will then be asked for the name of the User, Computer, or Object to search
    for. The search will then be performed and the results will be displayed to the user.

    .EXAMPLE
    Example: Search-AD -TextResults $true

    .EXAMPLE
    Example: Search-AD -TextResults $false

    .INPUTS
    # Search-AD does not take pipeline input.

    .OUTPUTS
    Search-AD will output an object of the search results if the $TextResults variable is false. If the $TextResults variable is true, then Search-AD will output the search results in text format.

    .NOTES
    Need to add the ability to search without asking the user for input.

    #>
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [bool]$TextResults
    )
    # Ask the user if they want to search for a computer, user or all objects.
    [string]$SearchType = Read-Host "Do you want to search for a Computer, User or All objects? (Default:A, c/u/A)"
    # Check if the $SearchType is not equal to 'C', 'U', or 'A', or is empty. The check should be case insensitive.
    if ($SearchType -ne 'C' -and $SearchType -ne 'U' -and $SearchType -ne 'A' -and $SearchType -ne 'c' -and $SearchType -ne 'u' -and $SearchType -ne 'a' -or $SearchType -eq '') {
        Write-Host "Warrning: The SearchType given was empty. Defaulting to all Objects" -ForegroundColor Yellow
        $SearchType = 'A'
    }

    # Ask the user for the obect name to search for.
    [string]$AdObect = Read-Host "Enter the name of the User/Computer/Object to search for"

    # Confirm the user given string is not empty.
    if ($AdObect -eq '') {
        Write-Host "Error: Empty search paramater given." -ForegroundColor Red
        return
    }

    # If the user wants to search for a computer, then search for the computer.
    if ($SearchType -eq 'C' -or $SearchType -eq 'c') {
        # Search for the given Computer in Active Directory.
        [Object]$SearchResults = Get-AdComputer -Filter "(Name -like '*$AdObect*') -and (Enabled -eq 'True')" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName
    }

    # If the user wants to search for a user, then search for the user.
    if ($SearchType -eq 'U' -or $SearchType -eq 'u') {
        # Search for the given User in Active Directory.
        [Object]$SearchResults = Get-AdUser -Filter "(Name -like '*$AdObect*') -and (Enabled -eq 'True')" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName
    }

    # If the user wants to search for all objects, then search for the object.
    if ($SearchType -eq 'A' -or $SearchType -eq 'a') {
        # Search for the given Object in Active Directory.
        [Object]$SearchResults = Get-AdObject -Filter "(Name -like '*$AdObect*')" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName
    }

    # Check if the $SearchResults variable is empty.
    if ($null -eq $SearchResults) {
        Write-Host "Error: '$AdObect' was not found in Active Directory." -ForegroundColor Red
        return
    }

    # If the user wants the results in text format, then display the results to the user.
    if ($TextResults) {
        Write-Host "The following objects were found to match in Active Directory:" -ForegroundColor Yellow
        $SearchResults | Format-List
        return
    }
    # If the user wants the results in a object format, then return the results to the user.
    return $SearchResults
# End of the Search-ADUser function.
}

function Start-DailyInactiveUserAudit {
    <#
    .SYNOPSIS
    Function to start the daily inactive user audit if enabled.

    .DESCRIPTION
    Function to start the daily inactive user audit.

    .EXAMPLE
    Start-DailyInactiveUserAudit

    .NOTES

    #>

    # Check if the $global:InactiveUserAudit is set to $true. If it is, then run the Search-MultipleInactiveUsers function.
    if ($global:InactiveUserAudit -eq $true) {
        # Run the function to search for inactive users.
        Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $false
    }
# End of Start-DailyInactiveUserAudit function
}

function Start-DailyInactiveComputerAudit {
    <#
    .SYNOPSIS
    Function to start the daily inactive computers audit if enabled.

    .DESCRIPTION
    Function to start the daily inactive computers audit.

    .EXAMPLE
    Start-DailyInactivecomputersAudit

    .NOTES

    #>

    # Check if the $global:InactiveComputerAudit is set to $true. If it is, then run the Search-MultipleInactiveComputers function.
    if ($global:InactiveComputerAudit -eq $true) {
        # Run the function to search for inactive computers.
        Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $global:InactiveDays -ReportOnly $false
    }
# End of Start-DailyInactiveUserAudit function
}

Function Test-ADSecurityBestPractices {
    <#
    .SYNOPSIS
    Function containing test for security best practices in Active Directory.

    .DESCRIPTION
    This audit will look for many small security and best practices recommendations. Most of the tests are simple but could leave an AD server open to attack.

    Test performed include the following
        - AD Password Policy review.
        - Audit AD objects that pose a risk of DCSync attack.
        - Find, w/ option to fix, unprivileged accounts with "adminCount=1" attribute set.
            REF Link: https://cybergladius.social/@CyberGladius/109649278142902592
        - Users and computers with non-default Primary Group IDs(A method of hiding backdoor accounts).
        - Disabled accounts with Group Membership other than 'Domain Users' group.
        - Computers in the default "Computers" folder. Unsorted computers will likely be missing GPOs.

    .EXAMPLE
    Test-ADSecurityBestPractices

    .INPUTS
    Test-ADSecurityBestPractices does not take pipeline input.

    .OUTPUTS
    The output is a list of security best practices in Active Directory.

    .NOTES

    #>

    # Ask the user if they want to save the results to a text file. If yes, then start the transcript and save the results to a text file current directory with the name "ADSecurityBestPracticesTestResults_<DATETIME>.txt".
    [string]$SaveResults = Read-Host "Do you want to save the results to a text file? (default=Y, Y/n)"
    if ($SaveResults -eq 'Y' -or $SaveResults -eq 'y' -or $SaveResults -eq '') {
        Start-Transcript -Path "$global:ReportsPath\ADSecurityBestPracticesTestResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
    }

    # Test for the AD Password Policy.
    Write-Host "Testing the AD Password Policy" -ForegroundColor White
    Test-PasswordPolicy
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for DCSync permissions.
    Write-Host "The following AD Objects have DCSync permissions and could be used to perform a DCSync Attack." -ForegroundColor Yellow
    Write-Host "Some or all of these AD Objects with DCSync permissions may be completely expected, depend on your environment." -ForegroundColor Yellow
    Search-DcSyncRisk -ReturnAcl | Out-AclDetailsLite
    Write-Host "======================================================================================" -ForegroundColor White

    # Check for high risk permissions.
    Write-Host "The following AD Objects have high risk permissions." -ForegroundColor Yellow
    Search-HighRiskAdAce -ReturnAcl | Out-AclDetailsLite
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for Unprivileged accounts with adminCount=1, use the Search-ADUserAdminCountHighPrivilegedGroups function.
    Write-Host "Testing for Unprivileged accounts with adminCount=1" -ForegroundColor Yellow
    Search-ADUserAdminCountHighPrivilegedGroups
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for Usersand computerswith non-default Primary Group IDs
    Write-Host "Testing for Users and computers with non-default Primary Group IDs" -ForegroundColor Yellow
    Search-ADUserNonDefaultPrimaryGroup
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for Disabled accounts with Group Membership other than "Domain Users" group.
    Write-Host "Testing for Disabled accounts with Group Membership other than 'Domain Users' group" -ForegroundColor Yellow
    Search-DisabledADAccountWithGroupMembership
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for Computers in the default "Computers" folder.
    Write-Host "Testing for Computers in the default 'Computers' folder" -ForegroundColor Yellow
    Write-Host "Systems in the default 'Computers' folder are likely missing GPOs since they are not organized into a specific OU; thus, security holes." -ForegroundColor Yellow
    Get-ADComputerInDefaultFolder
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for inactive users.
    Write-Host "Testing for inactive users" -ForegroundColor Yellow
    Search-MultipleInactiveUsers -InactiveUsersLocations $global:InactiveUsersLocations -InactiveDays $global:InactiveDays -ReportOnly $true
    Write-Host "======================================================================================" -ForegroundColor White

    # Test for inactive computers.
    Write-Host "Testing for inactive computers" -ForegroundColor Yellow
    Search-MultipleInactiveComputers -InactiveComputersLocations $global:InactiveComputersLocations -InactiveDays $global:InactiveDays -ReportOnly $true
    Write-Host "======================================================================================" -ForegroundColor White

    # Run a password audit. This test uses the Get-PasswordAuditAdminReport function from the "AD-PowerAdmin_PasswordAudit.psm1" module.
    Write-Host "Running a password audit" -ForegroundColor Yellow
    Get-PasswordAuditAdminReport

    # Stop the transcript.
    if ($SaveResults -eq 'Y' -or $SaveResults -eq 'y' -or $SaveResults -eq '') {
        Stop-Transcript -ErrorAction:SilentlyContinue | Out-Null
    }
# End of Test-ADSecurityBestPractices function
}

Function Test-PasswordPolicy {
    <#
    .SYNOPSIS
    Function to test the AD Password Policy.

    .DESCRIPTION
    Get the current domain password policy settings, then review the settings and display any settings that are not set to the recommended values.

    .EXAMPLE
    Test-PasswordPolicy

    .INPUTS
    Test-PasswordPolicy does not take pipeline input.

    .OUTPUTS
    None.

    .NOTES

    #>

    $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy

    # Check if the $PasswordPolicy variable is empty.
    if ($null -eq $PasswordPolicy) {
        Write-Host "Error: The Password Policy was not found." -ForegroundColor Red
        return
    }

    # Check if the Password Policy settings are set to the recommended values.
    # Check if the Password Policy setting "ComplexityEnabled" is set to $true.
    if ($PasswordPolicy.ComplexityEnabled -eq $true) {
        Write-Host "The Password Policy setting 'ComplexityEnabled' is set to $($PasswordPolicy.ComplexityEnabled). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'ComplexityEnabled' is set to $($PasswordPolicy.ComplexityEnabled). This should be set to true." -ForegroundColor Red
    }

    # Check if the Password Policy setting "LockoutDuration" is set to 00:00:30.
    if ($PasswordPolicy.LockoutDuration -le '00:30:00') {
        Write-Host "The Password Policy setting 'LockoutDuration' is set to $($PasswordPolicy.LockoutDuration). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'LockoutDuration' is set to $($PasswordPolicy.LockoutDuration). This should be set to 00:00:30." -ForegroundColor Red
    }

    # Check if the Password Policy setting "LockoutObservationWindow" is set to 00:00:30.
    if ($PasswordPolicy.LockoutObservationWindow -le '00:30:00') {
        Write-Host "The Password Policy setting 'LockoutObservationWindow' is set to $($PasswordPolicy.LockoutObservationWindow). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'LockoutObservationWindow' is set to $($PasswordPolicy.LockoutObservationWindow). This should be set to 00:00:30." -ForegroundColor Red
    }

    # Check if the Password Policy setting "LockoutThreshold" is set to 5.
    if ($PasswordPolicy.LockoutThreshold -le 5) {
        Write-Host "The Password Policy setting 'LockoutThreshold' is set to $($PasswordPolicy.LockoutThreshold). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'LockoutThreshold' is set to $($PasswordPolicy.LockoutThreshold). This should be set to 5." -ForegroundColor Red
    }

    # Check if the Password Policy setting "MaxPasswordAge" is set to 42.
    if ($PasswordPolicy.MaxPasswordAge -le '90.00:00:00') {
        Write-Host "The Password Policy setting 'MaxPasswordAge' is set to $($PasswordPolicy.MaxPasswordAge). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'MaxPasswordAge' is set to $($PasswordPolicy.MaxPasswordAge)." -ForegroundColor Yellow
    }
    Write-Host "The Password Policy setting 'MaxPasswordAge' recommendations have changed recently(2022)." -ForegroundColor Yellow
    Write-Host "    We no longer suggest forcing users to update their passwords every 90-days." -ForegroundColor Yellow
    Write-Host "    If you want to know more read here: https://cybergladius.com/password-policy-best-practices-in-2023/" -ForegroundColor Yellow

    # Check if the Password Policy setting "MinPasswordAge" is set to 1.
    if ($PasswordPolicy.MinPasswordAge -ge '1.00:00:00') {
        Write-Host "The Password Policy setting 'MinPasswordAge' is set to $($PasswordPolicy.MinPasswordAge). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'MinPasswordAge' is set to $($PasswordPolicy.MinPasswordAge). This should be set to 1." -ForegroundColor Red
    }

    # Check if the Password Policy setting "MinPasswordLength" is set to 14.
    if ($PasswordPolicy.MinPasswordLength -ge 14) {
        Write-Host "The Password Policy setting 'MinPasswordLength' is set to $($PasswordPolicy.MinPasswordLength). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'MinPasswordLength' is set to $($PasswordPolicy.MinPasswordLength). This should be set to 14." -ForegroundColor Red
    }

    # Check if the Password Policy setting "PasswordHistoryCount" is set to 24.
    if ($PasswordPolicy.PasswordHistoryCount -ge 24) {
        Write-Host "The Password Policy setting 'PasswordHistoryCount' is set to $($PasswordPolicy.PasswordHistoryCount). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'PasswordHistoryCount' is set to $($PasswordPolicy.PasswordHistoryCount). This should be set to 24." -ForegroundColor Red
    }

    # Check if the Password Policy setting "ReversibleEncryptionEnabled" is set to $false.
    if ($PasswordPolicy.ReversibleEncryptionEnabled -eq $false) {
        Write-Host "The Password Policy setting 'ReversibleEncryptionEnabled' is set to $($PasswordPolicy.ReversibleEncryptionEnabled). Good!" -ForegroundColor Green
    } else {
        Write-Host "The Password Policy setting 'ReversibleEncryptionEnabled' is set to $($PasswordPolicy.ReversibleEncryptionEnabled). This should be set to false." -ForegroundColor Red
    }

# End of Test-PasswordPolicy function
}