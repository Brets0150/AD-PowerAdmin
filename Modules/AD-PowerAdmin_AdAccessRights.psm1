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
    $global:Menu.Remove('HighRiskAd-AceAudit')
    $global:Menu.Remove('DCSyncRiskAclAudit')

    # Append $global:Menu with the menu items to be displayed.
    $global:Menu += @{
        'HighRiskAd-AceAudit' = @{
            Title    = "Audit High Risk Ad-ACE"
            Label    = "Audit AD objects with high risk ACEs on the root domain."
            Module   = "AD-PowerAdmin_AdAccessRights"
            Function = "Search-HighRiskAdAce"
            Command  = "Search-HighRiskAdAce"
        }
        'DCSyncRiskAclAudit' = @{
            Title    = "Audit DCSync Risk ACEs"
            Label    = "Audit AD objects with DCSync rights ACEs on the root domain."
            Module   = "AD-PowerAdmin_AdAccessRights"
            Function = 'Search-DcSyncRisk'
            Command  = 'Search-DcSyncRisk'
        }
    }
}

Initialize-Module

Function Get-AdGuids {
    <#
    .SYNOPSIS
        Function to build a vaiable containing AD GUIDs, their human-readable name, and their objectClass.

    .DESCRIPTION
        Build an array of hashtables containing AD GUIDs, their human-readable name, and their objectClass. The array is then used to look up ObjectTypes/Permissions/PermissionSets/ExtentedRight name from its GUID.
        There are three types of objectClasses that we are looking for:
            1. controlAccessRight: These are the ExtendedRights.
            2. attributeSchema: These are the Object attributes, but confusingly, the attributes every object has(like a User will have a "Phone Number" attribute on their AD user object) are also themself objects.
            3. classSchema: These are the Object types(aka objectClass(es)), like User, Group, OU, etc.

    .EXAMPLE
        PS> $AdGuids = Get-AdGuids

        PS> $AdGuids | Where-Object { $_.GUID -eq '9432c620-033c-4db7-8b58-14ef6d0bf477' }
            GUID                                 Name                ObjectClass
            ----                                 ----                -----------
            9432c620-033c-4db7-8b58-14ef6d0bf477 Refresh-Group-Cache controlAccessRight

    .NOTES

    #>

    # Creating an empty dictionary
    [array]$GuidDictionary = @()
    $SchemaIDGuids = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -LDAPFilter '(SchemaIDGUID=*)' -Properties Name, SchemaIDGUID, ObjectClass
    $ExtendedRights = Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -LDAPFilter '(ObjectClass=controlAccessRight)' -Properties Name, RightsGUID, ObjectClass

    ForEach($SchemaIDGuid in $SchemaIDGuids) {
        try {
            [PSCustomObject]$Item = [ordered]@{
                GUID        = [GUID]$SchemaIDGuid.SchemaIDGUID
                Name        = [string]$SchemaIDGuid.Name
                ObjectClass = [string]$SchemaIDGuid.ObjectClass
            }
            $GuidDictionary += [PSCustomObject]$Item
            # Clear-Variable Item
        }
        catch {
            <# Didn't put anything here because I just want a silent error when building the hashtable. #>
            Write-host "Encountered Error:"$_.Exception.Message -ForegroundColor red
        }
    }

    ForEach($ExtendedRight in $ExtendedRights) {
        try {
            [PSCustomObject]$Item = [ordered]@{
                GUID        = [GUID]$ExtendedRight.RightsGUID
                Name        = [string]$ExtendedRight.Name
                ObjectClass = [string]$ExtendedRight.ObjectClass
            }
            $GuidDictionary += [PSCustomObject]$Item
            # Clear-Variable Item
        }
        catch {
            <# Didn't put anything here because I just want a silent error when building the hashtable. #>
            Write-host "Encountered Error:"$_.Exception.Message -ForegroundColor red
        }
    }

    try {
        # Add the "All" GUID to the dictionary. This is so we can lookup the "All" permissions. This is not a real GUID.
        # This GUID is found in the out put of many command variable built into PowerShell, but it always implies a wildcard; so "All" or "any".
        [PSCustomObject]$Item = [ordered]@{
            GUID        = [GUID]"00000000-0000-0000-0000-000000000000"
            Name        = [string]"All"
            ObjectClass = [string]"Any"
        }
        $GuidDictionary += [PSCustomObject]$Item
        #Clear-Variable Item
    }
    catch {
        <# Didn't put anything here because I just want a silent error when building the hashtable. #>
        Write-host "Encountered Error:"$_.Exception.Message -ForegroundColor red
    }

    # Return the dictionary
    return $GuidDictionary

# End of Get-AdGuids function
}

Function Get-AdAcl {
    <#
    .SYNOPSIS
    Function to get a Active Directory object ACL.

    .DESCRIPTION
    This function gets Active Directory(AD) ACL of an object. It uses the "Get-ACL" cmdlet, but creates AD specific data for each ACE in the ACL.
    If the -AdObjectPath parameter is empty, then the root domain object is used. If the -AdObjectPath parameter is not empty, then the ACL from the object is used.

    .PARAMETER AdObjectPath
    The distinguished name of the AD object to get the ACL from. If empty, then the root domain object is used.

    .EXAMPLE
    $DomainAcl = Get-AdAcl
    $OUAcl = Get-AdAcl -AdObjectPath "OU=Network.Groups,DC=acme,DC=com"

    .OUTPUTS
    The output is an array of ACE HashTables.

    Example Output on one ACE HashTable within the array:
        AceApplicableTo       : DC=acme,DC=com
        IdentityReference     : ACME\Enterprise Key Admins
        ActiveDirectoryRights : ReadProperty, WriteProperty
        InheritanceType       : All
        ObjectType            : 5b47d60f-6090-40b2-9f37-2a4de88f3063
        InheritedObjectType   : 00000000-0000-0000-0000-000000000000
        ObjectFlags           : ObjectAceTypePresent
        AccessControlType     : Allow
        IsInherited           : False
        InheritanceFlags      : ContainerInherit
        PropagationFlags      : None

    .NOTES

    #>
    # Parameter
    Param(
        [Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$true)]
        [string]$AdObjectPath
    )

    Begin {
        # Check is the $AdObjectPath is empty. If it is empty, then display a warning and set the $AdObjectPath to the root domain object.
        if ($null -eq "$AdObjectPath" -or "$AdObjectPath" -eq '') {
            # Write-Host "The AdObjectPath parameter is empty, defaulting to root domain object..." -ForegroundColor yellow
            [string]$AdObjectPath = "$($(Get-ADDomain).DistinguishedName)"
        }

        # Try to Get-ADObject the $AdObjectPath. If empty, or some other data curruption, then catch the error and throw a terminating error.
        try {
            # Check if the $AdObjectPath is a distinguished name that exists in AD. If it is not, then an error message and exit the function.
            if (-not ( Get-ADObject -Filter { DistinguishedName -eq $AdObjectPath } ) ) {
                # If this error, then the object does not exist in AD.
                throw "Error: The AdObjectPath parameter is not a distinguished name that exists in AD!"
            }
        }
        catch {
            # If this error, then $AdObjectPath is empty or the data is improperly formatted.
            throw "Error: The data in the AdObjectPath parameter is empty or improperly formatted!"
        }

        # Get the Domain distinguished path.
        # $AdPath = "AD:$($(Get-ADDomain).DistinguishedName)"
        $AdPath = "AD:$($AdObjectPath)"

        # Get the access control list (ACL) for the specified Active Directory path
        $ACL = Get-Acl "$AdPath"

        # Check if the ACL is empty. If it is, then an error message and exit the function.
        if ($null -eq $ACL) {
            throw "Error: Get-Acl on the AD object, `"$($AdObjectPath)`", failed!"
        }

        # initialize an array to hold the ACEs HashTables.
        [array]$AdAcl = @()
    }
    Process{
        # For each ACE in the ACL, add to a Hashtable ACE, then add that hashtable to the $AdAcl array.
        foreach ($ACE in $ACL.Access) {
            [PSCustomObject]$ACE = [ordered]@{
                AceApplicableTo       = $AdObjectPath
                IdentityReference     = $ACE.IdentityReference
                ActiveDirectoryRights = $ACE.ActiveDirectoryRights
                InheritanceType       = $ACE.InheritanceType
                ObjectType            = $ACE.ObjectType
                InheritedObjectType   = $ACE.InheritedObjectType
                ObjectFlags           = $ACE.ObjectFlags
                AccessControlType     = $ACE.AccessControlType
                IsInherited           = $ACE.IsInherited
                InheritanceFlags      = $ACE.InheritanceFlags
                PropagationFlags      = $ACE.PropagationFlags
            }
            $AdAcl += [PSCustomObject]$ACE
        }
    }
    End {
        # Return the $AdAcl array.
        return $AdAcl
    }
# End of Get-AdAcl function
}

function Get-ExtendedAcl {
    <#
    .SYNOPSIS
    Function to get convert the output of the Get-AdAcl function to a human readable format and add additional data to each ACE, including an explanation of what the ACE does.

    .DESCRIPTION
    This function will take the output of the Get-AdAcl function and deobfuscates and expand the data within each ACE of the ACL.
    The goal is to make the ACL human readable and easier to each ACE understandable.

    For more information on how ACEs work, see the following links:
        URL: https://cybergladius.com/the-active-directory-access-control-list-explained/

    What ACE data is added or expanded apon by using this functions?
    - Basic ACE information.
        0. AceApplicableTo: The AD object that the ACE is applied to.
        1. IdentityReference: The account name that the ACE is applied to. Name changed to 'SecurityPrincipal' for clarity.
        2. ActiveDirectoryRights: The rights that the ACE is granting. Name changed to 'AdRight' for clarity.
        3. ObjectType: The object type that the ACE is granting rights to. Name changed to 'RightObjectGuid' for clarity.
        4. AccessControlType: The type of access that the ACE is granting. Name changed to 'Access' for clarity.
        5. InheritanceType: The type of inheritance that the ACE is granting. Name changed to 'Inheritance' for clarity.
        6. InheritedObjectType: The object type that the ACE is inherited to. Name changed to 'InheritedObjectTypeGuid' for clarity.
        7. InheritanceFlags: The inheritance flags that the ACE is granting. Name unchanged.
        8. PropagationFlags: The propagation flags that the ACE is granting. Name unchanged.

    - Extended ACE information.
        1. SecurityPrincipalMembers: The members of the IdentityReference that can leverage the ACE. AKA: IdentityReference == Administrators, Get all members of the Administrators group.
        2. Explanation: A human readable explanation of how the ACE works. What the ACE is granting, to what object, and what object type.
        3. Convert the RightObjectGuid/ObjectType to its human readable name.
        4. Convert the InheritedObjectTypeGuid/InheritedObjectType to its human readable name.
        5. Remove extraneous data from the ACE. Example: Remove ObjectFlags, InheritanceFlags, PropagationFlags. These are not needed for the explanation of how the ACE works.

    Process the ACL passed to this function, and foreach ACE in the ACL, do the following:
        1. Look up the SecurityPrincipal(IdentityReference) in AD and get the AD object details. If the SecurityPrincipal is not in AD, show an error and then pass.
            SecurityPrincipal with "NT AUTHORITY" in their name will be passed. Example: "NT AUTHORITY\SYSTEM" and "NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS". There is no way(that I know of) to get the AD object for these accounts.
        2. Convert the "ObjectTypes/Permissions/PermissionSets/ExtentedRight" GUID to its human readable name using the Get-AdGuids function output.
        3. Look up the InheritedObjectTypeGuid/InheritedObjectType in the Get-AdGuids function output and convert it to its human readable name.
        4. Based on the Inheritance/InheritanceType and type is RightObjectGuid values, build a explanation of how the ACE works.
        5. If the SecurityPrincipal is a group then get all members of the group and add them to the $SecurityPrincipalMembers variable.
           NOTE: This is a recursive function. If the group has groups as members, then it will get all members of the group and add them to the $SecurityPrincipalMembers variable.
        6. Create a new ACE hashtable object and add the ACE details we gathered to the object.
        7. Add the new ACE hashtable object to the $ExtendedAcl array variable.
        8. After processing all ACEs in the ACL, return the $ExtendedAcl array variable.

        Vocabulary:
        - ACE = Access Control Entry. The ACE contains a permission/right for a security principal(another AD object; aka User, Group, ect..) over an object.
                Example ACE: "Domain Admins" has "GenericAll" permission over the "Domain Admins" group.
        - ACL = Access Control List. An ACL is a list of ACEs on an object. In this function, we get the ACL on the root of the AD domain; aka 1 ACL.
        - ACEs = Access Control Entries. The ACL is a list of ACEs. Just meaning multiple.
        - ACLs = Access Control Lists. Not applicable to this function, since we are only getting the ACL on the root of the domain; aka 1 ACL at a time.
        - Security Principal = Another authenticated AD object; aka User, Group, ect..
        - Inheritance = The ACE is inherited to another AD object. The ACE is not directly applied to the AD object.
        - InheritanceType = The type of inheritance that the ACE is granting. Example: "None", "Descendents", "All", "Children", "SelfAndChildren".
        - InheritanceFlags = The inheritance flags that the ACE is granting. Ignore this value and just use the $Inheritance/InheritanceType variable and its definitions.
        - PropagationFlags = The propagation flags that the ACE is granting. Ignore this value and just use the $Inheritance/InheritanceType variable and its definitions.
        - InheritedObjectType = The object type that the ACE is inherited to. Example: Group, User, Computer, ect...
        - InheritedObjectTypeGuid = The object type that the ACE is inherited to. Example: "bf967aba-0de6-11d0-a285-00aa003049e2" = Group, "bf967a9c-0de6-11d0-a285-00aa003049e2" = User, ect...
        - SecurityPrincipalMembers = The members of the IdentityReference that the ACE is inherited to. AKA: The members of the group that the ACE is inherited to based on the InheritanceType.
        - RightObjectGuid = Another name for ObjectType. A ObjectTypes/Permissions/PermissionSets/ExtentedRight GUID.
        - AdRights = The rights that the ACE is granting. Example: "GenericAll", "GenericWrite", "WriteDacl", ect...
        - Access = The type of access that the ACE is granting. Example: "Allow", "Deny".


    .Parameter ACL (Mandatory)
    The output of the Get-AdAcl function; an array of ACE hashtables.

    .Parameter IncludeOldName (Optional)
    Include the old name used in the original ACE in the output. Basically, keep the IdentityReference property name as "IdentityReference" instead of changing it to "SecurityPrincipal".
    Without this switch, the output only shows important data and is easier to read.
    Default is $false.

    .Parameter IncludeSpecialIdentities (Optional)
    Include special identities in the output. Special identities are accounts that are not AD objects, but are used in ACEs. Such as "Everyone", "CREATOR OWNER", "CREATOR GROUP", and "NT AUTHORITY\*".
    Default is $false.

    .EXAMPLE
    PS> Get-ExtendedAcl -ACL (Get-AdAcl)
    PS> $ExtendedAcl = Get-AdAcl | Get-ExtendedAcl

    .INPUTS
    This function accepts an array of Active Directory ACE hashtables; output or the filtered output of the Get-AdAcl function.

    .OUTPUTS
    An array variable with netsted hashtables of the ACL with the added/expanded ACE data. The nested hashtables contains the extended ACEs and inside that hashtable there is another hashtable of the SecurityPrincipalMembers.

    Example of ONE ACE Hashtable embedded in the array variable:

    PS> Get-AdAcl -AdObjectPath 'OU=Network.Groups,DC=acme,DC=com' | Get-ExtendedAcl

        AceApplicableTo          : OU=Network.Groups,DC=acme,DC=com
        SecurityPrincipal        : BUILTIN\Pre-Windows 2000 Compatible Access
        AdRights                 : ListChildren
        Access                   : Allow
        RightObjectName          : All
        IsInherited              : True
        Inheritance              : All
        InheritedObjectTypeName  : Any
        ExplainAce               : The "BUILTIN\Pre-Windows 2000 Compatible Access" group has Allow ListChildren rights to "All" objects, object attributes, and ExtendedRights on
                                "OU=Network.Groups,DC=acme,DC=com", and all child descendent objects of "OU=Network.Groups,DC=acme,DC=com", with the AD objectClass of "Any".
        SecurityPrincipalMembers : {@{SamAccountName=FL-222$; DistinguishedName=CN=FL-222,OU=Domain Controllers,DC=acme,DC=com; ObjectType=computer; RightObjectName=All; AdRights=ListChildren;
                                InheritedRightFrom=BUILTIN\Pre-Windows 2000 Compatible Access; AceApplicableTo=OU=Network.Groups,DC=acme,DC=com}}

    PS> Get-AdAcl -AdObjectPath 'OU=Network.Groups,DC=acme,DC=com' | Get-ExtendedAcl -IncludeOldName

        AceApplicableTo          : OU=Network.Groups,DC=acme,DC=com
        SecurityPrincipal        : BUILTIN\Pre-Windows 2000 Compatible Access
        IdentityReference        : BUILTIN\Pre-Windows 2000 Compatible Access
        AdRights                 : ListChildren
        ActiveDirectoryRights    : ListChildren
        Access                   : Allow
        AccessControlType        : Allow
        RightObjectName          : All
        RightObjectGuid          : 00000000-0000-0000-0000-000000000000
        ObjectType               : 00000000-0000-0000-0000-000000000000
        IsInherited              : True
        Inheritance              : All
        InheritanceType          : All
        InheritanceFlags         : ContainerInherit
        PropagationFlags         : None
        InheritedObjectTypeGuid  : 00000000-0000-0000-0000-000000000000
        InheritedObjectTypeName  : Any
        ExplainAce               : The "BUILTIN\Pre-Windows 2000 Compatible Access" group has Allow ListChildren rights to "All" objects, object attributes, and ExtendedRights on
                                "OU=Network.Groups,DC=acme,DC=com", and all child descendent objects of "OU=Network.Groups,DC=acme,DC=com", with the AD objectClass of "Any".
        SecurityPrincipalMembers : {@{SamAccountName=FL-222$; DistinguishedName=CN=FL-222,OU=Domain Controllers,DC=acme,DC=com; ObjectType=computer; RightObjectName=All; AdRights=ListChildren;
                                InheritedRightFrom=BUILTIN\Pre-Windows 2000 Compatible Access; AceApplicableTo=OU=Network.Groups,DC=acme,DC=com}}

    .NOTES

    #>
    # Parameters
    Param(
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)]
        [array]$ACL,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$false)]
        [switch]$IncludeOldName,
        [Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$false)]
        [switch]$IncludeSpecialIdentities
    )

    Begin {
        # Get the current Domains A "revision level", "identifier authority", and "domain identifier" and put the whole value in a string variable that would match the begining of a SID format.
        $DomainSID = (Get-ADDomain).DomainSID.Value

        # Create a dictionary of GUIDs and their names.
        $AdGuids = Get-AdGuids

        # Define the $ExtendedAcl variable as a hashtable. This will be the output of this function.
        [array]$ExtendedAcl = @()
    }

    Process {

        # Check if the ACL is empty. If it is, then an error message and exit the function.
        if ($null -eq $ACL) {
            Write-Host "Error: The ACL parameter is empty." -ForegroundColor Red
            return
        }
        foreach ($ACE in $ACL) {
            # Check if the ACL is empty. If it is, then an error message and exit the function.
            if ($null -eq $ACE) {
                Write-Host "Error: The ACL contains empty ACE." -ForegroundColor Red
                return
            }
        }

        # Foreach ACE in the ACL, get the ACE details and add it to the $ExtendedAcl variable.
        ForEach ( $ACE in $ACL ) {
            # Set basic ACE information.

            # Setting the variables to the ACE properties.
            # I know this is pointless and I could just use the $ACE.<property>, but this allows me to change the variable names to ones that are not so concusing.
            [string]$AceApplicableTo         = $ACE.AceApplicableTo # AKA: The AD object that the ACE is applied to.
            [string]$SecurityPrincipal       = $ACE.IdentityReference # AKA: Account/ad-object name.
            [string]$AdRights                = $ACE.ActiveDirectoryRights # AKA: WriteProperty, ReadProperty, ExtendedRight, ect...
            [string]$RightObjectGuid         = $ACE.ObjectType # AKA: object rights attribute
            [string]$Access                  = $ACE.AccessControlType # AKA: Allow or Deny
            [string]$IsInherited             = $ACE.IsInherited # AKA: True or False
            [string]$Inheritance             = $ACE.InheritanceType # AKA: None, Descendents, All, Children, SelfAndChildren
            [string]$InheritedObjectTypeGuid = $ACE.InheritedObjectType # AKA: The object type that the ACE is inherited to; Group, User, Computer, ect...
            [string]$InheritanceFlags        = $ACE.InheritanceFlags # Ignore this value and just use the $Inheritance(InheritanceType) variable and its definitions.
            [string]$PropagationFlags        = $ACE.PropagationFlags # Ignore this value and just use the $Inheritance(InheritanceType) variable and its definitions.
            [bool]$SpecialSecurityPrincipal  = $false
            [bool]$ExpandSecurityPrincipal   = $true
            [array]$SecurityPrincipalMembers = @() # AKA: The members of the IdentityReference that the ACE is inherited to.
            [hashtable]$NewAce               = @{}

            ########
            # Step 1
            # If the $SecurityPrincipal contains the Domain SID, then get the AD object by using the ObjectSid.
            # In my experiance, if the IdentityReference is a SID, then it is a deleted object.
            If ($SecurityPrincipal -like "*$DomainSID*") {
                $SecurityPrincipalAdObject = Get-ADObject -Filter {ObjectSid -eq $SecurityPrincipal} -Properties SamAccountName, DistinguishedName, ObjectClass -ErrorAction SilentlyContinue
            }

            # If the $SecurityPrincipal does not contain the Domain SID, then split the account name into domain account name.
            # Data Example: "Domain\AccountName"
            If ($SecurityPrincipal -notlike "*$DomainSID*") {

                # If $SkipSpecialIdentity is true then skip the special accounts.
                if (-not $IncludeSpecialIdentities) {
                    # Skip the special accounts.
                    # 'NT AUTHORITY\*'
                    if ( "$SecurityPrincipal" -like 'NT AUTHORITY\*' ) {
                        continue
                    }
                    # 'Everyone'
                    if ( "$SecurityPrincipal" -eq 'Everyone' ) {
                        continue
                    }
                    # "CREATOR OWNER"
                    if ( "$SecurityPrincipal" -eq 'CREATOR OWNER' ) {
                        continue
                    }
                    # "CREATOR GROUP"
                    if ( "$SecurityPrincipal" -eq 'CREATOR GROUP' ) {
                        continue
                    }
                }

                # If this far then we are going to process special identity $SecurityPrincipal groups and users.
                #   These special identities are not AD objects, so we need to create a fake AD object for them.
                #   There is not a good way to fully process these special identities, so we will just add the basic information to the $NewAce hashtable and move on.
                #   If you have a better way to process these special identities, please let me know.

                # 'NT AUTHORITY\*'
                if ( "$SecurityPrincipal" -like 'NT AUTHORITY\*' ) {
                    $Domain, $SamAccountName = $SecurityPrincipal -split '\\', 2
                    [bool]$SpecialSecurityPrincipal       = $true
                    [string]$SpecialSecurityPrincipalType = $SecurityPrincipal
                    # This turns off any commands that try to lookup the everyone account in AD and try to find memebers of the everyone group; because it does not exist.
                    [bool]$ExpandSecurityPrincipal        = $false
                    # The "Everyone" account is not a AD object, so we need to create a fake AD object for it.
                    [PSCustomObject]$SecurityPrincipalAdObject = @{
                        SamAccountName    = $SamAccountName
                        DistinguishedName = "CN=$($SamAccountName),CN=Builtin,$($((Get-ADDomain).DistinguishedName).ToString())"
                        ObjectClass       = 'group'
                    }
                }

                # 'Everyone'
                # The "Everyone" account is not a AD object, so we need to create a fake AD object for it.
                # ACE with this account will disable the $ExpandSecurityPrincipal code.
                # Meanning will will not try to lookup the everyone account in AD and try to find memebers of the everyone group; because it does not exist.
                if ( "$SecurityPrincipal" -eq 'Everyone' ) {
                    [bool]$SpecialSecurityPrincipal       = $true
                    [string]$SpecialSecurityPrincipalType = $SecurityPrincipal
                    # This turns off any commands that try to lookup the everyone account in AD and try to find memebers of the everyone group; because it does not exist.
                    [bool]$ExpandSecurityPrincipal        = $false
                    # The "Everyone" account is not a AD object, so we need to create a fake AD object for it.
                    [PSCustomObject]$SecurityPrincipalAdObject = @{
                        SamAccountName    = 'Everyone'
                        DistinguishedName = "CN=Everyone,CN=Builtin,$($((Get-ADDomain).DistinguishedName).ToString())"
                        ObjectClass       = 'group'
                    }
                }

                # "CREATOR OWNER"
                if ( "$SecurityPrincipal" -eq 'CREATOR OWNER' ) {
                    [bool]$SpecialSecurityPrincipal = $true
                    [string]$SpecialSecurityPrincipalType = $SecurityPrincipal
                    [string]$SecurityPrincipal = $(Get-ADObject -Identity $AceApplicableTo -Properties *).nTSecurityDescriptor.Owner
                }

                # "CREATOR GROUP"
                if ( "$SecurityPrincipal" -eq 'CREATOR GROUP' ) {
                    [bool]$SpecialSecurityPrincipal = $true
                    [string]$SpecialSecurityPrincipalType = $SecurityPrincipal
                    [string]$SecurityPrincipal = $(Get-ADObject -Identity $AceApplicableTo -Properties *).nTSecurityDescriptor.Group
                }

                # if $ExpandSecurityPrincipal is $true, then extened the $SecurityPrincipal by querying AD for the AD object.
                if ($ExpandSecurityPrincipal) {

                    # Split the account name into domain and name.
                    $Domain, $SamAccountName = $SecurityPrincipal -split '\\', 2

                    # If the $Domain or SAMName is empty, or if either are not defined, then continue to the next account.
                    if ( $Domain -eq '' -or $SamAccountName -eq '' -or $null -eq $Domain -or $null -eq $SamAccountName ) {
                        Write-Host "Error: Cannot determine the Domain name and Account name from `"$($SecurityPrincipal)`"." -ForegroundColor Red
                        continue
                    }
                    # Get the AD object by using the SamAccountName.
                    $SecurityPrincipalAdObject = Get-ADObject -Filter {SamAccountName -eq $SamAccountName} -Properties SamAccountName, DistinguishedName, ObjectClass -ErrorAction SilentlyContinue
                }
            }

            # If the $SecurityPrincipalAdObject is empty, then continue to the next account.
            # So I added this code because I was finding old SID's in the ACLs that were deleted objects.
            # However, the core cause of this issue is the object not being within THIS domain forest.
            # I am not sure, but I think this may also be triggered by shared trust relationships between domains forests.
            # I do not have a way to test this, so I am not sure. Please let me know if you find out.
            if (-not $SecurityPrincipalAdObject) {
                Write-Host "Error: AD Object `"$($SecurityPrincipal)`" not found in AD!" -ForegroundColor Red
                Write-Host "AD Object SID: `"$($SecurityPrincipal)`"" -ForegroundColor Red
                Write-Host "Review and remove old accounts from ACL." -ForegroundColor Red
                continue
            }

            ########
            # Step 2
            # If $RightObjectGuid eq "00000000-0000-0000-0000-000000000000", then the ACE is a "GenericAll" permission. If it is not, then look up the $RightObjectGuid in the $AdGuids and store it in the $RightName variable.
            if ($RightObjectGuid -eq "00000000-0000-0000-0000-000000000000") {
                $RightObjectName = "All"
            } else {
                # Look Up the ObjectClass name from the $PermissionGuid($ACE.ObjectType) within the $AdGuids and store it in the $PermissionName variable.
                $RightObjectName = $AdGuids | Where-Object {$_.GUID -eq $RightObjectGuid} | Select-Object -ExpandProperty Name
            }

            ########
            # Step 3
            # If $InheritedObjectType eq "00000000-0000-0000-0000-000000000000", then the ACE is inherited to all child objects types.
            if ($InheritedObjectTypeGuid -eq "00000000-0000-0000-0000-000000000000") {
                [string]$InheritedObjectTypeName = "Any"
            } else {
                [string]$InheritedObjectTypeName = $AdGuids | Where-Object {$_.GUID -eq $InheritedObjectTypeGuid} | Select-Object -ExpandProperty Name
            }

            ########
            # Step 4
            # Based on the $RightObjectGuid, $Inheritance, and $InheritedObjectTypeGuid, build a explanation of how the ACE works.
            # Example: "The "ACME\Enterprise Admins" group has Allow GenericAll rights to "All" objects, object attributes, and ExtendedRights on "DC=acme,DC=com", and all child descendent objects of "DC=acme,DC=com", with the AD object type of "Any"."

            # Get the objectClass of the $RightObjectGuid and crate a message based on the objectClass for the ACE explanation.
            #    1. controlAccessRight: These are the ExtendedRights.
            #    2. attributeSchema: These are the Object attributes, but confusingly, the attributes every object has(like a User will have a "Phone Number" attribute on their AD user object) are also themself objects.
            #    3. classSchema: These are the Object types(aka objectClass(es)), like User, Group, OU, etc.

            switch ($AdGuids | Where-Object {$_.GUID -eq $RightObjectGuid} | Select-Object -ExpandProperty objectClass) {
                'controlAccessRight' {
                    [string]$InheritanceObjectMessage = "of `"$($RightObjectName)`""
                }
                'attributeSchema' {
                    [string]$InheritanceObjectMessage = "to the `"$($RightObjectName)`" object attributes"
                }
                'classSchema' {
                    [string]$InheritanceObjectMessage = "on `"$($RightObjectName)`" objects"
                }
                'Any' {
                    [string]$InheritanceObjectMessage = "to `"$($RightObjectName)`" objects, object attributes, and ExtendedRights"
                }
            }

            <#
            ---- AD Rights Inheritance ----
            None == Indicates no inheritance. The ACE information is only used on the object on which the ACE is set.
                        ACE information is not inherited by any descendents of the object.

            Descendents == Indicates inheritance that includes the object's immediate children and the descendants of
                            the object's children, but not the object itself.

            All == Indicates inheritance that includes the object to which the ACE is applied, the object's immediate
                   children, and the descendents of the object's children.

            Children == Indicates inheritance that includes the object's immediate children only, not the object itself
                        or the descendents of its children.

            SelfAndChildren == Indicates inheritance that includes the object itself and its immediate children.
                               It does not include the descendents of its children.

            #>

            switch ($Inheritance) {
                'None' {
                    [string]$InheritanceMessage = "on `"$AceApplicableTo`", but NO child objects of `"$AceApplicableTo`"."
                }
                'Descendents' {
                    [string]$InheritanceMessage = "on the child objects and their descendents of `"$AceApplicableTo`", but not `"$AceApplicableTo`" itself, with the AD objectClass of `"$InheritedObjectTypeName`"."
                }
                'All' {
                    [string]$InheritanceMessage = "on `"$AceApplicableTo`", and all child descendent objects of `"$AceApplicableTo`", with the AD objectClass of `"$InheritedObjectTypeName`"."
                }
                'Children' {
                    [string]$InheritanceMessage = "to `"$AceApplicableTo`"'s immediate child objects, but NOT descendent of those child objects, and not `"$AceApplicableTo`" itself, with the AD objectClass of `"$InheritedObjectTypeName`"."
                }
                'SelfAndChildren' {
                    [string]$InheritanceMessage = "on `"$AceApplicableTo`" and immediate child objects, but NOT descendent of those child objects, with the AD objectClass of `"$InheritedObjectTypeName`"."
                }
            }

            # Case $SpecialSecurityPrincipal is true, $SecurityPrincipalMessgae is set to the special case message, else it is set to the normal message.
            if ($SpecialSecurityPrincipal) {
                [string]$SecurityPrincipalMessage = "The `"$($SecurityPrincipal)`" $($SecurityPrincipalAdObject.ObjectClass) via the special identity group `"$($SpecialSecurityPrincipalType)`","
            } else {
                [string]$SecurityPrincipalMessage = "The `"$($SecurityPrincipal)`" $($SecurityPrincipalAdObject.ObjectClass)"
            }

            # Assemble the final explanation of how the ACE works.
            [string]$ExplainAce = "$($SecurityPrincipalMessage) has $($Access) $($AdRights) rights $($InheritanceObjectMessage) $($InheritanceMessage)"

            ########
            # Step 5
            # Expand the IdentityReference property and get all members of the IdentityReference.

            # Set the $ADData variable to an empty array so we can use it to store the AD object details.
            $ADData = @()

            # If $Inheritance ne "None", then get all members of the SecurityPrincipal/IdentityReference.
            # if ($Inheritance -ne 'None') {

            # IF $ExpandSecurityPrincipal is true, then get the AD object details SamAccountName, DistinguishedName, and ObjectClass.
            if ($ExpandSecurityPrincipal) {

                # If the $SecurityPrincipalAdObject has a ObjectClass of "group", recursively get all members of the group and put it in a new variable. Then get the data of the accounts in the new variable and add it to the $ADData variable.
                if ($SecurityPrincipalAdObject.ObjectClass -eq 'group') {
                    # look up all members of the group. Recursive is set to $Recusive, which is based on the InheritanceType.
                    $GroupsMembershipUsers = Get-ADGroupMember -Recursive -Identity $SecurityPrincipalAdObject.DistinguishedName
                    # Foreach member of the group, get the AD object details SamAccountName, DistinguishedName, and ObjectClass.
                    foreach ($GroupMember in $GroupsMembershipUsers) {
                        $ADData += Get-ADObject -Filter "distinguishedName -eq `'$($GroupMember.DistinguishedName)`'" -Properties SamAccountName, DistinguishedName, ObjectClass
                    }
                }

                # If the $SecurityPrincipalAdObject has a ObjectClass that is not group(Computer, MSA-Account, User, ect...), Get the object's SamAccountName, DistinguishedName, & ObjectClass and add it to the $ADData variable.
                if ($SecurityPrincipalAdObject.ObjectClass -ne 'group') {
                    $ADData += Get-ADObject -Filter "distinguishedName -eq `'$($SecurityPrincipalAdObject.DistinguishedName)`'" -Properties SamAccountName, DistinguishedName, ObjectClass
                }
                # }

                # Foreach AD Object(User, Computer, ServiceAccount) in $ADData, get the object details SamAccountName, DistinguishedName, and ObjectClass, along
                #   with the ObjectClass GUID and ObjectClass name, and add it to the $SecurityPrincipalMembers variable.
                foreach ($User in $ADData) {
                    # Look Up the ObjectClass name from the $PermissionGuid($ACE.ObjectType) within the $AdGuids and store it in the $RightObjectName variable.
                    $RightObjectName = $AdGuids | Where-Object {$_.GUID -eq $RightObjectGuid} | Select-Object -ExpandProperty Name

                    # Create a new temporary object to store the AD object details.
                    [PSCustomObject]$ADUserData = [ordered]@{
                        SamAccountName     = $User.SamAccountName
                        DistinguishedName  = $User.DistinguishedName
                        ObjectType         = $User.ObjectClass
                        RightObjectName    = $RightObjectName
                        AdRights           = $AdRights
                        InheritedRightFrom = $SecurityPrincipal
                        AceApplicableTo    = $AceApplicableTo
                    }
                    # Add the temporary object to the $SecurityPrincipalMembers variable.
                    $SecurityPrincipalMembers += [PSCustomObject]$ADUserData

                    # Clear the temporary object.
                    Clear-Variable ADUserData
                }
            }

            ########
            # Step 6
            # Create a new temporary object to store the AD object details.

            # If the $IncludeOldName switch is used, then add the old name to the $NewAce variable.
            if ($IncludeOldName) {
                [PSCustomObject]$NewAce = [ordered]@{
                    AceApplicableTo          = $AceApplicableTo
                    SecurityPrincipal        = $SecurityPrincipal
                    IdentityReference        = $SecurityPrincipal
                    AdRights                 = $AdRights
                    ActiveDirectoryRights    = $AdRights
                    Access                   = $Access
                    AccessControlType        = $Access
                    RightObjectName          = $RightObjectName
                    RightObjectGuid          = $RightObjectGuid
                    ObjectType               = $RightObjectGuid
                    IsInherited              = $IsInherited
                    Inheritance              = $Inheritance
                    InheritanceType          = $Inheritance
                    InheritanceFlags         = $InheritanceFlags
                    PropagationFlags         = $PropagationFlags
                    InheritedObjectTypeGuid  = $InheritedObjectTypeGuid
                    InheritedObjectTypeName  = $InheritedObjectTypeName
                    ExplainAce               = $ExplainAce
                    SecurityPrincipalMembers = $SecurityPrincipalMembers
                }
            }

            # If the $IncludeOldName switch is not used, then do not add the old name to the $NewAce variable.
            if (-not $IncludeOldName) {
                [PSCustomObject]$NewAce = [ordered]@{
                    AceApplicableTo          = $AceApplicableTo
                    SecurityPrincipal        = $SecurityPrincipal
                    AdRights                 = $AdRights
                    Access                   = $Access
                    RightObjectName          = $RightObjectName
                    IsInherited              = $IsInherited
                    Inheritance              = $Inheritance
                    InheritedObjectTypeName  = $InheritedObjectTypeName
                    ExplainAce               = $ExplainAce
                    SecurityPrincipalMembers = $SecurityPrincipalMembers
                }
            }

            ########
            # Step 7
            # Add the $NewAce variable to the $ExtendedAcl variable.
            $ExtendedAcl += [PSCustomObject]$NewAce

            # Clear the temporary object.
            Clear-Variable ADData, NewAce, SecurityPrincipalMembers
        }
    }

    End {
        ########
        # Step 8
        #Return the $ExtendedAcl variable.
        return $ExtendedAcl
   }
# End of the Get-ExtendedAcl function.
}

function Search-DcSyncRisk {
    <#
    .SYNOPSIS
    Function to search for AD objects with DCSync permissions.

    .DESCRIPTION
    Get a list of AD objects with DCSync permissions by pulling the ACL from the domain. Then enumerate all members of the AD objects that inherit DCSync permissions.

    .EXAMPLE
    Search-DcSyncRisk

    .PARAMETER ReturnAcl
    If the $ReturnAcl switch is used, then return the filtered ACL, and do not display the results to the user.

    .INPUTS
    Search-DcSyncRisk does not take pipeline input.

    .OUTPUTS
    By default the output will be an AD objects with DCSync permissions.
    If the $ReturnAcl switch is used, then the output will be a filter version of the ACL(Array(hashtable)), with the added/expanded ACE data(from the Get-ExtendedAcl function).

    .NOTES

    #>

    Param (
    [Parameter(Mandatory=$false,Position=1)]
        [switch]$ReturnAcl
    )

    <#
        Get all objects with enough DCSync permissions to perform a DCSync attack.

        Here is the URL to MS documentation on the permissions: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = DS-Replication-Get-Changes-All
        "89e95b76-444d-4c62-991a-0facbeda640c" = DS-Replication-Get-Changes-In-Filtered-Set

        So there are the 3 GUIDs that we are looking for, but also many other general permissions that can be used to perform a DCSync attack.

        If I missed any, please let me know.
    #>

    # Set the $DCSyncAcl variable to an empty array.
    $DCSyncAcl = @()

    foreach ($DomainAce in (Get-AdAcl)) {
        if ((
                $DomainAce.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
                $DomainAce.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" -or
                $DomainAce.ObjectType -eq "89e95b76-444d-4c62-991a-0facbeda640c"
            ) -or (
                $DomainAce.ActiveDirectoryRights -like "*GenericAll*" -and
                $DomainAce.ObjectType -eq "00000000-0000-0000-0000-000000000000"
            ) -or (
                $DomainAce.ActiveDirectoryRights -like "*GenericWrite*" -and
                $DomainAce.ObjectType -eq "00000000-0000-0000-0000-000000000000"
            ) -or (
                $DomainAce.ActiveDirectoryRights -like "*WriteDacl*" -and
                $DomainAce.ObjectType -eq "00000000-0000-0000-0000-000000000000"
            ) -or (
                $DomainAce.ActiveDirectoryRights -like "*WriteOwner*" -and
                $DomainAce.ObjectType -eq "00000000-0000-0000-0000-000000000000"
            ) -or (
                $DomainAce.ActiveDirectoryRights -like "*WriteProperty*" -and
                $DomainAce.ObjectType -eq "00000000-0000-0000-0000-000000000000"
            ) -or (
                $DomainAce.ActiveDirectoryRights -like "*AllExtendedRights*"
            )
        ){
            #$DomainAce | Get-Member | Out-Default
            # Add the ACE to the $DCSyncAcl variable.
            $DCSyncAcl += $DomainAce
        }

    }

    # Extend the ACL data.
    $DCSyncAcl = Get-ExtendedAcl -ACL $DCSyncAcl

    # If the $ReturnAcl switch is used, then return the filtered ACL, and display the results to the user.
    if (!$ReturnAcl) {
        # Ask the user if they want to save the results to a text file.
        [string]$SaveResults = Read-Host "Do you want to save the results to a text file? (default=Y, Y/n)"
        if ($SaveResults -eq 'Y' -or $SaveResults -eq 'y' -or $SaveResults -eq '') {
            Start-Transcript -Path "$global:ThisScriptDir\DcSyncAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
        }
        # Send the $DCSyncAcl array to the Out-AclDetails function to display the results to the user.
        $DCSyncAcl | Out-AclDetails
    }

    # If the $ReturnAcl switch is used, then return the filtered ACL, and do not display the results to the user.
    if ($ReturnAcl) {
        return $DCSyncAcl
    }
# End of the Search-DcSyncRisk function.
}

Function Search-HighRiskAdAce {
    <#
    .SYNOPSIS
    Function to search for AD objects with weak permissions.

    .DESCRIPTION
    This function will search for AD objects with high risk permissions.
        - "GenericAll" permissions.
        - "GenericWrite" permissions.
        - "WriteDacl" permissions.

    .EXAMPLE
    Search-HighRiskAdAce

    .PARAMETER ReturnAcl
    If the $ReturnAcl switch is used, then return the filtered ACL, and do not display the results to the user.

    .INPUTS
    Search-HighRiskAdAce does not take pipeline input.

    .OUTPUTS
    By default the output will be an AD objects with high risk permissions.
    If the $ReturnAcl switch is used, then the output will be a filter version of the ACL(Array(hashtable)), with the added/expanded ACE data(from the Get-ExtendedAcl function).

    .NOTES

    #>

    Param (
    [Parameter(Mandatory=$false,Position=1)]
        [switch]$ReturnAcl
    )

    # Create a dictionary of GUIDs and their names.
    $HighPrivilegedAcl = @()

    <#
    Foreach object in the Get-AdAcl, check if the object contains a "GenericAll", "GenericWrite", "WriteOwner",
    "WriteDacl", "WriteProperty", "WriteMembers", "AllExtendedRights"
    #>
    foreach ($ACL in (Get-AdAcl)) {
        if ($ACL.IdentityReference -and
            (
            $ACL.ActiveDirectoryRights -like "*GenericAll*" -or
            $ACL.ActiveDirectoryRights -like "*GenericWrite*" -or
            $ACL.ActiveDirectoryRights -like "*WriteDacl*" -or
            $ACL.ActiveDirectoryRights -like "*WriteOwner*" -or
            $ACL.ActiveDirectoryRights -like "*WriteProperty*" -or
            $ACL.ActiveDirectoryRights -like "*WriteMembers*" -or
            $ACL.ActiveDirectoryRights -like "*AllExtendedRights*"
            )
        ){
            # Add the matching ACL to the $WeakAdPermissions variable.
            $HighPrivilegedAcl += $ACL
        }
    }

    # Extend the ACL data.
    $HighPrivilegedAcl = Get-ExtendedAcl -ACL $HighPrivilegedAcl

    # if the $ReturnAcl switch is used, then return the ACL.
    if (!$ReturnAcl) {
        # Ask the user if they want to save the results to a text file.
        [string]$SaveResults = Read-Host "Do you want to save the results to a text file? (default=Y, Y/n)"
        if ($SaveResults -eq 'Y' -or $SaveResults -eq 'y' -or $SaveResults -eq '') {
            Start-Transcript -Path "$global:ThisScriptDir\HighRiskAceAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
        }

        # Send the $HighPrivilegedAcl array to the Out-AclDetails function to display the results to the user.
        $HighPrivilegedAcl | Out-AclDetails
    }

    # If the $ReturnAcl switch is used, then return the ACL.
    if ($ReturnAcl) {
        return $HighPrivilegedAcl
    }
# End of the Search-HighRiskAdAce function.
}

function Out-AclDetails {

    # Parameter help description
    Param(
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)]
        [array]$ACL
    )

    Begin {
        # Confirm the $ACL is not empty.
        if ($null -eq $ACL) {
            return
        }
        # Set the $Count variable to 0.
        $Count = 0
    }

    Process{
        # Foreach ACE in the ACL array, orginized the data and output it to the user.
        ForEach ( $ACE in $ACL ) {
            Write-Host "`"$($ACE.SecurityPrincipal)`" has the following ACE:" -ForegroundColor Yellow
            $ACE | Select-Object -Property SecurityPrincipal, Access, AdRights, RightObjectName, Inheritance, InheritedObjectTypeName | Out-Default
            $ACE.ExplainAce | Out-Default
            Write-Host ""
            # Check if the $ACE has SecurityPrincipal.
            if ($ACE.SecurityPrincipalMembers.Count -gt 0) {
                Write-Host "The following AD objects are members of the `"$($ACE.SecurityPrincipal)`" and can use this right." -ForegroundColor Red
                $ACE.SecurityPrincipalMembers | Select-Object -Property SamAccountName, RightObjectName, InheritedRightFrom, AceApplicableTo | Out-Default
            }
            Write-Host "------" -ForegroundColor Green

            # Increment the $Count variable by 1.
            $Count++
        }
    }

    End {
        # If the cound is zero then output that no objects were found.
        if ($Count -eq 0) {
            Write-Host "No ACEs objects were found." -ForegroundColor Green
        } else {
            # Display the number of objects that were found.
            Write-Host "The number of objects that were found: $Count" -ForegroundColor Yellow
        }
    }
# End of the Out-AclDetails function.
}

function Out-AclDetailsLite {

    # Parameter help description
    Param(
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)]
        [array]$ACL
    )

    Begin {
        # Confirm the $ACL is not empty.
        if ($null -eq $ACL) {
            return
        }
        # Set the $Count variable to 0.
        $Count = 0

        # Set the $SecurityPrincipalMembersList variable to an empty array.
        [array]$SecurityPrincipalMembersList = @()
    }

    Process{
        # Foreach ACE in the ACL array, orginized the data and output it to the user.
        ForEach ( $ACE in $ACL ) {
            # Check if the $ACE has SecurityPrincipal.
            if ($ACE.SecurityPrincipalMembers.Count -gt 0) {
                foreach ($SecurityPrincipalMember in $($ACE.SecurityPrincipalMembers)){
                    $MemberDetails = $SecurityPrincipalMember | Select-Object -Property SamAccountName, RightObjectName, InheritedRightFrom, AceApplicableTo
                    $SecurityPrincipalMembersList += $MemberDetails
                    # Increment the $Count variable by 1.
                    $Count++
                }
            }
        }
    }

    End {
        # If the cound is zero then output that no objects were found.
        if ($Count -eq 0) {
            Write-Host "No ACEs objects were found." -ForegroundColor Green
        }
        # If count is greater than 0, then display the number of objects that were found.
        if ($Count -gt 0) {
            Write-Host "The number user objects with this right that were found: $Count" -ForegroundColor Yellow
            $SecurityPrincipalMembersList | Select-Object -Property SamAccountName, RightObjectName, InheritedRightFrom, AceApplicableTo | Out-Default
        }
    }
# End of the Out-AclDetailsLite function.
}