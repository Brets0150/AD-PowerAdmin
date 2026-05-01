Function Initialize-Module {
    <#
    .SYNOPSIS
    Registers Exchange AD Security menu items and unattended jobs.
    #>

    $global:Menu.Remove('ExchangeAdSecurityMenu')
    $global:SubMenus.Remove('ExchangeAdSecurityMenu')
    $global:UnattendedJobs.Remove('ExchangeAuditReport')

    $global:SubMenus += @{
        'ExchangeAdSecurityMenu' = @{
            Title = "Exchange AD Security Audits"
            Items = @{
                'ExchangeDomainRootAce' = @{
                    Title   = "Domain Root ACE Audit"
                    Label   = "Audit the domain root ACL for dangerous permissions held by Exchange-related security groups."
                    Command = "Search-ExchangeDomainRootAce"
                }
                'ExchangeGroupMembership' = @{
                    Title   = "Exchange Group Membership"
                    Label   = "Audit membership of Exchange security groups and flag unexpected or suspicious members."
                    Command = "Search-ExchangeGroupMembership"
                }
                'ExchangeGroupAclRisk' = @{
                    Title   = "Exchange Group ACL Risk"
                    Label   = "Audit who can control Exchange Windows Permissions and other Exchange groups via dangerous ACEs."
                    Command = "Search-ExchangeGroupAclRisk"
                }
                'ExchangeAuditReport' = @{
                    Title   = "Full Exchange Audit Report"
                    Label   = "Run all Exchange AD security checks and export a combined CSV report. Sends email if configured."
                    Command = "Get-ExchangeAuditReport"
                }
                'RemoveExchangeAce' = @{
                    Title   = "Remove Dangerous ACE"
                    Label   = "Interactively remove dangerous Exchange-related ACEs from the domain root. Requires confirmation."
                    Command = "Remove-ExchangeDangerousAce"
                }
            }
        }
    }

    $global:Menu += @{
        'ExchangeAdSecurityMenu' = @{
            Title    = "Exchange AD Security"
            Label    = "Audit and remediate Exchange-related Active Directory permission escalation risks, including WriteDACL paths to DCSync on the domain root."
            Module   = "AD-PowerAdmin_ExchangeAdSecurity"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'ExchangeAdSecurityMenu'"
        }
    }

    $global:UnattendedJobs += @{
        'ExchangeAuditReport' = @{
            Title    = "Exchange AD Security Audit"
            Label    = "Full Exchange AD security audit: domain root ACEs, group membership, group ACL risk, and DCSync rights."
            Module   = "AD-PowerAdmin_ExchangeAdSecurity"
            Function = "Get-ExchangeAuditReport"
            Daily    = $global:ExchangeADSecurityAudit
            Command  = "Get-ExchangeAuditReport"
        }
    }
}

Initialize-Module

Function Search-ExchangeDomainRootAce {
    <#
    .SYNOPSIS
    Audits the domain root ACL for dangerous permissions held by Exchange security groups.

    .DESCRIPTION
    Reads the domain root ACL and filters for ACEs where an Exchange-related security group
    (as defined in $global:ExchangeGroupsToAudit) holds rights of WriteDacl, GenericAll,
    WriteOwner, GenericWrite, or AllExtendedRights. Dangerous findings are tagged with a
    severity rating of Critical or High per the exchange_ad_permission_escalation dossier.

    .PARAMETER ReturnAcl
    Return the enriched ACE list for pipeline or orchestration use instead of displaying output.

    .EXAMPLE
    Search-ExchangeDomainRootAce

    .EXAMPLE
    $Results = Search-ExchangeDomainRootAce -ReturnAcl
    #>
    Param (
        [Parameter(Mandatory=$false, Position=1)]
        [switch]$ReturnAcl
    )

    $DangerousRights = @('WriteDacl','GenericAll','WriteOwner','GenericWrite','AllExtendedRights')

    $DomainAcl = Get-AdAcl

    $FilteredAcl = New-Object System.Collections.Generic.List[object]
    foreach ($Ace in $DomainAcl) {
        $GroupNamePart = $Ace.IdentityReference.ToString().Split('\')[-1]
        if ($global:ExchangeGroupsToAudit -notcontains $GroupNamePart) {
            continue
        }

        $RightsMatch = $false
        foreach ($Right in $DangerousRights) {
            if ($Ace.ActiveDirectoryRights -like "*$Right*") {
                $RightsMatch = $true
                break
            }
        }
        if ($RightsMatch) {
            $FilteredAcl.Add($Ace)
        }
    }

    if ($FilteredAcl.Count -gt 0) {
        $EnrichedAcl = Get-ExtendedAcl -ACL $FilteredAcl
    } else {
        $EnrichedAcl = New-Object System.Collections.Generic.List[object]
    }

    foreach ($Ace in $EnrichedAcl) {
        $Sev = 'High'
        if ($Ace.AdRights -like '*WriteDacl*' -or $Ace.AdRights -like '*GenericAll*' -or $Ace.AdRights -like '*WriteOwner*') {
            $Sev = 'Critical'
        }
        $Ace | Add-Member -NotePropertyName 'Severity' -NotePropertyValue $Sev -Force
    }

    if ($ReturnAcl) {
        return $EnrichedAcl
    }

    if ($EnrichedAcl.Count -eq 0) {
        Write-Host "[OK] No dangerous Exchange-related ACEs found on the domain root." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Dangerous Exchange-related ACEs found on the domain root!" -ForegroundColor Red
        [string]$SaveResults = Read-Host "Save results to a text file? (default=Y, Y/n)"
        if ($SaveResults -eq 'Y' -or $SaveResults -eq 'y' -or $SaveResults -eq '') {
            Start-Transcript -Path "$global:ReportsPath\ExchangeDomainRootAce_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
        }
        $EnrichedAcl | Out-AclDetails
        Export-AdPowerAdminData -Data $EnrichedAcl -ReportName "ExchangeDomainRootAce"
    }
}

Function Search-ExchangeGroupMembership {
    <#
    .SYNOPSIS
    Audits membership of Exchange security groups and flags unexpected members.

    .DESCRIPTION
    Recursively enumerates members of each group defined in $global:ExchangeGroupsToAudit.
    Members whose SamAccountName does not match known Exchange service account patterns and
    whose ObjectClass is not 'computer' are flagged as suspect. Groups not found in AD are
    skipped with a warning (Exchange may not be installed).

    .PARAMETER ReturnData
    Return the membership list for pipeline or orchestration use instead of displaying output.

    .EXAMPLE
    Search-ExchangeGroupMembership

    .EXAMPLE
    $Members = Search-ExchangeGroupMembership -ReturnData
    #>
    Param (
        [Parameter(Mandatory=$false, Position=1)]
        [switch]$ReturnData
    )

    $ExchangeServicePatterns = @(
        '*Exchange*',
        '*HealthMailbox*',
        '*SystemMailbox*',
        '*MSOL_*',
        '*AADConnect*'
    )

    $Results = New-Object System.Collections.Generic.List[object]

    foreach ($GroupName in $global:ExchangeGroupsToAudit) {
        try {
            $AdGroup = Get-ADGroup -Identity $GroupName -ErrorAction Stop
        } catch {
            Write-Host "[WARN] Group not found: '$GroupName'. Exchange may not be installed in this environment." -ForegroundColor Yellow
            continue
        }

        try {
            $Members = Get-ADGroupMember -Identity $AdGroup.DistinguishedName -Recursive -ErrorAction Stop
        } catch {
            Write-Host "[WARN] Could not enumerate members of '$GroupName': $($_.Exception.Message)" -ForegroundColor Yellow
            continue
        }

        foreach ($Member in $Members) {
            $IsSuspect = $true

            if ($Member.ObjectClass -eq 'computer') {
                $IsSuspect = $false
            } else {
                foreach ($Pattern in $ExchangeServicePatterns) {
                    if ($Member.SamAccountName -like $Pattern) {
                        $IsSuspect = $false
                        break
                    }
                }
            }

            $Results.Add([PSCustomObject]@{
                GroupName         = $GroupName
                MemberName        = $Member.Name
                SamAccountName    = $Member.SamAccountName
                ObjectClass       = $Member.ObjectClass
                DistinguishedName = $Member.DistinguishedName
                IsSuspect         = $IsSuspect
            })
        }
    }

    if ($ReturnData) {
        return $Results
    }

    if ($Results.Count -eq 0) {
        Write-Host "[OK] No members found in Exchange security groups (groups may not exist)." -ForegroundColor Green
        return
    }

    Write-Host ""
    Write-Host "Exchange Security Group Membership" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------------------------"
    foreach ($Entry in $Results) {
        $Color = 'White'
        $SuspectLabel = ''
        if ($Entry.IsSuspect) {
            $Color = 'Red'
            $SuspectLabel = ' [SUSPECT]'
        }
        Write-Host ("  Group: {0,-40} Member: {1,-30} Class: {2}{3}" -f `
            $Entry.GroupName, $Entry.SamAccountName, $Entry.ObjectClass, $SuspectLabel) -ForegroundColor $Color
    }
    Write-Host ""

    Export-AdPowerAdminData -Data $Results -ReportName "ExchangeGroupMembership"
}

Function Search-ExchangeGroupAclRisk {
    <#
    .SYNOPSIS
    Audits who can control the Exchange Windows Permissions group via dangerous ACEs.

    .DESCRIPTION
    Reads the ACL on the Exchange Windows Permissions group object and identifies principals
    holding GenericAll, WriteDACL, WriteOwner, GenericWrite, or WriteProperty rights. Anyone
    with these rights can modify the group and thereby inherit its domain-root WriteDACL
    escalation path.

    .PARAMETER ReturnAcl
    Return the enriched ACE list for pipeline or orchestration use instead of displaying output.

    .EXAMPLE
    Search-ExchangeGroupAclRisk

    .EXAMPLE
    $Results = Search-ExchangeGroupAclRisk -ReturnAcl
    #>
    Param (
        [Parameter(Mandatory=$false, Position=1)]
        [switch]$ReturnAcl
    )

    $DangerousGroupRights = @('GenericAll','WriteDacl','WriteOwner','GenericWrite','WriteProperty')

    try {
        $ExchangeGroup = Get-ADGroup -Identity "Exchange Windows Permissions" -ErrorAction Stop
    } catch {
        Write-Host "[WARN] 'Exchange Windows Permissions' group not found. Exchange may not be installed." -ForegroundColor Yellow
        if ($ReturnAcl) { return (New-Object System.Collections.Generic.List[object]) }
        return
    }

    $GroupAcl = Get-AdAcl -AdObjectPath $ExchangeGroup.DistinguishedName

    $FilteredAcl = New-Object System.Collections.Generic.List[object]
    foreach ($Ace in $GroupAcl) {
        $RightsMatch = $false
        foreach ($Right in $DangerousGroupRights) {
            if ($Ace.ActiveDirectoryRights -like "*$Right*") {
                $RightsMatch = $true
                break
            }
        }
        if ($RightsMatch) {
            $FilteredAcl.Add($Ace)
        }
    }

    if ($FilteredAcl.Count -gt 0) {
        $EnrichedAcl = Get-ExtendedAcl -ACL $FilteredAcl
    } else {
        $EnrichedAcl = New-Object System.Collections.Generic.List[object]
    }

    if ($ReturnAcl) {
        return $EnrichedAcl
    }

    if ($EnrichedAcl.Count -eq 0) {
        Write-Host "[OK] No dangerous ACEs found on the Exchange Windows Permissions group." -ForegroundColor Green
    } else {
        Write-Host "[WARN] Principals with dangerous control over 'Exchange Windows Permissions' found!" -ForegroundColor Red
        [string]$SaveResults = Read-Host "Save results to a text file? (default=Y, Y/n)"
        if ($SaveResults -eq 'Y' -or $SaveResults -eq 'y' -or $SaveResults -eq '') {
            Start-Transcript -Path "$global:ReportsPath\ExchangeGroupAclRisk_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
        }
        $EnrichedAcl | Out-AclDetails
        Export-AdPowerAdminData -Data $EnrichedAcl -ReportName "ExchangeGroupAclRisk"
    }
}

Function New-ExchangeAuditTextReport {
    <#
    .SYNOPSIS
    Builds a categorized, explanatory text report of Exchange AD security findings.
    #>
    Param(
        [Parameter(Mandatory=$false)] [object]$DomainRootAceResults,
        [Parameter(Mandatory=$false)] [object]$GroupMembershipResults,
        [Parameter(Mandatory=$false)] [object]$GroupAclRiskResults,
        [Parameter(Mandatory=$false)] [object]$DcSyncExchangeResults,
        [Parameter(Mandatory=$false)] [string]$OverallSeverity = 'Clean',
        [Parameter(Mandatory=$false)] [object]$SuspectMembers
    )

    if ($null -eq $DomainRootAceResults)  { $DomainRootAceResults  = @() }
    if ($null -eq $GroupMembershipResults) { $GroupMembershipResults = @() }
    if ($null -eq $GroupAclRiskResults)   { $GroupAclRiskResults   = @() }
    if ($null -eq $DcSyncExchangeResults) { $DcSyncExchangeResults  = @() }
    if ($null -eq $SuspectMembers)        { $SuspectMembers         = @() }

    $Sep      = '=' * 72
    $SubSep   = '-' * 72
    $WikiBase = 'https://github.com/Brets0150/AD-PowerAdmin/wiki/Exchange-AD-Security-Audit'

    $Lines = New-Object System.Collections.Generic.List[string]

    # ------------------------------------------------------------------ Header
    $Lines.Add($Sep)
    $Lines.Add('Exchange AD Security Audit Report')
    $Lines.Add("Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    try {
        $Domain = Get-ADDomain
        $Lines.Add("Domain    : $($Domain.DNSRoot) / $($Domain.DistinguishedName)")
    } catch {
        $Lines.Add("Domain    : (could not retrieve)")
    }
    $Lines.Add("Severity  : $OverallSeverity")
    $Lines.Add($Sep)
    $Lines.Add('')

    # ----------------------------------------------------------------- Summary
    $Lines.Add('SUMMARY')
    $Lines.Add($SubSep)
    $Lines.Add("  Domain Root Dangerous ACEs : $($DomainRootAceResults.Count)")
    $Lines.Add("  Suspect Group Members      : $($SuspectMembers.Count)")
    $Lines.Add("  Exchange Group Control Risk: $($GroupAclRiskResults.Count)")
    $Lines.Add("  Exchange-related DCSync    : $($DcSyncExchangeResults.Count)")
    $Lines.Add('')
    $Lines.Add('For in-depth guidance on this vulnerability and its remediations, see:')
    $Lines.Add("  $WikiBase")
    $Lines.Add('')

    # ------------------------------------------------------- Finding 1: Domain Root ACE
    if ($DomainRootAceResults -and $DomainRootAceResults.Count -gt 0) {
        $MaxSeverity = 'High'
        if ($DomainRootAceResults | Where-Object { $_.Severity -eq 'Critical' }) {
            $MaxSeverity = 'Critical'
        }
        $Lines.Add($Sep)
        $Lines.Add("FINDING [$MaxSeverity]: DANGEROUS EXCHANGE PERMISSIONS ON DOMAIN ROOT")
        $Lines.Add($Sep)
        $Lines.Add('')
        $Lines.Add('The following Exchange security groups hold dangerous rights on the domain')
        $Lines.Add('root. These rights allow the ACL to be rewritten, enabling an attacker')
        $Lines.Add('to grant themselves DCSync replication rights and extract all password')
        $Lines.Add('hashes from the domain.')
        $Lines.Add('')

        $Lines.Add(("  {0,-35} {1,-22} {2}" -f 'Group', 'Rights', 'Severity'))
        $Lines.Add(("  {0,-35} {1,-22} {2}" -f ('-' * 35), ('-' * 22), ('-' * 8)))

        $GroupedByPrincipal = $DomainRootAceResults | Group-Object -Property SecurityPrincipal
        foreach ($PrincipalGroup in $GroupedByPrincipal) {
            $AllRights       = ($PrincipalGroup.Group | Select-Object -ExpandProperty AdRights | Select-Object -Unique) -join ', '
            $GroupSeverity   = if ($PrincipalGroup.Group | Where-Object { $_.Severity -eq 'Critical' }) { 'Critical' } else { 'High' }
            $PrincipalDisplay = $PrincipalGroup.Name
            $RightsDisplay    = $AllRights
            if ($PrincipalDisplay.Length -gt 35) { $PrincipalDisplay = $PrincipalDisplay.Substring(0, 32) + '...' }
            if ($RightsDisplay.Length    -gt 22) { $RightsDisplay    = $RightsDisplay.Substring(0, 19)    + '...' }
            $Lines.Add(("  {0,-35} {1,-22} {2}" -f $PrincipalDisplay, $RightsDisplay, $GroupSeverity))
        }
        $Lines.Add('')

        $Lines.Add('WHAT THIS MEANS')
        $Lines.Add($SubSep)
        $Lines.Add('  WriteDACL on the domain root lets any group member rewrite the domain')
        $Lines.Add('  ACL. GenericAll provides full control over the domain object. Either')
        $Lines.Add('  right creates a direct path from Exchange group membership to DCSync-')
        $Lines.Add('  level access -- the ability to replicate all password hashes from every')
        $Lines.Add('  domain controller, including privileged accounts and KRBTGT.')
        $Lines.Add('')

        $Lines.Add('HOW AN ATTACKER CAN EXPLOIT THIS')
        $Lines.Add($SubSep)
        $Lines.Add('  1. Gain control of any account in Exchange Windows Permissions (e.g.,')
        $Lines.Add('     phishing, credential stuffing, privilege abuse, or NTLM relay).')
        $Lines.Add('  2. Use WriteDACL to grant an attacker-controlled account the extended')
        $Lines.Add('     rights DS-Replication-Get-Changes and DS-Replication-Get-Changes-All')
        $Lines.Add('     on the domain root object.')
        $Lines.Add('  3. Run DCSync to dump all AD password hashes, including KRBTGT.')
        $Lines.Add('  4. Use the KRBTGT hash to forge Golden Tickets for persistent,')
        $Lines.Add('     undetected access to any resource in the domain.')
        $Lines.Add('')
        $Lines.Add('  PrivExchange variant: a mailbox-enabled user can coerce Exchange server')
        $Lines.Add('  authentication and relay NTLM to LDAP, bypassing step 1 entirely if')
        $Lines.Add('  LDAP signing and channel binding are not enforced on domain controllers.')
        $Lines.Add('')

        $Lines.Add('REMEDIATION')
        $Lines.Add($SubSep)
        $Lines.Add('  1. Patch Exchange to the latest supported cumulative update.')
        $Lines.Add('  2. Run AD preparation from the patched CU:')
        $Lines.Add('       Setup.exe /PrepareAD /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF')
        $Lines.Add('       Setup.exe /PrepareAllDomains /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF')
        $Lines.Add('  3. Re-audit using this tool. If dangerous ACEs persist after PrepareAD,')
        $Lines.Add('     use "Remove Dangerous ACE" from the Exchange AD Security submenu.')
        $Lines.Add('  4. Enforce LDAP signing (GPO):')
        $Lines.Add('       Domain controller: LDAP server signing requirements = Require signing')
        $Lines.Add('  5. Enforce LDAP channel binding (GPO):')
        $Lines.Add('       Domain controller: LDAP server channel binding token requirements = Always')
        $Lines.Add('  6. Monitor Exchange Windows Permissions for membership changes')
        $Lines.Add('     (Event IDs 4728, 4756, 4757).')
        $Lines.Add('  7. Monitor domain root ACL changes (Event IDs 5136, 4662).')
        $Lines.Add('')
        $Lines.Add("  Detailed guidance: $WikiBase#finding-domain-root-ace")
        $Lines.Add('')
    }

    # ------------------------------------------------ Finding 2: Suspect Group Members
    if ($SuspectMembers -and $SuspectMembers.Count -gt 0) {
        $Lines.Add($Sep)
        $Lines.Add('FINDING [MEDIUM]: SUSPECT MEMBERS IN EXCHANGE SECURITY GROUPS')
        $Lines.Add($Sep)
        $Lines.Add('')
        $Lines.Add('The following members in Exchange security groups do not match known')
        $Lines.Add('Exchange service account patterns. Each flagged member inherits the')
        $Lines.Add("group's domain-root permissions, including any dangerous rights.")
        $Lines.Add('')

        $Lines.Add(("  {0,-30} {1,-25} {2,-12} {3}" -f 'Group', 'SamAccountName', 'ObjectClass', 'IsSuspect'))
        $Lines.Add(("  {0,-30} {1,-25} {2,-12} {3}" -f ('-' * 30), ('-' * 25), ('-' * 12), ('-' * 9)))

        $GroupedByGroup = $SuspectMembers | Group-Object -Property GroupName
        foreach ($GroupEntry in $GroupedByGroup) {
            foreach ($Member in $GroupEntry.Group) {
                $GrpDisplay   = $GroupEntry.Name
                $SamDisplay   = $Member.SamAccountName
                $ClassDisplay = $Member.ObjectClass
                if ($GrpDisplay.Length   -gt 30) { $GrpDisplay   = $GrpDisplay.Substring(0, 27)   + '...' }
                if ($SamDisplay.Length   -gt 25) { $SamDisplay   = $SamDisplay.Substring(0, 22)    + '...' }
                if ($ClassDisplay.Length -gt 12) { $ClassDisplay = $ClassDisplay.Substring(0, 9)   + '...' }
                $Lines.Add(("  {0,-30} {1,-25} {2,-12} {3}" -f $GrpDisplay, $SamDisplay, $ClassDisplay, 'YES'))
            }
        }
        $Lines.Add('')

        $Lines.Add('WHAT THIS MEANS')
        $Lines.Add($SubSep)
        $Lines.Add('  Non-Exchange accounts in Exchange security groups inherit that group''s')
        $Lines.Add('  Active Directory rights. If the group holds WriteDACL or GenericAll on')
        $Lines.Add('  the domain root, each unexpected member is a potential starting point')
        $Lines.Add('  for the Exchange-to-DCSync escalation path.')
        $Lines.Add('')

        $Lines.Add('HOW AN ATTACKER CAN EXPLOIT THIS')
        $Lines.Add($SubSep)
        $Lines.Add('  An attacker who compromises any flagged account gains the group''s')
        $Lines.Add('  domain-root rights directly, without needing to compromise an Exchange')
        $Lines.Add('  server or Exchange-specific service account. The escalation steps are')
        $Lines.Add('  identical to the domain root ACE finding once the account is under')
        $Lines.Add('  attacker control.')
        $Lines.Add('')

        $Lines.Add('REMEDIATION')
        $Lines.Add($SubSep)
        $Lines.Add('  1. Review each flagged member. Confirm whether their presence is')
        $Lines.Add('     authorized for legitimate Exchange operation.')
        $Lines.Add('  2. Remove any unauthorized or unnecessary members from the group.')
        $Lines.Add('  3. Restrict who can add members to Exchange Windows Permissions')
        $Lines.Add('     (see Exchange Group ACL Risk check in this tool).')
        $Lines.Add('  4. Enable monitoring for group membership changes (Event IDs 4728,')
        $Lines.Add('     4729, 4756, 4757).')
        $Lines.Add('')
        $Lines.Add("  Detailed guidance: $WikiBase#finding-group-membership")
        $Lines.Add('')
    }

    # ----------------------------------------------- Finding 3: Group ACL Risk
    if ($GroupAclRiskResults -and $GroupAclRiskResults.Count -gt 0) {
        $Lines.Add($Sep)
        $Lines.Add('FINDING [CRITICAL]: DANGEROUS CONTROL OVER EXCHANGE WINDOWS PERMISSIONS')
        $Lines.Add($Sep)
        $Lines.Add('')
        $Lines.Add('The following principals hold rights on the Exchange Windows Permissions')
        $Lines.Add('group object that allow them to modify its membership or ACL. Anyone')
        $Lines.Add('with such control inherits the full Exchange-to-DCSync escalation path.')
        $Lines.Add('')

        $Lines.Add(("  {0,-40} {1}" -f 'Principal', 'Rights'))
        $Lines.Add(("  {0,-40} {1}" -f ('-' * 40), ('-' * 28)))
        foreach ($Ace in $GroupAclRiskResults) {
            $PrincipalDisplay = $Ace.SecurityPrincipal
            $RightsDisplay    = $Ace.AdRights
            if ($PrincipalDisplay.Length -gt 40) { $PrincipalDisplay = $PrincipalDisplay.Substring(0, 37) + '...' }
            if ($RightsDisplay.Length    -gt 28) { $RightsDisplay    = $RightsDisplay.Substring(0, 25)    + '...' }
            $Lines.Add(("  {0,-40} {1}" -f $PrincipalDisplay, $RightsDisplay))
        }
        $Lines.Add('')

        $Lines.Add('WHAT THIS MEANS')
        $Lines.Add($SubSep)
        $Lines.Add('  Anyone with GenericAll, WriteDACL, WriteOwner, GenericWrite, or')
        $Lines.Add('  WriteProperty over Exchange Windows Permissions can add themselves or')
        $Lines.Add('  another account to the group or alter its ACL. This extends the')
        $Lines.Add('  escalation path to principals that are not currently group members.')
        $Lines.Add('')

        $Lines.Add('HOW AN ATTACKER CAN EXPLOIT THIS')
        $Lines.Add($SubSep)
        $Lines.Add('  1. Compromise any account listed above.')
        $Lines.Add('  2. Use its group-control right to add an attacker-controlled account')
        $Lines.Add('     to Exchange Windows Permissions.')
        $Lines.Add('  3. Use the group''s WriteDACL on the domain root to grant DCSync rights.')
        $Lines.Add('  4. Run DCSync to extract all domain password hashes.')
        $Lines.Add('')

        $Lines.Add('REMEDIATION')
        $Lines.Add($SubSep)
        $Lines.Add('  1. Review each listed principal. Confirm whether their control over')
        $Lines.Add('     the group is required for legitimate Exchange operation.')
        $Lines.Add('  2. Remove any unnecessary GenericAll, WriteDACL, or WriteOwner rights')
        $Lines.Add('     from non-Exchange administrative accounts on this group.')
        $Lines.Add('  3. Restrict Exchange Windows Permissions management to the minimum')
        $Lines.Add('     required Exchange service accounts.')
        $Lines.Add('  4. Monitor for ACL changes on the group object (Event IDs 5136, 4662).')
        $Lines.Add('')
        $Lines.Add("  Detailed guidance: $WikiBase#finding-group-acl-risk")
        $Lines.Add('')
    }

    # ------------------------------------------ Finding 4: Exchange DCSync Rights
    if ($DcSyncExchangeResults -and $DcSyncExchangeResults.Count -gt 0) {
        $Lines.Add($Sep)
        $Lines.Add('FINDING [CRITICAL]: EXCHANGE-RELATED DCSYNC RIGHTS DETECTED')
        $Lines.Add($Sep)
        $Lines.Add('')
        $Lines.Add('An Exchange-related group or account holds DCSync replication rights on')
        $Lines.Add('the domain root. This may indicate the escalation path has already been')
        $Lines.Add('used to stage a DCSync capability, or that Exchange itself was granted')
        $Lines.Add('these rights during /PrepareAD.')
        $Lines.Add('')

        $Lines.Add(("  {0,-40} {1}" -f 'Principal', 'Replication Right'))
        $Lines.Add(("  {0,-40} {1}" -f ('-' * 40), ('-' * 28)))
        foreach ($Ace in $DcSyncExchangeResults) {
            $PrincipalDisplay = $Ace.SecurityPrincipal
            $RightsDisplay    = $Ace.RightObjectName
            if ($PrincipalDisplay.Length -gt 40) { $PrincipalDisplay = $PrincipalDisplay.Substring(0, 37) + '...' }
            if ($RightsDisplay.Length    -gt 28) { $RightsDisplay    = $RightsDisplay.Substring(0, 25)    + '...' }
            $Lines.Add(("  {0,-40} {1}" -f $PrincipalDisplay, $RightsDisplay))
        }
        $Lines.Add('')

        $Lines.Add('WHAT THIS MEANS')
        $Lines.Add($SubSep)
        $Lines.Add('  DS-Replication-Get-Changes and DS-Replication-Get-Changes-All are the')
        $Lines.Add('  two extended rights required to perform a DCSync attack. Finding them')
        $Lines.Add('  on an Exchange-related group means any member of that group can run')
        $Lines.Add('  DCSync right now, without any additional ACL changes.')
        $Lines.Add('')

        $Lines.Add('HOW AN ATTACKER CAN EXPLOIT THIS')
        $Lines.Add($SubSep)
        $Lines.Add('  An attacker who joins or compromises a member of the listed group can')
        $Lines.Add('  immediately run DCSync without needing to first abuse WriteDACL. If')
        $Lines.Add('  these rights were granted by an attacker rather than Exchange /PrepareAD,')
        $Lines.Add('  the domain may already be compromised and the KRBTGT hash extracted.')
        $Lines.Add('')

        $Lines.Add('REMEDIATION')
        $Lines.Add($SubSep)
        $Lines.Add('  1. Determine whether this right is a legitimate Exchange grant or an')
        $Lines.Add('     attacker modification. Check the ACL change audit log (Event ID 5136)')
        $Lines.Add('     and operation audit log (Event ID 4662) for who granted the right')
        $Lines.Add('     and when.')
        $Lines.Add('  2. If unauthorized: treat this as a potential compromise. Initiate')
        $Lines.Add('     incident response. Reset KRBTGT twice (with DC replication interval')
        $Lines.Add('     between resets). Rotate all privileged account passwords.')
        $Lines.Add('  3. If authorized but unnecessary: remove the extended right via Active')
        $Lines.Add('     Directory Users and Computers or AD Administrative Center.')
        $Lines.Add('  4. Run Exchange /PrepareAD from the latest supported CU to normalize')
        $Lines.Add('     Exchange-granted rights to their expected minimal values.')
        $Lines.Add('')
        $Lines.Add("  Detailed guidance: $WikiBase#finding-exchange-dcsync-rights")
        $Lines.Add('')
    }

    # ---------------------------------------------------------------- Clean state
    if ($OverallSeverity -eq 'Clean') {
        $Lines.Add($Sep)
        $Lines.Add('ALL CHECKS PASSED')
        $Lines.Add($Sep)
        $Lines.Add('')
        $Lines.Add('  [OK] No dangerous Exchange-related ACEs found on the domain root.')
        $Lines.Add('  [OK] No unexpected members found in Exchange security groups.')
        $Lines.Add('  [OK] No dangerous control over Exchange Windows Permissions found.')
        $Lines.Add('  [OK] No Exchange-related DCSync rights detected.')
        $Lines.Add('')
        $Lines.Add('  Continue to monitor for changes using scheduled runs of this tool.')
        $Lines.Add('')
    }

    # ------------------------------------------------------------------- Footer
    $Lines.Add($Sep)
    $Lines.Add('REMEDIATION VALIDATION CHECKLIST')
    $Lines.Add($SubSep)
    $Lines.Add('  [ ] Exchange is on a supported cumulative update.')
    $Lines.Add('  [ ] Exchange /PrepareAD has been rerun from the patched CU.')
    $Lines.Add('  [ ] /PrepareDomain or /PrepareAllDomains has been run where required.')
    $Lines.Add('  [ ] Exchange Windows Permissions has no WriteDACL on the domain root.')
    $Lines.Add('  [ ] Exchange Trusted Subsystem has no unnecessary GenericAll or WriteDACL.')
    $Lines.Add('  [ ] No unexpected members exist in Exchange Windows Permissions.')
    $Lines.Add('  [ ] No unexpected principals hold DCSync rights.')
    $Lines.Add('  [ ] LDAP signing is enforced on all domain controllers.')
    $Lines.Add('  [ ] LDAP channel binding is enforced on all domain controllers.')
    $Lines.Add('  [ ] Alerts exist for changes to Exchange privileged group membership.')
    $Lines.Add('  [ ] Alerts exist for domain root ACL changes (Event IDs 5136, 4662).')
    $Lines.Add('')
    $Lines.Add('  Full vulnerability dossier:')
    $Lines.Add('  https://github.com/Brets0150/AD-PowerAdmin/wiki/exchange_ad_permission_escalation')
    $Lines.Add('')
    $Lines.Add($Sep)
    $Lines.Add('END OF REPORT')
    $Lines.Add($Sep)

    return ($Lines -join "`r`n")
}

Function Get-ExchangeAuditReport {
    <#
    .SYNOPSIS
    Runs all Exchange AD security checks and produces a combined report.

    .DESCRIPTION
    Orchestrates Search-ExchangeDomainRootAce, Search-ExchangeGroupMembership,
    Search-ExchangeGroupAclRisk, and Search-DcSyncRisk to produce a unified severity
    rating, a flat CSV report, and a categorized text report with per-finding explanations,
    attack scenarios, and remediation steps. Sends an email alert when ExchangeADSecurityAudit
    is enabled and SMTP is configured.

    .EXAMPLE
    Get-ExchangeAuditReport
    #>

    Write-Host ""
    Write-Host "Exchange AD Security Audit" -ForegroundColor Cyan
    Write-Host "======================================================================"

    Write-Host "  [1/4] Checking domain root ACL for dangerous Exchange ACEs..." -ForegroundColor Cyan
    $DomainRootAceResults = Search-ExchangeDomainRootAce -ReturnAcl

    Write-Host "  [2/4] Auditing Exchange group membership..." -ForegroundColor Cyan
    $GroupMembershipResults = Search-ExchangeGroupMembership -ReturnData

    Write-Host "  [3/4] Auditing who can control Exchange Windows Permissions..." -ForegroundColor Cyan
    $GroupAclRiskResults = Search-ExchangeGroupAclRisk -ReturnAcl

    Write-Host "  [4/4] Checking for Exchange-related DCSync rights..." -ForegroundColor Cyan
    $AllDcSyncRights = Search-DcSyncRisk -ReturnAcl
    $DcSyncExchangeResults = New-Object System.Collections.Generic.List[object]
    if ($AllDcSyncRights -and $AllDcSyncRights.Count -gt 0) {
        foreach ($DcSyncAce in $AllDcSyncRights) {
            $Principal = $DcSyncAce.SecurityPrincipal
            $IsExchangeRelated = $false
            foreach ($ExchangeGroup in $global:ExchangeGroupsToAudit) {
                if ($Principal -like "*$ExchangeGroup*") {
                    $IsExchangeRelated = $true
                    break
                }
            }
            if ($IsExchangeRelated) {
                $DcSyncExchangeResults.Add($DcSyncAce)
            }
        }
    }

    $SuspectMembers = @()
    if ($GroupMembershipResults -and $GroupMembershipResults.Count -gt 0) {
        $SuspectMembersRaw = $GroupMembershipResults | Where-Object { $_.IsSuspect -eq $true }
        if ($null -ne $SuspectMembersRaw) { $SuspectMembers = $SuspectMembersRaw }
    }

    $OverallSeverity = 'Clean'

    if ($DomainRootAceResults -and $DomainRootAceResults.Count -gt 0) {
        $HasCriticalRight = $DomainRootAceResults | Where-Object {
            $_.AdRights -like '*WriteDacl*' -or $_.AdRights -like '*GenericAll*' -or $_.AdRights -like '*WriteOwner*'
        }
        if ($HasCriticalRight) {
            $OverallSeverity = 'Critical'
        } elseif ($OverallSeverity -ne 'Critical') {
            $OverallSeverity = 'High'
        }
    }

    if ($GroupAclRiskResults -and $GroupAclRiskResults.Count -gt 0) {
        $OverallSeverity = 'Critical'
    }

    if ($DcSyncExchangeResults.Count -gt 0) {
        $OverallSeverity = 'Critical'
    }

    if ($OverallSeverity -eq 'Clean' -and $SuspectMembers -and $SuspectMembers.Count -gt 0) {
        $OverallSeverity = 'Medium'
    }

    Write-Host ""
    Write-Host "======================================================================"
    Write-Host "Exchange AD Security Audit Summary" -ForegroundColor Cyan

    $SeverityColor = switch ($OverallSeverity) {
        'Critical' { 'Red' }
        'High'     { 'Red' }
        'Medium'   { 'Yellow' }
        default    { 'Green' }
    }

    Write-Host ("  Overall Severity           : {0}" -f $OverallSeverity) -ForegroundColor $SeverityColor
    Write-Host ("  Domain Root Dangerous ACEs : {0}" -f ($DomainRootAceResults.Count))
    Write-Host ("  Suspect Group Members      : {0}" -f ($SuspectMembers.Count))
    Write-Host ("  Exchange Group Control Risk: {0}" -f ($GroupAclRiskResults.Count))
    Write-Host ("  Exchange-related DCSync    : {0}" -f ($DcSyncExchangeResults.Count))
    Write-Host "======================================================================"
    Write-Host ""

    $CombinedReport = New-Object System.Collections.Generic.List[object]

    foreach ($Ace in $DomainRootAceResults) {
        $CombinedReport.Add([PSCustomObject]@{
            CheckType         = 'DomainRootACE'
            AceApplicableTo   = $Ace.AceApplicableTo
            SecurityPrincipal = $Ace.SecurityPrincipal
            AdRights          = $Ace.AdRights
            Access            = $Ace.Access
            RightObjectName   = $Ace.RightObjectName
            IsInherited       = $Ace.IsInherited
            Inheritance       = $Ace.Inheritance
            ExplainAce        = $Ace.ExplainAce
            Severity          = $Ace.Severity
            IsSuspect         = ''
        })
    }

    foreach ($Member in $GroupMembershipResults) {
        $CombinedReport.Add([PSCustomObject]@{
            CheckType         = 'GroupMembership'
            AceApplicableTo   = $Member.GroupName
            SecurityPrincipal = $Member.SamAccountName
            AdRights          = ''
            Access            = ''
            RightObjectName   = ''
            IsInherited       = ''
            Inheritance       = ''
            ExplainAce        = $Member.DistinguishedName
            Severity          = ''
            IsSuspect         = $Member.IsSuspect
        })
    }

    foreach ($Ace in $GroupAclRiskResults) {
        $CombinedReport.Add([PSCustomObject]@{
            CheckType         = 'GroupAclRisk'
            AceApplicableTo   = $Ace.AceApplicableTo
            SecurityPrincipal = $Ace.SecurityPrincipal
            AdRights          = $Ace.AdRights
            Access            = $Ace.Access
            RightObjectName   = $Ace.RightObjectName
            IsInherited       = $Ace.IsInherited
            Inheritance       = $Ace.Inheritance
            ExplainAce        = $Ace.ExplainAce
            Severity          = 'Critical'
            IsSuspect         = ''
        })
    }

    foreach ($Ace in $DcSyncExchangeResults) {
        $CombinedReport.Add([PSCustomObject]@{
            CheckType         = 'DCSync'
            AceApplicableTo   = $Ace.AceApplicableTo
            SecurityPrincipal = $Ace.SecurityPrincipal
            AdRights          = $Ace.AdRights
            Access            = $Ace.Access
            RightObjectName   = $Ace.RightObjectName
            IsInherited       = $Ace.IsInherited
            Inheritance       = $Ace.Inheritance
            ExplainAce        = $Ace.ExplainAce
            Severity          = 'Critical'
            IsSuspect         = ''
        })
    }

    Export-AdPowerAdminData -Data $CombinedReport -ReportName "ExchangeAdSecurityAuditReport" -Force

    if ($global:ExchangeADSecurityAudit -eq $true -and
        $global:SMTPServer -ne '' -and
        $global:ADAdminEmail -ne '') {

        [string]$EmailBody  = "Exchange AD Security Audit Complete.`r`n"
        [string]$EmailBody += "Overall Severity: $OverallSeverity`r`n`r`n"
        [string]$EmailBody += "Domain Root Dangerous ACEs : $($DomainRootAceResults.Count)`r`n"
        [string]$EmailBody += "Suspect Group Members      : $($SuspectMembers.Count)`r`n"
        [string]$EmailBody += "Exchange Group Control Risk: $($GroupAclRiskResults.Count)`r`n"
        [string]$EmailBody += "Exchange-related DCSync    : $($DcSyncExchangeResults.Count)`r`n`r`n"
        [string]$EmailBody += "Review the exported CSV report in $global:ReportsPath for details."

        Send-Email -ToEmail $global:ADAdminEmail `
                   -FromEmail $global:ReportsEmailFrom `
                   -Subject "ADPowerAdmin: Exchange AD Security Audit - Severity: $OverallSeverity" `
                   -Body $EmailBody
    }

    $TextReport = New-ExchangeAuditTextReport `
        -DomainRootAceResults  $DomainRootAceResults `
        -GroupMembershipResults $GroupMembershipResults `
        -GroupAclRiskResults   $GroupAclRiskResults `
        -DcSyncExchangeResults $DcSyncExchangeResults `
        -OverallSeverity       $OverallSeverity `
        -SuspectMembers        $SuspectMembers

    Write-Host ""
    Write-Host $TextReport

    $TextReportPath = "$global:ReportsPath\ExchangeAdSecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    try {
        $TextReport | Out-File -FilePath $TextReportPath -Encoding ASCII -Force
        if (Test-Path -Path $TextReportPath) {
            Write-Host "[OK] Text report saved: $TextReportPath" -ForegroundColor Green
        }
    } catch {
        Write-Host "[FAIL] Could not save text report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Function Remove-ExchangeDangerousAce {
    <#
    .SYNOPSIS
    Interactively removes dangerous Exchange-related ACEs from the domain root ACL.

    .DESCRIPTION
    Identifies dangerous ACEs held by Exchange security groups on the domain root, exports a
    pre-change backup, prompts for explicit confirmation (user must type CONFIRM), removes the
    ACEs, and verifies the result. Exports a post-change report.

    IMPORTANT: Removing the ACE without first running Exchange Setup /PrepareAD from a
    patched cumulative update may cause the ACE to reappear. Perform Exchange remediation
    steps documented in the wiki before using this function.

    .EXAMPLE
    Remove-ExchangeDangerousAce
    #>

    Write-Host ""
    Write-Host "Exchange Domain Root ACE Removal" -ForegroundColor Cyan
    Write-Host "======================================================================"

    $DangerousAces = Search-ExchangeDomainRootAce -ReturnAcl

    if ($DangerousAces.Count -eq 0) {
        Write-Host "[OK] No dangerous Exchange-related ACEs found on the domain root. No action needed." -ForegroundColor Green
        return
    }

    Write-Host "[WARN] The following dangerous ACEs will be targeted for removal:" -ForegroundColor Yellow
    $DangerousAces | Out-AclDetails

    Write-Host ""
    Write-Host "Exporting pre-change backup..." -ForegroundColor Cyan
    Export-AdPowerAdminData -Data $DangerousAces -ReportName "ExchangeDomainRootAce_PreChange" -Force

    Write-Host ""
    Write-Host "======================================================================"
    Write-Host "WARNING: You are about to modify the domain root ACL." -ForegroundColor Red
    Write-Host "         This action cannot be automatically undone." -ForegroundColor Red
    Write-Host "         A backup has been exported to $global:ReportsPath." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Recommended prerequisite: run Exchange Setup /PrepareAD from a patched" -ForegroundColor Yellow
    Write-Host "cumulative update before removing ACEs. Without it the ACE may reappear." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Type CONFIRM (all caps) to proceed, or anything else to cancel:" -ForegroundColor Yellow
    [string]$Confirmation = Read-Host "Confirmation"

    if ($Confirmation -ne 'CONFIRM') {
        Write-Host "Operation cancelled. No changes made." -ForegroundColor Yellow
        return
    }

    $DomainDN = (Get-ADDomain).DistinguishedName
    $RawAcl = Get-Acl "AD:\$DomainDN"

    $RemovalCount = 0
    foreach ($DangerousAce in $DangerousAces) {
        $PrincipalNamePart = $DangerousAce.SecurityPrincipal.ToString().Split('\')[-1]
        $RawAcesToRemove = $RawAcl.Access | Where-Object {
            $_.IdentityReference.Value.Split('\')[-1] -eq $PrincipalNamePart -and
            $_.ActiveDirectoryRights.ToString() -eq $DangerousAce.AdRights.ToString()
        }
        foreach ($RawAce in $RawAcesToRemove) {
            $RawAcl.RemoveAccessRule($RawAce) | Out-Null
            $RemovalCount++
        }
    }

    if ($RemovalCount -gt 0) {
        Set-Acl -Path "AD:\$DomainDN" -AclObject $RawAcl
        Write-Host "[OK] $RemovalCount ACE(s) removed from domain root ACL." -ForegroundColor Green
    } else {
        Write-Host "[WARN] No matching raw ACEs were found to remove. The ACL may have already changed." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "Verifying removal..." -ForegroundColor Cyan
    $PostRemovalAces = Search-ExchangeDomainRootAce -ReturnAcl

    if ($PostRemovalAces.Count -eq 0) {
        Write-Host "[OK] Verification passed. No dangerous Exchange ACEs remain on the domain root." -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Verification failed. $($PostRemovalAces.Count) dangerous ACE(s) still present." -ForegroundColor Red
        $PostRemovalAces | Out-AclDetails
    }

    Write-Host ""
    Write-Host "Exporting post-change report..." -ForegroundColor Cyan
    Export-AdPowerAdminData -Data $PostRemovalAces -ReportName "ExchangeDomainRootAce_PostChange" -Force
}
