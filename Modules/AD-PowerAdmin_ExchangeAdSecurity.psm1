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

Function Get-ExchangeAuditReport {
    <#
    .SYNOPSIS
    Runs all Exchange AD security checks and produces a combined report.

    .DESCRIPTION
    Orchestrates Search-ExchangeDomainRootAce, Search-ExchangeGroupMembership,
    Search-ExchangeGroupAclRisk, and Search-DcSyncRisk to produce a unified severity
    rating and CSV report. Sends an email alert when ExchangeADSecurityAudit is enabled
    and SMTP is configured.

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
        $SuspectMembers = $GroupMembershipResults | Where-Object { $_.IsSuspect -eq $true }
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
