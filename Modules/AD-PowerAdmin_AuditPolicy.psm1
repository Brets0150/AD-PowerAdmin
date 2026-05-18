#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory

# ===========================================================================
# Module-scope data tables (private)
# ===========================================================================

# Maps audit subcategory display names to their fixed Windows GUIDs.
# These GUIDs are invariant across all Windows versions that support Advanced Audit Policy.
# Names match exactly what auditpol.exe /get /category:* /r returns in the Subcategory column.
$script:AuditSubcategoryGuids = @{
    'Credential Validation'              = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'Kerberos Authentication Service'    = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    'Kerberos Service Ticket Operations' = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    'Other Account Logon Events'         = '{0CCE9241-69AE-11D9-BED3-505054503030}'
    'Computer Account Management'        = '{0CCE9236-69AE-11D9-BED3-505054503030}'
    'Distribution Group Management'      = '{0CCE9238-69AE-11D9-BED3-505054503030}'
    'Security Group Management'          = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'User Account Management'            = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Other Account Management Events'    = '{0CCE923A-69AE-11D9-BED3-505054503030}'
    'DPAPI Activity'                     = '{0CCE922D-69AE-11D9-BED3-505054503030}'
    'Process Creation'                   = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'Process Termination'                = '{0CCE922C-69AE-11D9-BED3-505054503030}'
    'RPC Events'                         = '{0CCE922E-69AE-11D9-BED3-505054503030}'
    'Directory Service Access'           = '{0CCE923B-69AE-11D9-BED3-505054503030}'
    'Directory Service Changes'          = '{0CCE923C-69AE-11D9-BED3-505054503030}'
    'Directory Service Replication'      = '{0CCE923D-69AE-11D9-BED3-505054503030}'
    'Detailed Directory Service Replication' = '{0CCE923E-69AE-11D9-BED3-505054503030}'
    'Account Lockout'                    = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    'Logoff'                             = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'Logon'                              = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Special Logon'                      = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'Group Membership'                   = '{0CCE9249-69AE-11D9-BED3-505054503030}'
    'Network Policy Server'              = '{0CCE9243-69AE-11D9-BED3-505054503030}'
    'Other Logon/Logoff Events'          = '{0CCE921C-69AE-11D9-BED3-505054503030}'
    'Application Generated'              = '{0CCE9222-69AE-11D9-BED3-505054503030}'
    'Certification Services'             = '{0CCE9221-69AE-11D9-BED3-505054503030}'
    'Detailed File Share'                = '{0CCE9244-69AE-11D9-BED3-505054503030}'
    'File Share'                         = '{0CCE9224-69AE-11D9-BED3-505054503030}'
    'File System'                        = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Connection'      = '{0CCE9226-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Packet Drop'     = '{0CCE9225-69AE-11D9-BED3-505054503030}'
    'Handle Manipulation'                = '{0CCE9223-69AE-11D9-BED3-505054503030}'
    'Kernel Object'                      = '{0CCE921F-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events'         = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'Registry'                           = '{0CCE921E-69AE-11D9-BED3-505054503030}'
    'Removable Storage'                  = '{0CCE9245-69AE-11D9-BED3-505054503030}'
    'SAM'                                = '{0CCE9220-69AE-11D9-BED3-505054503030}'
    'Central Policy Staging'             = '{0CCE9246-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change'                = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'Authentication Policy Change'       = '{0CCE9230-69AE-11D9-BED3-505054503030}'
    'Authorization Policy Change'        = '{0CCE9231-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Policy Change'   = '{0CCE9233-69AE-11D9-BED3-505054503030}'
    'MPSSVC Rule-Level Policy Change'    = '{0CCE9232-69AE-11D9-BED3-505054503030}'
    'Other Policy Change Events'         = '{0CCE9234-69AE-11D9-BED3-505054503030}'
    'Non Sensitive Privilege Use'        = '{0CCE9229-69AE-11D9-BED3-505054503030}'
    'Other Privilege Use Events'         = '{0CCE922A-69AE-11D9-BED3-505054503030}'
    'Sensitive Privilege Use'            = '{0CCE9228-69AE-11D9-BED3-505054503030}'
    'IPsec Driver'                       = '{0CCE9213-69AE-11D9-BED3-505054503030}'
    'Other System Events'                = '{0CCE9214-69AE-11D9-BED3-505054503030}'
    'Security State Change'              = '{0CCE9210-69AE-11D9-BED3-505054503030}'
    'Security System Extension'          = '{0CCE9211-69AE-11D9-BED3-505054503030}'
    'System Integrity'                   = '{0CCE9212-69AE-11D9-BED3-505054503030}'
}

# Maps baseline setting strings to audit.csv integer values and auditpol.exe text.
$script:AuditInclusionMap = @{
    'NoAuditing'        = @{ CsvValue = 0; AuditpolText = 'No Auditing' }
    'Success'           = @{ CsvValue = 1; AuditpolText = 'Success' }
    'Failure'           = @{ CsvValue = 2; AuditpolText = 'Failure' }
    'SuccessAndFailure' = @{ CsvValue = 3; AuditpolText = 'Success and Failure' }
}

# Reverse map: auditpol.exe text -> numeric bit value used for coverage checks.
# Success=1, Failure=2, SuccessAndFailure=3 (1|2). A setting is compliant when
# (actual_bits -band expected_bits) -eq expected_bits.
$script:AuditpolTextToBitValue = @{
    'No Auditing'        = 0
    'Success'            = 1
    'Failure'            = 2
    'Success and Failure'= 3
}

# Audit policy baselines sourced from AD_Audit_Policy_Baseline_Dossier.md.
$script:AuditPolicyTemplates = @{
    StandardComputer = @{
        Name      = 'Standard Computer Audit Policy Baseline'
        AppliesTo = @('Workstation', 'MemberServer')
        AuditPolicy = @{
            'Credential Validation'           = 'SuccessAndFailure'
            'Computer Account Management'     = 'Success'
            'Other Account Management Events' = 'Success'
            'Security Group Management'       = 'Success'
            'User Account Management'         = 'SuccessAndFailure'
            'DPAPI Activity'                  = 'Success'
            'Process Creation'                = 'Success'
            'Account Lockout'                 = 'Success'
            'Logon'                           = 'SuccessAndFailure'
            'Logoff'                          = 'Success'
            'Special Logon'                   = 'Success'
            'Group Membership'                = 'Success'
            'Network Policy Server'           = 'SuccessAndFailure'
            'Removable Storage'               = 'SuccessAndFailure'
            'Other Object Access Events'      = 'SuccessAndFailure'
            'Audit Policy Change'             = 'SuccessAndFailure'
            'Authentication Policy Change'    = 'Success'
            'Authorization Policy Change'     = 'SuccessAndFailure'
            'MPSSVC Rule-Level Policy Change' = 'Success'
            'Sensitive Privilege Use'         = 'Failure'
            'Security State Change'           = 'Success'
            'Security System Extension'       = 'SuccessAndFailure'
            'System Integrity'               = 'SuccessAndFailure'
            'IPsec Driver'                   = 'SuccessAndFailure'
            'Other System Events'            = 'SuccessAndFailure'
        }
        EventLogs = @{
            'Security'                              = @{ MinKB = 196608;   PreferredKB = 1048576 }
            'System'                                = @{ MinKB = 32768;    PreferredKB = 65536 }
            'Application'                           = @{ MinKB = 32768;    PreferredKB = 65536 }
            'Windows PowerShell'                    = @{ MinKB = 65536;    PreferredKB = 262144 }
            'Microsoft-Windows-PowerShell/Operational' = @{ MinKB = 65536; PreferredKB = 262144 }
        }
        ExtraChecks = @{
            CheckAdvancedAuditOverride = $true
            CheckNtlmAuditSettings     = $false
            CheckDomainObjectSacl      = $false
        }
    }

    DomainController = @{
        Name      = 'Domain Controller Audit Policy Baseline'
        AppliesTo = @('DomainController')
        AuditPolicy = @{
            'Credential Validation'              = 'SuccessAndFailure'
            'Kerberos Authentication Service'    = 'SuccessAndFailure'
            'Kerberos Service Ticket Operations' = 'SuccessAndFailure'
            'Other Account Logon Events'         = 'SuccessAndFailure'
            'Computer Account Management'        = 'SuccessAndFailure'
            'Distribution Group Management'      = 'SuccessAndFailure'
            'Security Group Management'          = 'SuccessAndFailure'
            'User Account Management'            = 'SuccessAndFailure'
            'Other Account Management Events'    = 'SuccessAndFailure'
            'DPAPI Activity'                     = 'Success'
            'Process Creation'                   = 'Success'
            'Directory Service Access'           = 'SuccessAndFailure'
            'Directory Service Changes'          = 'SuccessAndFailure'
            'Account Lockout'                    = 'Success'
            'Logon'                              = 'SuccessAndFailure'
            'Logoff'                             = 'Success'
            'Special Logon'                      = 'Success'
            'Group Membership'                   = 'Success'
            'Network Policy Server'              = 'SuccessAndFailure'
            'Other Logon/Logoff Events'          = 'SuccessAndFailure'
            'SAM'                                = 'SuccessAndFailure'
            'Other Object Access Events'         = 'SuccessAndFailure'
            'Removable Storage'                  = 'SuccessAndFailure'
            'Audit Policy Change'                = 'SuccessAndFailure'
            'Authentication Policy Change'       = 'SuccessAndFailure'
            'Authorization Policy Change'        = 'SuccessAndFailure'
            'MPSSVC Rule-Level Policy Change'    = 'Success'
            'Sensitive Privilege Use'            = 'SuccessAndFailure'
            'Security State Change'              = 'SuccessAndFailure'
            'Security System Extension'          = 'SuccessAndFailure'
            'System Integrity'                  = 'SuccessAndFailure'
            'IPsec Driver'                      = 'SuccessAndFailure'
            'Other System Events'               = 'SuccessAndFailure'
        }
        EventLogs = @{
            'Security'                              = @{ MinKB = 1048576;  PreferredKB = 2097152 }
            'System'                                = @{ MinKB = 65536;    PreferredKB = 262144 }
            'Application'                           = @{ MinKB = 65536;    PreferredKB = 262144 }
            'Directory Service'                     = @{ MinKB = 262144;   PreferredKB = 1048576 }
            'Windows PowerShell'                    = @{ MinKB = 262144;   PreferredKB = 524288 }
            'Microsoft-Windows-PowerShell/Operational' = @{ MinKB = 262144; PreferredKB = 524288 }
        }
        ExtraChecks = @{
            CheckAdvancedAuditOverride = $true
            CheckNtlmAuditSettings     = $true
            CheckDomainObjectSacl      = $true
        }
    }
}

# Severity-to-color mapping for console output.
$script:SeverityColors = @{
    'Compliant'     = 'Green'
    'Informational' = 'Cyan'
    'Medium'        = 'Yellow'
    'High'          = 'DarkYellow'
    'Critical'      = 'Red'
}

$script:SeverityPrefixes = @{
    'Compliant'     = '[OK]  '
    'Informational' = '[INFO]'
    'Medium'        = '[WARN]'
    'High'          = '[HIGH]'
    'Critical'      = '[FAIL]'
}

# Short descriptions shown under each finding, keyed by subcategory display name.
$script:SubcategoryDescriptions = @{
    'Credential Validation'                      = 'NTLM credential validation on the authenticating DC. Events 4776 (success/failure).'
    'Kerberos Authentication Service'            = 'Kerberos TGT (AS) requests. Events 4768; key for AS-REP Roasting and authentication abuse detection.'
    'Kerberos Service Ticket Operations'         = 'Kerberos service ticket (TGS) requests. Events 4769/4770; key for Kerberoasting detection.'
    'Other Account Logon Events'                 = 'Miscellaneous account logon events such as replay detection. Event 4649.'
    'Computer Account Management'                = 'Computer account creation, modification, and deletion. Events 4741-4743.'
    'Distribution Group Management'              = 'Distribution group membership and management changes. Events 4744-4753.'
    'Security Group Management'                  = 'Security group membership changes including privileged groups. Events 4727-4735, 4754-4758.'
    'User Account Management'                    = 'User account creation, deletion, password changes, enable/disable, and rename. Events 4720-4738.'
    'Other Account Management Events'            = 'Miscellaneous account management events not covered by other subcategories.'
    'Process Creation'                           = 'New process creation. Event 4688; enables command-line logging when combined with command-line auditing policy.'
    'Process Termination'                        = 'Process termination. Event 4689; high volume and lower investigative value in most environments.'
    'DPAPI Activity'                             = 'DPAPI encryption and decryption operations used by browsers and credential managers. Events 4692/4693.'
    'RPC Events'                                 = 'RPC connections to remote systems. Event 5712; typically high volume.'
    'Directory Service Access'                   = 'Access to Active Directory objects (reads and queries). Event 4662; requires object SACLs to generate events.'
    'Directory Service Changes'                  = 'Modifications to Active Directory objects. Events 5136/5137/5138/5141; requires object SACLs to generate events.'
    'Directory Service Replication'              = 'AD replication partner activity. Events 4932/4933; useful for DCSync-style attack detection.'
    'Detailed Directory Service Replication'     = 'Detailed replication attribute-level events. High volume; use only for targeted investigations.'
    'Network Policy Server'                      = 'NPS RADIUS authentication and accounting events. Events 6272-6280; captures VPN, wireless 802.1x, and dial-in authentication success and failure.'
    'Account Lockout'                            = 'Account lockout events. Event 4740; critical for identifying lockout sources and password spray activity.'
    'Logon'                                      = 'Interactive, network, batch, and service logons. Events 4624 (success) and 4625 (failure); essential for logon visibility.'
    'Logoff'                                     = 'User session logoff. Event 4634; useful for session duration and concurrent session analysis.'
    'Special Logon'                              = 'Logons using sensitive privileges (admin equivalent). Event 4672; detects privileged account authentication.'
    'Group Membership'                           = 'Group SIDs present in the logon token. Event 4627; shows which group memberships were active at logon time.'
    'Other Logon/Logoff Events'                  = 'Miscellaneous logon events such as cached credential use, NPS, and terminal service reconnections.'
    'File System'                                = 'File and folder access events. Event 4663; only useful when SACLs are configured on target objects.'
    'Registry'                                   = 'Registry key access and modification. Event 4657; only useful when SACLs are configured on target keys.'
    'SAM'                                        = 'Security Account Manager and LSA database access attempts. Event 4661; relevant to credential dumping detection.'
    'Removable Storage'                          = 'Removable media (USB, external drive) access. Event 4663; used for DLP and data exfiltration detection.'
    'File Share'                                 = 'SMB file share access. Events 5140/5145; useful on file servers for share access auditing.'
    'Detailed File Share'                        = 'Per-file SMB access within shares. Very high volume; use only with WEF or SIEM collection.'
    'Other Object Access Events'                 = 'Miscellaneous object access including Task Scheduler and COM+ objects. Events 4698-4702.'
    'Certification Services'                     = 'Certificate Authority operations including issuance, revocation, and template changes. Events 4870-4882 (AD CS only).'
    'Filtering Platform Connection'              = 'Windows Filtering Platform (WFP) accepted and blocked connections. Very high volume.'
    'Filtering Platform Packet Drop'             = 'WFP dropped packets. Very high volume; better handled by firewall logs or EDR.'
    'Central Policy Staging'                     = 'Dynamic Access Control staging policy evaluation. Event 4818.'
    'Handle Manipulation'                        = 'Object handle open and close operations. Events 4656/4658; typically high volume.'
    'Kernel Object'                              = 'Kernel object handle acquisition. Event 4656; high volume, low default value.'
    'Audit Policy Change'                        = 'Changes to audit policy settings. Event 4719; detects attempts to disable or reduce audit coverage.'
    'Authentication Policy Change'               = 'Kerberos and authentication policy changes. Events 4706-4713, 4865-4867.'
    'Authorization Policy Change'                = 'User rights assignment changes. Events 4704/4705; tracks who gains new system privileges.'
    'MPSSVC Rule-Level Policy Change'            = 'Windows Firewall rule additions, modifications, and deletions. Events 4946-4950.'
    'Filtering Platform Policy Change'           = 'WFP and IPsec policy changes. Can be noisy; enable for firewall or IPsec investigations.'
    'Other Policy Change Events'                 = 'Miscellaneous policy changes including cryptographic policy and EFS data recovery agents.'
    'Sensitive Privilege Use'                    = 'Use of sensitive privileges such as SeDebugPrivilege and SeTcbPrivilege. Events 4673/4674; high-value for privilege abuse detection.'
    'Non Sensitive Privilege Use'                = 'Use of non-sensitive privileges such as SeChangeNotifyPrivilege. Very high volume and low investigative value.'
    'Other Privilege Use Events'                 = 'Miscellaneous privilege use events not covered by other subcategories.'
    'Security State Change'                      = 'Security system state changes including startup and shutdown. Events 4608/4609/4616.'
    'Security System Extension'                  = 'Security authentication package and notification DLL loading. Events 4610-4614; detects unauthorized package loading.'
    'System Integrity'                           = 'Audit subsystem integrity events including dropped audit packets and RPC failures. Events 4612/4615/4618; critical for detecting log gaps.'
    'IPsec Driver'                               = 'IPsec driver activity. Events 4960-4963; useful for network policy enforcement monitoring.'
    'Other System Events'                        = 'Miscellaneous system security events such as BranchCache and cryptographic operation failures.'
    'Force audit policy subcategory settings override' = 'Registry key that ensures Advanced Audit Policy subcategory settings take precedence over legacy category-level settings.'
    'Domain Object SACL'                         = 'SACL audit rules on the domain root AD object. Required for Directory Service Access events to be generated.'
    'Configuration partition SACL'               = 'SACL audit rules on the AD Configuration partition. Required for Directory Service Access events on configuration objects.'
    'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' = 'Controls whether outbound NTLM authentications generate audit events. Value 2 = Audit all (Events 8001/8002).'
    'Network security: Restrict NTLM: Audit NTLM authentication in this domain' = 'Controls whether domain NTLM authentications generate audit events. Value 7 = Enable all (Event 4004).'
    'Network security: Restrict NTLM: Audit Incoming NTLM Traffic'             = 'Controls whether inbound NTLM authentications generate audit events. Value 1 = Audit all accounts (Event 8003).'
}

# Short descriptions for event log findings, keyed by the base log name.
$script:EventLogDescriptions = @{
    'Security'                                    = 'Primary security audit log. Records all enabled audit subcategory events from the Security event provider.'
    'System'                                      = 'OS-level events including service state changes, driver loads, and system errors.'
    'Application'                                 = 'Application-generated events and errors from installed services and software.'
    'Directory Service'                           = 'Active Directory replication, directory access, and schema events (domain controllers only).'
    'Windows PowerShell'                          = 'Windows PowerShell module loading and session pipeline events.'
    'Microsoft-Windows-PowerShell/Operational'    = 'PowerShell script block execution and module load events; key for detecting malicious PowerShell activity.'
    'DNS Server'                                  = 'DNS Server query and zone change events (DNS Server role only).'
    'DFS Replication'                             = 'DFS-R replication state and conflict events (DFS Replication role only).'
}

# ===========================================================================
# Initialize-Module
# ===========================================================================

Function Initialize-Module {
    <#
    .SYNOPSIS
        Registers the Audit Policy Management submenu in the AD-PowerAdmin framework.

    .DESCRIPTION
        Adds menu and job entries to $global:Menu, $global:SubMenus, and $global:UnattendedJobs.
        The daily unattended job is only registered when $global:AuditPolicyDailyCheck is $true.

    .EXAMPLE
        Initialize-Module
    #>
    $global:Menu.Remove('AuditPolicyMgmt')
    $global:SubMenus.Remove('AuditPolicyMenu')
    $global:UnattendedJobs.Remove('ADPAuditPolicyCheck')

    $global:SubMenus += @{
        'AuditPolicyMenu' = @{
            Title       = "Audit Policy Management"
            HelpCommand = "Show-ADPAuditPolicyHelp"
            Items = @{
                'AuditCheck' = @{
                    Title   = "Audit Policy Compliance Check"
                    Label   = "Collect effective audit policy settings from the local system (and optionally a remote system), compare against the recommended baseline, and report gaps by severity."
                    Command = "Start-ADPAuditPolicyCheck"
                }
                'DeployDC' = @{
                    Title   = "Deploy DC Baseline GPO"
                    Label   = "Create and link a Group Policy Object enforcing the Domain Controller audit policy baseline to the Domain Controllers OU."
                    Command = "New-ADPAuditPolicyGpo -Baseline DomainController"
                }
                'DeployStd' = @{
                    Title   = "Deploy Standard Computer Baseline GPO"
                    Label   = "Create a Group Policy Object enforcing the Standard Computer audit policy baseline and link it to an administrator-selected OU."
                    Command = "New-ADPAuditPolicyGpo -Baseline StandardComputer"
                }
                'ExportReport' = @{
                    Title   = "Export Audit Policy Report"
                    Label   = "Run the compliance check and export all findings to a CSV file in the Reports directory."
                    Command = "Export-ADPAuditPolicyReport"
                }
                'GpoDiagnostic' = @{
                    Title   = "Diagnose Audit Policy GPO"
                    Label   = "Run six targeted checks to identify why a deployed audit policy GPO is not applying settings: GPO existence, AD object CSE registration, link state, SYSVOL content, effective policy on a target DC, and Group Policy processing events."
                    Command = "Test-ADPAuditPolicyGpoDiagnostic"
                }
            }
        }
    }

    $global:Menu += @{
        'AuditPolicyMgmt' = @{
            Title    = "Audit Policy Management"
            Label    = "Check and enforce Windows audit policy baselines. Identify missing or misconfigured audit subcategories, event log sizing gaps, and deploy GPO-based baselines for domain controllers and standard computers."
            Module   = "AD-PowerAdmin_AuditPolicy"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'AuditPolicyMenu'"
        }
    }

    if ($global:AuditPolicyDailyCheck) {
        $global:UnattendedJobs += @{
            'ADPAuditPolicyCheck' = @{
                Title    = "Daily Audit Policy Compliance Check"
                Label    = "Run the audit policy compliance check daily and write findings to the Reports directory."
                Module   = "AD-PowerAdmin_AuditPolicy"
                Function = "Start-ADPAuditPolicyCheck"
                Daily    = $true
                Command  = "Start-ADPAuditPolicyCheck -Unattended"
            }
        }
    }
}

Initialize-Module

# ===========================================================================
# Private helpers
# ===========================================================================

Function Get-ADPAuditPolicyBaseline {
    # Returns the baseline hashtable for the given name. Private.
    Param([string]$Name)
    return $script:AuditPolicyTemplates[$Name]
}


Function New-ADPAuditFinding {
    # Creates a standardized audit finding object. Private.
    Param(
        [string]$ComputerName  = $env:COMPUTERNAME,
        [string]$Baseline      = '',
        [string]$Category      = '',
        [string]$SettingName   = '',
        [string]$ExpectedValue = '',
        [string]$ActualValue   = '',
        [string]$Status        = 'NonCompliant',
        [string]$Severity      = 'Medium',
        [string]$Reason        = '',
        [string]$Remediation   = ''
    )
    return [PSCustomObject]@{
        ComputerName  = $ComputerName
        Baseline      = $Baseline
        Category      = $Category
        SettingName   = $SettingName
        ExpectedValue = $ExpectedValue
        ActualValue   = $ActualValue
        Status        = $Status
        Severity      = $Severity
        Reason        = $Reason
        Remediation   = $Remediation
    }
}


Function Show-ADPAuditFindings {
    # Prints non-compliant findings to the console with color coding and word wrapping. Private.
    Param(
        [PSCustomObject[]]$Findings,
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $Indent = '         '  # 9 spaces -- aligns with text after '[FAIL] '

    Write-Host ""
    Write-Host "--- Audit Policy Compliance Results: $ComputerName ---" -ForegroundColor White

    $NonCompliant = $Findings | Where-Object { $_.Status -ne 'Compliant' }
    $Compliant    = $Findings | Where-Object { $_.Status -eq 'Compliant' }

    foreach ($Finding in ($NonCompliant | Sort-Object -Property @{Expression={
        switch ($_.Severity) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Informational' {3} default {4} }
    }})) {
        $Prefix = $script:SeverityPrefixes[$Finding.Severity]
        $Color  = $script:SeverityColors[$Finding.Severity]
        if (-not $Prefix) { $Prefix = '[????]' }
        if (-not $Color)  { $Color  = 'White' }

        Write-Host ""
        Write-Host "$Prefix $($Finding.SettingName)" -ForegroundColor $Color

        # Look up a short description for this finding.
        $Desc = $script:SubcategoryDescriptions[$Finding.SettingName]
        if (-not $Desc -and $Finding.Category -eq 'Event Log') {
            $BaseLogName = $Finding.SettingName -replace ' log(| maximum size| enabled| retention mode)$', ''
            $Desc = $script:EventLogDescriptions[$BaseLogName]
        }
        if ($Desc) {
            Write-WrappedText -Label 'Use:      ' -Text $Desc -Indent $Indent -ForegroundColor DarkCyan
        }

        Write-WrappedText -Label 'Expected: ' -Text $Finding.ExpectedValue -Indent $Indent -ForegroundColor Gray
        Write-WrappedText -Label 'Actual:   ' -Text $Finding.ActualValue   -Indent $Indent -ForegroundColor Gray
        if ($Finding.Reason) {
            Write-WrappedText -Label 'Reason:   ' -Text $Finding.Reason -Indent $Indent -ForegroundColor Gray
        }
    }

    Write-Host ""
    # @() forces an array so .Count is always an integer even when Where-Object returns a
    # single object (scalar PSCustomObject). In PS5.1, .Count on a scalar PSCustomObject
    # returns $null, not 1, causing the count to display as blank in the summary line.
    $Critical      = @($NonCompliant | Where-Object { $_.Severity -eq 'Critical' }).Count
    $High          = @($NonCompliant | Where-Object { $_.Severity -eq 'High' }).Count
    $Medium        = @($NonCompliant | Where-Object { $_.Severity -eq 'Medium' }).Count
    $Informational = @($NonCompliant | Where-Object { $_.Severity -eq 'Informational' }).Count

    Write-Host "Summary: $($Findings.Count) checks -- " -NoNewline -ForegroundColor White
    Write-Host "$($Compliant.Count) Compliant  " -NoNewline -ForegroundColor Green
    Write-Host "$Critical Critical  "            -NoNewline -ForegroundColor Red
    Write-Host "$High High  "                    -NoNewline -ForegroundColor DarkYellow
    Write-Host "$Medium Medium  "                -NoNewline -ForegroundColor Yellow
    Write-Host "$Informational Informational"               -ForegroundColor Cyan
    Write-Host ""
}

Function Format-ADPAuditSettingLabel {
    # Converts an audit inclusion key to a short display string for the help page. Private.
    Param([string]$Key)
    if ([string]::IsNullOrEmpty($Key)) { return '[Not Req.]' }
    switch ($Key) {
        'SuccessAndFailure' { return 'Succ + Fail' }
        'Success'           { return 'Success    ' }
        'Failure'           { return 'Failure    ' }
        default             { return '[Not Req.]' }
    }
}

# ===========================================================================
# Exported functions
# ===========================================================================

Function Start-ADPAuditPolicyCheck {
    <#
    .SYNOPSIS
        Runs the full audit policy compliance check for the local system.

    .DESCRIPTION
        Detects the local system role (Domain Controller, Member Server, or Workstation),
        selects the appropriate baseline, collects the effective audit policy and event log
        sizes, and compares them against the baseline. Results are printed to the console
        color-coded by severity. Optionally audits a specified remote system for comparison.

        When run with -Unattended, prompts are suppressed and findings are written to the
        Reports directory via Export-AdPowerAdminData.

    .PARAMETER Unattended
        Suppresses all interactive prompts and writes findings to the Reports directory.

    .EXAMPLE
        Start-ADPAuditPolicyCheck
    .EXAMPLE
        Start-ADPAuditPolicyCheck -Unattended
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$Unattended
    )

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Audit Policy Compliance Check" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    if ($Unattended) {
        $TargetComputer = $env:COMPUTERNAME
    } else {
        Write-Host "[INFO] Enter a computer name to audit, or press Enter for the local host ($env:COMPUTERNAME)." -ForegroundColor Cyan
        $RawInput = Read-Host "Target computer"
        $TargetComputer = if ([string]::IsNullOrWhiteSpace($RawInput)) { $env:COMPUTERNAME } else { $RawInput.Trim() }
    }

    $IsLocal = ($TargetComputer -eq $env:COMPUTERNAME) -or ($TargetComputer -eq 'localhost') -or ($TargetComputer -eq '127.0.0.1')

    # Detect system role on the target.
    if ($IsLocal) {
        $TargetRole = Get-SystemRole
    } else {
        Write-Host "[INFO] Connecting to $TargetComputer to detect system role..." -ForegroundColor Cyan
        try {
            $ProductType = Invoke-Command -ComputerName $TargetComputer -ScriptBlock {
                (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType
            } -ErrorAction Stop
            $TargetRole = switch ($ProductType) { 2 { 'DomainController' } 3 { 'MemberServer' } default { 'Workstation' } }
        } catch {
            Write-Host "[WARN] Could not detect role on $TargetComputer ($_ ). Defaulting to StandardComputer baseline." -ForegroundColor Yellow
            $TargetRole = 'MemberServer'
        }
    }

    $BaselineName = if ($TargetRole -eq 'DomainController') { 'DomainController' } else { 'StandardComputer' }
    Write-Host "[INFO] Target: $TargetComputer  Role: $TargetRole  Baseline: $BaselineName" -ForegroundColor Cyan

    $AuditData = Get-ADPAuditPolicyStatus       -ComputerName $TargetComputer
    $EventLogs = Get-ADPEventLogStorageStatus    -ComputerName $TargetComputer
    $Findings  = Compare-ADPAuditPolicyBaseline -AuditData $AuditData -EventLogs $EventLogs -Baseline $BaselineName -ComputerName $TargetComputer

    $Template = Get-ADPAuditPolicyBaseline -Name $BaselineName
    if ($Template.ExtraChecks.CheckDomainObjectSacl) {
        $Findings += Test-ADPDirectoryServiceSacl -ComputerName $TargetComputer
    }
    if ($Template.ExtraChecks.CheckNtlmAuditSettings) {
        $Findings += Test-ADPNtlmAuditSettings -ComputerName $TargetComputer
    }

    Show-ADPAuditFindings -Findings $Findings -ComputerName $TargetComputer

    if ($Unattended) {
        $NonCompliant = $Findings | Where-Object { $_.Status -ne 'Compliant' }
        if ($NonCompliant.Count -gt 0) {
            Export-AdPowerAdminData -Data $Findings -ReportName "AuditPolicyReport"
        }
    }
}

Function Get-ADPAuditPolicyStatus {
    <#
    .SYNOPSIS
        Collects effective audit policy settings from a local or remote system.

    .DESCRIPTION
        Runs auditpol.exe /get /category:* /r and parses the CSV output. On a remote system,
        the command is executed via Invoke-Command (requires WinRM). Returns a collection of
        objects representing current audit subcategory settings.

    .PARAMETER ComputerName
        Target computer name. Defaults to the local system.

    .OUTPUTS
        Collection of PSCustomObjects with Subcategory, InclusionSetting, and MachineName.

    .EXAMPLE
        Get-ADPAuditPolicyStatus
    .EXAMPLE
        Get-ADPAuditPolicyStatus -ComputerName DC01
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $IsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost') -or ($ComputerName -eq '127.0.0.1')

    try {
        if ($IsLocal) {
            $RawCsv = & auditpol.exe /get /category:* /r 2>$null
        } else {
            $RawCsv = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                & auditpol.exe /get /category:* /r 2>$null
            } -ErrorAction Stop
        }

        if (-not $RawCsv) {
            Write-Host "[FAIL] auditpol.exe returned no output from $ComputerName." -ForegroundColor Red
            return @()
        }

        $Parsed = $RawCsv | ConvertFrom-Csv
        return $Parsed
    } catch {
        Write-Host "[FAIL] Could not collect audit policy from ${ComputerName}: $_" -ForegroundColor Red
        return @()
    }
}

Function Get-ADPEventLogStorageStatus {
    <#
    .SYNOPSIS
        Collects event log size, enabled state, and retention mode from a system.

    .DESCRIPTION
        Queries Get-WinEvent -ListLog for the Security, System, Application, Directory Service,
        Windows PowerShell, and PowerShell Operational logs. Also checks the ADMX-based
        policy registry path for GPO-configured maximum sizes. Returns a collection of
        log status objects.

    .PARAMETER ComputerName
        Target computer name. Defaults to the local system.

    .OUTPUTS
        Collection of PSCustomObjects with LogName, IsEnabled, MaxSizeKB, LogMode,
        RecordCount, and PolicyMaxSizeKB.

    .EXAMPLE
        Get-ADPEventLogStorageStatus
    .EXAMPLE
        Get-ADPEventLogStorageStatus -ComputerName DC01
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $LogNames = @(
        'Security',
        'System',
        'Application',
        'Directory Service',
        'Windows PowerShell',
        'Microsoft-Windows-PowerShell/Operational'
    )

    $IsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or ($ComputerName -eq 'localhost') -or ($ComputerName -eq '127.0.0.1')

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($LogName in $LogNames) {
        try {
            if ($IsLocal) {
                $LogInfo = Get-WinEvent -ListLog $LogName -ErrorAction Stop
            } else {
                $LogInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                    param($LN)
                    Get-WinEvent -ListLog $LN -ErrorAction SilentlyContinue
                } -ArgumentList $LogName -ErrorAction Stop
            }

            if ($null -eq $LogInfo) { continue }

            $MaxSizeKB = [math]::Round($LogInfo.MaximumSizeInBytes / 1KB)

            # Check ADMX policy registry path for GPO-managed size (KB).
            $PolicyMaxSizeKB = 0
            $PolicyRegKey    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\$LogName"
            try {
                if ($IsLocal) {
                    $RegVal = Get-ItemProperty -Path $PolicyRegKey -Name MaxSize -ErrorAction SilentlyContinue
                    if ($RegVal) { $PolicyMaxSizeKB = [int]$RegVal.MaxSize }
                } else {
                    $PolicyMaxSizeKB = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                        param($Key)
                        $v = Get-ItemProperty -Path $Key -Name MaxSize -ErrorAction SilentlyContinue
                        if ($v) { [int]$v.MaxSize } else { 0 }
                    } -ArgumentList $PolicyRegKey -ErrorAction SilentlyContinue
                }
            } catch { $PolicyMaxSizeKB = 0 }

            $Results.Add([PSCustomObject]@{
                ComputerName     = $ComputerName
                LogName          = $LogInfo.LogName
                IsEnabled        = $LogInfo.IsEnabled
                MaxSizeKB        = $MaxSizeKB
                LogMode          = $LogInfo.LogMode.ToString()
                RecordCount      = $LogInfo.RecordCount
                PolicyMaxSizeKB  = $PolicyMaxSizeKB
            })
        } catch {
            # Log not present on this system (e.g. Directory Service on a non-DC). Skip silently.
        }
    }

    return $Results.ToArray()
}

Function Compare-ADPAuditPolicyBaseline {
    <#
    .SYNOPSIS
        Compares collected audit policy and event log data against a named baseline.

    .DESCRIPTION
        Iterates every subcategory and event log defined in the selected baseline and
        produces a structured finding object for each. Findings have severity levels of
        Critical, High, Medium, Informational, or Compliant.

        Also checks whether the Advanced Audit Policy subcategory override registry key
        (SCENoApplyLegacyAuditPolicy) is enabled; a missing or disabled key is Critical
        because it means subcategory settings may be silently ignored.

    .PARAMETER AuditData
        Collection returned by Get-ADPAuditPolicyStatus.

    .PARAMETER EventLogs
        Collection returned by Get-ADPEventLogStorageStatus.

    .PARAMETER Baseline
        Baseline name: 'StandardComputer' or 'DomainController'.

    .PARAMETER ComputerName
        Computer the data was collected from. Used in finding objects.

    .OUTPUTS
        [PSCustomObject[]] array of finding objects.

    .EXAMPLE
        $Data = Get-ADPAuditPolicyStatus
        $Logs = Get-ADPEventLogStorageStatus
        Compare-ADPAuditPolicyBaseline -AuditData $Data -EventLogs $Logs -Baseline DomainController
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [PSObject[]]$AuditData,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [PSObject[]]$EventLogs,

        [Parameter(Mandatory=$true)]
        [ValidateSet('StandardComputer', 'DomainController')]
        [string]$Baseline,

        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Template = Get-ADPAuditPolicyBaseline -Name $Baseline

    # Build an index of current auditpol data keyed by Subcategory name.
    $AuditIndex = @{}
    foreach ($Row in $AuditData) {
        $Key = ($Row.Subcategory).Trim()
        $AuditIndex[$Key] = $Row
    }

    # --- Subcategory compliance ---
    $CriticalSubcategories = @(
        'Logon', 'Account Lockout', 'Security State Change', 'System Integrity',
        'Audit Policy Change', 'Credential Validation', 'Kerberos Authentication Service',
        'Kerberos Service Ticket Operations', 'Directory Service Access', 'Directory Service Changes'
    )

    foreach ($SubcatName in $Template.AuditPolicy.Keys) {
        $ExpectedKey = $Template.AuditPolicy[$SubcatName]
        $ExpectedText = $script:AuditInclusionMap[$ExpectedKey].AuditpolText

        $CurrentRow = $AuditIndex[$SubcatName]
        if ($null -eq $CurrentRow) {
            $Severity = if ($CriticalSubcategories -contains $SubcatName) { 'Critical' } else { 'High' }
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Audit Subcategory' -SettingName $SubcatName `
                -ExpectedValue $ExpectedText -ActualValue 'Not Found' `
                -Status 'Missing' -Severity $Severity `
                -Reason "Subcategory '$SubcatName' was not returned by auditpol.exe. The system may not support this subcategory." `
                -Remediation "Apply the $Baseline audit policy baseline GPO."))
            continue
        }

        $ActualText   = ($CurrentRow.'Inclusion Setting').Trim()
        $ExpectedBits = $script:AuditInclusionMap[$ExpectedKey].CsvValue
        $ActualBits   = $script:AuditpolTextToBitValue[$ActualText]

        # Compliant when actual bits cover all bits required by baseline.
        # 'Success and Failure' (3) covers 'Success' (1): 3 -band 1 = 1 = expected.
        $Covers = ($null -ne $ActualBits) -and (($ActualBits -band $ExpectedBits) -eq $ExpectedBits)

        if ($Covers) {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Audit Subcategory' -SettingName $SubcatName `
                -ExpectedValue $ExpectedText -ActualValue $ActualText `
                -Status 'Compliant' -Severity 'Compliant' `
                -Reason '' -Remediation ''))
        } else {
            $Severity = if ($CriticalSubcategories -contains $SubcatName) { 'Critical' } else { 'High' }
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Audit Subcategory' -SettingName $SubcatName `
                -ExpectedValue $ExpectedText -ActualValue $ActualText `
                -Status 'NonCompliant' -Severity $Severity `
                -Reason "Audit subcategory '$SubcatName' is set to '$ActualText' but the $Baseline baseline requires '$ExpectedText'." `
                -Remediation "Apply the $Baseline audit policy baseline GPO."))
        }
    }

    # --- Advanced Audit Policy override key ---
    [bool]$IsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or
                     ($ComputerName -eq 'localhost') -or
                     ($ComputerName -eq '127.0.0.1')
    try {
        [object]$OverrideVal = $null
        if ($IsLocal) {
            $OverrideVal = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                -Name 'SCENoApplyLegacyAuditPolicy' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
        } else {
            $OverrideVal = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                    -Name 'SCENoApplyLegacyAuditPolicy' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
            } -ErrorAction SilentlyContinue
        }
        if ($OverrideVal -eq 1) {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Security Option' -SettingName 'Force audit policy subcategory settings override' `
                -ExpectedValue 'Enabled (1)' -ActualValue "Enabled ($OverrideVal)" `
                -Status 'Compliant' -Severity 'Compliant' `
                -Reason '' -Remediation ''))
        } else {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Security Option' -SettingName 'Force audit policy subcategory settings override' `
                -ExpectedValue 'Enabled (1)' -ActualValue "$(if ($null -eq $OverrideVal) { 'Not Set' } else { "Disabled ($OverrideVal)" })" `
                -Status 'NonCompliant' -Severity 'Critical' `
                -Reason "SCENoApplyLegacyAuditPolicy is not enabled. Without this key, category-level audit policy settings can silently override Advanced Audit Policy subcategory settings, causing security-critical subcategories to produce no events." `
                -Remediation "Enable 'Audit: Force audit policy subcategory settings to override audit policy category settings' via GPO Security Options, or apply the baseline GPO."))
        }
    } catch {
        Write-Host "[WARN] Could not read SCENoApplyLegacyAuditPolicy registry key." -ForegroundColor Yellow
    }

    # --- Event log size compliance ---
    $LogIndex = @{}
    foreach ($Log in $EventLogs) { $LogIndex[$Log.LogName] = $Log }

    foreach ($LogName in $Template.EventLogs.Keys) {
        $Target    = $Template.EventLogs[$LogName]
        $MinKB     = $Target.MinKB
        $PrefKB    = $Target.PreferredKB
        $LogStatus = $LogIndex[$LogName]

        $MinMB  = [math]::Round($MinKB  / 1024, 0)
        $PrefMB = [math]::Round($PrefKB / 1024, 0)

        if ($null -eq $LogStatus) {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Event Log' -SettingName "$LogName log" `
                -ExpectedValue ">= ${MinMB} MB" -ActualValue 'Log not found' `
                -Status 'Missing' -Severity 'Medium' `
                -Reason "The '$LogName' event log was not found on this system." `
                -Remediation 'Verify the log name and that the applicable Windows role is installed.'))
            continue
        }

        if (-not $LogStatus.IsEnabled) {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Event Log' -SettingName "$LogName log enabled" `
                -ExpectedValue 'Enabled' -ActualValue 'Disabled' `
                -Status 'NonCompliant' -Severity 'Critical' `
                -Reason "The '$LogName' event log is disabled. No events will be recorded." `
                -Remediation "Enable the '$LogName' event log."))
            continue
        }

        $ActualKB = $LogStatus.MaxSizeKB
        $ActualMB = [math]::Round($ActualKB / 1024, 0)
        if ($ActualKB -lt $MinKB) {
            $Severity = if ($LogName -eq 'Security') { 'Critical' } else { 'High' }
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Event Log' -SettingName "$LogName log maximum size" `
                -ExpectedValue ">= ${MinMB} MB" -ActualValue "${ActualMB} MB" `
                -Status 'NonCompliant' -Severity $Severity `
                -Reason "The '$LogName' log maximum size is ${ActualMB} MB, which is below the compliance minimum of ${MinMB} MB. Log events may roll over before investigation is possible." `
                -Remediation "Increase the '$LogName' log maximum size. Apply the $Baseline baseline GPO to enforce the recommended size."))
        } elseif ($ActualKB -lt $PrefKB) {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Event Log' -SettingName "$LogName log maximum size" `
                -ExpectedValue ">= ${PrefMB} MB (preferred)" -ActualValue "${ActualMB} MB" `
                -Status 'NonCompliant' -Severity 'Informational' `
                -Reason "The '$LogName' log meets the compliance minimum (${MinMB} MB) but is below the operational preferred size of ${PrefMB} MB." `
                -Remediation "Consider increasing the '$LogName' log maximum size to ${PrefMB} MB."))
        } else {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Event Log' -SettingName "$LogName log maximum size" `
                -ExpectedValue ">= ${PrefMB} MB" -ActualValue "${ActualMB} MB" `
                -Status 'Compliant' -Severity 'Compliant' `
                -Reason '' -Remediation ''))
        }

        if ($LogStatus.LogMode -eq 'DoNotOverwrite') {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline $Baseline `
                -Category 'Event Log' -SettingName "$LogName log retention mode" `
                -ExpectedValue 'Circular (Overwrite as needed)' -ActualValue 'DoNotOverwrite' `
                -Status 'NonCompliant' -Severity 'High' `
                -Reason "The '$LogName' log is set to 'Do Not Overwrite'. When the log fills, new events will be discarded, creating an event black hole unless disk capacity and log collection are actively monitored." `
                -Remediation "Set the '$LogName' log to 'Overwrite events as needed' unless you have a confirmed SIEM or WEF forwarding pipeline."))
        }
    }

    return $Findings.ToArray()
}

Function Test-ADPAuditPolicyGpoDiagnostic {
    <#
    .SYNOPSIS
        Diagnoses why audit policy GPO settings are not applying to a target system.

    .DESCRIPTION
        Runs six targeted checks to identify why a deployed audit policy GPO is not
        producing the expected effective policy on a domain controller or member system.

        Check 1 - GPO Existence: Confirms the named GPO exists in the domain.
        Check 2 - AD Object CSE Registration: Verifies that both the Security Settings
                  CSE GUID {827D319E-...} and the Audit Policy Configuration CSE GUID
                  {F3CCC681-...} are registered in gPCMachineExtensionNames on the GPO AD
                  object. The Security CSE processes GptTmpl.inf; the Audit Policy CSE is
                  the dedicated extension that processes audit.csv. Without both GUIDs
                  registered, the GP client skips the corresponding file on every gpupdate
                  and GPMC omits the affected section from the Settings display.
        Check 3 - GPO Link State: Verifies the GPO is linked, enabled, and enforced.
        Check 4 - SYSVOL Content: Verifies audit.csv and GptTmpl.inf exist with expected
                  content, and that gpt.ini version matches the AD object versionNumber.
        Check 5 - Effective Policy: Queries auditpol.exe on the target system and
                  compares against the baseline to confirm what is and is not applying.
        Check 6 - GP Processing Events: Reads the Group Policy Operational log on the
                  target system for Security CSE ({827D319E-...}) and Audit Policy CSE
                  ({F3CCC681-...}) processing events in the last 24 hours.

    .EXAMPLE
        Test-ADPAuditPolicyGpoDiagnostic
    #>
    [CmdletBinding()]
    Param()

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Audit Policy GPO Diagnostic" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "  Which baseline GPO do you want to diagnose?" -ForegroundColor White
    Write-Host "  1. Domain Controller baseline  (ADPA-AuditPolicy-DomainControllers)" -ForegroundColor Gray
    Write-Host "  2. Standard Computer baseline  (ADPA-AuditPolicy-StandardComputers)" -ForegroundColor Gray
    Write-Host ""
    $Selection = (Read-Host "  Enter 1 or 2 [default: 1]").Trim()
    if ($Selection -eq '2') {
        $GpoName      = 'ADPA-AuditPolicy-StandardComputers'
        $BaselineName = 'StandardComputer'
    } else {
        $GpoName      = 'ADPA-AuditPolicy-DomainControllers'
        $BaselineName = 'DomainController'
    }

    Write-Host ""
    Write-Host "  Enter the computer name to query for effective audit policy." -ForegroundColor White
    Write-Host "  For a DC: enter the DC hostname. Press Enter for this system ($env:COMPUTERNAME)." -ForegroundColor Gray
    $RawTarget = (Read-Host "  Target computer").Trim()
    $TargetDC  = if ([string]::IsNullOrWhiteSpace($RawTarget)) { $env:COMPUTERNAME } else { $RawTarget }
    $IsLocal   = ($TargetDC -eq $env:COMPUTERNAME) -or ($TargetDC -eq 'localhost') -or ($TargetDC -eq '127.0.0.1')

    Write-Host ""
    Write-Host "  GPO:      $GpoName" -ForegroundColor Cyan
    Write-Host "  Target:   $TargetDC" -ForegroundColor Cyan
    Write-Host "  Baseline: $BaselineName" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray

    [object]$GpoObject       = $null
    [object]$GpoAdObj        = $null
    [string]$GpoGuidStr      = $null
    [string]$DomainDN        = $null
    [string]$Domain          = $null
    [int]$AdVersion          = -1
    [int]$NonCompliantCount  = 0

    try {
        $ADDomain = Get-ADDomain -ErrorAction Stop
        $DomainDN = $ADDomain.DistinguishedName
        $Domain   = $ADDomain.DNSRoot
    } catch {
        Write-Host "[WARN] Could not resolve domain: $_" -ForegroundColor Yellow
    }

    # =========================================================================
    # Check 1: GPO Existence
    # =========================================================================
    Write-Host ""
    Write-Host "  CHECK 1: GPO Existence" -ForegroundColor White
    Write-Host "  ----------------------" -ForegroundColor DarkGray

    try {
        $GpoObject  = Get-GPO -Name $GpoName -ErrorAction Stop
        $GpoGuidStr = $GpoObject.Id.ToString('B').ToUpper()
        Write-Host "  [OK]   GPO found." -ForegroundColor Green
        Write-Host "         Name:     $GpoName" -ForegroundColor DarkGray
        Write-Host "         GUID:     $GpoGuidStr" -ForegroundColor DarkGray
        Write-Host "         Status:   $($GpoObject.GpoStatus)" -ForegroundColor DarkGray
        Write-Host "         Modified: $($GpoObject.ModificationTime)" -ForegroundColor DarkGray
    } catch {
        Write-Host "  [FAIL] GPO '$GpoName' was not found in the domain." -ForegroundColor Red
        Write-Host "         Use the deployment function in this submenu to create it." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Cannot continue without a GPO." -ForegroundColor Red
        Read-Host "  Press Enter to return to the menu"
        return
    }

    # =========================================================================
    # Check 2: AD Object CSE Registration (Security CSE + Audit Policy CSE)
    # =========================================================================
    Write-Host ""
    Write-Host "  CHECK 2: CSE Registration in the GPO AD Object" -ForegroundColor White
    Write-Host "  -----------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  gPCMachineExtensionNames on the GPO AD object tells the GP client which CSEs" -ForegroundColor DarkGray
    Write-Host "  to invoke. Advanced Audit Policy requires TWO separate CSE GUIDs:" -ForegroundColor DarkGray
    Write-Host "    Security CSE     {827D319E-...}  processes GptTmpl.inf" -ForegroundColor DarkGray
    Write-Host "    Audit Policy CSE {F3CCC681-...}  processes audit.csv" -ForegroundColor DarkGray
    Write-Host "  Either missing GUID causes the GP client to skip the corresponding file." -ForegroundColor DarkGray
    Write-Host ""

    [string]$SecurityCseGuid    = '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'
    [string]$AuditPolicyCseGuid = '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}'

    try {
        $GpoAdObj = Get-ADObject `
            -Filter "Name -eq '$GpoGuidStr' -and ObjectClass -eq 'groupPolicyContainer'" `
            -Properties gPCMachineExtensionNames, versionNumber `
            -ErrorAction Stop

        if ($null -eq $GpoAdObj) {
            Write-Host "  [FAIL] GPO AD object not found for GUID $GpoGuidStr." -ForegroundColor Red
            Write-Host "         This may indicate an AD replication delay. Wait and retry." -ForegroundColor Yellow
        } else {
            $ExtNames  = [string]$GpoAdObj.gPCMachineExtensionNames
            $AdVersion = [int]$GpoAdObj.versionNumber

            $HasSecurityCse    = $ExtNames -match [regex]::Escape($SecurityCseGuid)
            $HasAuditPolicyCse = $ExtNames -match [regex]::Escape($AuditPolicyCseGuid)

            if ($HasSecurityCse) {
                Write-Host "  [OK]   Security Settings CSE {827D319E-...} is registered." -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Security Settings CSE {827D319E-...} is NOT registered." -ForegroundColor Red
                Write-Host "         GptTmpl.inf (SCENoApplyLegacyAuditPolicy) will not be applied." -ForegroundColor Yellow
            }

            if ($HasAuditPolicyCse) {
                Write-Host "  [OK]   Audit Policy CSE {F3CCC681-...} is registered." -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Audit Policy CSE {F3CCC681-...} is NOT registered." -ForegroundColor Red
                Write-Host "         audit.csv will not be processed; Advanced Audit Policy will not apply." -ForegroundColor Yellow
                Write-Host "         This is the root cause of settings appearing in the editor but not applying." -ForegroundColor Yellow
            }

            if (-not $HasSecurityCse -or -not $HasAuditPolicyCse) {
                Write-Host "         Fix: redeploy the GPO using the deployment function in this submenu." -ForegroundColor Yellow
            }

            Write-Host "         gPCMachineExtensionNames: $ExtNames" -ForegroundColor DarkGray
            Write-Host "         AD object versionNumber:  $AdVersion" -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  [WARN] Could not query GPO AD object: $_" -ForegroundColor Yellow
    }

    # =========================================================================
    # Check 3: GPO Link State
    # =========================================================================
    Write-Host ""
    Write-Host "  CHECK 3: GPO Link State" -ForegroundColor White
    Write-Host "  -----------------------" -ForegroundColor DarkGray

    try {
        [xml]$GpoReport = Get-GPOReport -Name $GpoName -ReportType Xml -ErrorAction Stop
        $Links = @($GpoReport.GPO.LinksTo)

        $HasRealLinks = ($Links.Count -gt 0) -and ($null -ne $Links[0]) -and ($null -ne $Links[0].SOMPath)

        if (-not $HasRealLinks) {
            Write-Host "  [FAIL] GPO is not linked to any OU or container." -ForegroundColor Red
            Write-Host "         Link the GPO in Group Policy Management or run the deployment function." -ForegroundColor Yellow
        } else {
            Write-Host "  [INFO] GPO is linked to $($Links.Count) location(s):" -ForegroundColor Cyan
            $HasDisabledLink = $false
            foreach ($Link in $Links) {
                $SomPath    = [string]$Link.SOMPath
                $Enabled    = [string]$Link.Enabled
                $NoOverride = [string]$Link.NoOverride

                if ($Enabled -ne 'true') {
                    $StateColor = 'Red'
                    $StateNote  = '  <- DISABLED; settings will not apply'
                    $HasDisabledLink = $true
                } elseif ($NoOverride -ne 'true') {
                    $StateColor = 'Yellow'
                    $StateNote  = '  <- not enforced; a higher-priority GPO can override'
                } else {
                    $StateColor = 'Green'
                    $StateNote  = ''
                }

                Write-Host "         -> $SomPath" -NoNewline -ForegroundColor $StateColor
                Write-Host "  [Enabled=$Enabled  Enforced=$NoOverride]$StateNote" -ForegroundColor DarkGray

                if ($BaselineName -eq 'DomainController' -and $DomainDN) {
                    if ($SomPath -notmatch 'Domain Controllers') {
                        Write-Host "         [WARN] DC baseline linked to '$SomPath'; DCs may not receive this policy." -ForegroundColor Yellow
                    }
                }
            }
            if (-not $HasDisabledLink) {
                Write-Host "  [OK]   All links are enabled." -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  [WARN] Could not retrieve GPO report: $_" -ForegroundColor Yellow
    }

    # =========================================================================
    # Check 4: SYSVOL Content
    # =========================================================================
    Write-Host ""
    Write-Host "  CHECK 4: SYSVOL Content" -ForegroundColor White
    Write-Host "  -----------------------" -ForegroundColor DarkGray

    if ([string]::IsNullOrEmpty($Domain) -or [string]::IsNullOrEmpty($GpoGuidStr)) {
        Write-Host "  [WARN] Cannot check SYSVOL: domain name or GPO GUID not resolved." -ForegroundColor Yellow
    } else {
        $SysvolBase = "\\$Domain\SYSVOL\$Domain\Policies\$GpoGuidStr"
        $AuditCsv   = "$SysvolBase\Machine\Microsoft\Windows NT\Audit\audit.csv"
        $GptTmplInf = "$SysvolBase\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        $GptIniPath = "$SysvolBase\gpt.ini"

        if (Test-Path $AuditCsv) {
            try {
                $CsvLines      = @(Get-Content -Path $AuditCsv -Encoding UTF8 -ErrorAction Stop)
                $DataRows      = @($CsvLines | Select-Object -Skip 1 | Where-Object { $_ -match '\S' })
                $ExpectedCount = (Get-ADPAuditPolicyBaseline -Name $BaselineName).AuditPolicy.Count
                if ($DataRows.Count -ge $ExpectedCount) {
                    Write-Host "  [OK]   audit.csv present. Data rows: $($DataRows.Count) (expected $ExpectedCount)." -ForegroundColor Green
                } else {
                    Write-Host "  [WARN] audit.csv present but has only $($DataRows.Count) rows (expected $ExpectedCount)." -ForegroundColor Yellow
                    Write-Host "         The file may be incomplete. Redeploy the GPO." -ForegroundColor Yellow
                }
                Write-Host "         Path: $AuditCsv" -ForegroundColor DarkGray
            } catch {
                Write-Host "  [WARN] audit.csv exists but could not be read: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [FAIL] audit.csv not found in SYSVOL." -ForegroundColor Red
            Write-Host "         Path checked: $AuditCsv" -ForegroundColor DarkGray
            Write-Host "         Redeploy the GPO to recreate the SYSVOL content." -ForegroundColor Yellow
        }

        if (Test-Path $GptTmplInf) {
            try {
                $InfContent = Get-Content -Path $GptTmplInf -Encoding ASCII -Raw -ErrorAction Stop
                if ($InfContent -match 'SCENoApplyLegacyAuditPolicy') {
                    Write-Host "  [OK]   GptTmpl.inf present with SCENoApplyLegacyAuditPolicy." -ForegroundColor Green
                } else {
                    Write-Host "  [WARN] GptTmpl.inf present but SCENoApplyLegacyAuditPolicy is missing." -ForegroundColor Yellow
                    Write-Host "         Legacy category-level settings may silently override subcategory settings." -ForegroundColor Yellow
                    Write-Host "         Redeploy the GPO to restore this entry." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  [WARN] GptTmpl.inf exists but could not be read: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [WARN] GptTmpl.inf not found in SYSVOL." -ForegroundColor Yellow
            Write-Host "         Path checked: $GptTmplInf" -ForegroundColor DarkGray
        }

        if (Test-Path $GptIniPath) {
            try {
                $GptLines    = Get-Content -Path $GptIniPath -Encoding ASCII -ErrorAction Stop
                $VersionLine = $GptLines | Where-Object { $_ -match '^Version\s*=' } | Select-Object -First 1
                if ($VersionLine) {
                    [int]$GptVersion = [int](($VersionLine -split '=', 2)[1].Trim())
                    if ($AdVersion -lt 0) {
                        Write-Host "  [INFO] gpt.ini Version=$GptVersion (AD object version unavailable)." -ForegroundColor Cyan
                    } elseif ($GptVersion -eq $AdVersion) {
                        Write-Host "  [OK]   gpt.ini version ($GptVersion) matches AD object versionNumber ($AdVersion)." -ForegroundColor Green
                    } else {
                        Write-Host "  [WARN] gpt.ini version ($GptVersion) != AD object versionNumber ($AdVersion)." -ForegroundColor Yellow
                        Write-Host "         SYSVOL replication may be delayed or the AD object was not updated." -ForegroundColor Yellow
                        Write-Host "         Wait for replication to complete and then run gpupdate /force." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "  [WARN] gpt.ini found but Version line could not be parsed." -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  [WARN] gpt.ini exists but could not be read: $_" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [FAIL] gpt.ini not found at: $GptIniPath" -ForegroundColor Red
        }
    }

    # =========================================================================
    # Check 5: Effective Audit Policy on Target System
    # =========================================================================
    Write-Host ""
    Write-Host "  CHECK 5: Effective Audit Policy on $TargetDC" -ForegroundColor White
    Write-Host "  $(('-' * (43 + $TargetDC.Length)))" -ForegroundColor DarkGray

    try {
        $AuditData = Get-ADPAuditPolicyStatus -ComputerName $TargetDC
        if ($AuditData.Count -eq 0) {
            Write-Host "  [WARN] Could not retrieve audit policy from $TargetDC. Check WinRM connectivity." -ForegroundColor Yellow
        } else {
            $Template   = Get-ADPAuditPolicyBaseline -Name $BaselineName
            $AuditIndex = @{}
            foreach ($Row in $AuditData) { $AuditIndex[($Row.Subcategory).Trim()] = $Row }

            $NonCompliantList = [System.Collections.Generic.List[string]]::new()
            $CompliantCount   = 0

            foreach ($SubcatName in ($Template.AuditPolicy.Keys | Sort-Object)) {
                $ExpectedKey  = $Template.AuditPolicy[$SubcatName]
                $ExpectedBits = $script:AuditInclusionMap[$ExpectedKey].CsvValue
                $ExpectedText = $script:AuditInclusionMap[$ExpectedKey].AuditpolText
                $Row          = $AuditIndex[$SubcatName]

                if ($null -eq $Row) {
                    $NonCompliantList.Add("[not found] $SubcatName")
                    continue
                }
                $ActualText = ($Row.'Inclusion Setting').Trim()
                $ActualBits = $script:AuditpolTextToBitValue[$ActualText]
                $Covers     = ($null -ne $ActualBits) -and (($ActualBits -band $ExpectedBits) -eq $ExpectedBits)
                if ($Covers) {
                    $CompliantCount++
                } else {
                    $NonCompliantList.Add("[wrong] $SubcatName -- want '$ExpectedText', got '$ActualText'")
                }
            }

            $NonCompliantCount = $NonCompliantList.Count
            $TotalCount        = $Template.AuditPolicy.Count

            if ($NonCompliantCount -eq 0) {
                Write-Host "  [OK]   All $TotalCount baseline subcategories are compliant on $TargetDC." -ForegroundColor Green
                Write-Host "         GPO is applying correctly. If the compliance check still shows failures," -ForegroundColor Cyan
                Write-Host "         verify you are running it against this same target." -ForegroundColor Cyan
            } else {
                Write-Host "  [FAIL] $NonCompliantCount of $TotalCount subcategories are NOT compliant on $TargetDC." -ForegroundColor Red
                $ShowCount = [math]::Min(15, $NonCompliantCount)
                foreach ($Item in ($NonCompliantList | Select-Object -First $ShowCount)) {
                    Write-Host "         $Item" -ForegroundColor DarkGray
                }
                if ($NonCompliantCount -gt $ShowCount) {
                    Write-Host "         ... and $($NonCompliantCount - $ShowCount) more subcategories" -ForegroundColor DarkGray
                }
                Write-Host "         GP settings have not applied to this system." -ForegroundColor Yellow
                Write-Host "         See Check 2 (CSE registration) and Check 6 (events) for root cause." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [WARN] Could not complete effective policy check: $_" -ForegroundColor Yellow
    }

    # =========================================================================
    # Check 6: GP Processing Events on Target System
    # =========================================================================
    Write-Host ""
    Write-Host "  CHECK 6: Group Policy Operational Events on $TargetDC (last 24 hours)" -ForegroundColor White
    Write-Host "  $(('-' * (55 + $TargetDC.Length)))" -ForegroundColor DarkGray

    $GpLogName = 'Microsoft-Windows-GroupPolicy/Operational'

    try {
        $FilterHash = @{
            LogName   = $GpLogName
            Id        = @(4001, 4004, 4016, 5016, 6016, 7016)
            StartTime = (Get-Date).AddHours(-24)
        }

        if ($IsLocal) {
            $GpEvents = @(Get-WinEvent -FilterHashtable $FilterHash -ErrorAction SilentlyContinue |
                Select-Object Id, TimeCreated, Message)
        } else {
            $GpEvents = @(Invoke-Command -ComputerName $TargetDC -ScriptBlock {
                param($F)
                Get-WinEvent -FilterHashtable $F -ErrorAction SilentlyContinue |
                    Select-Object Id, TimeCreated, Message
            } -ArgumentList $FilterHash -ErrorAction Stop)
        }

        if ($GpEvents.Count -eq 0) {
            Write-Host "  [WARN] No Group Policy events (4001/4004/4016/5016/6016/7016) in last 24h." -ForegroundColor Yellow
            Write-Host "         Run: gpupdate /force /target:computer on $TargetDC then rerun." -ForegroundColor Yellow
        } else {
            $GpStarted   = @($GpEvents | Where-Object { $_.Id -eq 4001 })
            $GpCompleted = @($GpEvents | Where-Object { $_.Id -eq 4004 })
            $CseSuccess  = @($GpEvents | Where-Object { $_.Id -eq 5016 })
            $CseWarning  = @($GpEvents | Where-Object { $_.Id -eq 6016 })
            $CseFailed   = @($GpEvents | Where-Object { $_.Id -eq 7016 })

            Write-Host "  [INFO] Events in last 24 hours:" -ForegroundColor Cyan
            Write-Host "         GP refresh started  (4001): $($GpStarted.Count)" -ForegroundColor DarkGray
            Write-Host "         GP refresh completed (4004): $($GpCompleted.Count)" -ForegroundColor DarkGray
            Write-Host "         CSE completed OK    (5016): $($CseSuccess.Count)" -ForegroundColor DarkGray
            Write-Host "         CSE warning         (6016): $($CseWarning.Count)" -ForegroundColor DarkGray
            Write-Host "         CSE failed          (7016): $($CseFailed.Count)" -ForegroundColor DarkGray

            $AllCseEvents = @($CseSuccess + $CseWarning + $CseFailed)
            $AuditCseEvents = @($AllCseEvents | Where-Object {
                ([string]$_.Message -match 'Security') -or ([string]$_.Message -match '827D319E') -or
                ([string]$_.Message -match 'F3CCC681') -or ([string]$_.Message -match 'Audit Policy')
            })

            if ($AuditCseEvents.Count -gt 0) {
                $MostRecent = @($AuditCseEvents | Sort-Object TimeCreated -Descending | Select-Object -First 5)
                Write-Host ""
                Write-Host "  [INFO] Audit policy CSE events (most recent first):" -ForegroundColor Cyan
                foreach ($Evt in $MostRecent) {
                    $Tag   = switch ($Evt.Id) { 5016 { '[OK]  ' } 6016 { '[WARN]' } 7016 { '[FAIL]' } default { '[INFO]' } }
                    $Color = switch ($Evt.Id) { 5016 { 'Green' } 6016 { 'Yellow' } 7016 { 'Red' } default { 'Cyan' } }
                    Write-Host "         $Tag $($Evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  ID $($Evt.Id)" -ForegroundColor $Color
                    $FirstLine = (([string]$Evt.Message -split "`n")[0]).Trim()
                    if ($FirstLine.Length -gt 110) { $FirstLine = $FirstLine.Substring(0, 110) + '...' }
                    Write-Host "               $FirstLine" -ForegroundColor DarkGray
                }
                if ($CseFailed.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  [FAIL] Audit policy CSE errors found. GP is failing to apply settings." -ForegroundColor Red
                    Write-Host "         Event Viewer on ${TargetDC}: Applications and Services Logs ->" -ForegroundColor Yellow
                    Write-Host "         Microsoft -> Windows -> GroupPolicy -> Operational for full error." -ForegroundColor Yellow
                } else {
                    $AuditCseSuccess = @($CseSuccess | Where-Object {
                        ([string]$_.Message -match 'Security') -or ([string]$_.Message -match '827D319E') -or
                        ([string]$_.Message -match 'F3CCC681') -or ([string]$_.Message -match 'Audit Policy')
                    })
                    if ($AuditCseSuccess.Count -gt 0) {
                        Write-Host ""
                        Write-Host "  [OK]   Audit policy CSEs ran and completed successfully on $TargetDC." -ForegroundColor Green
                        if ($NonCompliantCount -gt 0) {
                            Write-Host "  [WARN] CSEs ran but audit policy is still non-compliant." -ForegroundColor Yellow
                            Write-Host "         A higher-precedence GPO may be overriding the subcategory settings." -ForegroundColor Yellow
                            Write-Host "         Run: Get-GPResultantSetOfPolicy -ReportType Xml on $TargetDC" -ForegroundColor Yellow
                        }
                    }
                }
            } else {
                Write-Host ""
                if ($GpCompleted.Count -gt 0) {
                    Write-Host "  [WARN] GP refreshed $($GpCompleted.Count) time(s) but neither audit policy CSE was invoked." -ForegroundColor Yellow
                    Write-Host "         This confirms Check 2: Security or Audit Policy CSE GUID missing from" -ForegroundColor Yellow
                    Write-Host "         gPCMachineExtensionNames. Fix: redeploy the GPO, then run gpupdate /force." -ForegroundColor Yellow
                } else {
                    Write-Host "  [WARN] No GP refresh events and no audit policy CSE events found in last 24 hours." -ForegroundColor Yellow
                    Write-Host "         Run 'gpupdate /force /target:computer' on $TargetDC then rerun." -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Write-Host "  [WARN] Could not read GP Operational log on ${TargetDC}: $_" -ForegroundColor Yellow
        Write-Host "         Ensure WinRM is enabled and the account has Event Log Reader permissions." -ForegroundColor DarkGray
    }

    # =========================================================================
    # Resolution guide
    # =========================================================================
    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  RESOLUTION GUIDE" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Steps in order of likelihood:" -ForegroundColor White
    Write-Host "  1. Check 2 failed (Security or Audit Policy CSE GUID missing from AD object):" -ForegroundColor Gray
    Write-Host "     -> Both {827D319E-...} (Security) and {F3CCC681-...} (Audit Policy) must" -ForegroundColor Gray
    Write-Host "        be in gPCMachineExtensionNames. Redeploy via 'Deploy DC Baseline GPO'" -ForegroundColor Gray
    Write-Host "        or 'Deploy Standard Computer Baseline GPO' to correct both GUIDs." -ForegroundColor Gray
    Write-Host "  2. Check 4 shows gpt.ini / AD object version mismatch:" -ForegroundColor Gray
    Write-Host "     -> SYSVOL replication is lagging. Wait 15+ minutes and rerun this check." -ForegroundColor Gray
    Write-Host "  3. Check 3 shows a disabled or missing link:" -ForegroundColor Gray
    Write-Host "     -> Enable or recreate the GPO link in Group Policy Management Console." -ForegroundColor Gray
    Write-Host "  4. Check 6 shows CSE errors:" -ForegroundColor Gray
    Write-Host "     -> Review Event Viewer for the full error. Check SYSVOL permissions." -ForegroundColor Gray
    Write-Host "  5. All checks pass but policy still does not match baseline:" -ForegroundColor Gray
    Write-Host "     -> A higher-precedence GPO is overriding the audit subcategory settings." -ForegroundColor Gray
    Write-Host "        Run: Get-GPResultantSetOfPolicy -ReportType Xml on the target system." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  After any fix: run 'gpupdate /force /target:computer' on $TargetDC" -ForegroundColor Cyan
    Write-Host ""
    Read-Host "  Press Enter to return to the menu"
}

Function New-ADPAuditPolicyGpo {
    <#
    .SYNOPSIS
        Creates and deploys an audit policy baseline GPO.

    .DESCRIPTION
        Creates a GPO named 'ADPA-AuditPolicy-DomainControllers' or
        'ADPA-AuditPolicy-StandardComputers' and configures it with:
          - Advanced Audit Policy subcategory settings (audit.csv)
          - The subcategory override security option
          - Event log maximum sizes via ADMX registry keys
          - NTLM audit registry settings (Domain Controller baseline only)

        The Domain Controller GPO is automatically linked to the Domain Controllers OU.
        The Standard Computer GPO prompts the administrator to select a target OU.

    .PARAMETER Baseline
        The baseline to deploy: 'DomainController' or 'StandardComputer'.

    .EXAMPLE
        New-ADPAuditPolicyGpo -Baseline DomainController
    .EXAMPLE
        New-ADPAuditPolicyGpo -Baseline StandardComputer
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('DomainController', 'StandardComputer')]
        [string]$Baseline
    )

    $Template = Get-ADPAuditPolicyBaseline -Name $Baseline
    $GpoName  = if ($Baseline -eq 'DomainController') {
        'ADPA-AuditPolicy-DomainControllers'
    } else {
        'ADPA-AuditPolicy-StandardComputers'
    }

    Write-Host ""
    Write-Host "[INFO] Deploying $($Template.Name)..." -ForegroundColor Cyan
    Write-Host "[INFO] GPO name: $GpoName" -ForegroundColor Cyan

    # 1. Create GPO.
    $GpoObject = New-ADPAGPO -Name $GpoName -Description $Template.Name
    if ($null -eq $GpoObject) {
        Write-Host "[FAIL] Could not create or retrieve GPO '$GpoName'. Aborting." -ForegroundColor Red
        return
    }

    # 2. Build audit.csv entries from the baseline.
    $AuditEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($SubcatName in $Template.AuditPolicy.Keys) {
        $SettingKey = $Template.AuditPolicy[$SubcatName]
        $Guid = $script:AuditSubcategoryGuids[$SubcatName]
        if (-not $Guid) {
            Write-Host "[WARN] No GUID found for subcategory '$SubcatName'. Skipping." -ForegroundColor Yellow
            continue
        }
        $CsvValue = $script:AuditInclusionMap[$SettingKey].CsvValue
        $AuditEntries.Add(@{
            Subcategory      = $SubcatName
            GUID             = $Guid
            InclusionSetting = $CsvValue
        })
    }
    $Ok = Set-GPOAdvancedAuditPolicy -GpoName $GpoName -AuditEntries $AuditEntries.ToArray()
    if (-not $Ok) {
        Write-Host "[WARN] Advanced Audit Policy entries could not be written. The GPO was created but is not fully configured." -ForegroundColor Yellow
    } else {
        $VerifyEntries = Get-GPOAdvancedAuditPolicy -GpoName $GpoName
        $VerifyCount   = if ($VerifyEntries) { @($VerifyEntries).Count } else { 0 }
        if ($VerifyCount -eq $AuditEntries.Count) {
            Write-Host "[OK]  audit.csv verified: $VerifyCount subcategory entries confirmed in SYSVOL." -ForegroundColor Green
        } else {
            Write-Host "[WARN] audit.csv row mismatch: expected $($AuditEntries.Count) entries, read back $VerifyCount. SYSVOL write may be incomplete." -ForegroundColor Yellow
        }
    }

    # 3. Enable subcategory override via GptTmpl.inf Registry Values section.
    Set-GPOSecuritySetting -GpoName $GpoName `
        -Section 'Registry Values' `
        -Key 'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy' `
        -Value '4,1' | Out-Null

    # 4. Write event log sizes via ADMX registry path (KB values).
    $EventLogAdmxBase = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog'
    $LogAdmxNames = @{
        'Security'           = 'Security'
        'System'             = 'System'
        'Application'        = 'Application'
        'Windows PowerShell' = 'Windows PowerShell'
    }

    foreach ($LogDisplayName in $LogAdmxNames.Keys) {
        if (-not $Template.EventLogs.ContainsKey($LogDisplayName)) { continue }
        $SizeKB    = $Template.EventLogs[$LogDisplayName].PreferredKB
        $AdmxName  = $LogAdmxNames[$LogDisplayName]
        $RegKey    = "$EventLogAdmxBase\$AdmxName"
        Set-GPORegistrySetting -GpoName $GpoName -Key $RegKey -ValueName 'MaxSize' -Type 'DWord' -Value $SizeKB | Out-Null
        Set-GPORegistrySetting -GpoName $GpoName -Key $RegKey -ValueName 'Retention' -Type 'String' -Value '0' | Out-Null
    }

    # 4b. DC-only: Directory Service log maximum size.
    # The ADMX-backed path (SOFTWARE\Policies\Microsoft\Windows\EventLog\...) is only
    # processed by the Event Log service for logs covered by the built-in EventLog.admx
    # template (Security, System, Application). The Directory Service log is application-
    # registered and reads its size exclusively from the legacy SYSTEM registry key
    # (value in BYTES, not KB). This is a non-ADMX Extra Registry Setting.
    if ($Baseline -eq 'DomainController' -and $Template.EventLogs.ContainsKey('Directory Service')) {
        [int]$DsBytes = [int]($Template.EventLogs['Directory Service'].PreferredKB) * 1024
        Set-GPORegistrySetting -GpoName $GpoName `
            -Key  'HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Directory Service' `
            -ValueName 'MaxSize' -Type 'DWord' -Value $DsBytes | Out-Null
    }

    # 5. DC-only: NTLM audit registry settings.
    if ($Baseline -eq 'DomainController') {
        $NtlmBase = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
        Set-GPORegistrySetting -GpoName $GpoName -Key $NtlmBase -ValueName 'RestrictSendingNTLMTraffic' -Type 'DWord' -Value 2 | Out-Null
        Set-GPORegistrySetting -GpoName $GpoName -Key $NtlmBase -ValueName 'AuditNTLMInDomain'           -Type 'DWord' -Value 7 | Out-Null
        Set-GPORegistrySetting -GpoName $GpoName -Key $NtlmBase -ValueName 'InboundNTLMTraffic'          -Type 'DWord' -Value 1 | Out-Null
    }

    # 5b. Set gPCMachineExtensionNames to the definitive correct value.
    #     Set-GPRegistryValue (steps 4 and 5) rewrites gPCMachineExtensionNames on the
    #     GPO AD object to include only the Registry CSE block, erasing the Security CSE
    #     and Audit Policy CSE blocks that Update-GptIniVersion registered.
    #
    #     Three CSE blocks are required for this GPO:
    #       Registry CSE       {35378EAC-...} -- Registry.pol (event log sizes, NTLM)
    #       Security CSE       {827D319E-...} -- GptTmpl.inf (SCENoApplyLegacyAuditPolicy)
    #       Audit Policy CSE   {F3CCC681-...} -- audit.csv (Advanced Audit Policy subcategories)
    #
    #     The Audit Policy CSE was confirmed as the missing block by ldapsearch comparison
    #     of a PS-only GPO vs a GPO that was saved once through the GPMC editor -- GPMC
    #     adds {F3CCC681-...} when it processes audit.csv, which is what triggers both the
    #     Settings display to show Advanced Audit Policy and the GP client to apply it.
    #
    #     We use DN-based lookup (not Filter) so a missing object throws, not silently returns null.
    try {
        $SecurityCseBlock    = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
        $RegistryCseBlock    = '[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]'
        $AuditPolicyCseBlock = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'

        # Emit GPO identity info before any AD call so a DN construction bug is visible.
        Write-Host "[DBG] GpoObject type   : $($GpoObject.GetType().FullName)" -ForegroundColor DarkGray
        Write-Host "[DBG] GpoObject.Id     : $($GpoObject.Id)" -ForegroundColor DarkGray
        Write-Host "[DBG] GpoObject.DisplayName: $($GpoObject.DisplayName)" -ForegroundColor DarkGray

        $GpoGuidStr = '{' + $GpoObject.Id.ToString().ToUpper() + '}'
        Write-Host "[DBG] GpoGuidStr       : $GpoGuidStr" -ForegroundColor DarkGray

        $DomainDN5b = (Get-ADDomain -ErrorAction Stop).DistinguishedName
        Write-Host "[DBG] DomainDN         : $DomainDN5b" -ForegroundColor DarkGray

        $GpoDN = "CN=$GpoGuidStr,CN=Policies,CN=System,$DomainDN5b"
        Write-Host "[DBG] Computed GPO DN  : $GpoDN" -ForegroundColor DarkGray

        # Verify the object exists via filter before attempting DN-based lookup,
        # so a missing object produces a clear message rather than a cryptic AD error.
        $GpoByFilter = Get-ADObject -LDAPFilter "(cn=$GpoGuidStr)" `
            -SearchBase "CN=Policies,CN=System,$DomainDN5b" `
            -Properties distinguishedName -ErrorAction SilentlyContinue
        if ($GpoByFilter) {
            Write-Host "[DBG] Filter-search found: $($GpoByFilter.DistinguishedName)" -ForegroundColor DarkGray
        } else {
            Write-Host "[WARN] Filter-search found NO object with cn=$GpoGuidStr under CN=Policies,CN=System,$DomainDN5b" -ForegroundColor Yellow
            Write-Host "       The GPO AD object may not have replicated yet, or the GUID is wrong." -ForegroundColor Yellow
        }

        $GpoAdObj2 = Get-ADObject -Identity $GpoDN `
            -Properties gPCMachineExtensionNames -ErrorAction Stop

        $CurrentExt = [string]$GpoAdObj2.gPCMachineExtensionNames
        Write-Host "[INFO] gPCMachineExtensionNames before: '$CurrentExt'" -ForegroundColor DarkGray

        # Parse existing blocks so any additional CSE blocks added by other tools are preserved.
        $AllBlocks = [System.Collections.Generic.List[string]]::new()
        [regex]::Matches($CurrentExt, '\[[^\]]+\]') | ForEach-Object { $AllBlocks.Add($_.Value) }
        if ($AllBlocks -notcontains $SecurityCseBlock)    { $AllBlocks.Add($SecurityCseBlock) }
        if ($AllBlocks -notcontains $RegistryCseBlock)    { $AllBlocks.Add($RegistryCseBlock) }
        if ($AllBlocks -notcontains $AuditPolicyCseBlock) { $AllBlocks.Add($AuditPolicyCseBlock) }
        $FinalExt = ($AllBlocks | Sort-Object) -join ''

        Set-ADObject -Identity $GpoDN `
            -Replace @{ gPCMachineExtensionNames = $FinalExt } -ErrorAction Stop
        Write-Host "[OK]  gPCMachineExtensionNames set: '$FinalExt'" -ForegroundColor Green
    } catch {
        Write-Host "[WARN] Could not set gPCMachineExtensionNames on GPO AD object: $_" -ForegroundColor Yellow
        Write-Host "[DBG]  Exception type    : $($_.Exception.GetType().FullName)" -ForegroundColor DarkGray
        Write-Host "[DBG]  Exception message : $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host "[DBG]  Script position   : $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkGray
    }

    # 6. Link GPO.
    if ($Baseline -eq 'DomainController') {
        try {
            $DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
            $DCsOU    = "OU=Domain Controllers,$DomainDN"
            $Linked   = Add-GPOLink -GpoName $GpoName -Target $DCsOU -Enforced 'Yes'
            if ($Linked) {
                Write-Host "[OK]  GPO linked to: $DCsOU" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Could not automatically link GPO to Domain Controllers OU. Link it manually." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[WARN] Could not resolve domain to link GPO: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[INFO] Select the OU to link this GPO to." -ForegroundColor Cyan
        $TargetOU = Search-SingleAdObject
        if ($TargetOU -and $TargetOU.DistinguishedName) {
            $Linked = Add-GPOLink -GpoName $GpoName -Target $TargetOU.DistinguishedName -Enforced 'Yes'
            if ($Linked) {
                Write-Host "[OK]  GPO linked to: $($TargetOU.DistinguishedName)" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Could not link GPO to selected OU. Link it manually." -ForegroundColor Yellow
            }
        } else {
            Write-Host "[INFO] No OU selected. GPO created but not linked. Link it manually using Group Policy Management." -ForegroundColor Cyan
        }
    }

    Write-Host ""
    Write-Host "[OK]  $($Template.Name) GPO deployment complete." -ForegroundColor Green
    Write-Host "      Run 'gpupdate /force' on target systems to apply." -ForegroundColor Cyan
}

Function Export-ADPAuditPolicyReport {
    <#
    .SYNOPSIS
        Runs the audit policy compliance check and exports findings to a CSV file.

    .DESCRIPTION
        Runs the full local audit policy compliance check (including DC extra checks when
        applicable), then writes all findings to a timestamped CSV in the Reports directory.

    .EXAMPLE
        Export-ADPAuditPolicyReport
    #>
    [CmdletBinding()]
    Param()

    Write-Host "[INFO] Running audit policy compliance check for export..." -ForegroundColor Cyan

    $LocalRole    = Get-SystemRole
    $BaselineName = if ($LocalRole -eq 'DomainController') { 'DomainController' } else { 'StandardComputer' }
    $Computer     = $env:COMPUTERNAME

    $AuditData = Get-ADPAuditPolicyStatus -ComputerName $Computer
    $EventLogs = Get-ADPEventLogStorageStatus -ComputerName $Computer
    $Findings  = Compare-ADPAuditPolicyBaseline -AuditData $AuditData -EventLogs $EventLogs -Baseline $BaselineName -ComputerName $Computer

    $Template = Get-ADPAuditPolicyBaseline -Name $BaselineName
    if ($Template.ExtraChecks.CheckDomainObjectSacl) {
        $Findings += Test-ADPDirectoryServiceSacl -ComputerName $Computer
    }
    if ($Template.ExtraChecks.CheckNtlmAuditSettings) {
        $Findings += Test-ADPNtlmAuditSettings -ComputerName $Computer
    }

    Export-AdPowerAdminData -Data $Findings -ReportName "AuditPolicyReport"
    Write-Host "[OK]  Report saved to: $global:ReportsPath" -ForegroundColor Green
}

Function Show-ADPAuditPolicyHelp {
    <#
    .SYNOPSIS
        Displays the Audit Policy Management help page and baseline comparison reference.

    .DESCRIPTION
        Prints a formatted reference covering the purpose of the module, when to use each
        baseline, a side-by-side subcategory comparison table with color coding, event log
        size targets by role, and descriptions of the DC-only additional checks.

    .EXAMPLE
        Show-ADPAuditPolicyHelp
    #>
    [CmdletBinding()]
    Param()

    $StdTemplate = $script:AuditPolicyTemplates['StandardComputer']
    $DcTemplate  = $script:AuditPolicyTemplates['DomainController']

    # Ordered category -> subcategory grouping for the comparison table.
    $CategoryGroups = [ordered]@{
        'Account Logon' = @(
            'Credential Validation',
            'Kerberos Authentication Service',
            'Kerberos Service Ticket Operations',
            'Other Account Logon Events'
        )
        'Account Management' = @(
            'Computer Account Management',
            'Distribution Group Management',
            'Security Group Management',
            'User Account Management',
            'Other Account Management Events'
        )
        'Detailed Tracking' = @(
            'DPAPI Activity',
            'Process Creation'
        )
        'DS Access' = @(
            'Directory Service Access',
            'Directory Service Changes'
        )
        'Logon / Logoff' = @(
            'Account Lockout',
            'Logon',
            'Logoff',
            'Special Logon',
            'Group Membership',
            'Network Policy Server',
            'Other Logon/Logoff Events'
        )
        'Object Access' = @(
            'SAM',
            'Removable Storage',
            'Other Object Access Events'
        )
        'Policy Change' = @(
            'Audit Policy Change',
            'Authentication Policy Change',
            'Authorization Policy Change',
            'MPSSVC Rule-Level Policy Change'
        )
        'Privilege Use' = @(
            'Sensitive Privilege Use'
        )
        'System' = @(
            'Security State Change',
            'Security System Extension',
            'System Integrity',
            'IPsec Driver',
            'Other System Events'
        )
    }

    try { Clear-Host } catch { Write-Host ([char]27 + "[2J" + [char]27 + "[H") -NoNewline }

    # =========================================================================
    # Title and Purpose
    # =========================================================================
    Write-Host ""
    Write-Host "  AUDIT POLICY MANAGEMENT -- HELP" -ForegroundColor Cyan
    Write-Host "  ================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  PURPOSE" -ForegroundColor Cyan
    Write-Host "  -------" -ForegroundColor Cyan
    Write-WrappedText -Label '' -Text ('Windows ships with a minimal default audit configuration. Without deliberate ' +
        'enforcement, critical security subcategories such as Kerberos Authentication Service, Directory Service ' +
        'Changes, and Sensitive Privilege Use generate no events. Attackers exploit this silence: techniques like ' +
        'Kerberoasting, DCSync, pass-the-hash, and credential dumping leave no trace if the relevant subcategories ' +
        'are not enabled.') `
        -Indent '  ' -ForegroundColor Gray
    Write-Host ""
    Write-WrappedText -Label '' -Text ('This module audits the effective audit policy on a target system, compares ' +
        'it against a hardened baseline matched to the system role, and reports gaps by severity. It also deploys ' +
        'GPO-based baselines that enforce the correct settings domain-wide via Group Policy, eliminating manual ' +
        'configuration and preventing policy drift over time.') `
        -Indent '  ' -ForegroundColor Gray

    # =========================================================================
    # Baseline overview
    # =========================================================================
    Write-Host ""
    Write-Host ""
    Write-Host "  BASELINES" -ForegroundColor Cyan
    Write-Host "  ---------" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Standard Computer " -NoNewline -ForegroundColor White
    Write-Host "(workstations and member servers)" -ForegroundColor Gray
    Write-WrappedText -Label '' -Text ('Covers common security events: credential validation, logon and logoff, ' +
        'account management, process creation, audit policy changes, and privilege use failures. Sized for the lower ' +
        'event volume typical of non-DC systems. Security event log minimum is 192 MB.') `
        -Indent '    ' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Domain Controller " -NoNewline -ForegroundColor White
    Write-Host "(strict superset of the Standard Computer baseline)" -ForegroundColor DarkYellow
    Write-WrappedText -Label '' -Text ('Adds Kerberos subcategories -- TGT requests (AS) and service ticket ' +
        'requests (TGS) -- required to detect Kerberoasting and AS-REP Roasting. Adds Directory Service Access and ' +
        'Directory Service Changes to detect DCSync and unauthorized AD object modification, though these ' +
        'subcategories require SACL audit rules on AD objects to generate events. Escalates many settings from ' +
        'Success-only to Success+Failure to capture failed attempts. Adds NTLM audit registry settings to expose ' +
        'NTLM relay and downgrade attacks. Requires significantly larger event logs: Security log minimum is 1 GB.') `
        -Indent '    ' -ForegroundColor Gray

    # =========================================================================
    # Subcategory comparison table
    # =========================================================================
    Write-Host ""
    Write-Host ""
    Write-Host "  AUDIT SUBCATEGORY COMPARISON" -ForegroundColor Cyan
    Write-Host "  ----------------------------" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Color legend:" -ForegroundColor DarkGray
    Write-Host "    " -NoNewline
    Write-Host "White  " -NoNewline -ForegroundColor White
    Write-Host "- Same setting required by both baselines" -ForegroundColor DarkGray
    Write-Host "    " -NoNewline
    Write-Host "Cyan   " -NoNewline -ForegroundColor Cyan
    Write-Host "- Domain Controller requires more than Standard Computer" -ForegroundColor DarkGray
    Write-Host "    " -NoNewline
    Write-Host "Yellow " -NoNewline -ForegroundColor Yellow
    Write-Host "- Domain Controller only; not required on Standard computers" -ForegroundColor DarkGray
    Write-Host "    " -NoNewline
    Write-Host "Gray   " -NoNewline -ForegroundColor DarkGray
    Write-Host "- Not required in this baseline" -ForegroundColor DarkGray
    Write-Host ""

    [int]$Col1W = 42
    [int]$Col2W = 14

    Write-Host "    $('Subcategory'.PadRight($Col1W))$('Standard'.PadRight($Col2W))Domain Ctrl" -ForegroundColor DarkGray
    Write-Host "    $(('-' * $Col1W))$(('-' * $Col2W))$('-' * 14)" -ForegroundColor DarkGray

    foreach ($CatName in $CategoryGroups.Keys) {
        Write-Host ""
        Write-Host "  [$CatName]" -ForegroundColor Cyan

        foreach ($SubcatName in $CategoryGroups[$CatName]) {
            $StdKey = $StdTemplate.AuditPolicy[$SubcatName]
            $DcKey  = $DcTemplate.AuditPolicy[$SubcatName]

            $StdLabel = (Format-ADPAuditSettingLabel $StdKey).PadRight($Col2W)
            $DcLabel  = (Format-ADPAuditSettingLabel $DcKey).PadRight(14)
            $NamePad  = $SubcatName.PadRight($Col1W)

            $StdColor = if ([string]::IsNullOrEmpty($StdKey)) { 'DarkGray' } else { 'White' }
            $DcColor  = if ([string]::IsNullOrEmpty($DcKey)) {
                'DarkGray'
            } elseif ([string]::IsNullOrEmpty($StdKey)) {
                'Yellow'
            } elseif ($DcKey -ne $StdKey) {
                'Cyan'
            } else {
                'White'
            }

            Write-Host "    $NamePad" -NoNewline -ForegroundColor White
            Write-Host $StdLabel      -NoNewline -ForegroundColor $StdColor
            Write-Host $DcLabel                  -ForegroundColor $DcColor
        }
    }

    # =========================================================================
    # Event log size targets
    # =========================================================================
    Write-Host ""
    Write-Host ""
    Write-Host "  EVENT LOG SIZE TARGETS" -ForegroundColor Cyan
    Write-Host "  ----------------------" -ForegroundColor Cyan
    Write-Host ""

    [string[]]$LogOrder = @(
        'Security',
        'System',
        'Application',
        'Directory Service',
        'Windows PowerShell',
        'Microsoft-Windows-PowerShell/Operational'
    )

    Write-Host "    $('Log'.PadRight(46))$('Standard Min'.PadRight(14))DC Min" -ForegroundColor DarkGray
    Write-Host "    $(('-' * 46))$(('-' * 14))$('-' * 14)" -ForegroundColor DarkGray

    foreach ($LogName in $LogOrder) {
        $StdEntry = $StdTemplate.EventLogs[$LogName]
        $DcEntry  = $DcTemplate.EventLogs[$LogName]
        $StdText  = if ($StdEntry) { "$([math]::Round($StdEntry.MinKB / 1024)) MB" } else { '[DC Only]' }
        $DcText   = if ($DcEntry)  { "$([math]::Round($DcEntry.MinKB  / 1024)) MB" }  else { '---' }
        $StdColor = if (-not $StdEntry) { 'Yellow' } else { 'White' }

        Write-Host "    $($LogName.PadRight(46))" -NoNewline -ForegroundColor White
        Write-Host $StdText.PadRight(14)           -NoNewline -ForegroundColor $StdColor
        Write-Host $DcText                          -ForegroundColor White
    }

    # =========================================================================
    # DC-only additional checks
    # =========================================================================
    Write-Host ""
    Write-Host ""
    Write-Host "  DC-ONLY ADDITIONAL CHECKS" -ForegroundColor Cyan
    Write-Host "  -------------------------" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Directory Service SACL Auditing" -ForegroundColor White
    Write-WrappedText -Label '' -Text ('Enabling Directory Service Access and Directory Service Changes subcategories ' +
        'is necessary but not sufficient. Those subcategories generate no events unless SACL audit rules are ' +
        'configured on Active Directory objects. The compliance check validates that SACL rules exist on the domain ' +
        'root and the Configuration partition. A missing SACL is rated Critical because DS auditing is effectively ' +
        'disabled regardless of what auditpol.exe reports. To configure manually: open ADSI Edit, right-click the ' +
        'domain root, go to Properties -> Security -> Advanced -> Auditing, and add an audit entry for Everyone or ' +
        'Authenticated Users covering at minimum Read all properties and Write all properties.') `
        -Indent '    ' -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NTLM Audit Settings" -ForegroundColor White
    Write-WrappedText -Label '' -Text ('Three registry values under HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 ' +
        'control NTLM audit verbosity. The DC baseline sets RestrictSendingNTLMTraffic=2 (audit all outbound NTLM, ' +
        'Events 8001/8002), AuditNTLMInDomain=7 (audit all domain NTLM, Event 4004), and InboundNTLMTraffic=1 ' +
        '(audit inbound NTLM, Event 8003). These settings provide visibility into NTLM relay attempts, credential ' +
        'relay attacks, and environments where Kerberos should replace NTLM but has not been enforced.') `
        -Indent '    ' -ForegroundColor Gray

    # =========================================================================
    # GPO deployment notes
    # =========================================================================
    Write-Host ""
    Write-Host ""
    Write-Host "  GPO DEPLOYMENT" -ForegroundColor Cyan
    Write-Host "  --------------" -ForegroundColor Cyan
    Write-Host ""
    Write-WrappedText -Label '' -Text ("'Deploy DC Baseline GPO' creates 'ADPA-AuditPolicy-DomainControllers' and " +
        "automatically links it Enforced to the Domain Controllers OU. 'Deploy Standard Computer Baseline GPO' " +
        "creates 'ADPA-AuditPolicy-StandardComputers' and prompts for the OU to link to. Both operations are " +
        "idempotent: re-running updates an existing GPO rather than creating a duplicate. After linking, run " +
        "'gpupdate /force' on target systems or wait for the next Group Policy refresh interval.") `
        -Indent '    ' -ForegroundColor Gray
    Write-Host ""
    Write-WrappedText -Label '' -Text ("Each deployed GPO registers three Client-Side Extension (CSE) blocks in the " +
        "gPCMachineExtensionNames attribute of the GPO AD object: the Registry CSE " +
        "({35378EAC-...}) for event log size and NTLM registry settings, the Security " +
        "Settings CSE ({827D319E-...}) for GptTmpl.inf (subcategory override key), and " +
        "the Audit Policy Configuration CSE ({F3CCC681-...}) for audit.csv (subcategory " +
        "settings). All three must be present for the GP client to apply the complete " +
        "baseline. Use 'Diagnose Audit Policy GPO' to verify CSE registration if settings " +
        "do not appear to be applying.") `
        -Indent '    ' -ForegroundColor Gray

    Write-Host ""
    Read-Host "  Press Enter to return to the menu"
}

Function Test-ADPDirectoryServiceSacl {
    <#
    .SYNOPSIS
        Checks whether SACL auditing is configured on the domain root AD object.

    .DESCRIPTION
        Domain controllers require SACL audit entries on Active Directory objects for
        Directory Service Access and Directory Service Changes audit subcategories to
        generate any events. This function checks the domain root and configuration
        partition objects for existing audit rules. A missing SACL means DS audit
        subcategories produce no events regardless of audit policy settings.

        This check is meaningful only on domain controllers.

    .PARAMETER ComputerName
        Computer name used in finding objects. Defaults to local.

    .OUTPUTS
        [PSCustomObject[]] finding objects.

    .EXAMPLE
        Test-ADPDirectoryServiceSacl
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $Targets = @(
        @{ Label = 'Domain root object'; Path = '' }
        @{ Label = 'Configuration partition'; Path = '' }
    )

    try {
        $DomainObj = Get-ADDomain -ErrorAction Stop
        $Targets[0].Path = "AD:$($DomainObj.DistinguishedName)"
        $Targets[1].Path = "AD:CN=Configuration,$($DomainObj.DistinguishedName)"
    } catch {
        $Findings.Add((New-ADPAuditFinding `
            -ComputerName $ComputerName -Baseline 'DomainController' `
            -Category 'Directory Service SACL' -SettingName 'Domain Object SACL' `
            -ExpectedValue 'Audit rules present' -ActualValue 'Could not query domain' `
            -Status 'Missing' -Severity 'High' `
            -Reason "Could not query Active Directory to check SACL entries: $_" `
            -Remediation 'Run this check from a system joined to the domain with the ActiveDirectory module available.'))
        return $Findings.ToArray()
    }

    foreach ($Target in $Targets) {
        try {
            $Acl        = Get-Acl -Path $Target.Path -Audit -ErrorAction Stop
            $AuditRules = $Acl.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])

            if ($AuditRules.Count -gt 0) {
                $Findings.Add((New-ADPAuditFinding `
                    -ComputerName $ComputerName -Baseline 'DomainController' `
                    -Category 'Directory Service SACL' -SettingName "$($Target.Label) SACL" `
                    -ExpectedValue 'Audit rules present' -ActualValue "$($AuditRules.Count) audit rule(s)" `
                    -Status 'Compliant' -Severity 'Compliant' `
                    -Reason '' -Remediation ''))
            } else {
                $Findings.Add((New-ADPAuditFinding `
                    -ComputerName $ComputerName -Baseline 'DomainController' `
                    -Category 'Directory Service SACL' -SettingName "$($Target.Label) SACL" `
                    -ExpectedValue 'Audit rules present' -ActualValue 'No audit rules' `
                    -Status 'NonCompliant' -Severity 'Critical' `
                    -Reason "Directory Service Access auditing is enabled but no SACL audit rules are configured on the $($Target.Label). Without SACLs, the Directory Service Access and Directory Service Changes subcategories generate no events, making DS audit policy ineffective." `
                    -Remediation 'Open ADSI Edit, right-click the domain root, select Properties > Security > Advanced > Auditing. Add an audit rule for Everyone (or Authenticated Users) covering Read all properties, Write all properties, and Full control.'))
            }
        } catch {
            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline 'DomainController' `
                -Category 'Directory Service SACL' -SettingName "$($Target.Label) SACL" `
                -ExpectedValue 'Audit rules present' -ActualValue 'Query failed' `
                -Status 'Missing' -Severity 'Medium' `
                -Reason "Could not query ACL for $($Target.Label): $_" `
                -Remediation 'Verify the ActiveDirectory module is loaded and the account has permission to read AD object security descriptors.'))
        }
    }

    return $Findings.ToArray()
}

Function Test-ADPNtlmAuditSettings {
    <#
    .SYNOPSIS
        Checks NTLM audit registry settings on a domain controller.

    .DESCRIPTION
        Reads three NTLM audit registry values under
        HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 and compares them against
        recommended settings. These values control whether NTLM authentication events
        are captured for outbound, inbound, and domain NTLM traffic.

        This check is meaningful only on domain controllers.

    .PARAMETER ComputerName
        Computer name used in finding objects. Defaults to local.

    .OUTPUTS
        [PSCustomObject[]] finding objects.

    .EXAMPLE
        Test-ADPNtlmAuditSettings
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$ComputerName = $env:COMPUTERNAME
    )

    $Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    $NtlmChecks = @(
        @{
            ValueName    = 'RestrictSendingNTLMTraffic'
            Recommended  = 2
            FriendlyName = 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'
            Reason       = "Outbound NTLM traffic is not set to 'Audit all'. Setting this to 2 (Audit all) enables Event 8001/8002 generation for outbound NTLM authentications, supporting NTLM usage discovery and lateral movement investigations."
            Remediation  = "Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic to 2 via GPO or local policy."
        }
        @{
            ValueName    = 'AuditNTLMInDomain'
            Recommended  = 7
            FriendlyName = 'Network security: Restrict NTLM: Audit NTLM authentication in this domain'
            Reason       = "Domain NTLM authentication auditing is not fully enabled. Setting to 7 (Enable all) enables Event 4004 generation for all NTLM authentications within the domain, supporting detection of NTLM relay and downgrade attacks."
            Remediation  = "Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\AuditNTLMInDomain to 7 via GPO or local policy."
        }
        @{
            ValueName    = 'InboundNTLMTraffic'
            Recommended  = 1
            FriendlyName = 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic'
            Reason       = "Inbound NTLM traffic auditing is not enabled. Setting to 1 (Audit all accounts) enables Event 8003 generation for inbound NTLM authentications, supporting visibility into NTLM pass-through and relay attempts."
            Remediation  = "Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\InboundNTLMTraffic to 1 via GPO or local policy."
        }
    )

    $RegBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

    foreach ($Check in $NtlmChecks) {
        try {
            $RegVal = (Get-ItemProperty -Path $RegBase -Name $Check.ValueName -ErrorAction SilentlyContinue).($Check.ValueName)
            if ($null -eq $RegVal) {
                $ActualText = 'Not configured'
                $Status     = 'Missing'
                $Severity   = 'High'
            } elseif ([int]$RegVal -eq $Check.Recommended) {
                $Findings.Add((New-ADPAuditFinding `
                    -ComputerName $ComputerName -Baseline 'DomainController' `
                    -Category 'NTLM Audit' -SettingName $Check.FriendlyName `
                    -ExpectedValue $Check.Recommended.ToString() -ActualValue $RegVal.ToString() `
                    -Status 'Compliant' -Severity 'Compliant' `
                    -Reason '' -Remediation ''))
                continue
            } else {
                $ActualText = $RegVal.ToString()
                $Status     = 'NonCompliant'
                $Severity   = 'High'
            }

            $Findings.Add((New-ADPAuditFinding `
                -ComputerName $ComputerName -Baseline 'DomainController' `
                -Category 'NTLM Audit' -SettingName $Check.FriendlyName `
                -ExpectedValue $Check.Recommended.ToString() -ActualValue $ActualText `
                -Status $Status -Severity $Severity `
                -Reason $Check.Reason `
                -Remediation $Check.Remediation))
        } catch {
            Write-Host "[WARN] Could not read NTLM registry value '$($Check.ValueName)': $_" -ForegroundColor Yellow
        }
    }

    return $Findings.ToArray()
}
