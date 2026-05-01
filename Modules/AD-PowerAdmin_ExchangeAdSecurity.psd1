@{
    RootModule        = 'AD-PowerAdmin_ExchangeAdSecurity.psm1'
    ModuleVersion     = '1.0'
    GUID              = 'f1a068de-1809-49db-8ef6-66e151f0b124'
    Author            = 'CyberGladius'
    CompanyName       = 'CyberGladius.com'
    Copyright         = '(c) 2024 CyberGladius. All rights reserved.'
    Description       = 'Audits and remediates Exchange-related Active Directory permission escalation risks, including WriteDACL paths to DCSync on the domain root.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-Module',
        'Search-ExchangeDomainRootAce',
        'Search-ExchangeGroupMembership',
        'Search-ExchangeGroupAclRisk',
        'Get-ExchangeAuditReport',
        'Remove-ExchangeDangerousAce'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    FileList          = @(
        'AD-PowerAdmin_ExchangeAdSecurity.psm1',
        'AD-PowerAdmin_ExchangeAdSecurity.psd1'
    )
    PrivateData = @{
        PSData = @{
            Tags         = @()
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            Channel      = 'Production'
            ReleaseNotes = 'v1.0 Production - Initial release. Detects Exchange-to-DCSync escalation paths via domain root ACL audit, Exchange group membership audit, Exchange group ACL control audit, and guided dangerous ACE removal. Includes categorized text report with per-finding attack scenarios and remediation steps.'
        }
    }
}
