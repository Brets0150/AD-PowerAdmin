#
# Module manifest for module 'AD-PowerAdmin_SmbAdminShareAudit'
#
# Author: CyberGladius
#

@{
    RootModule        = 'AD-PowerAdmin_SmbAdminShareAudit.psm1'
    ModuleVersion     = '1.0'
    GUID              = '81108d4b-a91a-4550-8ff9-80455708ce5c'
    Author            = 'CyberGladius'
    CompanyName       = 'CyberGladius.com'
    Copyright         = '(c) 2026 CyberGladius. All rights reserved.'
    Description       = 'Audits, detects, reports, and safely remediates SMB Windows administrative share abuse (ATT&CK T1021.002).'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Initialize-Module',
        'Get-ADAdminShareInventory',
        'Test-ADAdminShareRegistryPolicy',
        'Test-ADSMBFirewallExposure',
        'Get-ADLocalAdminExposure',
        'Test-ADLAPSCoverage',
        'Search-ADAdminShareAccessEvents',
        'Invoke-ADAdminShareExposureAudit',
        'Invoke-ADAdminShareSafeRemediation',
        'Restore-ADAdminShareRemediationBackup'
    )

    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()

    FileList          = @(
        'AD-PowerAdmin_SmbAdminShareAudit.psm1',
        'AD-PowerAdmin_SmbAdminShareAudit.psd1'
    )

    PrivateData = @{
        PSData = @{
            Tags         = @()
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            Channel      = 'Alpha'
            ReleaseNotes = @'
v1.0 -- Initial release.
- Get-ADAdminShareInventory: enumerate hidden SMB admin shares on all enabled AD computers.
- Test-ADAdminShareRegistryPolicy: check AutoShareWks and AutoShareServer registry values remotely.
- Test-ADSMBFirewallExposure: audit inbound SMB firewall rules for broad exposure.
- Get-ADLocalAdminExposure: enumerate local Administrators for risky domain principals.
- Test-ADLAPSCoverage: query AD for LAPS attribute presence and staleness.
- Search-ADAdminShareAccessEvents: search Security event logs for admin share access events.
- Invoke-ADAdminShareExposureAudit: orchestrated full audit with CSV and text report export.
- Invoke-ADAdminShareSafeRemediation: staged, confirmation-gated remediation with JSON backup.
- Restore-ADAdminShareRemediationBackup: rollback from a remediation backup file.
'@
        }
    }
}
