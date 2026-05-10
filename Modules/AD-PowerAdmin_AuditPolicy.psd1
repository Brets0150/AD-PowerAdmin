@{
    RootModule        = 'AD-PowerAdmin_AuditPolicy.psm1'
    ModuleVersion     = '1.9'
    GUID              = 'a7c3f851-2d4e-4b9a-8f6c-0e1d5a3b7c9f'
    Author            = 'CyberGladius'
    CompanyName       = 'CyberGladius.com'
    Copyright         = '(c) 2026 CyberGladius. All rights reserved.'
    Description       = 'AD-PowerAdmin Audit Policy Management. Audits Windows audit policy settings against hardened baselines for domain controllers and standard computers. Identifies missing or misconfigured audit subcategories, under-sized event logs, disabled SACL auditing, and missing NTLM audit settings. Deploys GPO-based baselines for both computer roles.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-Module',
        'Start-ADPAuditPolicyCheck',
        'Get-ADPAuditPolicyStatus',
        'Get-ADPEventLogStorageStatus',
        'Compare-ADPAuditPolicyBaseline',
        'New-ADPAuditPolicyGpo',
        'Export-ADPAuditPolicyReport',
        'Show-ADPAuditPolicyHelp',
        'Test-ADPDirectoryServiceSacl',
        'Test-ADPNtlmAuditSettings',
        'Test-ADPAuditPolicyGpoDiagnostic'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    FileList          = @(
        'AD-PowerAdmin_AuditPolicy.psm1',
        'AD-PowerAdmin_AuditPolicy.psd1'
    )
    PrivateData = @{
        PSData = @{
            Channel      = 'Production'
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            ReleaseNotes = 'v1.1: Added Show-ADPAuditPolicyHelp (H key in submenu) with baseline comparison table, event log size targets, and DC-only check descriptions. GPO links are now created Enforced. v1.2: Fixed SCENoApplyLegacyAuditPolicy check to use Invoke-Command on remote targets. v1.3: Added Test-ADPAuditPolicyGpoDiagnostic -- six-check diagnostic for identifying why an audit policy GPO is not applying settings. v1.4: Fixed gPCMachineExtensionNames update in New-ADPAuditPolicyGpo to use DN-based lookup and explicitly set both the Security CSE block and Registry CSE block, preventing the Settings display omission caused by the prior Filter-based lookup that could silently return null. v1.5: Added Audit Policy Configuration CSE block ({F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}) to the definitive gPCMachineExtensionNames write in step 5b. Without this block the GP client never invokes the Audit Policy CSE and Advanced Audit Policy settings from audit.csv are never applied. v1.6: Fixed New-ADPAuditPolicyGpo to include Directory Service log in the ADMX registry key deployment; the DomainController baseline already defined a 256 MB minimum and 1 GB preferred size for this log but the GPO writer omitted it from the $LogAdmxNames dictionary. v1.7: Fixed Directory Service log GPO deployment to use the legacy SYSTEM registry path (HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Directory Service\MaxSize, value in bytes) instead of the ADMX path; the Event Log service does not process the ADMX path for application-registered logs. Fixed Show-ADPAuditFindings summary line: wrapped Where-Object calls in @() to force array context before .Count; in PS5.1 calling .Count on a scalar PSCustomObject returned by Where-Object yields $null, causing the High count to display as blank when exactly 1 High finding exists. v1.8: Updated Test-ADPAuditPolicyGpoDiagnostic Check 6 to filter for both Security CSE ({827D319E-...}) and Audit Policy Configuration CSE ({F3CCC681-...}) events; previously only matched Security CSE events, so a missing Audit Policy CSE would not surface in event output. Updated Resolution Guide step 1 to name both required CSE GUIDs. Updated Show-ADPAuditPolicyHelp GPO Deployment section to document all three CSE blocks registered by each deployment. v1.9: Promoted Get-ADPSystemRole to AD-PowerAdmin_Utils as Get-SystemRole; promoted Write-ADPWrappedText to AD-PowerAdmin_Utils as Write-WrappedText. Both functions are generic framework utilities with no audit-policy-specific logic. All call sites updated to use the new names from Utils.'
        }
    }
}
