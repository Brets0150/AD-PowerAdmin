@{
    RootModule        = 'AD-PowerAdmin_GPOMgr.psm1'
    ModuleVersion     = '1.1'
    GUID              = '36938a72-1125-4682-a65c-87d2af298de9'
    Author            = 'CyberGladius'
    CompanyName       = 'CyberGladius.com'
    Copyright         = '(c) 2026 CyberGladius. All rights reserved.'
    Description       = 'AD-PowerAdmin Group Policy Manager. Provides a neutral GPO infrastructure layer for the AD-PowerAdmin framework. Supports creating, configuring, linking, auditing, and deleting Group Policy Objects. Exposes Install-ADPAGPOBaseline as a shared API that other AD-PowerAdmin modules use to deploy GPO-based enforcement without reimplementing GPO management logic.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-Module',
        'Find-ADPAGPO',
        'Test-ADPAGPO',
        'New-ADPAGPO',
        'Set-ADPAGPORegistrySetting',
        'Remove-ADPAGPORegistrySetting',
        'Add-ADPAGPOLink',
        'Remove-ADPAGPOLink',
        'Set-ADPAGPOPermission',
        'Export-ADPAGPOReport',
        'Remove-ADPAGPO',
        'Install-ADPAGPOBaseline',
        'Remove-ADPAGPOBaseline',
        'Search-ADPAGPOSetting'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    FileList          = @(
        'AD-PowerAdmin_GPOMgr.psm1',
        'AD-PowerAdmin_GPOMgr.psd1'
    )
    PrivateData = @{
        PSData = @{
            Channel      = 'Beta'
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            ReleaseNotes = 'v1.0: Initial release of the Group Policy Manager module. Provides Find-ADPAGPO, Test-ADPAGPO, New-ADPAGPO, Set/Remove-ADPAGPORegistrySetting, Add/Remove-ADPAGPOLink, Set-ADPAGPOPermission, Export-ADPAGPOReport, Remove-ADPAGPO, Install-ADPAGPOBaseline, Remove-ADPAGPOBaseline, and Search-ADPAGPOSetting. v1.1: Promoted to Beta after successful production domain validation via Honeypot module integration.'
        }
    }
}
