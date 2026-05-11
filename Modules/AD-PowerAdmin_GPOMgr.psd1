@{
    RootModule        = 'AD-PowerAdmin_GPOMgr.psm1'
    ModuleVersion     = '3.0'
    GUID              = '36938a72-1125-4682-a65c-87d2af298de9'
    Author            = 'CyberGladius'
    CompanyName       = 'CyberGladius.com'
    Copyright         = '(c) 2026 CyberGladius. All rights reserved.'
    Description       = 'AD-PowerAdmin Group Policy Manager. Provides a neutral GPO infrastructure layer for the AD-PowerAdmin framework. Supports creating, configuring, linking, auditing, and deleting Group Policy Objects. Exposes Install-ADPAGPOBaseline as a shared API that other AD-PowerAdmin modules use to deploy GPO-based enforcement without reimplementing GPO management logic.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-Module',
        'Find-GPO',
        'Test-GPO',
        'Export-GPOReport',
        'Get-GPOBackupList',
        'Get-GPOAdvancedAuditPolicy',
        'Search-GPOSetting',
        'Search-GPOSecuritySetting',
        'New-ADPAGPO',
        'Set-GPORegistrySetting',
        'Set-GPOPermission',
        'Set-GPOSecuritySetting',
        'Set-GPOAdvancedAuditPolicy',
        'Add-GPOLink',
        'Install-GPOBaseline',
        'Backup-ADPAGPO',
        'Backup-AllGPOs',
        'Restore-GPOBackup',
        'Invoke-GPOModification',
        'Remove-GPORegistrySetting',
        'Remove-GPOLink',
        'Remove-ADPAGPO',
        'Remove-GPOBaseline',
        'Show-GPOMgrHelp'
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
            Channel      = 'Production'
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            ReleaseNotes = 'v1.0: Initial release. v1.1: Promoted to Beta after Honeypot module integration. v1.2: Added Backup-ADPAGPO, Backup-AllADPAGPOs, Get-ADPAGPOBackupList, Restore-ADPAGPOBackup, Invoke-ADPAGPOModification. Added interactive GPO Manager submenu with backup and restore actions. v1.3: Added Set-ADPAGPOSecuritySetting, ConvertFrom-IniString, ConvertTo-IniLines, Update-GptIniVersion. v1.4: Added Search-ADPAGPOSecuritySetting -- single-pass scan of all GPO GptTmpl.inf files for a list of Section+Key settings, returning exact and partial matches for pre-deployment overlap detection. v1.5: Added Set-ADPAGPOAdvancedAuditPolicy, Get-ADPAGPOAdvancedAuditPolicy. v1.6: Fixed Update-GptIniVersion to also update GPO AD object gPCMachineExtensionNames. v1.7: Fixed Set-ADPAGPOAdvancedAuditPolicy to write audit.csv as Unicode (UTF-16 LE) matching the encoding the Security Configuration Engine requires; previously written as UTF-8 which caused the SCE to skip the file entirely. v1.8: Fixed audit.csv column layout (Inclusion Setting = text label, Setting Value = integer), subcategory name prefix ("Audit "), and GUID casing (lowercase) to match the format produced by the GPMC UI. Previous layout caused the Advanced Audit Policy snapin to crash with a FormatException on Convert.ToUInt32 of an empty Setting Value field. v1.9: Fixed audit.csv encoding back to UTF-8 without BOM -- direct SYSVOL hex comparison confirmed the GPMC-generated file has no BOM; the UTF-16 LE BOM written since v1.7 prevented the SCE from processing the file. Fixed ConvertTo-IniLines to write Key=Value without spaces (matching Windows INI format). Fixed Update-GptIniVersion to never write gPCMachineExtensionNames into gpt.ini -- that field belongs in the GPO AD object only. v2.0: Fixed the missing Audit Policy Configuration CSE ({F3CCC681-B74C-4060-9F26-CD84525DCA2A}) from gPCMachineExtensionNames. Advanced Audit Policy (audit.csv) requires this dedicated CSE GUID in addition to the Security Settings CSE ({827D319E-...}); without it the GP client never invokes the Audit Policy CSE and GPMC omits the Advanced Audit Policy section from the Settings report. Confirmed by ldapsearch comparison of a PS-only GPO versus a GPO saved once through the GPMC editor. Added ExtraCseBlocks parameter to Update-GptIniVersion so callers can register additional CSE blocks; Set-GPOAdvancedAuditPolicy now passes the Audit Policy CSE block. v3.0: Pre-production refactor. Renamed 19 public functions -- removed ADPA abbreviation where no native GroupPolicy cmdlet conflict exists (New-ADPAGPO, Remove-ADPAGPO, Backup-ADPAGPO retain ADPA to avoid collision with native New-GPO, Remove-GPO, Backup-GPO). Reordered all functions into framework-standard verb groups: Retrieval (Find, Test, Export, Get, Search), Modification (New, Set, Add, Install, Backup, Restore, Invoke), Removal (Remove). Removed Get-ResolvedDomain -- migrated to AD-PowerAdmin_Utils as a shared framework utility.'
        }
    }
}
