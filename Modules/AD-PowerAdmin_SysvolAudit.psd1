@{
    RootModule        = 'AD-PowerAdmin_SysvolAudit.psm1'
    ModuleVersion     = '1.0'
    GUID              = 'd4e2b7a1-3f9c-4e8d-b5a2-6c1f0e3d9b7a'
    Author            = 'CyberGladius'
    Description       = 'Audits SYSVOL and NETLOGON for credential exposure, weak file permissions, GPO delegation risk, and external script path abuse.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-Module',
        'Get-SysvolScriptInventory',
        'Search-SysvolSecrets',
        'Search-SysvolGppCpassword',
        'Search-SysvolPermissions',
        'Search-GpoDelegation',
        'Search-GpoExternalScriptPaths',
        'Start-SysvolAudit',
        'Start-SysvolGppCpasswordCheck'
    )
    PrivateData = @{
        PSData = @{
            Channel      = 'Beta'
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            ReleaseNotes = 'Initial release of SYSVOL security audit module.'
        }
    }
}
