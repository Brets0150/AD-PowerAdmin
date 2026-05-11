@{
    RootModule        = 'AD-PowerAdmin_GPOBestPracticesDeployer.psm1'
    ModuleVersion     = '1.4'
    GUID              = 'a02d8ae5-6393-493c-903e-8449ea2e4198'
    Author            = 'CyberGladius'
    CompanyName       = 'CyberGladius.com'
    Copyright         = '(c) 2026 CyberGladius. All rights reserved.'
    Description       = 'AD-PowerAdmin Best Practices GPO Deployer. Provides a submenu of recommended Group Policy security baseline configurations. All GPO operations are delegated to the AD-PowerAdmin_GPOMgr module -- this module contains no direct GroupPolicy cmdlet calls.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Initialize-Module',
        'Invoke-GPOBestPracticeDeployment'
    )
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    FileList          = @(
        'AD-PowerAdmin_GPOBestPracticesDeployer.psm1',
        'AD-PowerAdmin_GPOBestPracticesDeployer.psd1'
    )
    PrivateData = @{
        PSData = @{
            Channel      = 'Production'
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            RequiredADPAModules = @('AD-PowerAdmin_GPOMgr')
            ReleaseNotes = 'v1.0: Initial release with Set-BestPracticeDisableLMHashStorage. v1.1: Refactored to data-driven architecture. Best practices are now defined as entries in $script:GPOBestPractices; Initialize-Module builds the submenu dynamically. Replaced per-setting public functions with a single generalized Invoke-GPOBestPracticeDeployment dispatcher. Adding a new best practice now requires only a new entry in the definitions array. v1.2: Extended RegistrySettings and new SecuritySettings entry fields with Configurable (bool) and Prompt (string) for administrator-overridable values. Added Resolve-ConfigurableSettings private helper. Added SecuritySettings support to both deployment paths via Set-GPOSecuritySetting. Added DefaultDomainPasswordPolicy best practice entry with 8 configurable account and lockout policy settings. v1.3: Added Assert-ADPAModuleDependency check in Initialize-Module -- module will not register if AD-PowerAdmin_GPOMgr is unavailable. Updated all 7 GPOMgr call sites to use v3.0 renamed function names. Added Variants field support to $script:GPOBestPractices entries -- when a best practice defines a Variants array, Invoke-GPOBestPracticeDeployment presents a choice list before coverage checking, then merges the selected variant registry settings into the deployment path. Added Select-BestPracticeVariant private helper. Added EnableNTLMAuditPolicy best practice (AuditNTLMInDomain, AuditReceivingNTLMTraffic). Added DisableNTLMProtocols best practice with three variants: disable LM/NTLMv1 only (LmCompatibilityLevel=5), restrict domain NTLM authentication (RestrictNTLMInDomain), or both combined. v1.4: Promoted to Production. Function order refactored to comply with verb-group ordering standard (Show then Select then Resolve in retrieval group; all Invoke functions together in modification group). No logic changes.'
        }
    }
}
