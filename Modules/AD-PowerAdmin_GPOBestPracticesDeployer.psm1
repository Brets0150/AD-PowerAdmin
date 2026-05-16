#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory

# ===========================================================================
# Best Practice Definitions
#
# To add a new best-practice setting, append a new hashtable to this array.
# Initialize-Module reads $script:GPOBestPractices at load time to build the
# submenu dynamically. No other change is required to register it in the menu.
#
# Required fields per entry:
#   Id             [string]      Unique identifier used as the submenu key and
#                                for dispatch inside Invoke-GPOBestPracticeDeployment.
#   Title          [string]      Short title displayed in the submenu (~20 chars).
#   Label          [string]      Longer description shown below the title in the
#                                submenu (150-250 chars).
#   Description    [string[]]    Lines of text explaining the threat and the setting.
#                                Each element is one line printed during deployment.
#   AppliesTo      [string[]]    One or more scope labels describing what this policy
#                                targets. Shown during deployment to guide link placement.
#                                Examples: 'All Computers', 'Workstations', 'Domain Controllers',
#                                'User Accounts', 'Service Accounts'.
#   Note           [string]      Optional supplementary note (empty string if unused).
#                                Printed in a distinct color after the description.
#   DefaultGpoName [string]      Default GPO name offered when creating a new GPO.
#   GpoDescription [string]      Comment stored on the GPO object in Active Directory.
#   RegistrySettings [hashtable[]] One or more registry-backed settings to apply.
#                                Each entry: @{Key; ValueName; Type; Value;
#                                  [Configurable]; [Prompt]}
#   SecuritySettings [hashtable[]] One or more security template settings to apply
#                                (account policy, lockout policy, security options).
#                                Stored in GptTmpl.inf via Set-GPOSecuritySetting.
#                                Each entry: @{Section; Key; Value;
#                                  [Configurable]; [Prompt]}
#
# Optional per-setting fields (apply to both RegistrySettings and SecuritySettings):
#   Configurable     [bool]   If $true, the administrator is prompted before
#                             deployment to confirm or override the default Value.
#                             Omit or set $false to apply the value silently.
#   Prompt           [string] Message shown when Configurable = $true. Should
#                             describe the setting and include the valid range or
#                             allowed values so the administrator can make an
#                             informed choice.
# ===========================================================================
$script:GPOBestPractices = @(
    @{
        Id             = 'DisableLMHash'
        Title          = 'Disable LM Hash Storage'
        Label          = "Enforces 'Network security: Do not store LAN Manager hash value on next password change'. Eliminates stored LM hashes, blocking offline LM-hash cracking and pass-the-hash attacks against legacy credentials."
        AppliesTo      = @('All Computers', 'Workstations', 'Servers', 'Domain Controllers')
        Description    = @(
            'LAN Manager (LM) hashes are a legacy authentication credential.',
            'They are cryptographically weak: the password is padded to 14 characters,',
            'split into two 7-character halves, and each half is DES-encrypted independently.',
            'This makes LM hashes trivial to crack offline and exposes every user account',
            'to pass-the-hash and credential-dumping attacks via tools such as Mimikatz.'
        )
        Note           = "Existing LM hashes are removed at each user's next password change. Consider forcing a domain-wide password reset after applying this setting."
        DefaultGpoName = 'CorpSec-Disable-LMHash'
        GpoDescription = 'Disables LM hash storage. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
        RegistrySettings = @(
            @{
                Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
                ValueName = 'NoLMHash'
                Type      = 'DWord'
                Value     = 1
            }
        )
    },
    @{
        Id             = 'RequireSmbSigning'
        Title          = 'Require SMB Signing'
        Label          = "Requires SMB packet signing for all client and server SMB communications. Eliminates unsigned SMB sessions vulnerable to relay, tampering, and man-in-the-middle attacks."
        AppliesTo      = @('All Computers', 'Domain Controllers', 'Servers', 'Workstations')
        Description    = @(
            'SMB signing digitally signs each SMB packet so the receiving system can verify',
            'it was not modified in transit. Without required signing, SMB sessions may be',
            'unsigned and vulnerable to relay-style attacks and in-transit tampering.',
            'Two settings enforce signing: the client-side (outbound connection) and the',
            'server-side (inbound connection). Both must be enabled to fully close the exposure.'
        )
        Note           = 'May break legacy NAS devices, older Samba servers, and appliances that do not support SMB signing. Test in a pilot OU before broad deployment and document any exceptions.'
        DefaultGpoName = 'CorpSec-Require-SMB-Signing'
        GpoDescription = 'Requires SMB signing for all client and server SMB communications. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
        RegistrySettings = @(
            @{
                Key       = 'HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters'
                ValueName = 'RequireSecuritySignature'
                Type      = 'DWord'
                Value     = 1
            },
            @{
                Key       = 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters'
                ValueName = 'RequireSecuritySignature'
                Type      = 'DWord'
                Value     = 1
            }
        )
    },
    @{
        Id             = 'DefaultDomainPasswordPolicy'
        Title          = 'Domain Password Policy'
        Label          = "Configures the domain password and account lockout policy: minimum length, complexity, age, history, and lockout thresholds. Recommended defaults are pre-filled; all numeric fields are configurable."
        AppliesTo      = @('All Domain User Accounts')
        Description    = @(
            'The Default Domain Password Policy governs password requirements for all',
            'domain user accounts. Weak password policies are a primary enabler of',
            'brute-force, password spray, and credential stuffing attacks.',
            'IMPORTANT: Account policy settings (password and lockout) are enforced by',
            'Windows ONLY when the GPO is linked to the domain root -- not to OUs.',
            'If creating a new GPO, link it to the domain root or apply to the Default',
            'Domain Policy. Linking to an OU will have no effect on domain user accounts.'
        )
        Note           = 'Changes take effect at next logon or password change. Notify users of stricter requirements before enforcing. PasswordComplexity is fixed at Enabled (1) and cannot be relaxed.'
        DefaultGpoName = 'CorpSec-Default-Domain-Password-Policy'
        GpoDescription = 'Enforces domain password and account lockout policy. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
        RegistrySettings = @()
        SecuritySettings = @(
            @{
                Section      = 'System Access'
                Key          = 'MinimumPasswordLength'
                Value        = 14
                Configurable = $true
                Prompt       = 'Minimum password length in characters (recommended: 14; NIST SP 800-63B minimum: 8). Enter a number:'
            },
            @{
                Section      = 'System Access'
                Key          = 'PasswordComplexity'
                Value        = 1
                Configurable = $false
                Prompt       = ''
            },
            @{
                Section      = 'System Access'
                Key          = 'PasswordHistorySize'
                Value        = 24
                Configurable = $true
                Prompt       = 'Password history count -- number of previous passwords that cannot be reused (recommended: 24; range: 0-24). Enter a number:'
            },
            @{
                Section      = 'System Access'
                Key          = 'MaximumPasswordAge'
                Value        = 90
                Configurable = $true
                Prompt       = 'Maximum password age in days before expiry (recommended: 90; enter 0 to disable expiry). Enter a number:'
            },
            @{
                Section      = 'System Access'
                Key          = 'MinimumPasswordAge'
                Value        = 1
                Configurable = $true
                Prompt       = 'Minimum password age in days before a user can change again (recommended: 1; prevents immediate re-use to bypass history; enter 0 to allow immediate change). Enter a number:'
            },
            @{
                Section      = 'System Access'
                Key          = 'LockoutBadCount'
                Value        = 5
                Configurable = $true
                Prompt       = 'Account lockout threshold -- failed logon attempts before lockout (recommended: 5; enter 0 to disable lockout). Enter a number:'
            },
            @{
                Section      = 'System Access'
                Key          = 'LockoutDuration'
                Value        = 30
                Configurable = $true
                Prompt       = 'Account lockout duration in minutes (recommended: 30; enter 0 to require administrator unlock). Enter a number:'
            },
            @{
                Section      = 'System Access'
                Key          = 'ResetLockoutCount'
                Value        = 30
                Configurable = $true
                Prompt       = 'Observation window in minutes -- failed logon counter resets after this interval (recommended: 30; must be less than or equal to lockout duration). Enter a number:'
            }
        )
    },
    @{
        Id             = 'EnableNTLMAuditPolicy'
        Title          = 'Enable NTLM Audit Policy'
        Label          = "Enables NTLM authentication auditing on domain controllers. Populates the NTLM Operational event log so administrators can identify which systems, users, and service accounts still use NTLMv1 or NTLMv2 before enforcing blocking policies."
        AppliesTo      = @('Domain Controllers')
        Description    = @(
            'NTLM authentication events are not logged by default. Without auditing enabled,',
            'administrators cannot determine which clients, users, or service accounts still',
            'rely on NTLMv1 or NTLMv2 before enforcing a blocking policy. Enabling audit',
            'first prevents unexpected outages during NTLM restriction rollout.',
            'IMPORTANT: Apply this GPO to the Domain Controllers OU only. After applying,',
            'allow 14-30 days of data collection before reviewing logs or enforcing blocks.'
        )
        Note           = 'After applying this policy, use the AD-PowerAdmin Event Log Manager NTLM search to review authentication patterns across all domain controllers.'
        DefaultGpoName = 'CorpSec-NTLM-Audit-Policy'
        GpoDescription = 'Enables NTLM authentication auditing on domain controllers. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
        RegistrySettings = @(
            @{
                Key          = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
                ValueName    = 'AuditNTLMInDomain'
                Type         = 'DWord'
                Value        = 7
                Configurable = $true
                Prompt       = 'NTLM domain audit level: 2=DC authentication only, 4=All domain account auth, 6=All domain accounts with server info, 7=Enable all (recommended). Enter a number:'
            },
            @{
                Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
                ValueName = 'AuditReceivingNTLMTraffic'
                Type      = 'DWord'
                Value     = 2
            }
        )
    },
    @{
        Id             = 'DisableNTLMProtocols'
        Title          = 'Disable NTLM Protocols'
        Label          = "Disables NTLM protocols via Group Policy. Option 1 disables NTLMv1 and LM outbound while keeping NTLMv2. Option 2 disables all NTLM (v1, v2, and LM) outbound and denies all NTLM inbound on all machines and DCs. AUDIT FIRST using Enable NTLM Audit Policy before applying option 2."
        AppliesTo      = @('All Computers', 'Domain Controllers', 'Servers', 'Workstations')
        Description    = @(
            'NTLM authentication, especially NTLMv1, exposes credential material to capture,',
            'offline cracking, pass-the-hash, and relay attacks. Disabling NTLMv1 forces',
            'clients to use NTLMv2 at minimum. Restricting all domain NTLM eliminates relay',
            'risk for domain accounts but requires Kerberos to be functional for all services.',
            'IMPORTANT: Always audit NTLM usage before enforcing restrictions.',
            'Legacy devices, printers, NAS appliances, and embedded systems may break.',
            'Use the Enable NTLM Audit Policy GPO and review logs before deploying this.'
        )
        Note           = 'Fix Kerberos dependencies before applying Option 2: use FQDNs instead of IP addresses, correct missing SPNs, and update legacy applications. Always start with Option 1 and escalate to Option 2 only after confirming no NTLM-dependent breakage.'
        SelectionGuide = @(
            'Option 1 -- Recommended starting point for most environments.',
            '  Removes NTLMv1 and LM (the weakest NTLM variants) while keeping NTLMv2 available',
            '  for services that have not yet been migrated to Kerberos. Breakage is typically',
            '  limited to very old embedded devices and legacy Samba servers.',
            '',
            'Option 2 -- Full NTLM elimination. Apply only after validating with Option 1.',
            '  Disables NTLMv2 in addition to NTLMv1 and LM. Requires the Enable NTLM Audit',
            '  Policy GPO to have been running for at least 14-30 days with zero remaining',
            '  NTLM events. All systems must be reachable by FQDN, all SPNs must be correctly',
            '  registered, and Kerberos must be fully functional before this is safe to apply.',
            '  Printers, NAS appliances, and legacy line-of-business applications frequently',
            '  require NTLM and must be remediated or excepted before enabling this option.'
        )
        DefaultGpoName = 'CorpSec-Disable-NTLM'
        GpoDescription = 'NTLM protocol restriction policy. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
        RegistrySettings = @()
        Variants = @(
            @{
                Label          = '1. Disable NTLMv1 and LM outbound; deny NTLMv1 and LM inbound  (all machines and DCs; NTLMv2 still allowed)'
                DefaultGpoName = 'CorpSec-Disable-NTLMv1-LM'
                GpoDescription = 'Disables NTLMv1 and LM outbound and denies NTLMv1 and LM inbound on all machines. NTLMv2 remains allowed. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
                RegistrySettings = @(
                    @{
                        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
                        ValueName = 'LmCompatibilityLevel'
                        Type      = 'DWord'
                        Value     = 5
                    }
                )
            },
            @{
                Label          = '2. Disable all NTLM outbound; deny all NTLM inbound  (all machines and DCs; blocks NTLMv1, NTLMv2, and LM -- AUDIT FIRST)'
                DefaultGpoName = 'CorpSec-Disable-All-NTLM'
                GpoDescription = 'Disables all NTLM (v1, v2, LM) outbound and denies all NTLM inbound on all machines and domain controllers. Deployed by AD-PowerAdmin Best Practices GPO Deployer.'
                RegistrySettings = @(
                    @{
                        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
                        ValueName = 'LmCompatibilityLevel'
                        Type      = 'DWord'
                        Value     = 5
                    },
                    @{
                        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
                        ValueName = 'RestrictSendingNTLMTraffic'
                        Type      = 'DWord'
                        Value     = 2
                    },
                    @{
                        Key       = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
                        ValueName = 'RestrictReceivingNTLMTraffic'
                        Type      = 'DWord'
                        Value     = 2
                    },
                    @{
                        Key       = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
                        ValueName = 'RestrictNTLMInDomain'
                        Type      = 'DWord'
                        Value     = 7
                    }
                )
            }
        )
    }
)

# ===========================================================================
# Module Initialization
# ===========================================================================

Function Initialize-Module {
    <#
    .SYNOPSIS
        Registers the Best Practices GPO Deployer submenu in the AD-PowerAdmin framework.

    .DESCRIPTION
        Reads $script:GPOBestPractices and dynamically builds the submenu. Each
        entry in the array becomes one numbered item in the submenu. All GPO
        operations are delegated to the AD-PowerAdmin_GPOMgr module -- this
        module contains no direct GroupPolicy cmdlet calls.

        To add a new best-practice setting, append an entry to $script:GPOBestPractices
        at the top of this file. No other change is required.

    .EXAMPLE
        Initialize-Module
    #>
    # Bootstrap Utils -- it loads alphabetically after this module (U > G), so
    # Assert-ADPAModuleDependency may not be available yet. Import it on demand.
    if (-not (Get-Module -Name 'AD-PowerAdmin_Utils')) {
        $UtilsPath = Join-Path $global:ModulesPath 'AD-PowerAdmin_Utils.psd1'
        if (Test-Path $UtilsPath) {
            try { Import-Module $UtilsPath -Force -ErrorAction Stop } catch { }
        }
    }
    if (-not (Assert-ADPAModuleDependency -RequiredModules @('AD-PowerAdmin_GPOMgr'))) {
        Write-Host "[WARN] AD-PowerAdmin_GPOBestPracticesDeployer was not registered: required module AD-PowerAdmin_GPOMgr is unavailable." -ForegroundColor Yellow
        return
    }

    $global:Menu.Remove('GPOBestPracticesDeployer')
    $global:SubMenus.Remove('GPOBestPracticesDeployerMenu')

    $Items = @{}
    foreach ($BP in $script:GPOBestPractices) {
        $Items[$BP.Id] = @{
            Title   = $BP.Title
            Label   = $BP.Label
            Command = "Invoke-GPOBestPracticeDeployment '$($BP.Id)'"
        }
    }

    $global:SubMenus += @{
        'GPOBestPracticesDeployerMenu' = @{
            Title = "Best Practices GPO Deployer"
            Items = $Items
        }
    }

    $global:Menu += @{
        'GPOBestPracticesDeployer' = @{
            Title    = "Best Practices GPO Deployer"
            Label    = "Apply recommended Group Policy security baselines. Select a setting to apply it to the Default Domain Policy or a new linked GPO. All modifications to existing GPOs include automatic pre-change backup."
            Module   = "AD-PowerAdmin_GPOBestPracticesDeployer"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'GPOBestPracticesDeployerMenu'"
        }
    }
}

Initialize-Module

# ===========================================================================
# Retrieval Functions
# ===========================================================================

Function Show-BPCoverageReport {
    # Displays a formatted overlap report grouping results by GPO name.
    # Exact matches (same value already enforced) are shown in green.
    # Partial matches (same setting, different value) are shown in yellow.
    param([PSCustomObject[]]$Results)

    [bool]$HasExact   = ($null -ne ($Results | Where-Object { $_.MatchType -eq 'Exact' }))
    [bool]$HasPartial = ($null -ne ($Results | Where-Object { $_.MatchType -eq 'Partial' }))

    if ($HasPartial) {
        Write-Host "  [WARN] Overlapping settings found -- one or more settings exist at different values." -ForegroundColor Yellow
    } else {
        Write-Host "  [WARN] These settings are already enforced by existing GPO(s)." -ForegroundColor Yellow
    }
    Write-Host ""

    $ByGpo = $Results | Group-Object GpoName
    foreach ($Group in $ByGpo | Sort-Object Name) {
        Write-Host "  GPO: $($Group.Name)" -ForegroundColor Cyan
        foreach ($R in $Group.Group | Sort-Object SettingName) {
            $Color  = if ($R.MatchType -eq 'Exact') { 'Green' } else { 'Yellow' }
            $Label  = "       $($R.SettingName)".PadRight(38)
            $Values = "current=$($R.CurrentValue)".PadRight(18) + "expected=$($R.ExpectedValue)".PadRight(18)
            Write-Host "$Label $Values [$($R.MatchType)]" -ForegroundColor $Color
        }
        Write-Host ""
    }

    if ($HasExact)   { Write-Host "  [Exact]   Setting already enforced at the expected value." -ForegroundColor Green }
    if ($HasPartial) { Write-Host "  [Partial] Setting exists at a DIFFERENT value -- applying may conflict or have no effect." -ForegroundColor Yellow }
    Write-Host ""
}

Function Select-GPOApplicationMode {
    # Prompts the user to choose how to apply a best-practice setting.
    # Returns 'DDP' (Default Domain Policy), 'New' (create new GPO), or '' (cancel).
    Write-Host ""
    Write-Host "  How would you like to apply this setting?" -ForegroundColor Cyan
    Write-Host "  1. Apply to the Default Domain Policy"
    Write-Host "  2. Create a new GPO and link it to a target"
    Write-Host "  Q. Cancel"
    Write-Host ""

    while ($true) {
        [string]$Choice = Read-Host "  Select"
        switch ($Choice.ToUpper()) {
            '1' { return 'DDP' }
            '2' { return 'New' }
            'Q' { return ''    }
            default {
                Write-Host "  Invalid selection. Enter 1, 2, or Q." -ForegroundColor Yellow
            }
        }
    }
}

Function Select-BestPracticeVariant {
    # Presents a numbered list of variant choices and returns the selected variant
    # hashtable, or $null if the user cancels. Used by Invoke-GPOBestPracticeDeployment
    # when a best-practice entry defines a Variants array instead of a fixed RegistrySettings list.
    param(
        [Parameter(Mandatory=$true)]
        [hashtable[]]$Variants
    )

    Write-Host ""
    Write-Host "  Select a variant to deploy:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $Variants.Count; $i++) {
        Write-Host "  $($Variants[$i].Label)"
    }
    Write-Host "  Q. Cancel"
    Write-Host ""

    while ($true) {
        [string]$Choice = Read-Host "  Select"
        if ($Choice.ToUpper() -eq 'Q') { return $null }
        [int]$Index = 0
        if ([int]::TryParse($Choice, [ref]$Index) -and $Index -ge 1 -and $Index -le $Variants.Count) {
            return $Variants[$Index - 1]
        }
        Write-Host "  Invalid selection. Enter 1-$($Variants.Count) or Q." -ForegroundColor Yellow
    }
}

Function Resolve-ConfigurableSettings {
    # Returns a resolved copy of a settings array. For each entry where
    # Configurable = $true, displays the Prompt, shows the default Value, and
    # allows the administrator to accept the default or enter an override.
    # Non-configurable entries are passed through unchanged.
    param(
        [Parameter(Mandatory=$true)]
        [hashtable[]]$Settings
    )
    $Resolved = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($Setting in $Settings) {
        if ($Setting.Configurable -eq $true) {
            Write-Host ""
            Write-Host "  $($Setting.Prompt)" -ForegroundColor Cyan
            Write-Host "  Recommended default: $($Setting.Value)" -ForegroundColor White
            while ($true) {
                [string]$UserInput = Read-Host "  Enter value (press Enter to accept default)"
                if ([string]::IsNullOrWhiteSpace($UserInput)) {
                    $FinalValue = $Setting.Value
                    break
                }
                [int]$ParsedInt = 0
                if ([int]::TryParse($UserInput, [ref]$ParsedInt)) {
                    $FinalValue = $ParsedInt
                    break
                }
                Write-Host "  Value must be a whole number. Try again." -ForegroundColor Yellow
            }
            $Copy = @{}
            foreach ($K in $Setting.Keys) { $Copy[$K] = $Setting[$K] }
            $Copy['Value'] = $FinalValue
            $Resolved.Add($Copy)
        } else {
            $Resolved.Add($Setting)
        }
    }
    return $Resolved.ToArray()
}

# ===========================================================================
# Modification Functions
# ===========================================================================

Function Invoke-BestPracticeApplyToDDP {
    # Applies all settings from a best-practice definition to the Default Domain
    # Policy. Configurable values are resolved first. Registry settings are applied
    # via Invoke-GPOModification (which handles backup). Security template
    # settings are applied via Set-GPOSecuritySetting. For entries that have
    # only security settings, Backup-ADPAGPO is called directly before modification.
    param([hashtable]$BestPractice)

    [bool]$HasRegistry = ($null -ne $BestPractice.RegistrySettings -and $BestPractice.RegistrySettings.Count -gt 0)
    [bool]$HasSecurity = ($null -ne $BestPractice.SecuritySettings -and $BestPractice.SecuritySettings.Count -gt 0)

    $ResolvedRegistry = if ($HasRegistry) { Resolve-ConfigurableSettings -Settings $BestPractice.RegistrySettings } else { @() }
    $ResolvedSecurity = if ($HasSecurity) { Resolve-ConfigurableSettings -Settings $BestPractice.SecuritySettings } else { @() }

    Write-Host ""
    Write-Host "  Applying '$($BestPractice.Title)' to the Default Domain Policy..." -ForegroundColor Cyan

    [string]$BackupId   = ''
    [string]$BackupPath = ''
    [bool]$OverallOk    = $true

    if ($HasRegistry) {
        $Result = Invoke-GPOModification `
            -GpoName 'Default Domain Policy' `
            -RegistrySettings $ResolvedRegistry
        $BackupId   = $Result.BackupId
        $BackupPath = $Result.BackupPath
        if ($Result.Status -eq 'Failed') {
            Write-Host ""
            Write-Host "  [FAIL] Operation did not complete successfully." -ForegroundColor Red
            $Result.Errors | ForEach-Object { Write-Host "         - $_" -ForegroundColor Red }
            return
        }
        if ($Result.Status -eq 'Partial') { $OverallOk = $false }
    } elseif ($HasSecurity) {
        $BackupResult = Backup-ADPAGPO -GpoName 'Default Domain Policy'
        if ($BackupResult.Status -ne 'Success') {
            Write-Host ""
            Write-Host "  [FAIL] Backup of Default Domain Policy failed. Modification aborted." -ForegroundColor Red
            return
        }
        $BackupId   = $BackupResult.BackupId
        $BackupPath = $BackupResult.BackupPath
    }

    foreach ($Setting in $ResolvedSecurity) {
        $SetOk = Set-GPOSecuritySetting -GpoName 'Default Domain Policy' `
            -Section $Setting.Section -Key $Setting.Key -Value $Setting.Value.ToString()
        if (-not $SetOk) { $OverallOk = $false }
    }

    Write-Host ""
    if ($OverallOk) {
        Write-Host "  [OK] Setting applied to Default Domain Policy." -ForegroundColor Green
        if ($BackupId)   { Write-Host "       Backup ID  : $BackupId"   -ForegroundColor Green }
        if ($BackupPath) { Write-Host "       Backup Path: $BackupPath" -ForegroundColor Green }
    } else {
        Write-Host "  [WARN] Operation partially succeeded. Review the output above." -ForegroundColor Yellow
    }
}

Function Invoke-BestPracticeCreateNewGpo {
    # Creates a new GPO, applies all settings (registry and security template),
    # navigates the OU tree for a link target, links, and verifies.
    # Configurable values are resolved via prompts before the GPO is created.
    param([hashtable]$BestPractice)

    [bool]$HasRegistry = ($null -ne $BestPractice.RegistrySettings -and $BestPractice.RegistrySettings.Count -gt 0)
    [bool]$HasSecurity = ($null -ne $BestPractice.SecuritySettings -and $BestPractice.SecuritySettings.Count -gt 0)

    $ResolvedRegistry = if ($HasRegistry) { Resolve-ConfigurableSettings -Settings $BestPractice.RegistrySettings } else { @() }
    $ResolvedSecurity = if ($HasSecurity) { Resolve-ConfigurableSettings -Settings $BestPractice.SecuritySettings } else { @() }

    Write-Host ""
    [string]$GpoName = Read-Host "  Enter GPO name (press Enter for default: $($BestPractice.DefaultGpoName))"
    if ([string]::IsNullOrWhiteSpace($GpoName)) { $GpoName = $BestPractice.DefaultGpoName }

    $NewGpo = New-ADPAGPO -Name $GpoName -Description $BestPractice.GpoDescription
    if ($null -eq $NewGpo) {
        Write-Host "  [FAIL] Could not create GPO '$GpoName'. Operation aborted." -ForegroundColor Red
        return
    }

    [bool]$AllSettingsOk = $true

    foreach ($Setting in $ResolvedRegistry) {
        $SetOk = Set-GPORegistrySetting -GpoName $GpoName `
            -Key $Setting.Key -ValueName $Setting.ValueName `
            -Type $Setting.Type -Value $Setting.Value
        if (-not $SetOk) { $AllSettingsOk = $false }
    }

    foreach ($Setting in $ResolvedSecurity) {
        $SetOk = Set-GPOSecuritySetting -GpoName $GpoName `
            -Section $Setting.Section -Key $Setting.Key -Value $Setting.Value.ToString()
        if (-not $SetOk) { $AllSettingsOk = $false }
    }

    if (-not $AllSettingsOk) {
        Write-Host "  [WARN] One or more settings could not be applied." -ForegroundColor Yellow
        [string]$Proceed = Read-Host "  Continue to linking step anyway? (Y/N)"
        if ($Proceed.ToUpper() -ne 'Y') {
            Write-Host "  [INFO] Linking skipped. GPO '$GpoName' exists but may be misconfigured." -ForegroundColor Yellow
            return
        }
    }

    Write-Host ""
    Write-Host "  Select an OU or domain root to link the GPO to:" -ForegroundColor Cyan
    [string]$SelectedTarget = Get-AdOuSearch
    if ([string]::IsNullOrEmpty($SelectedTarget)) {
        Write-Host "  [WARN] No target selected. GPO '$GpoName' was created but not linked." -ForegroundColor Yellow
        Write-Host "         Link it manually from GPO Manager or the Group Policy Management Console." -ForegroundColor Yellow
        return
    }

    $LinkedOk = Add-GPOLink -GpoName $GpoName -Target $SelectedTarget
    if (-not $LinkedOk) {
        Write-Host "  [FAIL] GPO '$GpoName' was created but linking to '$SelectedTarget' failed." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  Verifying GPO configuration..." -ForegroundColor Cyan
    $VerifyOk = Test-GPO -Name $GpoName `
        -RegistrySettings $ResolvedRegistry `
        -Links @($SelectedTarget)

    Write-Host ""
    if ($VerifyOk) {
        Write-Host "  [OK] GPO '$GpoName' is created, configured, and linked to '$SelectedTarget'." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Deployment completed but verification found issues. Review the output above." -ForegroundColor Yellow
    }
}

Function Invoke-GPOBestPracticeDeployment {
    <#
    .SYNOPSIS
        Runs the deployment workflow for a named best-practice GPO setting.

    .DESCRIPTION
        Looks up the best practice by ID in $script:GPOBestPractices, presents
        the description and registry details, checks for existing GPO coverage,
        prompts the user to apply to the Default Domain Policy or create a new
        GPO, then delegates all GPO operations to the AD-PowerAdmin_GPOMgr module.

        This function contains no direct GroupPolicy cmdlet calls.

        The submenu Command string for each best practice is:
          "Invoke-GPOBestPracticeDeployment '<Id>'"

    .PARAMETER BestPracticeId
        The Id field of the entry in $script:GPOBestPractices to deploy.

    .EXAMPLE
        Invoke-GPOBestPracticeDeployment 'DisableLMHash'
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$BestPracticeId
    )

    $BP = $script:GPOBestPractices | Where-Object { $_.Id -eq $BestPracticeId } | Select-Object -First 1
    if ($null -eq $BP) {
        Write-Host "[FAIL] Unknown best practice ID: '$BestPracticeId'." -ForegroundColor Red
        Write-Host "       Valid IDs: $($script:GPOBestPractices.Id -join ', ')" -ForegroundColor Yellow
        return
    }

    [bool]$IsVariantEntry = ($null -ne $BP.Variants -and $BP.Variants.Count -gt 0)

    # -----------------------------------------------------------------------
    # HELP SECTION
    # Displayed first so the administrator understands what the settings do
    # and, for variant entries, which option to choose before any scan or
    # selection prompt appears.
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "  === $($BP.Title) ===" -ForegroundColor Cyan
    Write-Host ""

    if ($BP.AppliesTo -and $BP.AppliesTo.Count -gt 0) {
        Write-Host "  Applies To: $($BP.AppliesTo -join ', ')" -ForegroundColor Magenta
        Write-Host ""
    }

    foreach ($Line in $BP.Description) {
        Write-Host "  $Line" -ForegroundColor Yellow
    }

    # For non-variant entries show the full settings summary here so the
    # administrator knows exactly what will be written before the scan runs.
    if (-not $IsVariantEntry) {
        if ($null -ne $BP.RegistrySettings -and $BP.RegistrySettings.Count -gt 0) {
            Write-Host ""
            foreach ($S in $BP.RegistrySettings) {
                [string]$Tag = if ($S.Configurable) { ' [configurable]' } else { '' }
                Write-Host "  Setting : $($S.ValueName) = $($S.Value) ($($S.Type))$Tag" -ForegroundColor White
                Write-Host "  Registry: $($S.Key)" -ForegroundColor White
            }
        }
        if ($null -ne $BP.SecuritySettings -and $BP.SecuritySettings.Count -gt 0) {
            Write-Host ""
            foreach ($S in $BP.SecuritySettings) {
                [string]$Tag = if ($S.Configurable) { ' [configurable]' } else { '' }
                Write-Host "  Policy  : $($S.Key) = $($S.Value) [$($S.Section)]$Tag" -ForegroundColor White
            }
        }
    }

    # For variant entries show the SelectionGuide so the administrator can
    # compare options before the variant selection prompt appears.
    if ($IsVariantEntry -and $null -ne $BP.SelectionGuide -and $BP.SelectionGuide.Count -gt 0) {
        Write-Host ""
        foreach ($Line in $BP.SelectionGuide) {
            Write-Host "  $Line" -ForegroundColor White
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($BP.Note)) {
        Write-Host ""
        Write-Host "  NOTE: $($BP.Note)" -ForegroundColor DarkGray
    }
    Write-Host ""

    # -----------------------------------------------------------------------
    # COVERAGE SCAN
    # Runs after the help section but before any user selection so the
    # administrator sees what is already in the domain while the context is
    # still fresh. For variant entries all settings across all variants are
    # scanned (deduplicated) so the full picture is visible before the
    # variant is chosen.
    # -----------------------------------------------------------------------
    Write-Host "  Checking existing GPOs for overlapping settings..." -ForegroundColor Cyan
    $CoverageResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Build the settings list to scan.
    $RegistryToScan = if ($IsVariantEntry) {
        $Seen     = [System.Collections.Generic.HashSet[string]]::new()
        $Combined = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($V in $BP.Variants) {
            foreach ($S in $V.RegistrySettings) {
                if ($Seen.Add("$($S.Key)|$($S.ValueName)")) { $Combined.Add($S) }
            }
        }
        $Combined.ToArray()
    } else {
        $BP.RegistrySettings
    }

    if ($null -ne $RegistryToScan) {
        foreach ($Setting in $RegistryToScan) {
            $Hits = Search-GPOSetting -Key $Setting.Key -ValueName $Setting.ValueName `
                -ExpectedValue $Setting.Value -Force
            foreach ($H in $Hits) {
                $CoverageResults.Add([PSCustomObject]@{
                    GpoName       = $H.GpoName
                    SettingName   = $H.ValueName
                    CurrentValue  = $H.ActualValue
                    ExpectedValue = [string]$Setting.Value
                    MatchType     = if ($H.Matches) { 'Exact' } else { 'Partial' }
                })
            }
        }
    }

    if ($null -ne $BP.SecuritySettings -and $BP.SecuritySettings.Count -gt 0) {
        [hashtable[]]$SecTerms = @($BP.SecuritySettings | ForEach-Object {
            @{ Section = $_.Section; Key = $_.Key; ExpectedValue = $_.Value.ToString() }
        })
        $SecHits = Search-GPOSecuritySetting -Settings $SecTerms -Force
        foreach ($H in $SecHits) {
            $CoverageResults.Add([PSCustomObject]@{
                GpoName       = $H.GpoName
                SettingName   = $H.Key
                CurrentValue  = $H.ActualValue
                ExpectedValue = $H.ExpectedValue
                MatchType     = if ($H.Matches) { 'Exact' } else { 'Partial' }
            })
        }
    }

    if ($CoverageResults.Count -gt 0) {
        Show-BPCoverageReport -Results $CoverageResults.ToArray()
        [string]$Continue = Read-Host "  Proceed anyway? (Y/N)"
        if ($Continue.ToUpper() -ne 'Y') {
            Write-Host "  [INFO] Operation cancelled." -ForegroundColor Cyan
            return
        }
    } else {
        Write-Host "  [INFO] No overlapping settings found in existing GPOs." -ForegroundColor Green
        Write-Host ""
    }

    # -----------------------------------------------------------------------
    # VARIANT SELECTION
    # Appears after the help section and coverage scan so the administrator
    # has full context (what the options do, what already exists) before
    # making a selection.
    # -----------------------------------------------------------------------
    if ($IsVariantEntry) {
        $SelectedVariant = Select-BestPracticeVariant -Variants $BP.Variants
        if ($null -eq $SelectedVariant) {
            Write-Host "  [INFO] Operation cancelled." -ForegroundColor Cyan
            return
        }
        $BP = $BP.Clone()
        $BP['RegistrySettings'] = $SelectedVariant.RegistrySettings
        if ($SelectedVariant.ContainsKey('DefaultGpoName')) { $BP['DefaultGpoName'] = $SelectedVariant.DefaultGpoName }
        if ($SelectedVariant.ContainsKey('GpoDescription')) { $BP['GpoDescription'] = $SelectedVariant.GpoDescription }

        Write-Host ""
        foreach ($S in $BP.RegistrySettings) {
            [string]$Tag = if ($S.Configurable) { ' [configurable]' } else { '' }
            Write-Host "  Setting : $($S.ValueName) = $($S.Value) ($($S.Type))$Tag" -ForegroundColor White
            Write-Host "  Registry: $($S.Key)" -ForegroundColor White
        }
        Write-Host ""
    }

    # Prompt for application mode and dispatch
    [string]$Mode = Select-GPOApplicationMode
    if ([string]::IsNullOrEmpty($Mode)) {
        Write-Host "  [INFO] Operation cancelled." -ForegroundColor Cyan
        return
    }

    if ($Mode -eq 'DDP') {
        Invoke-BestPracticeApplyToDDP -BestPractice $BP
    } else {
        Invoke-BestPracticeCreateNewGpo -BestPractice $BP
    }
}
