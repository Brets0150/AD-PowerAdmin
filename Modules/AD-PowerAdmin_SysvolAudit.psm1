Function Initialize-Module {
    <#
    .SYNOPSIS
    Registers SYSVOL audit menu entries and unattended jobs with the AD-PowerAdmin framework.

    .DESCRIPTION
    Initialize-Module is called automatically when the module is imported. It adds the
    SYSVOL Security Audit submenu and two unattended job entries to the global framework
    hashtables. Stale entries are removed first to allow safe module reloading.

    .EXAMPLE
    Initialize-Module

    .NOTES
    Must be called at module scope (outside any function) so it runs on import.
    #>

    $global:Menu.Remove('SysvolAudit')
    if ($global:SubMenus.ContainsKey('SysvolAuditMenu')) { $global:SubMenus.Remove('SysvolAuditMenu') }
    $global:UnattendedJobs.Remove('SysvolGppCpasswordCheck')
    $global:UnattendedJobs.Remove('SysvolFullAudit')

    $global:SubMenus += @{
        'SysvolAuditMenu' = @{
            Title = "SYSVOL Security Audit"
            Items = @{
                'SysvolInventory' = @{
                    Title   = "Script Inventory"
                    Label   = "Enumerate all script and configuration files stored in SYSVOL and NETLOGON. Produces a timestamped CSV inventory report."
                    Command = "Get-SysvolScriptInventory"
                }
                'SysvolSecrets' = @{
                    Title   = "Credential & Risk Pattern Scan"
                    Label   = "Scan SYSVOL and NETLOGON scripts for embedded credentials (passwords, tokens, API keys) and high-risk execution patterns (IEX, encoded commands, WebClient downloads, RunAs). Classifies findings as Critical or High."
                    Command = "Search-SysvolScriptRisks"
                }
                'SysvolGppCpassword' = @{
                    Title   = "GPP cpassword Scan"
                    Label   = "Search Group Policy Preference XML files in SYSVOL for cpassword values. All findings are Critical. The AES-256 decryption key was publicly disclosed in MS14-025."
                    Command = "Search-SysvolGppCpassword"
                }
                'SysvolPermissions' = @{
                    Title   = "Permission Scan"
                    Label   = "Audit SYSVOL file and folder ACLs for write or modify rights granted to broad principals such as Everyone, Domain Users, Authenticated Users, or Domain Computers."
                    Command = "Search-SysvolPermissions"
                }
                'GpoDelegation' = @{
                    Title   = "GPO Delegation Audit"
                    Label   = "Identify GPOs with edit rights assigned to non-Tier-0 identities, stale accounts, or broad security groups. Requires the GroupPolicy module (RSAT-GPMC)."
                    Command = "Search-GpoDelegation"
                }
                'GpoExternalPaths' = @{
                    Title   = "External Script Paths"
                    Label   = "Export GPO definitions and identify script references pointing to UNC paths outside SYSVOL and NETLOGON. External paths may reside on servers with weaker access controls."
                    Command = "Search-GpoExternalScriptPaths"
                }
                'SysvolFullAudit' = @{
                    Title   = "Full SYSVOL Audit"
                    Label   = "Run all six SYSVOL audit checks in sequence: inventory, credential and risk pattern scan, GPP cpassword, permissions, GPO delegation, and external paths. Prints a findings summary on completion."
                    Command = "Start-SysvolAudit"
                }
            }
        }
    }

    $global:Menu += @{
        'SysvolAudit' = @{
            Title    = "SYSVOL Security Audit"
            Label    = "Audit SYSVOL and NETLOGON for credential exposure, weak file permissions, excessive GPO delegation, and external script path abuse."
            Module   = "AD-PowerAdmin_SysvolAudit"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'SysvolAuditMenu'"
        }
    }

    $global:UnattendedJobs += @{
        'SysvolGppCpasswordCheck' = @{
            Title    = "SYSVOL GPP cpassword Check"
            Label    = "Daily scheduled check for GPP cpassword values in SYSVOL. Writes a Critical warning to the console if any are found. Controlled by the SysvolGppCpasswordAudit setting."
            Module   = "AD-PowerAdmin_SysvolAudit"
            Function = "Start-SysvolGppCpasswordCheck"
            Daily    = $true
            Command  = "Start-SysvolGppCpasswordCheck"
        }
        'SysvolFullAudit' = @{
            Title    = "SYSVOL Full Audit"
            Label    = "Run all SYSVOL security audit checks on demand. Invoke with: .\AD-PowerAdmin.ps1 -Unattended -JobName SysvolFullAudit"
            Module   = "AD-PowerAdmin_SysvolAudit"
            Function = "Start-SysvolAudit"
            Daily    = $false
            Command  = "Start-SysvolAudit"
        }
    }
}

Initialize-Module

# --- Private Helpers ---

Function Get-SysvolRoots {
    # Returns the SYSVOL and NETLOGON UNC roots for the current domain.
    $Domain = $env:USERDNSDOMAIN
    return @(
        "\\$Domain\SYSVOL\$Domain",
        "\\$Domain\NETLOGON"
    )
}

Function Get-SysvolScriptFiles {
    # Returns PSCustomObjects (FullName, Name, Extension, Length, LastWriteTime, Location)
    # for all script and configuration files under SYSVOL and NETLOGON.
    $Extensions = @('.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta', '.xml', '.ini', '.config', '.txt')
    $Files = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($Root in (Get-SysvolRoots)) {
        $Location = if ($Root -match 'NETLOGON') { 'NETLOGON' } else { 'SYSVOL' }
        Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $Extensions -contains $_.Extension.ToLower() } |
            ForEach-Object {
                $Files.Add([PSCustomObject]@{
                    FullName      = $_.FullName
                    Name          = $_.Name
                    Extension     = $_.Extension
                    Length        = $_.Length
                    LastWriteTime = $_.LastWriteTime
                    Location      = $Location
                })
            }
    }
    return $Files
}

# --- Exported Functions ---

Function Get-SysvolScriptInventory {
    <#
    .SYNOPSIS
    Enumerates all script and configuration files stored in SYSVOL and NETLOGON.

    .DESCRIPTION
    === SYSVOL Script Inventory ===
        Walks the SYSVOL and NETLOGON shares and produces a timestamped CSV report of
        every script and configuration file found. File types inventoried:
        .ps1 .bat .cmd .vbs .js .wsf .hta .xml .ini .config .txt

        The inventory provides a baseline of what is present. Review files with old
        LastWriteTime values that may be orphaned, and any unexpected file types.

    .EXAMPLE
    Get-SysvolScriptInventory

    .NOTES
    #>
    [CmdletBinding()]
    Param([switch]$Force, [string]$ReportFile = '')

    $IsConsolidated = (-not [string]::IsNullOrWhiteSpace($ReportFile))
    if (-not $IsConsolidated) {
        $ReportFile = "$global:ReportsPath\SysvolAudit-Inventory_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        if (Test-Path -LiteralPath $ReportFile) { Remove-Item -LiteralPath $ReportFile -Force -ErrorAction SilentlyContinue }
    }

    $Files = Get-SysvolScriptFiles
    if ($Files.Count -eq 0) {
        Write-Host "[INFO] No script or configuration files found in SYSVOL or NETLOGON."
        Show-AuditReport -Data @() -Title "SYSVOL Script Inventory" `
            -HeaderFields @('FullName','Extension','SizeBytes','LastWriteTime','Location') `
            -DetailFields @() -RiskField '' -OutputFile $ReportFile
        return $Files
    }

    $Results = $Files | ForEach-Object {
        [PSCustomObject]@{
            FullName      = $_.FullName
            FileName      = $_.Name
            Extension     = $_.Extension
            SizeBytes     = $_.Length
            LastWriteTime = $_.LastWriteTime
            Location      = $_.Location
        }
    }

    Write-Host "[INFO] Found $($Results.Count) files in SYSVOL and NETLOGON."
    Export-AdPowerAdminData -Data $Results -ReportName "SysvolAudit-Inventory" -Force:$Force
    Show-AuditReport -Data $Results -Title "SYSVOL Script Inventory" `
        -HeaderFields @('FullName','Extension','SizeBytes','LastWriteTime','Location') `
        -DetailFields @() -RiskField '' -OutputFile $ReportFile
    return $Results
}

Function Search-SysvolScriptRisks {
    <#
    .SYNOPSIS
    Scans SYSVOL and NETLOGON scripts for embedded credentials and high-risk execution patterns.

    .DESCRIPTION
    === SYSVOL Credential & Risk Pattern Scan ===
        Searches all script and configuration files in SYSVOL and NETLOGON for patterns
        associated with embedded credentials (passwords, tokens, API keys) and high-risk
        execution behavior (ExecutionPolicy Bypass, IEX, WebClient downloads, encoded commands,
        RunAs, net use with credentials, SQL authentication flags).

        Critical patterns are matched using regex. High patterns are matched as literal strings.
        Findings are classified as Critical or High risk based on the matched pattern.

        Review the LineContent column for each finding. Pattern matches may include comment
        lines, documentation strings, or variable names that do not represent real credentials.
        All matches are exported for human triage -- no automatic filtering is applied.

    .EXAMPLE
    Search-SysvolScriptRisks

    .NOTES
    #>
    [CmdletBinding()]
    Param([switch]$Force, [string]$ReportFile = '')

    $IsConsolidated = (-not [string]::IsNullOrWhiteSpace($ReportFile))
    if (-not $IsConsolidated) {
        $ReportFile = "$global:ReportsPath\SysvolAudit-ScriptRisks_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        if (Test-Path -LiteralPath $ReportFile) { Remove-Item -LiteralPath $ReportFile -Force -ErrorAction SilentlyContinue }
    }

    $CriticalPatterns = @(
        'cpassword\s*=\s*"[^"]+',
        '(?<!c)password\s*=',
        'passwd\s*=',
        'pwd\s*=',
        '/user:',
        '-Password\s',
        'New-Object PSCredential',
        '-P\s'
    )

    $HighPatterns = @(
        'credential',
        'creds',
        'secret',
        'token',
        'apikey',
        'api_key',
        'client_secret',
        'net use',
        'runas',
        'sqlcmd',
        'IEX',
        'Invoke-Expression',
        'DownloadString',
        'WebClient',
        'Invoke-WebRequest',
        'ExecutionPolicy Bypass',
        '-EncodedCommand'
    )

    $Files = Get-SysvolScriptFiles
    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($File in $Files) {
        foreach ($Pattern in $CriticalPatterns) {
            Select-String -Path $File.FullName -Pattern $Pattern -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $Results.Add([PSCustomObject]@{
                        FilePath       = $_.Path
                        LineNumber     = $_.LineNumber
                        LineContent    = $_.Line.Trim()
                        MatchedPattern = $Pattern
                        RiskLevel      = 'Critical'
                        Location       = $File.Location
                    })
                }
        }
        foreach ($Pattern in $HighPatterns) {
            Select-String -Path $File.FullName -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue |
                ForEach-Object {
                    $Results.Add([PSCustomObject]@{
                        FilePath       = $_.Path
                        LineNumber     = $_.LineNumber
                        LineContent    = $_.Line.Trim()
                        MatchedPattern = $Pattern
                        RiskLevel      = 'High'
                        Location       = $File.Location
                    })
                }
        }
    }

    if ($Results.Count -eq 0) {
        Write-Host "[INFO] No credential or risk patterns found in SYSVOL or NETLOGON scripts."
        Show-AuditReport -Data @() -Title "SYSVOL Credential & Risk Pattern Scan" `
            -HeaderFields @('FilePath','Location','LineNumber','MatchedPattern','RiskLevel') `
            -DetailFields @('LineContent') -OutputFile $ReportFile
        return $Results
    }

    $CritCount = @($Results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $HighCount  = @($Results | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    Write-Host "[INFO] Credential & risk pattern scan complete. Critical: $CritCount  High: $HighCount"
    Write-Host "[NOTE] Review LineContent for each finding -- matches may include comments or documentation."
    Export-AdPowerAdminData -Data $Results -ReportName "SysvolAudit-ScriptRisks" -Force:$Force
    Show-AuditReport -Data $Results -Title "SYSVOL Credential & Risk Pattern Scan" `
        -HeaderFields @('FilePath','Location','LineNumber','MatchedPattern','RiskLevel') `
        -DetailFields @('LineContent') -OutputFile $ReportFile
    return $Results
}

Function Search-SysvolGppCpassword {
    <#
    .SYNOPSIS
    Searches Group Policy Preference XML files in SYSVOL for cpassword values.

    .DESCRIPTION
    === GPP cpassword Scan ===
        Targets the six known GPP file types that may contain cpassword attributes:
        Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml

        Findings are classified based on whether the cpassword attribute contains a value:
          Critical -- cpassword attribute is present with a non-empty encrypted value.
                      The AES-256 decryption key was publicly disclosed (MS14-025).
                      Treat as plaintext credential until password is rotated and file removed.
          Info     -- cpassword attribute is present but the value is empty.
                      Not currently exploitable, but the file should be reviewed and cleaned up.

        A ValuePresent field in the report indicates whether an actual password was found.

        Common locations:
        SYSVOL\<domain>\Policies\{GUID}\Machine\Preferences\
        SYSVOL\<domain>\Policies\{GUID}\User\Preferences\

    .EXAMPLE
    Search-SysvolGppCpassword

    .NOTES
    #>
    [CmdletBinding()]
    Param([switch]$Force, [string]$ReportFile = '')

    $IsConsolidated = (-not [string]::IsNullOrWhiteSpace($ReportFile))
    if (-not $IsConsolidated) {
        $ReportFile = "$global:ReportsPath\SysvolAudit-GppCpassword_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        if (Test-Path -LiteralPath $ReportFile) { Remove-Item -LiteralPath $ReportFile -Force -ErrorAction SilentlyContinue }
    }

    $Domain     = $env:USERDNSDOMAIN
    $SysvolRoot = "\\$Domain\SYSVOL\$Domain"
    $GppFiles   = @('Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Drives.xml', 'Printers.xml')
    $Results    = [System.Collections.Generic.List[PSCustomObject]]::new()

    $Found = Get-ChildItem -Path $SysvolRoot -Recurse -Include $GppFiles -File -ErrorAction SilentlyContinue
    if (-not $Found) {
        Write-Host "[INFO] No GPP XML files found in SYSVOL."
        return $Results
    }

    foreach ($File in $Found) {
        Select-String -Path $File.FullName -Pattern 'cpassword' -SimpleMatch -ErrorAction SilentlyContinue |
            ForEach-Object {
                $CpassValue   = [regex]::Match($_.Line, 'cpassword="([^"]*)"').Groups[1].Value
                $ValuePresent = ($CpassValue.Length -gt 0)
                $RiskLevel    = if ($ValuePresent) { 'Critical' } else { 'Info' }
                $Results.Add([PSCustomObject]@{
                    FilePath     = $_.Path
                    GppFileType  = $File.Name
                    LineNumber   = $_.LineNumber
                    LineContent  = $_.Line.Trim()
                    ValuePresent = $ValuePresent
                    RiskLevel    = $RiskLevel
                })
            }
    }

    if ($Results.Count -eq 0) {
        Write-Host "[INFO] No cpassword attributes found in SYSVOL GPP files."
        Show-AuditReport -Data @() -Title "GPP cpassword Scan" `
            -HeaderFields @('FilePath','GppFileType','LineNumber','ValuePresent') `
            -DetailFields @('LineContent') -OutputFile $ReportFile
        return $Results
    }

    $CritCount = @($Results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $InfoCount  = @($Results | Where-Object { $_.RiskLevel -eq 'Info'     }).Count
    if ($CritCount -gt 0) {
        Write-Host "[CRITICAL] $CritCount cpassword finding(s) with non-empty values. Treat as plaintext credential exposure and remediate immediately."
    }
    if ($InfoCount -gt 0) {
        Write-Host "[INFO] $InfoCount cpassword attribute(s) found with empty values -- not currently exploitable but should be cleaned up."
    }
    Export-AdPowerAdminData -Data $Results -ReportName "SysvolAudit-GppCpassword" -Force:$Force
    Show-AuditReport -Data $Results -Title "GPP cpassword Scan" `
        -HeaderFields @('FilePath','GppFileType','LineNumber','ValuePresent') `
        -DetailFields @('LineContent') -OutputFile $ReportFile
    return $Results
}

Function Search-SysvolPermissions {
    <#
    .SYNOPSIS
    Audits SYSVOL file and folder permissions for excessive write access granted to broad principals.

    .DESCRIPTION
    === SYSVOL Permission Scan ===
        Checks all files and folders under SYSVOL for write, modify, or FullControl rights
        granted to broad or non-administrative principals:
          Everyone, Authenticated Users, Domain Users, Domain Computers, BUILTIN\Users

        Risk classification:
          Critical -- script files (.ps1 .bat .cmd .vbs .js .wsf .hta) writable by Everyone,
                      Authenticated Users, or Domain Users
          High     -- other write-access on script files, or any folder writable by risky principals
          Medium   -- write access on non-script files (.xml .ini .config .txt)

    .EXAMPLE
    Search-SysvolPermissions

    .NOTES
    #>
    [CmdletBinding()]
    Param([switch]$Force, [string]$ReportFile = '')

    $IsConsolidated = (-not [string]::IsNullOrWhiteSpace($ReportFile))
    if (-not $IsConsolidated) {
        $ReportFile = "$global:ReportsPath\SysvolAudit-Permissions_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        if (Test-Path -LiteralPath $ReportFile) { Remove-Item -LiteralPath $ReportFile -Force -ErrorAction SilentlyContinue }
    }

    $Domain     = $env:USERDNSDOMAIN
    $SysvolRoot = "\\$Domain\SYSVOL\$Domain"

    $ScriptExts       = @('.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta')
    $RiskyPrincipals  = @('Everyone', 'Authenticated Users', 'Domain Users', 'Domain Computers', 'BUILTIN\Users')
    $BroadPrincipals  = @('Everyone', 'Authenticated Users', 'Domain Users')
    $RiskyRightsRegex = 'Write|Modify|FullControl|CreateFiles|CreateDirectories|ChangePermissions|TakeOwnership'

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $AllObjects  = @()
    $AllObjects += Get-ChildItem -Path $SysvolRoot -Recurse -File      -ErrorAction SilentlyContinue
    $AllObjects += Get-ChildItem -Path $SysvolRoot -Recurse -Directory -ErrorAction SilentlyContinue

    foreach ($Obj in $AllObjects) {
        $ObjectType = if ($Obj.PSIsContainer) { 'Folder' } else { 'File' }
        $Ext        = if (-not $Obj.PSIsContainer) { $Obj.Extension.ToLower() } else { '' }

        try {
            $Acl = Get-Acl -Path $Obj.FullName -ErrorAction Stop
        } catch {
            continue
        }

        foreach ($Ace in $Acl.Access) {
            $Identity = $Ace.IdentityReference.Value
            $Rights   = $Ace.FileSystemRights.ToString()

            $IsRisky = $false
            foreach ($Principal in $RiskyPrincipals) {
                if ($Identity -like "*$Principal*") { $IsRisky = $true; break }
            }
            if (-not $IsRisky) { continue }
            if ($Rights -notmatch $RiskyRightsRegex) { continue }

            $IsBroad = $false
            foreach ($Principal in $BroadPrincipals) {
                if ($Identity -like "*$Principal*") { $IsBroad = $true; break }
            }

            $RiskLevel = if ($ObjectType -eq 'Folder') {
                'High'
            } elseif ($ScriptExts -contains $Ext) {
                if ($IsBroad) { 'Critical' } else { 'High' }
            } else {
                'Medium'
            }

            $Results.Add([PSCustomObject]@{
                ObjectPath        = $Obj.FullName
                ObjectType        = $ObjectType
                Identity          = $Identity
                FileSystemRights  = $Rights
                AccessControlType = $Ace.AccessControlType.ToString()
                RiskLevel         = $RiskLevel
            })
        }
    }

    if ($Results.Count -eq 0) {
        Write-Host "[INFO] No excessive SYSVOL permissions found for risky principals."
        Show-AuditReport -Data @() -Title "SYSVOL Permission Scan" `
            -HeaderFields @('ObjectPath','ObjectType','Identity','FileSystemRights','AccessControlType') `
            -OutputFile $ReportFile
        return $Results
    }

    $CritCount = @($Results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $HighCount  = @($Results | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    $MedCount   = @($Results | Where-Object { $_.RiskLevel -eq 'Medium'   }).Count
    Write-Host "[INFO] Permission scan complete. Critical: $CritCount  High: $HighCount  Medium: $MedCount"
    Export-AdPowerAdminData -Data $Results -ReportName "SysvolAudit-Permissions" -Force:$Force
    Show-AuditReport -Data $Results -Title "SYSVOL Permission Scan" `
        -HeaderFields @('ObjectPath','ObjectType','Identity','FileSystemRights','AccessControlType') `
        -OutputFile $ReportFile
    return $Results
}

Function Get-GpoCustomRights {
    # Private helper: reads the raw AD security descriptor of a GPO object and returns a
    # human-readable string listing every Allow ACE for the specified trustee SID.
    # Used to expand the generic 'GpoCustom' label into its actual constituent rights.
    Param(
        [guid]$GpoId,
        [string]$TrusteeSid,
        [string]$TrusteeName,
        [string]$DomainDn
    )

    if ([string]::IsNullOrWhiteSpace($DomainDn)) {
        return '(domain DN unavailable; cannot read raw GPO ACL)'
    }

    # Well-known extended right GUIDs that appear in GPO security descriptors.
    $KnownExtRights = @{
        'edacfd8f-ffb3-11d1-b41d-00a0c968f939' = 'Apply Group Policy'
        'be2bb760-7f46-11d2-b9ad-00c04f79f805' = 'Update Group Policy'
        '59ba2f42-79a2-11d0-9020-00c04fc2d3cf' = 'General Information'
        'bc0ac240-79a9-11d0-9020-00c04fc2d4cf' = 'Group Membership'
        '77b5b886-944a-11d1-aebd-0000f80367c1' = 'Personal Information'
        'e45795b2-9455-11d1-aebd-0000f80367c1' = 'Email Information'
    }

    try {
        $GpoAdPath = "AD:\CN={$($GpoId.ToString().ToUpper())},CN=Policies,CN=System,$DomainDn"
        $Acl       = Get-Acl -Path $GpoAdPath -ErrorAction Stop
    } catch {
        return "(unable to read raw GPO AD ACL: $($_.Exception.Message))"
    }

    $Lines = [System.Collections.Generic.List[string]]::new()
    foreach ($Ace in $Acl.Access) {
        if ($Ace.AccessControlType.ToString() -ne 'Allow') { continue }

        # Match by SID (most reliable); fall back to name substring match for untranslatable accounts.
        $AceSidStr = ''
        try { $AceSidStr = $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch {}
        $NameMatch = $Ace.IdentityReference.Value -like "*$TrusteeName*"
        if ($AceSidStr -ne $TrusteeSid -and -not $NameMatch) { continue }

        $RightsStr  = $Ace.ActiveDirectoryRights.ToString()
        $ObjGuidStr = if ($Ace.ObjectType) { $Ace.ObjectType.ToString().ToLower() } else { '' }

        if ($ObjGuidStr -and $ObjGuidStr -ne '00000000-0000-0000-0000-000000000000') {
            $ExtName = if ($KnownExtRights.ContainsKey($ObjGuidStr)) {
                $KnownExtRights[$ObjGuidStr]
            } else {
                "attribute/right {$($Ace.ObjectType)}"
            }
            $Lines.Add("$RightsStr on [$ExtName]")
        } else {
            $Lines.Add($RightsStr)
        }
    }

    if ($Lines.Count -eq 0) {
        return '(no matching Allow ACEs found in the raw GPO AD security descriptor for this trustee)'
    }
    return ($Lines | Select-Object -Unique) -join '; '
}

Function Get-DelegationExplanation {
    # Private helper: builds VulnerabilityDetail, Impact, and Remediation text for a GPO delegation finding.
    Param(
        [string]$GpoName,
        [string]$TrusteeName,
        [string]$TrusteeType,
        [string]$Permission,
        [string]$LinkedToTier0,
        [string]$GpoStatus,
        [string]$ResolvedCustomRights = ''
    )

    $PermDesc = switch ($Permission) {
        'GpoEdit'                     { 'edit access (can modify all settings in the GPO: startup and logon script assignments, registry policy, security settings, software deployment packages, and administrative template values)' }
        'GpoEditDeleteModifySecurity' { 'full delegated control (can edit, delete, and modify the security descriptor of the GPO itself, including adding or revoking other principals'' delegations)' }
        'GpoCustom'                   {
            if ($ResolvedCustomRights) {
                "a custom permission set. The specific Active Directory rights granted to this trustee are: $ResolvedCustomRights"
            } else {
                'a non-standard custom permission set (the exact capabilities depend on the custom access mask; a custom delegation on a production GPO is itself anomalous and requires verification)'
            }
        }
        default                       { "$Permission access" }
    }

    $TierContext = switch ($LinkedToTier0) {
        'Yes'     { "This GPO is linked to the Domain Controllers OU or the domain root. Changes take effect on Domain Controllers (DC OU link) or on all domain-joined computers and users (domain root link)." }
        'No'      { "This GPO is not currently linked to the Domain Controllers OU or domain root. It applies to whatever OUs, sites, or domain scope it is linked to -- check the GPO''s Links tab in GPMC to determine scope." }
        'Unknown' { "Whether this GPO is linked to the Domain Controllers OU or domain root could not be determined during this scan. Review the Links tab in GPMC." }
        default   { "" }
    }

    $VulnerabilityDetail = "The identity '$TrusteeName' (type: $TrusteeType) holds $PermDesc on GPO '$GpoName' (GPO Status: $GpoStatus). '$TrusteeName' is outside the expected Tier-0 administrative set (Domain Admins, Enterprise Admins, SYSTEM, Group Policy Creator Owners, CREATOR OWNER). $TierContext Any account matching '$TrusteeName' can exercise this permission using GPMC or GroupPolicy PowerShell cmdlets without requiring Domain Admin rights."

    $ImpactBase = "An attacker who compromises any account satisfying '$TrusteeName' can: add or replace startup and logon scripts to execute arbitrary code on every machine in this GPO's scope; modify registry policy to install persistence or disable endpoint controls; alter security policy (e.g., disable password complexity, audit logging, or firewall rules); or add a Software Installation package pointing to a malicious MSI file. "
    $Impact = if ($LinkedToTier0 -eq 'Yes') {
        $ImpactBase + "Because this GPO applies to Domain Controllers or the full domain, any GPO modification results in code execution in SYSTEM or Domain Admin context across the entire Active Directory environment. This is a direct, single-step path to full domain compromise."
    } else {
        $ImpactBase + "Startup script modifications execute as SYSTEM on affected computers at every boot. Logon script modifications execute in the authenticated user''s context at every logon. Either path enables credential harvesting, lateral movement, or privilege escalation against accounts that authenticate to systems in this GPO''s scope."
    }

    $Remediation = "1. Open Group Policy Management Console (gpmc.msc). 2. In the left pane, expand Group Policy Objects and select '$GpoName'. 3. Click the Delegation tab in the right pane. 4. Locate the row for '$TrusteeName'. 5. If this delegation has no documented business justification: click Remove to revoke it. 6. If delegation is legitimately required: click Edit Security and reduce the permission to Read only -- never GpoEdit or GpoEditDeleteModifySecurity for non-Tier-0 identities. 7. GPO edit rights should be held exclusively by Domain Admins or Group Policy Creator Owners. 8. After revoking, run 'gpresult /r' on affected systems to confirm expected policy still applies."

    return @{
        VulnerabilityDetail = $VulnerabilityDetail
        Impact              = $Impact
        Remediation         = $Remediation
    }
}

Function Search-GpoDelegation {
    <#
    .SYNOPSIS
    Identifies GPOs with edit rights assigned to non-Tier-0 identities.

    .DESCRIPTION
    === GPO Delegation Audit ===
        Enumerates all GPOs and checks for GpoEdit, GpoEditDeleteModifySecurity, or GpoCustom
        rights assigned to identities outside the expected Tier-0 administrative set.

        Requires the GroupPolicy PowerShell module (RSAT-GPMC). If the module is unavailable,
        a warning is printed and the function returns without results.

        GPOs linked to the Domain Controllers OU or domain root are classified Critical.
        All other non-Tier-0 edit rights are classified High.

        Known safe trustees excluded from results:
        Domain Admins, Enterprise Admins, SYSTEM, NT AUTHORITY\SYSTEM,
        CREATOR OWNER, Group Policy Creator Owners, Administrator

    .EXAMPLE
    Search-GpoDelegation

    .NOTES
    #>
    [CmdletBinding()]
    Param([switch]$Force, [string]$ReportFile = '')

    $IsConsolidated = (-not [string]::IsNullOrWhiteSpace($ReportFile))
    if (-not $IsConsolidated) {
        $ReportFile = "$global:ReportsPath\SysvolAudit-GpoDelegation_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        if (Test-Path -LiteralPath $ReportFile) { Remove-Item -LiteralPath $ReportFile -Force -ErrorAction SilentlyContinue }
    }

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Warning "[WARN] GroupPolicy module not available. Install RSAT-GPMC or run from a Domain Controller."
        return
    }
    Import-Module GroupPolicy -ErrorAction Stop

    $RiskyPerms  = @('GpoEdit', 'GpoEditDeleteModifySecurity', 'GpoCustom')
    $SafeTrustees = @(
        'Domain Admins',
        'Enterprise Admins',
        'SYSTEM',
        'NT AUTHORITY\SYSTEM',
        'CREATOR OWNER',
        'Group Policy Creator Owners',
        'Administrator'
    )

    $Results    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Tier0Guids = @()
    $DomainDn   = ''

    try {
        $DomainDn    = (Get-ADDomain -ErrorAction Stop).DistinguishedName
        $DCOuDn      = "OU=Domain Controllers,$DomainDn"
        $DomainLinks = (Get-GPInheritance -Target $DomainDn -ErrorAction Stop).GpoLinks |
                       ForEach-Object { $_.GpoId.ToString().ToLower() -replace '[{}]', '' }
        $DcOuLinks   = (Get-GPInheritance -Target $DCOuDn   -ErrorAction Stop).GpoLinks |
                       ForEach-Object { $_.GpoId.ToString().ToLower() -replace '[{}]', '' }
        $Tier0Guids  = ($DomainLinks + $DcOuLinks) | Select-Object -Unique
    } catch {
        # Tier-0 link enrichment unavailable; LinkedToTier0 will be reported as Unknown.
    }

    foreach ($Gpo in (Get-GPO -All -ErrorAction SilentlyContinue)) {
        $Permissions = Get-GPPermission -Guid $Gpo.Id -All -ErrorAction SilentlyContinue
        if (-not $Permissions) { continue }

        foreach ($Perm in $Permissions) {
            if ($RiskyPerms -notcontains $Perm.Permission.ToString()) { continue }

            $TrusteeName = $Perm.Trustee.Name
            $IsSafe = $false
            foreach ($Safe in $SafeTrustees) {
                if ($TrusteeName -like "*$Safe*") { $IsSafe = $true; break }
            }
            if ($IsSafe) { continue }

            $GpoGuidStr    = $Gpo.Id.ToString().ToLower() -replace '[{}]', ''
            $LinkedToTier0 = if ($Tier0Guids.Count -gt 0) {
                if ($Tier0Guids -contains $GpoGuidStr) { 'Yes' } else { 'No' }
            } else { 'Unknown' }
            $RiskLevel = if ($LinkedToTier0 -eq 'Yes') { 'Critical' } else { 'High' }

            # For GpoCustom, resolve the actual raw AD rights before building the explanation.
            # If resolution succeeds and no write-level rights are present, this is a read-only
            # or deny-only ACE (e.g., Deny Apply Group Policy used for targeting exclusions) and
            # is not a delegation risk -- skip it. Only flag when write-level rights are confirmed
            # or when the resolution itself failed (unknown risk is treated as risky).
            $CustomRights = ''
            if ($Perm.Permission.ToString() -eq 'GpoCustom') {
                $CustomRights = Get-GpoCustomRights -GpoId $Gpo.Id `
                    -TrusteeSid $Perm.Trustee.Sid.ToString() `
                    -TrusteeName $TrusteeName `
                    -DomainDn $DomainDn

                $ResolutionSucceeded = $CustomRights -notmatch '^\('
                $HasWriteAccess      = $CustomRights -match 'Write|CreateChild|DeleteChild|DeleteTree|GenericAll|GenericWrite'
                if ($ResolutionSucceeded -and -not $HasWriteAccess) { continue }
            }

            $Expl = Get-DelegationExplanation -GpoName $Gpo.DisplayName -TrusteeName $TrusteeName `
                -TrusteeType $Perm.Trustee.SidType.ToString() -Permission $Perm.Permission.ToString() `
                -LinkedToTier0 $LinkedToTier0 -GpoStatus $Gpo.GpoStatus.ToString() `
                -ResolvedCustomRights $CustomRights

            $Results.Add([PSCustomObject]@{
                GPOName             = $Gpo.DisplayName
                GPOGuid             = $Gpo.Id.ToString()
                GPOStatus           = $Gpo.GpoStatus.ToString()
                Trustee             = $TrusteeName
                TrusteeType         = $Perm.Trustee.SidType.ToString()
                TrusteeSid          = $Perm.Trustee.Sid.ToString()
                Permission          = $Perm.Permission.ToString()
                CustomRights        = $CustomRights
                LinkedToTier0       = $LinkedToTier0
                RiskLevel           = $RiskLevel
                VulnerabilityDetail = $Expl.VulnerabilityDetail
                Impact              = $Expl.Impact
                Remediation         = $Expl.Remediation
            })
        }
    }

    if ($Results.Count -eq 0) {
        Write-Host "[INFO] No excessive GPO delegation found."
        Show-AuditReport -Data @() -Title "GPO Delegation Audit" `
            -HeaderFields @('GPOName','GPOGuid','GPOStatus','Trustee','TrusteeType','Permission','CustomRights','LinkedToTier0') `
            -DetailFields @('VulnerabilityDetail','Impact','Remediation') -OutputFile $ReportFile
        return $Results
    }

    $CritCount = @($Results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $HighCount  = @($Results | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    Write-Host "[INFO] GPO delegation audit complete. Critical: $CritCount  High: $HighCount"
    Export-AdPowerAdminData -Data $Results -ReportName "SysvolAudit-GpoDelegation" -Force:$Force
    Show-AuditReport -Data $Results -Title "GPO Delegation Audit" `
        -HeaderFields @('GPOName','GPOGuid','GPOStatus','Trustee','TrusteeType','Permission','CustomRights','LinkedToTier0') `
        -DetailFields @('VulnerabilityDetail','Impact','Remediation') -OutputFile $ReportFile
    return $Results
}

Function Get-AceExplanation {
    # Private helper: builds contextual security explanation fields for a single ACE finding.
    Param(
        [string]$TargetPath,
        [string]$ObjectType,
        [bool]$IsExec,
        [string]$Identity,
        [string]$Rights
    )

    $FileName = [System.IO.Path]::GetFileName($TargetPath)
    $Ext      = [System.IO.Path]::GetExtension($TargetPath).ToLower()

    $WhoDesc = switch -Wildcard ($Identity) {
        '*Everyone*'            { 'any user, including unauthenticated guests where guest access is permitted, or any authenticated domain user in standard configurations' }
        '*Authenticated Users*' { 'any user with a valid domain credential, including standard users, service accounts, and contractor or temporary accounts' }
        '*Domain Users*'        { 'every standard domain user account across the entire enterprise' }
        '*Domain Computers*'    { 'every domain-joined machine account, exploitable via code execution on any compromised domain host' }
        '*BUILTIN\Users*'       { 'all local user accounts and domain users who have authenticated to this system' }
        default                 { "any member of the group or account '$Identity'" }
    }

    $AccessRequired = switch -Wildcard ($Identity) {
        '*Everyone*'            { 'No authentication required in guest-enabled environments; any domain credential in standard AD configurations' }
        '*Authenticated Users*' { 'Any valid domain credential -- standard domain user, service account, or contractor account' }
        '*Domain Users*'        { 'Any standard domain user account (default group for all AD users)' }
        '*Domain Computers*'    { 'Code execution on any domain-joined computer (e.g., via phishing, local privilege escalation, or lateral movement)' }
        '*BUILTIN\Users*'       { 'Any user with interactive or remote logon access to this specific host' }
        default                 { "Membership in '$Identity', or compromise of any account with that membership" }
    }

    $RightsDesc = if ($Rights -match 'FullControl') {
        'full control (read, write, modify, delete, change permissions, and take ownership)'
    } elseif ($Rights -match 'Modify') {
        'modify rights (read, write, execute, and delete the file or its contents)'
    } elseif ($Rights -match 'ChangePermissions|TakeOwnership') {
        'permission management rights (ability to alter the ACL, including granting themselves or others full control)'
    } elseif ($Rights -match 'Write|CreateFiles|CreateDirectories') {
        'write rights (create or overwrite files within the target location)'
    } else {
        "elevated file system rights ($Rights)"
    }

    if ($ObjectType -eq 'File') {
        $FileType = switch ($Ext) {
            '.exe' { 'executable binary' }
            '.msi' { 'installer package' }
            '.dll' { 'dynamic-link library' }
            '.com' { 'executable' }
            '.ps1' { 'PowerShell script' }
            '.bat' { 'batch script' }
            '.cmd' { 'command script' }
            '.vbs' { 'VBScript' }
            '.js'  { 'JScript file' }
            '.wsf' { 'Windows Script File' }
            '.hta' { 'HTML Application (runs with elevated script trust)' }
            default { 'configuration file' }
        }
        if ($IsExec) {
            $SecurityImpact = "$Identity holds $RightsDesc on the $FileType '$FileName'. Because this file is referenced by a GPO, it executes automatically on target machines during startup or logon. An attacker who can write to this file can replace it with a malicious payload. Startup scripts run as SYSTEM; logon scripts run as the authenticated user. Either context allows privilege escalation, credential harvesting, or persistent backdoor installation across every machine affected by the GPO."
            $ExploitScenario = "Step 1 -- Attacker obtains any credential satisfying '$Identity' (requires $AccessRequired). Step 2 -- Attacker overwrites '$FileName' at '$TargetPath' with a malicious $FileType. Step 3 -- On next machine reboot or user logon, the GPO executes the attacker's payload in a privileged context (SYSTEM for startup, user context for logon). Step 4 -- Attacker achieves code execution without ever touching the GPO itself, bypassing GPMC delegation controls entirely."
        } else {
            $SecurityImpact = "$Identity holds $RightsDesc on '$FileName'. If this configuration file controls script paths, software sources, download URLs, or security policy values consumed by a GPO or startup process, an attacker can tamper with it to redirect execution to attacker-controlled resources, inject malicious commands, or disable protective controls."
            $ExploitScenario = "Step 1 -- Attacker obtains any credential satisfying '$Identity' (requires $AccessRequired). Step 2 -- Attacker modifies '$FileName' to redirect a path, inject a command, or alter a value the GPO or consuming process trusts. Step 3 -- The modified configuration is processed during the next GPO application cycle or startup, causing unintended behavior in the attacker's favor."
        }
    } else {
        $SecurityImpact = "$Identity holds $RightsDesc on the directory '$TargetPath'. Write access to a parent directory allows an attacker to replace any file within it, add new malicious files alongside legitimate ones, or delete existing scripts to cause denial of service. If any file in this directory is executed by a GPO startup script, logon script, scheduled task, or software deployment policy, the attacker can introduce code that runs in a privileged execution context."
        $ExploitScenario = "Step 1 -- Attacker obtains any credential satisfying '$Identity' (requires $AccessRequired). Step 2 -- Attacker replaces a legitimate script, binary, or installer in '$TargetPath' with a malicious version (or creates a new file with an expected name). Step 3 -- The GPO or startup process executes the attacker's file at the next application cycle. Because write access to the directory is sufficient to replace its contents, an attacker does not need modify rights on the individual files -- directory write access alone is the exploitable condition."
    }

    $LeastPrivDev = if ($ObjectType -eq 'File') {
        "GPO-referenced scripts and binaries must be writable only by Domain Admins or designated GPO administrators. The set of principals who can modify a GPO-executed file should be a strict subset of those who can edit the GPO itself. Granting $RightsDesc to '$Identity' creates an indirect privilege escalation path: an attacker can achieve GPO-level code execution without holding any GPO edit rights in GPMC, bypassing all GPO delegation controls and violating the principle of least privilege at the GPO execution boundary."
    } else {
        "Directories containing GPO-referenced content must restrict write access to Domain Admins and designated software distribution administrators. Granting $RightsDesc to '$Identity' means the effective security boundary around GPO-executed code is the directory ACL, not the GPMC permission model. Any principal with write access to this directory has de-facto ability to influence what code the GPO runs, regardless of whether they appear in any GPO delegation report."
    }

    return @{
        SecurityImpact    = $SecurityImpact
        ExploitScenario   = $ExploitScenario
        AccessRequired    = $AccessRequired
        LeastPrivDev      = $LeastPrivDev
    }
}

Function Search-GpoExternalScriptPaths {
    <#
    .SYNOPSIS
    Identifies GPO script references pointing to UNC paths outside SYSVOL and NETLOGON.

    .DESCRIPTION
    === External Script Path Review ===
        Exports all GPO definitions as XML to a temporary directory under ReportsPath,
        then searches the XML for UNC path references that do not resolve to SYSVOL or
        NETLOGON. External paths may reside on servers with weaker or less-monitored
        access controls, or reference decommissioned servers whose DNS names are reusable.

        Risk classification:
          High   -- UNC path server does not match the domain FQDN (truly external server).
                    These paths reference infrastructure outside the domain and warrant prompt review.
          Medium -- UNC path server matches the domain FQDN (e.g., a domain DFS namespace).
                    These paths are on the domain but outside SYSVOL and NETLOGON.

        A RiskLevel field is included in every output row.

        The temporary XML directory is always removed after parsing (try/finally).

        Requires the GroupPolicy PowerShell module (RSAT-GPMC).

    .EXAMPLE
    Search-GpoExternalScriptPaths

    .NOTES
    #>
    [CmdletBinding()]
    Param([switch]$Force, [string]$ReportFile = '')

    $IsConsolidated = (-not [string]::IsNullOrWhiteSpace($ReportFile))
    if (-not $IsConsolidated) {
        $ReportFile = "$global:ReportsPath\SysvolAudit-ExternalPaths_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
        if (Test-Path -LiteralPath $ReportFile) { Remove-Item -LiteralPath $ReportFile -Force -ErrorAction SilentlyContinue }
    }

    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Warning "[WARN] GroupPolicy module not available. Install RSAT-GPMC or run from a Domain Controller."
        return
    }
    Import-Module GroupPolicy -ErrorAction Stop

    $Domain  = $env:USERDNSDOMAIN.ToLower()
    $TempDir = "$global:ReportsPath\GpoXmlTemp_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

        # Case-insensitive comparer avoids lookup failures when the path returned by
        # Get-ChildItem differs in case from the string used to create the file.
        $GpoMap = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($Gpo in (Get-GPO -All -ErrorAction SilentlyContinue)) {
            $SafeName = $Gpo.DisplayName -replace '[\\/:*?"<>|]', '_'
            $OutFile  = "$TempDir\$($Gpo.Id)_$SafeName.xml"
            Get-GPOReport -Guid $Gpo.Id -ReportType Xml -Path $OutFile -ErrorAction SilentlyContinue
            $GpoMap[$OutFile] = @{ Name = $Gpo.DisplayName; Guid = $Gpo.Id.ToString() }
        }

        $GuidFilePattern = '^([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})_(.+)$'

        foreach ($XmlFile in (Get-ChildItem -Path $TempDir -Filter '*.xml' -File -ErrorAction SilentlyContinue)) {
            $GpoInfo = $GpoMap[$XmlFile.FullName]
            # Fallback: parse the GUID and sanitized display name separately from the filename.
            # The filename format is {guid}_{safename} so both components are recoverable
            # without conflating them into a single field.
            $GpoName = if ($GpoInfo) { $GpoInfo.Name } elseif ($XmlFile.BaseName -match $GuidFilePattern) { $Matches[2] } else { $XmlFile.BaseName }
            $GpoGuid = if ($GpoInfo) { $GpoInfo.Guid } elseif ($XmlFile.BaseName -match $GuidFilePattern) { $Matches[1] } else { '' }

            Select-String -Path $XmlFile.FullName -Pattern '\\\\' -ErrorAction SilentlyContinue |
                Where-Object { $_.Line -notmatch '\\SYSVOL\\' -and $_.Line -notmatch '\\NETLOGON' } |
                ForEach-Object {
                    $Line = $_.Line.Trim()

                    $ScriptType = 'Unknown'
                    if     ($Line -match '\.ps1') { $ScriptType = 'PowerShell' }
                    elseif ($Line -match '\.bat|\.cmd') { $ScriptType = 'Batch' }
                    elseif ($Line -match '\.vbs') { $ScriptType = 'VBScript' }
                    elseif ($Line -match '\.exe') { $ScriptType = 'Executable' }
                    elseif ($Line -match '\.msi') { $ScriptType = 'Installer' }

                    # Drive-map GPO settings use a path= XML attribute for the share path and carry no
                    # script extension. Mounting a shared folder is not a script execution risk.
                    if ($ScriptType -eq 'Unknown' -and ($Line -match 'path="\\\\' -or $Line -match "path='\\\\")) { return }

                    $UncMatch        = [regex]::Match($Line, '\\\\[^\s<>"]+')
                    $ReferencedShare = if ($UncMatch.Success) { $UncMatch.Value.TrimEnd('\') } else { '' }

                    $ServerPart = [regex]::Match($ReferencedShare, '\\\\([^\\]+)').Groups[1].Value.ToLower()
                    $RiskLevel  = if ($ServerPart -and ($ServerPart -ne $Domain)) { 'High' } else { 'Medium' }

                    $Results.Add([PSCustomObject]@{
                        GPOName         = $GpoName
                        GPOGuid         = $GpoGuid
                        ScriptType      = $ScriptType
                        IsExternal      = $true
                        ReferencedShare = $ReferencedShare
                        RiskLevel       = $RiskLevel
                        LineContent     = $Line
                    })
                }
        }
    } finally {
        if (Test-Path $TempDir) {
            Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Build a lookup map from each distinct UNC path back to the GPO(s) that reference it.
    # Multiple GPOs can reference the same external path; all are recorded.
    $PathToGpoMap = @{}
    foreach ($Ref in $Results) {
        $Key = $Ref.ReferencedShare.ToLower()
        if ([string]::IsNullOrWhiteSpace($Key)) { continue }
        if (-not $PathToGpoMap.ContainsKey($Key)) {
            $PathToGpoMap[$Key] = [System.Collections.Generic.List[PSCustomObject]]::new()
        }
        $PathToGpoMap[$Key].Add([PSCustomObject]@{
            GPOName    = $Ref.GPOName
            GPOGuid    = $Ref.GPOGuid
            ScriptType = $Ref.ScriptType
        })
    }

    $PermResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($Results.Count -eq 0) {
        Write-Host "[INFO] No external GPO script references found."
        Export-AdPowerAdminData -Data $Results     -ReportName "SysvolAudit-ExternalPaths"           -Force:$Force
        Export-AdPowerAdminData -Data @()          -ReportName "SysvolAudit-ExternalPathPermissions" -Force:$Force
        Show-AuditReport -Data $Results -Title "External GPO Script Paths" `
            -HeaderFields @('GPOName','GPOGuid','ScriptType','ReferencedShare') `
            -DetailFields @('LineContent') -OutputFile $ReportFile
        Show-AuditReport -Data @() -Title "External Path Permissions" `
            -HeaderFields @('ExternalPath','ObjectType','IdentitiesAndRights','SourceGPOName','GPOSetting') `
            -DetailFields @('SecurityImpact','ExploitScenario','AccessRequired','LeastPrivDev') -OutputFile $ReportFile
        return @{ PathRefs = $Results; PermFindings = @() }
    }

    $HighCount   = @($Results | Where-Object { $_.RiskLevel -eq 'High'   }).Count
    $MediumCount = @($Results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    Write-Host "[INFO] External script path review complete. High: $HighCount (external server)  Medium: $MediumCount (domain share)"
    Export-AdPowerAdminData -Data $Results -ReportName "SysvolAudit-ExternalPaths" -Force:$Force

    # Evaluate ACLs on every distinct external path and record individual ACE rows.
    $ExecExts        = @('.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta', '.exe', '.msi', '.dll', '.com')
    $RiskyPrincipals = @('Everyone', 'Authenticated Users', 'Domain Users', 'Domain Computers', 'BUILTIN\Users')
    $RiskyRightsRx   = 'Write|Modify|FullControl|CreateFiles|CreateDirectories|ChangePermissions|TakeOwnership'

    $CheckedPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Ref in $Results) {
        $TargetPath = $Ref.ReferencedShare
        if ([string]::IsNullOrWhiteSpace($TargetPath)) { continue }
        if (-not $CheckedPaths.Add($TargetPath))       { continue }

        # Resolve GPO traceability: which GPO(s) reference this path, and in what capacity.
        $GpoRefs       = if ($PathToGpoMap.ContainsKey($TargetPath.ToLower())) { $PathToGpoMap[$TargetPath.ToLower()] } else { @() }
        $SrcGpoName    = ($GpoRefs | ForEach-Object { $_.GPOName }    | Select-Object -Unique) -join '; '
        $SrcGpoGuid    = ($GpoRefs | ForEach-Object { $_.GPOGuid }    | Select-Object -Unique) -join '; '
        $SrcGpoSetting = ($GpoRefs | ForEach-Object { "$($_.ScriptType) Script Reference" } | Select-Object -Unique) -join ', '

        if (-not (Test-Path -LiteralPath $TargetPath -ErrorAction SilentlyContinue)) {
            $PermResults.Add([PSCustomObject]@{
                ExternalPath      = $TargetPath
                ObjectType        = 'Unknown'
                Identity          = 'N/A'
                FileSystemRights  = 'N/A'
                AccessControlType = 'N/A'
                RiskLevel         = 'Info'
                SourceGPOName     = $SrcGpoName
                SourceGPOGuid     = $SrcGpoGuid
                GPOSetting        = $SrcGpoSetting
                SecurityImpact    = 'Path could not be reached from the scanning host. If the server is decommissioned, its DNS name may be re-registerable by an attacker (DNS tombstoning), allowing them to host a malicious share at the expected path.'
                ExploitScenario   = 'If the referenced server is offline or decommissioned, an attacker can register a new machine using the same hostname, host a share at the expected path, and serve a malicious script to any GPO execution cycle that requests it. The GPO has no way to verify that the server is the original legitimate host.'
                AccessRequired    = 'Ability to register a DNS hostname matching the original server (requires a domain computer account or DNS record creation rights).'
                LeastPrivDev      = 'GPO script paths should always resolve to active, monitored infrastructure. A reference to an offline or decommissioned server is an orphaned attack surface that bypasses all access control on the share because the original ACLs no longer exist.'
                Note              = 'Path not reachable from this host'
            })
            continue
        }

        $IsFile     = (Get-Item -LiteralPath $TargetPath -ErrorAction SilentlyContinue) -is [System.IO.FileInfo]
        $ObjectType = if ($IsFile) { 'File' } else { 'Directory' }
        $Ext        = if ($IsFile) { [System.IO.Path]::GetExtension($TargetPath).ToLower() } else { '' }
        $IsExec     = $ExecExts -contains $Ext

        try {
            $Acl = Get-Acl -LiteralPath $TargetPath -ErrorAction Stop
        } catch {
            continue
        }

        foreach ($Ace in $Acl.Access) {
            if ($Ace.AccessControlType -ne 'Allow') { continue }
            $Identity = $Ace.IdentityReference.Value
            $Rights   = $Ace.FileSystemRights.ToString()

            $PrincipalMatch = $false
            foreach ($P in $RiskyPrincipals) {
                if ($Identity -like "*$P*") { $PrincipalMatch = $true; break }
            }
            if (-not $PrincipalMatch)             { continue }
            if ($Rights -notmatch $RiskyRightsRx) { continue }

            if ($IsExec -and $IsFile -and ($Identity -like '*Everyone*' -or $Identity -like '*Authenticated Users*' -or $Identity -like '*Domain Users*')) {
                $AceRisk = 'Critical'
            } elseif ($IsExec -or (-not $IsFile)) {
                $AceRisk = 'High'
            } else {
                $AceRisk = 'Medium'
            }

            $Expl = Get-AceExplanation -TargetPath $TargetPath -ObjectType $ObjectType -IsExec $IsExec -Identity $Identity -Rights $Rights

            $PermResults.Add([PSCustomObject]@{
                ExternalPath      = $TargetPath
                ObjectType        = $ObjectType
                Identity          = $Identity
                FileSystemRights  = $Rights
                AccessControlType = $Ace.AccessControlType.ToString()
                RiskLevel         = $AceRisk
                SourceGPOName     = $SrcGpoName
                SourceGPOGuid     = $SrcGpoGuid
                GPOSetting        = $SrcGpoSetting
                SecurityImpact    = $Expl.SecurityImpact
                ExploitScenario   = $Expl.ExploitScenario
                AccessRequired    = $Expl.AccessRequired
                LeastPrivDev      = $Expl.LeastPrivDev
                Note              = ''
            })
        }
    }

    # Consolidate individual ACE rows into one grouped record per path.
    # The CSV export retains all individual ACE rows for forensic completeness.
    # The terminal report shows the grouped view: each path once, with all identities summarised.
    $SeverityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Info' = 3 }
    $GroupedPermResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $PermResults | Group-Object -Property ExternalPath | ForEach-Object {
        $Group    = $_.Group
        $TopEntry = $Group | Sort-Object { $SeverityOrder[$_.RiskLevel] } | Select-Object -First 1
        $IdentitySummary = ($Group | ForEach-Object {
            "$($_.Identity): $($_.FileSystemRights) [$($_.RiskLevel)]"
        }) -join ' | '
        $GroupedPermResults.Add([PSCustomObject]@{
            ExternalPath        = $_.Name
            ObjectType          = $TopEntry.ObjectType
            RiskLevel           = $TopEntry.RiskLevel
            IdentitiesAndRights = $IdentitySummary
            SourceGPOName       = $TopEntry.SourceGPOName
            SourceGPOGuid       = $TopEntry.SourceGPOGuid
            GPOSetting          = $TopEntry.GPOSetting
            SecurityImpact      = $TopEntry.SecurityImpact
            ExploitScenario     = $TopEntry.ExploitScenario
            AccessRequired      = $TopEntry.AccessRequired
            LeastPrivDev        = $TopEntry.LeastPrivDev
            Note                = $TopEntry.Note
        })
    }

    if ($GroupedPermResults.Count -gt 0) {
        $PermCritCount = @($GroupedPermResults | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
        $PermHighCount = @($GroupedPermResults | Where-Object { $_.RiskLevel -eq 'High'     }).Count
        Write-Host "[INFO] External path permission check complete. $PermCritCount Critical path(s), $PermHighCount High path(s)."
    } else {
        Write-Host "[INFO] External path permission check complete. No risky ACEs found."
    }

    # Export individual ACE rows to CSV (forensic record); grouped data used for terminal display.
    Export-AdPowerAdminData -Data $PermResults        -ReportName "SysvolAudit-ExternalPathPermissions" -Force:$Force

    Show-AuditReport -Data $Results -Title "External GPO Script Paths" `
        -HeaderFields @('GPOName','GPOGuid','ScriptType','ReferencedShare') `
        -DetailFields @('LineContent') -OutputFile $ReportFile
    Show-AuditReport -Data $GroupedPermResults -Title "External Path Permissions" `
        -HeaderFields @('ExternalPath','ObjectType','IdentitiesAndRights','SourceGPOName','SourceGPOGuid','GPOSetting','Note') `
        -DetailFields @('SecurityImpact','ExploitScenario','AccessRequired','LeastPrivDev') -OutputFile $ReportFile

    return @{ PathRefs = $Results; PermFindings = $GroupedPermResults }
}

Function Start-SysvolAudit {
    <#
    .SYNOPSIS
    Runs all six SYSVOL audit checks in sequence and prints a findings summary.

    .DESCRIPTION
    === Full SYSVOL Audit ===
        Runs all six SYSVOL audit checks in sequence:
          1. Script Inventory
          2. Secret Scan
          3. GPP cpassword Scan
          4. Permission Scan
          5. GPO Delegation Audit
          6. External Script Path Review

        Each check exports its own timestamped CSV to the Reports directory.
        After all checks complete, a summary table is printed to the console.

    .EXAMPLE
    Start-SysvolAudit

    .NOTES
    #>

    $AuditReportFile = "$global:ReportsPath\SysvolAudit-FullReport_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
    if (Test-Path -LiteralPath $AuditReportFile) { Remove-Item -LiteralPath $AuditReportFile -Force -ErrorAction SilentlyContinue }
    $AuditHeader = @(
        "AD-PowerAdmin SYSVOL Security Audit",
        "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        ('=' * 82),
        ""
    )
    [System.IO.File]::AppendAllLines($AuditReportFile, [string[]]$AuditHeader, [System.Text.Encoding]::ASCII)

    Write-Host ""
    Write-Host "Starting Full SYSVOL Security Audit..."
    Write-Host "========================================"

    $InventoryResults  = Get-SysvolScriptInventory     -Force -ReportFile $AuditReportFile
    $SecretsResults    = Search-SysvolScriptRisks       -Force -ReportFile $AuditReportFile
    $GppResults        = Search-SysvolGppCpassword     -Force -ReportFile $AuditReportFile
    $SysvolPermResults = Search-SysvolPermissions      -Force -ReportFile $AuditReportFile
    $GpoDelResults     = Search-GpoDelegation          -Force -ReportFile $AuditReportFile
    $ExtOutput         = Search-GpoExternalScriptPaths -Force -ReportFile $AuditReportFile
    $ExtPathResults    = if ($ExtOutput -is [hashtable]) { $ExtOutput.PathRefs    } else { @() }
    $ExtPermResults    = if ($ExtOutput -is [hashtable]) { $ExtOutput.PermFindings } else { @() }

    $InventoryCount  = @($InventoryResults).Count
    $SecretCrit      = @($SecretsResults      | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $SecretHigh      = @($SecretsResults      | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    $GppCrit         = @($GppResults          | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $GppInfo         = @($GppResults          | Where-Object { $_.RiskLevel -eq 'Info'     }).Count
    $SysvolPermCrit  = @($SysvolPermResults   | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $SysvolPermHigh  = @($SysvolPermResults   | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    $GpoDelCrit      = @($GpoDelResults       | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $GpoDelHigh      = @($GpoDelResults       | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    $ExtHigh         = @($ExtPathResults      | Where-Object { $_.RiskLevel -eq 'High'     }).Count
    $ExtMedium       = @($ExtPathResults      | Where-Object { $_.RiskLevel -eq 'Medium'   }).Count
    $ExtPermCrit     = @($ExtPermResults      | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $ExtPermHigh     = @($ExtPermResults      | Where-Object { $_.RiskLevel -eq 'High'     }).Count

    $TotalCritical = $SecretCrit + $GppCrit + $SysvolPermCrit + $GpoDelCrit + $ExtPermCrit
    $TotalHigh     = $SecretHigh + $SysvolPermHigh + $GpoDelHigh + $ExtHigh + $ExtPermHigh

    Write-Host ""
    Write-Host "[SYSVOL Audit Summary]"
    Write-Host "-------------------------------------------------------"
    Write-Host ("Script Inventory:        {0} files found"                          -f $InventoryCount)
    Write-Host ("Credential & Risk Scan:  {0} Critical, {1} High"                  -f $SecretCrit, $SecretHigh)
    Write-Host ("GPP cpassword:           {0} Critical, {1} Info (empty)"          -f $GppCrit, $GppInfo)
    Write-Host ("Permission Scan:         {0} Critical, {1} High"                  -f $SysvolPermCrit, $SysvolPermHigh)
    Write-Host ("GPO Delegation:          {0} Critical, {1} High"                  -f $GpoDelCrit, $GpoDelHigh)
    Write-Host ("External Script Paths:   {0} High, {1} Medium"                    -f $ExtHigh, $ExtMedium)
    Write-Host ("Ext. Path Permissions:   {0} Critical, {1} High"                  -f $ExtPermCrit, $ExtPermHigh)
    Write-Host "-------------------------------------------------------"
    Write-Host ("Total Critical Findings: {0}"                                      -f $TotalCritical)
    Write-Host ("Total High Findings:     {0}"                                      -f $TotalHigh)
    Write-Host ""

    $SummaryLines = @(
        "",
        "[SYSVOL Audit Summary]",
        "-------------------------------------------------------",
        ("Script Inventory:        {0} files found"             -f $InventoryCount),
        ("Credential & Risk Scan:  {0} Critical, {1} High"      -f $SecretCrit, $SecretHigh),
        ("GPP cpassword:           {0} Critical, {1} Info"      -f $GppCrit, $GppInfo),
        ("Permission Scan:         {0} Critical, {1} High"      -f $SysvolPermCrit, $SysvolPermHigh),
        ("GPO Delegation:          {0} Critical, {1} High"      -f $GpoDelCrit, $GpoDelHigh),
        ("External Script Paths:   {0} High, {1} Medium"        -f $ExtHigh, $ExtMedium),
        ("Ext. Path Permissions:   {0} Critical, {1} High"      -f $ExtPermCrit, $ExtPermHigh),
        "-------------------------------------------------------",
        ("Total Critical Findings: {0}"                         -f $TotalCritical),
        ("Total High Findings:     {0}"                         -f $TotalHigh),
        ""
    )
    [System.IO.File]::AppendAllLines($AuditReportFile, [string[]]$SummaryLines, [System.Text.Encoding]::ASCII)
    Write-Host "[INFO] Full audit report saved to: $AuditReportFile" -ForegroundColor Green
}

Function Start-SysvolGppCpasswordCheck {
    <#
    .SYNOPSIS
    Daily scheduled check for GPP cpassword values in SYSVOL.

    .DESCRIPTION
    === SYSVOL GPP cpassword Daily Check ===
        Lightweight daily scan targeting only GPP XML files for cpassword values.
        Respects the SysvolGppCpasswordAudit setting -- returns silently if set to $false.
        If any cpassword values are found, a Critical warning is written to the console.
        No action is taken if the scan produces no findings.

    .EXAMPLE
    Start-SysvolGppCpasswordCheck

    .NOTES
    #>

    if (-not $global:SysvolGppCpasswordAudit) { return }

    $Results     = Search-SysvolGppCpassword -Force
    $CritResults = @($Results | Where-Object { $_.RiskLevel -eq 'Critical' })
    if ($CritResults.Count -eq 0) { return }

    Write-Host "[CRITICAL] $($CritResults.Count) GPP cpassword value(s) found in SYSVOL. Review the CSV report in the Reports directory."
}
