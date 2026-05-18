#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory


# ===========================================================================
# Module Initialization
# ===========================================================================

Function Initialize-Module {
    <#
    .SYNOPSIS
        Registers the GPO Manager interactive submenu in the AD-PowerAdmin framework.

    .DESCRIPTION
        Adds the GPO Manager backup and restore submenu to $global:Menu and
        $global:SubMenus. Also serves as the shared GPO infrastructure library for
        all other AD-PowerAdmin modules. All direct Group Policy interactions in the
        framework are routed through the functions exposed by this module.

    .EXAMPLE
        Initialize-Module
    #>
    $global:Menu.Remove('GPOMgr')
    $global:SubMenus.Remove('GPOMgrMenu')

    $global:SubMenus += @{
        'GPOMgrMenu' = @{
            Title = "GPO Manager"
            Items = @{
                'BackupAll' = @{
                    Title   = "Backup All GPOs"
                    Label   = "Back up every Group Policy Object in the domain to the AD-PowerAdmin Reports directory."
                    Command = "Backup-AllGPOs"
                }
                'BackupSingle' = @{
                    Title   = "Backup a GPO"
                    Label   = "Select a single Group Policy Object from the domain and create a backup copy."
                    Command = "Invoke-GPOMgrBackupSingleMenu"
                }
                'ListBackups' = @{
                    Title   = "List GPO Backups"
                    Label   = "Display all available GPO backups stored in the AD-PowerAdmin Reports directory."
                    Command = "Get-GPOBackupList | Format-Table GpoName, BackupDate, BackupId -AutoSize"
                }
                'Restore' = @{
                    Title   = "Restore a GPO"
                    Label   = "Select an available backup and restore it to the domain, overwriting the current GPO settings."
                    Command = "Restore-GPOBackup"
                }
                'Help' = @{
                    Title   = "Help"
                    Label   = "Display a plain-language guide explaining what GPO backups are, where they are stored, how to create and list backups, and how to restore a GPO."
                    Command = "Show-GPOMgrHelp"
                }
            }
        }
    }

    $global:Menu += @{
        'GPOMgr' = @{
            Title    = "GPO Manager"
            Label    = "Back up, restore, and manage Group Policy Objects. All GPO modifications made by AD-PowerAdmin features include automatic pre-change backup."
            Module   = "AD-PowerAdmin_GPOMgr"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'GPOMgrMenu'"
        }
    }
}



# ===========================================================================
# Private Helpers (not exported)
# ===========================================================================

Function Test-GPOMgrPreFlight {
    # Verifies the GroupPolicy module is available before any GPO operation.
    # Returns $false and prints a [FAIL] message with remediation instructions if not.
    try {
        Import-Module GroupPolicy -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Host "[FAIL] The GroupPolicy PowerShell module is not available on this system." -ForegroundColor Red
        Write-Host "       RSAT Group Policy Management Tools must be installed." -ForegroundColor Yellow
        Write-Host "       To install on Windows Server:" -ForegroundColor Yellow
        Write-Host "         Install-WindowsFeature -Name GPMC" -ForegroundColor Cyan
        Write-Host "       To install on Windows 10/11:" -ForegroundColor Yellow
        Write-Host "         Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0" -ForegroundColor Cyan
        return $false
    }
}

Function Invoke-GPOMgrBackupSingleMenu {
    # Private: presents a numbered list of all domain GPOs and backs up the selected one.
    $AllGpos = Find-GPO
    if ($AllGpos.Count -eq 0) {
        Write-Host "[INFO] No GPOs found in the domain." -ForegroundColor Cyan
        return
    }

    $MenuItems = @{}
    $Sorted = $AllGpos | Sort-Object DisplayName
    for ($i = 0; $i -lt $Sorted.Count; $i++) {
        $MenuItems[($i + 1)] = $Sorted[$i].DisplayName
    }

    $SelectedName = Show-Menu -MenuName "Select GPO to Back Up" -MenuItems $MenuItems
    if ([string]::IsNullOrEmpty($SelectedName)) {
        Write-Host "[INFO] Backup cancelled." -ForegroundColor Cyan
        return
    }

    Backup-ADPAGPO -GpoName $SelectedName | Out-Null
}

Function ConvertFrom-IniString {
    # Parses an array of INI-format strings into an ordered hashtable of sections.
    # Used internally for GptTmpl.inf and gpt.ini read operations.
    param([string[]]$Lines)
    $Sections = [ordered]@{}
    [string]$Current = ''
    foreach ($Line in $Lines) {
        $Line = $Line.Trim()
        if ($Line -match '^\[(.+)\]$') {
            $Current = $Matches[1]
            if (-not $Sections.Contains($Current)) { $Sections[$Current] = [ordered]@{} }
        } elseif ($Current -ne '' -and $Line -match '^([^;=\[]+)\s*=\s*(.*)$') {
            $Sections[$Current][$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
    return $Sections
}

Function ConvertTo-IniLines {
    # Serializes an ordered hashtable of sections to an array of INI-format strings.
    param([object]$Sections)
    $Lines = [System.Collections.Generic.List[string]]::new()
    foreach ($Section in $Sections.Keys) {
        $Lines.Add("[$Section]")
        foreach ($Key in $Sections[$Section].Keys) {
            $Lines.Add("$Key=$($Sections[$Section][$Key])")
        }
        $Lines.Add('')
    }
    return $Lines.ToArray()
}

Function Update-GptIniVersion {
    # Increments the machine-side version counter in a GPO's gpt.ini and updates
    # the GPO AD object's gPCMachineExtensionNames and versionNumber attributes.
    # The Group Policy client reads gPCMachineExtensionNames from the AD object,
    # not from gpt.ini -- gpt.ini contains only Version, displayName, and
    # displayName (matching the format Windows GPMC generates).
    #
    # ExtraCseBlocks: optional additional CSE blocks to register beyond the Security
    # CSE. Set-GPOAdvancedAuditPolicy passes the Audit Policy Configuration CSE
    # block here because audit.csv requires a separate CSE GUID from GptTmpl.inf.
    param(
        [string]$GptIniPath,
        [string[]]$ExtraCseBlocks = @()
    )
    [string]$SecurityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    [int]$NewVersion     = 1

    if (-not (Test-Path $GptIniPath)) {
        @('[General]', 'Version=1', 'displayName=New Group Policy Object') |
            Out-File -FilePath $GptIniPath -Encoding ASCII -Force
    } else {
        try {
            $Sections = ConvertFrom-IniString -Lines (Get-Content -Path $GptIniPath -Encoding ASCII)
            if (-not $Sections.Contains('General')) { $Sections['General'] = [ordered]@{} }
            [int]$VersionInt = 0
            if ($Sections['General'].Contains('Version')) {
                [int]::TryParse($Sections['General']['Version'], [ref]$VersionInt) | Out-Null
            }
            $Machine    = (($VersionInt -band 0xFFFF) + 1)
            $User       = (($VersionInt -shr 16) -band 0xFFFF)
            $NewVersion = (($User -shl 16) -bor $Machine)
            $Sections['General']['Version'] = $NewVersion.ToString()
            # Remove gPCMachineExtensionNames from gpt.ini if a previous version wrote it
            # there incorrectly -- it belongs in the AD object only.
            $Sections['General'].Remove('gPCMachineExtensionNames') | Out-Null
            ConvertTo-IniLines -Sections $Sections | Out-File -FilePath $GptIniPath -Encoding ASCII -Force
        } catch {
            Write-Host "[WARN] Could not update gpt.ini version: $_" -ForegroundColor Yellow
            return
        }
    }

    # Update the GPO AD object: versionNumber + gPCMachineExtensionNames.
    # Parse existing CSE blocks and merge in the Security CSE plus any extras,
    # then sort alphabetically (the format GPMC produces) before writing back.
    try {
        if ($GptIniPath -match '[/\\]Policies[/\\](\{[0-9A-Fa-f-]{36}\})[/\\]gpt\.ini') {
            $GpoGuid = $Matches[1].ToUpper()
            $GpoObj  = Get-ADObject -Filter "Name -eq '$GpoGuid' -and ObjectClass -eq 'groupPolicyContainer'" `
                -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
            if ($GpoObj) {
                $AdExt     = [string]$GpoObj.gPCMachineExtensionNames
                $AllBlocks = [System.Collections.Generic.List[string]]::new()
                [regex]::Matches($AdExt, '\[[^\]]+\]') | ForEach-Object { $AllBlocks.Add($_.Value) }
                if ($AllBlocks -notcontains $SecurityCse) { $AllBlocks.Add($SecurityCse) }
                foreach ($Extra in $ExtraCseBlocks) {
                    if (-not [string]::IsNullOrWhiteSpace($Extra) -and $AllBlocks -notcontains $Extra) {
                        $AllBlocks.Add($Extra)
                    }
                }
                $MergedExt = ($AllBlocks | Sort-Object) -join ''
                Set-ADObject -Identity $GpoObj.DistinguishedName `
                    -Replace @{ versionNumber = $NewVersion; gPCMachineExtensionNames = $MergedExt } `
                    -ErrorAction Stop
            }
        }
    } catch {
        Write-Host "[WARN] Could not update GPO AD object attributes: $_" -ForegroundColor Yellow
    }
}



# ===========================================================================
# Retrieval Functions (Find, Test, Export, Get, Search)
# ===========================================================================

Function Find-GPO {
    <#
    .SYNOPSIS
        Searches for Group Policy Objects by exact name or wildcard pattern.

    .DESCRIPTION
        Returns an array of GPO objects matching the supplied criteria.
        Always returns an array -- callers check .Count -eq 0 for "not found."
        Specify -Name for an exact match or -Pattern for a wildcard search.
        If neither is supplied, all GPOs in the domain are returned.

    .PARAMETER Name
        Exact display name of the GPO to find.

    .PARAMETER Pattern
        Wildcard pattern matched against GPO display names (e.g. "*SMB*").

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [Microsoft.GroupPolicy.Gpo[]]

    .EXAMPLE
        Find-GPO -Name "My-GPO"

    .EXAMPLE
        Find-GPO -Pattern "*Signing*"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, Position=1)]
        [string]$Name = '',

        [Parameter(Mandatory=$false)]
        [string]$Pattern = '',

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return @() }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if (-not [string]::IsNullOrWhiteSpace($Name)) {
        try {
            $Gpo = Get-GPO -Name $Name -Domain $ResolvedDomain -ErrorAction Stop
            return @($Gpo)
        } catch {
            return @()
        }
    }

    try {
        $AllGpos = Get-GPO -All -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not retrieve GPOs from domain '$ResolvedDomain': $_" -ForegroundColor Red
        return @()
    }

    if (-not [string]::IsNullOrWhiteSpace($Pattern)) {
        $AllGpos = $AllGpos | Where-Object { $_.DisplayName -like $Pattern }
    }

    return @($AllGpos)
}

Function Test-GPO {
    <#
    .SYNOPSIS
        Validates that a GPO exists and optionally contains expected settings and links.

    .DESCRIPTION
        Checks GPO existence, enabled status, registry-backed settings, and OU links.
        Writes [PASS] or [FAIL] per check unless -Quiet is specified.
        Used by other modules to verify their GPO is still in the expected state.

    .PARAMETER Name
        Display name of the GPO to validate.

    .PARAMETER RegistrySettings
        Array of hashtables describing expected registry settings.
        Each entry: @{Key='HKLM\...'; ValueName='...'; Type='DWord'; Value=1}

    .PARAMETER Links
        Array of OU or domain distinguished names that should be linked to this GPO.

    .PARAMETER Quiet
        Suppresses all console output. Only the return value is produced.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if all specified checks pass.

    .EXAMPLE
        Test-GPO -Name "My-GPO" -Links @("OU=Servers,DC=corp,DC=local")

    .EXAMPLE
        $ok = Test-GPO -Name "My-GPO" -Quiet
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [hashtable[]]$RegistrySettings = @(),

        [Parameter(Mandatory=$false)]
        [string[]]$Links = @(),

        [Parameter(Mandatory=$false)]
        [switch]$Quiet,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain
    $AllPass = $true

    # Check existence
    try {
        $Gpo = Get-GPO -Name $Name -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        if (-not $Quiet) { Write-Host "[FAIL] GPO '$Name' does not exist in domain '$ResolvedDomain'." -ForegroundColor Red }
        return $false
    }
    if (-not $Quiet) { Write-Host "[PASS] GPO '$Name' exists." -ForegroundColor Green }

    # Check enabled status
    if ($Gpo.GpoStatus -eq 'AllSettingsDisabled') {
        if (-not $Quiet) { Write-Host "[FAIL] GPO '$Name' has all settings disabled." -ForegroundColor Red }
        $AllPass = $false
    } else {
        if (-not $Quiet) { Write-Host "[PASS] GPO '$Name' status: $($Gpo.GpoStatus)." -ForegroundColor Green }
    }

    # Check registry settings
    if ($RegistrySettings.Count -gt 0) {
        foreach ($Setting in $RegistrySettings) {
            [bool]$Found = $false
            try {
                $RegVal = Get-GPRegistryValue -Name $Name -Domain $ResolvedDomain `
                    -Key $Setting.Key -ValueName $Setting.ValueName -ErrorAction Stop
                $Found = ($null -ne $RegVal)
            } catch {
                $Found = $false
            }
            if ($Found) {
                if (-not $Quiet) { Write-Host "[PASS] Registry setting '$($Setting.ValueName)' found under '$($Setting.Key)'." -ForegroundColor Green }
            } else {
                if (-not $Quiet) { Write-Host "[FAIL] Registry setting '$($Setting.ValueName)' under '$($Setting.Key)' not found in GPO '$Name'." -ForegroundColor Red }
                $AllPass = $false
            }
        }
    }

    # Check links
    foreach ($LinkTarget in $Links) {
        try {
            $Inheritance = Get-GPInheritance -Target $LinkTarget -Domain $ResolvedDomain -ErrorAction Stop
            $Linked = $Inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $Name }
            if ($null -ne $Linked) {
                if (-not $Quiet) { Write-Host "[PASS] GPO '$Name' is linked to '$LinkTarget'." -ForegroundColor Green }
            } else {
                if (-not $Quiet) { Write-Host "[FAIL] GPO '$Name' is NOT linked to '$LinkTarget'." -ForegroundColor Red }
                $AllPass = $false
            }
        } catch {
            if (-not $Quiet) { Write-Host "[FAIL] Could not verify link to '$LinkTarget': $_" -ForegroundColor Red }
            $AllPass = $false
        }
    }

    return $AllPass
}

Function Export-GPOReport {
    <#
    .SYNOPSIS
        Generates HTML and/or XML audit reports for a named GPO.

    .DESCRIPTION
        Saves one or both report formats to the AD-PowerAdmin Reports directory.
        Filenames include a sanitized GPO name and a timestamp.
        Returns an object with the paths of the files written.

    .PARAMETER GpoName
        Display name of the GPO to report on.

    .PARAMETER ReportType
        Report format: Html, Xml, or Both (default).

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject]@{ HtmlPath = [string]; XmlPath = [string] }
        Paths are empty strings for report types that were not generated.

    .EXAMPLE
        Export-GPOReport -GpoName "My-GPO"

    .EXAMPLE
        Export-GPOReport -GpoName "My-GPO" -ReportType Html
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Html','Xml','Both')]
        [string]$ReportType = 'Both',

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) {
        return [PSCustomObject]@{ HtmlPath = ''; XmlPath = '' }
    }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    # Verify GPO exists
    try {
        Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "[FAIL] GPO '$GpoName' not found in domain '$ResolvedDomain'." -ForegroundColor Red
        return [PSCustomObject]@{ HtmlPath = ''; XmlPath = '' }
    }

    # Build a filename-safe version of the GPO name
    $SafeName = $GpoName -replace '\s+', '-' -replace '[^A-Za-z0-9\-]', ''
    $Timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $HtmlPath  = ''
    $XmlPath   = ''

    if ($ReportType -eq 'Html' -or $ReportType -eq 'Both') {
        $HtmlPath = Join-Path $global:ReportsPath "GPOReport-$SafeName-$Timestamp.html"
        try {
            Get-GPOReport -Name $GpoName -Domain $ResolvedDomain -ReportType Html -Path $HtmlPath -ErrorAction Stop
            Write-Host "[OK] HTML report saved: $HtmlPath" -ForegroundColor Green
        } catch {
            Write-Host "[FAIL] Failed to generate HTML report: $_" -ForegroundColor Red
            $HtmlPath = ''
        }
    }

    if ($ReportType -eq 'Xml' -or $ReportType -eq 'Both') {
        $XmlPath = Join-Path $global:ReportsPath "GPOReport-$SafeName-$Timestamp.xml"
        try {
            Get-GPOReport -Name $GpoName -Domain $ResolvedDomain -ReportType Xml -Path $XmlPath -ErrorAction Stop
            Write-Host "[OK] XML report saved: $XmlPath" -ForegroundColor Green
        } catch {
            Write-Host "[FAIL] Failed to generate XML report: $_" -ForegroundColor Red
            $XmlPath = ''
        }
    }

    return [PSCustomObject]@{ HtmlPath = $HtmlPath; XmlPath = $XmlPath }
}

Function Get-GPOBackupList {
    <#
    .SYNOPSIS
        Returns a list of all available GPO backups in the AD-PowerAdmin backup directory.

    .DESCRIPTION
        Enumerates the GPOBackups subdirectory under $global:ReportsPath and parses
        the bkupInfo.xml manifest in each backup folder to extract the GPO display name,
        backup timestamp, and backup ID. Results are returned newest-first.

    .OUTPUTS
        [PSCustomObject[]] -- each: @{ GpoName; BackupDate; BackupId; BackupPath }
        Returns an empty array if no backups exist.

    .EXAMPLE
        Get-GPOBackupList | Format-Table -AutoSize

    .EXAMPLE
        $Backups = Get-GPOBackupList
    #>
    [CmdletBinding()]
    Param()

    $BackupDir = Join-Path $global:ReportsPath 'GPOBackups'
    $Results   = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not (Test-Path $BackupDir)) {
        Write-Host "[INFO] No GPO backup directory found at '$BackupDir'." -ForegroundColor Cyan
        return @()
    }

    $SubDirs = @(Get-ChildItem -Path $BackupDir -Directory -ErrorAction SilentlyContinue)
    if ($SubDirs.Count -eq 0) {
        Write-Host "[INFO] No GPO backups found in '$BackupDir'." -ForegroundColor Cyan
        return @()
    }

    foreach ($Dir in $SubDirs) {
        $ManifestPath = Join-Path $Dir.FullName 'bkupInfo.xml'
        if (-not (Test-Path $ManifestPath)) { continue }

        try {
            # Load via XmlDocument.Load() so the XML declaration's encoding is respected.
            $Manifest = [System.Xml.XmlDocument]::new()
            $Manifest.Load($ManifestPath)

            # bkupInfo.xml has BackupInst as the document root with a default namespace:
            #   <BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">
            # XPath //BackupInst will not match elements in a named namespace, so we use
            # DocumentElement to get the root directly instead.
            $BackupNode = $Manifest.DocumentElement
            if ($null -eq $BackupNode) { continue }

            # Use local-name() predicates so child lookups are namespace-independent.
            $GpoNameNode    = $BackupNode.SelectSingleNode('*[local-name()="GPODisplayName"]')
            $BackupIdNode   = $BackupNode.SelectSingleNode('*[local-name()="ID"]')
            $BackupDateNode = $BackupNode.SelectSingleNode('*[local-name()="BackupTime"]')

            if ($null -eq $GpoNameNode -or $null -eq $BackupIdNode) {
                Write-Host "[WARN] bkupInfo.xml in '$($Dir.Name)' is missing required fields -- skipping." -ForegroundColor Yellow
                continue
            }

            $GpoName    = $GpoNameNode.InnerText
            $BackupId   = $BackupIdNode.InnerText
            $BackupDate = if ($null -ne $BackupDateNode) { $BackupDateNode.InnerText } else { '' }

            if ([string]::IsNullOrWhiteSpace($GpoName)) { continue }

            $Results.Add([PSCustomObject]@{
                GpoName    = $GpoName
                BackupDate = $BackupDate
                BackupId   = $BackupId
                BackupPath = $Dir.FullName
            })
        } catch {
            Write-Host "[WARN] Could not read backup manifest '$ManifestPath': $_" -ForegroundColor Yellow
            continue
        }
    }

    return @($Results | Sort-Object BackupDate -Descending)
}

Function Get-GPOAdvancedAuditPolicy {
    <#
    .SYNOPSIS
        Reads Advanced Audit Policy subcategory settings from a GPO's audit.csv in SYSVOL.

    .DESCRIPTION
        Reads the audit.csv file from the named GPO's SYSVOL path and returns the parsed
        subcategory settings. Returns an empty collection if no audit.csv exists for the GPO.

    .PARAMETER GpoName
        Display name of the GPO to read.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        Collection of PSCustomObjects with properties:
          Subcategory, GUID, InclusionSetting (int), InclusionSettingText (string)

    .EXAMPLE
        Get-GPOAdvancedAuditPolicy -GpoName 'ADPA-AuditPolicy-DC'
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    $EmptyResult = @()
    if (-not (Test-GPOMgrPreFlight)) { return $EmptyResult }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    try {
        $Gpo = Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] GPO '$GpoName' not found in domain '$ResolvedDomain'." -ForegroundColor Red
        return $EmptyResult
    }

    try {
        $DomainObj = Get-ADDomain -Identity $ResolvedDomain -ErrorAction Stop
        $GpoIdStr  = $Gpo.Id.ToString('B').ToUpper()
        $PolicyDir = "\\$($DomainObj.DNSRoot)\SYSVOL\$($DomainObj.DNSRoot)\Policies\$GpoIdStr"
        $CsvPath   = Join-Path $PolicyDir 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    } catch {
        Write-Host "[FAIL] Could not determine SYSVOL path for GPO '$GpoName': $_" -ForegroundColor Red
        return $EmptyResult
    }

    if (-not (Test-Path $CsvPath)) {
        return $EmptyResult
    }

    try {
        $TextToInt = @{ 'No Auditing' = 0; 'Success' = 1; 'Failure' = 2; 'Success and Failure' = 3 }
        $Rows      = Import-Csv -Path $CsvPath -ErrorAction Stop
        $Result    = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($Row in $Rows) {
            $IncText  = ($Row.'Inclusion Setting').ToString().Trim()
            $SetVal   = ($Row.'Setting Value').ToString().Trim()
            $IncInt   = 0
            # New Windows format: Setting Value holds the integer; Inclusion Setting holds the text.
            # Old format (pre-fix): Inclusion Setting held the integer; Setting Value was empty.
            if (-not [string]::IsNullOrWhiteSpace($SetVal) -and [int]::TryParse($SetVal, [ref]$IncInt)) {
                # new format -- $IncInt is set from Setting Value
            } elseif ($TextToInt.ContainsKey($IncText)) {
                $IncInt = $TextToInt[$IncText]
            } else {
                [int]::TryParse($IncText, [ref]$IncInt) | Out-Null
            }
            $Result.Add([PSCustomObject]@{
                Subcategory          = $Row.'Subcategory'
                GUID                 = $Row.'Subcategory GUID'
                InclusionSetting     = $IncInt
                InclusionSettingText = $IncText
            })
        }
        return $Result.ToArray()
    } catch {
        Write-Host "[FAIL] Could not read audit.csv for GPO '$GpoName': $_" -ForegroundColor Red
        return $EmptyResult
    }
}

Function Search-GPOSetting {
    <#
    .SYNOPSIS
        Scans GPOs in the domain for a specific registry key or value.

    .DESCRIPTION
        Iterates all GPOs and queries each one with Get-GPRegistryValue to find registry
        settings matching the supplied key and optional value name. Works for both
        ADMX-backed Administrative Template settings and Extra Registry Settings.

        Use this before deploying a new GPO to detect existing policies that already
        enforce the same registry setting, preventing duplicate or conflicting configurations.

        Note: scanning all GPOs can be slow on large domains. A progress message is
        displayed before the scan begins.

    .PARAMETER Key
        Full registry key path to search for, e.g.
        "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters".

    .PARAMETER ValueName
        Optional value name within the key. If omitted, any value under the key matches.

    .PARAMETER ExpectedValue
        Optional. When supplied, only results where the actual value equals this are
        returned (Matches = $true).

    .PARAMETER Force
        Suppresses the progress warning and per-GPO progress output.
        Intended for use when called from other modules.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject[]] -- one object per matching setting:
        @{
            GpoName     = [string]
            GpoId       = [Guid]
            Key         = [string]
            ValueName   = [string]
            ActualValue = [object]
            Matches     = [bool]
        }

    .EXAMPLE
        Search-GPOSetting -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
            -ValueName "RequireSecuritySignature"

    .EXAMPLE
        Search-GPOSetting -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
            -ValueName "RequireSecuritySignature" -ExpectedValue 1
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Key,

        [Parameter(Mandatory=$false)]
        [string]$ValueName = '',

        [Parameter(Mandatory=$false)]
        $ExpectedValue = $null,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return @() }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    try {
        $AllGpos = Get-GPO -All -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not retrieve GPOs from domain '$ResolvedDomain': $_" -ForegroundColor Red
        return @()
    }

    if (-not $Force) {
        Write-Host "[INFO] Scanning $($AllGpos.Count) GPO(s) for registry key '$Key'." -ForegroundColor Cyan
        Write-Host "       This may take some time on domains with many GPOs." -ForegroundColor Yellow
    }

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Gpo in $AllGpos) {
        if (-not $Force) {
            Write-Host "  Scanning: $($Gpo.DisplayName)" -ForegroundColor DarkGray
        }

        try {
            if ([string]::IsNullOrWhiteSpace($ValueName)) {
                $RegValues = @(Get-GPRegistryValue -Name $Gpo.DisplayName -Domain $ResolvedDomain `
                    -Key $Key -ErrorAction SilentlyContinue)
            } else {
                $RegValues = @(Get-GPRegistryValue -Name $Gpo.DisplayName -Domain $ResolvedDomain `
                    -Key $Key -ValueName $ValueName -ErrorAction SilentlyContinue)
            }
        } catch {
            continue
        }

        foreach ($RegVal in $RegValues) {
            if ($null -eq $RegVal) { continue }
            [string]$NodeValueName = $RegVal.ValueName
            [object]$ActualValue   = $RegVal.Value
            [bool]$Matches = if ($null -eq $ExpectedValue) { $true } else { $ActualValue -eq $ExpectedValue }

            $Results.Add([PSCustomObject]@{
                GpoName     = $Gpo.DisplayName
                GpoId       = $Gpo.Id
                Key         = $Key
                ValueName   = $NodeValueName
                ActualValue = $ActualValue
                Matches     = $Matches
            })
        }
    }

    if (-not $Force) {
        if ($Results.Count -eq 0) {
            Write-Host "[INFO] No GPOs found containing the specified registry setting." -ForegroundColor Cyan
        } else {
            Write-Host "[INFO] Found $($Results.Count) matching setting(s) across $(@($Results | Select-Object -ExpandProperty GpoName -Unique).Count) GPO(s)." -ForegroundColor Green
            $Results | Select-Object GpoName, ValueName, ActualValue | Format-Table -AutoSize
        }
    }

    return $Results.ToArray()
}

Function Search-GPOSecuritySetting {
    <#
    .SYNOPSIS
        Scans all domain GPO security templates for specified Section + Key settings.

    .DESCRIPTION
        Enumerates all GPOs in the domain. For each GPO that has a GptTmpl.inf on the
        SYSVOL, reads the file and checks for any of the supplied Section + Key pairs.
        Returns one result object per match found, including the actual value configured
        and whether it matches the expected value.

        Performs a single SYSVOL pass per GPO regardless of how many settings are in
        the search list, making it efficient for entries with many security settings
        (such as the full domain password policy).

        Use this before deploying a best-practice entry that uses SecuritySettings to
        detect existing GPOs that already configure the same account or lockout policy
        settings, including configurations at different values (partial matches).

    .PARAMETER Settings
        Array of hashtables describing the settings to search for. Each entry must have:
          Section       [string] -- the INF section name, e.g. 'System Access'
          Key           [string] -- the setting key, e.g. 'MinimumPasswordLength'
          ExpectedValue [string] -- the value this deployment intends to set

    .PARAMETER Force
        Suppresses the progress message. Use when calling from other modules.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject[]] -- one object per match found:
        @{
            GpoName       = [string]
            GpoId         = [Guid]
            Section       = [string]
            Key           = [string]
            ActualValue   = [string]
            ExpectedValue = [string]
            Matches       = [bool]
        }

    .EXAMPLE
        Search-GPOSecuritySetting -Settings @(
            @{ Section='System Access'; Key='MinimumPasswordLength'; ExpectedValue='14' },
            @{ Section='System Access'; Key='LockoutBadCount';       ExpectedValue='5'  }
        ) -Force
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [hashtable[]]$Settings,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return @() }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    try {
        $AllGpos = Get-GPO -All -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not retrieve GPOs from domain '$ResolvedDomain': $_" -ForegroundColor Red
        return @()
    }

    if (-not $Force) {
        Write-Host "[INFO] Scanning $($AllGpos.Count) GPO security template(s) for $($Settings.Count) setting(s)." -ForegroundColor Cyan
    }

    try {
        $DomainObj   = Get-ADDomain -Identity $ResolvedDomain -ErrorAction Stop
        $SysvolBase  = "\\$($DomainObj.DNSRoot)\SYSVOL\$($DomainObj.DNSRoot)\Policies"
    } catch {
        Write-Host "[FAIL] Could not determine SYSVOL path: $_" -ForegroundColor Red
        return @()
    }

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Gpo in $AllGpos) {
        $GpoIdStr = $Gpo.Id.ToString('B').ToUpper()
        $InfPath  = "$SysvolBase\$GpoIdStr\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        if (-not (Test-Path $InfPath)) { continue }

        try {
            $Sections = ConvertFrom-IniString -Lines (Get-Content -Path $InfPath -Encoding Unicode -ErrorAction Stop)
        } catch { continue }

        foreach ($S in $Settings) {
            if (-not $Sections.Contains($S.Section)) { continue }
            if (-not $Sections[$S.Section].Contains($S.Key)) { continue }

            $ActualValue = $Sections[$S.Section][$S.Key]
            $Results.Add([PSCustomObject]@{
                GpoName       = $Gpo.DisplayName
                GpoId         = $Gpo.Id
                Section       = $S.Section
                Key           = $S.Key
                ActualValue   = $ActualValue
                ExpectedValue = $S.ExpectedValue
                Matches       = ($ActualValue -eq $S.ExpectedValue)
            })
        }
    }

    return $Results.ToArray()
}

Function Search-GPOContent {
    <#
    .SYNOPSIS
        Scans all domain GPOs for a specified type of policy content.

    .DESCRIPTION
        Enumerates all GPOs in the domain and, for each, extracts settings of the
        requested content type. A single switch (-ContentType) selects what to look
        for; type-specific parameters control the filter.

        Supported content types and their required/optional parameters:

          Registry        -- Reads registry settings via Get-GPRegistryValue.
                             -Key is required. -ValueName and -ExpectedValue are optional.

          SecurityTemplate -- Reads GptTmpl.inf INI settings from SYSVOL.
                             -Settings is required: array of @{Section; Key; ExpectedValue}.

          AdvancedAuditPolicy -- Reads audit.csv Advanced Audit Policy entries from SYSVOL.
                             -Subcategory is optional filter (exact match).

        All result objects share a common envelope (GpoName, GpoId, ContentType) with
        type-specific data in a Details property. This makes the output consistent
        regardless of content type and allows a single result set to be passed between
        functions without type-specific branching in the caller.

        The existing Search-GPOSetting and Search-GPOSecuritySetting functions are
        unchanged and continue to serve their existing callers. This function provides
        a unified interface for new code.

    .PARAMETER ContentType
        What to search for. One of: 'Registry', 'SecurityTemplate', 'AdvancedAuditPolicy'.

    .PARAMETER Key
        [Registry] Full registry key path, e.g. 'HKLM\System\...\Parameters'. Required.

    .PARAMETER ValueName
        [Registry] Optional value name within the key. Omit to return all values.

    .PARAMETER ExpectedValue
        [Registry] Optional. When supplied, Details.Matches = ($actual -eq $expected).

    .PARAMETER Settings
        [SecurityTemplate] Array of hashtables, each with Section, Key, ExpectedValue.

    .PARAMETER Subcategory
        [AdvancedAuditPolicy] Optional exact subcategory name to filter results.

    .PARAMETER Force
        Suppresses progress messages. Use when calling from other functions.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject[]] -- one object per match:
        @{
            GpoName     = [string]
            GpoId       = [Guid]
            ContentType = [string]
            Details     = [PSCustomObject]  # type-specific; see below
        }

        Registry Details:
            Key [string], ValueName [string], ActualValue [object], Matches [bool or $null]

        SecurityTemplate Details:
            Section [string], Key [string], ActualValue [string],
            ExpectedValue [string], Matches [bool]

        AdvancedAuditPolicy Details:
            Subcategory [string], InclusionSetting [int], InclusionSettingText [string]

    .EXAMPLE
        Search-GPOContent -ContentType AdvancedAuditPolicy -Subcategory 'Logon'

    .EXAMPLE
        Search-GPOContent -ContentType Registry `
            -Key 'HKLM\System\CurrentControlSet\Control\Lsa' -ValueName 'LmCompatibilityLevel'

    .EXAMPLE
        Search-GPOContent -ContentType SecurityTemplate -Settings @(
            @{ Section='System Access'; Key='MinimumPasswordLength'; ExpectedValue='14' }
        )
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Registry', 'SecurityTemplate', 'AdvancedAuditPolicy')]
        [string]$ContentType,

        [Parameter(Mandatory=$false)]
        [string]$Key = '',

        [Parameter(Mandatory=$false)]
        [string]$ValueName = '',

        [Parameter(Mandatory=$false)]
        $ExpectedValue = $null,

        [Parameter(Mandatory=$false)]
        [hashtable[]]$Settings = @(),

        [Parameter(Mandatory=$false)]
        [string]$Subcategory = '',

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return @() }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    # Validate type-specific required parameters.
    if ($ContentType -eq 'Registry' -and [string]::IsNullOrWhiteSpace($Key)) {
        Write-Host "[FAIL] -Key is required when ContentType='Registry'." -ForegroundColor Red
        return @()
    }
    if ($ContentType -eq 'SecurityTemplate' -and $Settings.Count -eq 0) {
        Write-Host "[FAIL] -Settings is required when ContentType='SecurityTemplate'." -ForegroundColor Red
        return @()
    }

    try {
        $AllGpos = Get-GPO -All -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not retrieve GPOs from domain '$ResolvedDomain': $_" -ForegroundColor Red
        return @()
    }

    # Resolve SYSVOL base once for SecurityTemplate (avoids per-GPO AD call).
    $SysvolBase = $null
    if ($ContentType -eq 'SecurityTemplate') {
        try {
            $DomainObj  = Get-ADDomain -Identity $ResolvedDomain -ErrorAction Stop
            $SysvolBase = "\\$($DomainObj.DNSRoot)\SYSVOL\$($DomainObj.DNSRoot)\Policies"
        } catch {
            Write-Host "[FAIL] Could not determine SYSVOL path: $_" -ForegroundColor Red
            return @()
        }
    }

    if (-not $Force) {
        Write-Host "[INFO] Scanning $($AllGpos.Count) GPO(s) for $ContentType content..." -ForegroundColor Cyan
    }

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Gpo in $AllGpos) {
        switch ($ContentType) {

            'Registry' {
                try {
                    if ([string]::IsNullOrWhiteSpace($ValueName)) {
                        $RegValues = @(Get-GPRegistryValue -Name $Gpo.DisplayName -Domain $ResolvedDomain `
                            -Key $Key -ErrorAction SilentlyContinue)
                    } else {
                        $RegValues = @(Get-GPRegistryValue -Name $Gpo.DisplayName -Domain $ResolvedDomain `
                            -Key $Key -ValueName $ValueName -ErrorAction SilentlyContinue)
                    }
                } catch { continue }

                foreach ($RegVal in $RegValues) {
                    if ($null -eq $RegVal) { continue }
                    [string]$RvName    = $RegVal.ValueName
                    [object]$RvActual  = $RegVal.Value
                    $RvMatches = if ($null -eq $ExpectedValue) { $null } else { $RvActual -eq $ExpectedValue }
                    $Results.Add([PSCustomObject]@{
                        GpoName     = $Gpo.DisplayName
                        GpoId       = $Gpo.Id
                        ContentType = 'Registry'
                        Details     = [PSCustomObject]@{
                            Key          = $Key
                            ValueName    = $RvName
                            ActualValue  = $RvActual
                            Matches      = $RvMatches
                        }
                    })
                }
            }

            'SecurityTemplate' {
                $GpoIdStr = $Gpo.Id.ToString('B').ToUpper()
                $InfPath  = "$SysvolBase\$GpoIdStr\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if (-not (Test-Path $InfPath)) { continue }

                try {
                    $Sections = ConvertFrom-IniString -Lines (Get-Content -Path $InfPath -Encoding Unicode -ErrorAction Stop)
                } catch { continue }

                foreach ($S in $Settings) {
                    if (-not $Sections.Contains($S.Section)) { continue }
                    if (-not $Sections[$S.Section].Contains($S.Key)) { continue }
                    $StActual = $Sections[$S.Section][$S.Key]
                    $Results.Add([PSCustomObject]@{
                        GpoName     = $Gpo.DisplayName
                        GpoId       = $Gpo.Id
                        ContentType = 'SecurityTemplate'
                        Details     = [PSCustomObject]@{
                            Section       = $S.Section
                            Key           = $S.Key
                            ActualValue   = $StActual
                            ExpectedValue = $S.ExpectedValue
                            Matches       = ($StActual -eq $S.ExpectedValue)
                        }
                    })
                }
            }

            'AdvancedAuditPolicy' {
                $Entries = Get-GPOAdvancedAuditPolicy -GpoName $Gpo.DisplayName -Domain $ResolvedDomain
                foreach ($Entry in $Entries) {
                    if ($Subcategory -and $Entry.Subcategory -ne $Subcategory) { continue }
                    $Results.Add([PSCustomObject]@{
                        GpoName     = $Gpo.DisplayName
                        GpoId       = $Gpo.Id
                        ContentType = 'AdvancedAuditPolicy'
                        Details     = [PSCustomObject]@{
                            Subcategory          = $Entry.Subcategory
                            InclusionSetting     = $Entry.InclusionSetting
                            InclusionSettingText = $Entry.InclusionSettingText
                        }
                    })
                }
            }
        }
    }

    return $Results.ToArray()
}



# ===========================================================================
# Modification Functions (New, Set, Add, Install, Backup, Restore, Invoke)
# ===========================================================================

Function New-ADPAGPO {
    <#
    .SYNOPSIS
        Creates a new Group Policy Object. Idempotent.

    .DESCRIPTION
        Creates a GPO with the given name and description. If a GPO with the same name
        already exists, the existing object is returned and an [OK] message is written
        unless -Force is specified. Supports -WhatIf.

    .PARAMETER Name
        Display name for the new GPO.

    .PARAMETER Description
        Optional comment stored on the GPO object.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .PARAMETER Force
        Suppresses the "GPO already exists" informational message.

    .OUTPUTS
        [Microsoft.GroupPolicy.Gpo] or $null on failure.

    .EXAMPLE
        New-ADPAGPO -Name "My-Security-Policy" -Description "Enforces security settings."

    .EXAMPLE
        New-ADPAGPO -Name "My-Security-Policy" -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Low')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [string]$Description = '',

        [Parameter(Mandatory=$false)]
        [string]$Domain = '',

        # Target DC for all GroupPolicy operations. Pass the PDC emulator FQDN when the
        # caller also needs to run Get-ADObject / Set-ADObject against the same object
        # immediately after creation, to avoid a replication race between DCs.
        [Parameter(Mandatory=$false)]
        [string]$Server = '',

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    if (-not (Test-GPOMgrPreFlight)) { return $null }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    $GpoQueryParams = @{ Name = $Name; Domain = $ResolvedDomain; ErrorAction = 'SilentlyContinue' }
    if ($Server) { $GpoQueryParams['Server'] = $Server }

    # Idempotency check
    $Existing = Get-GPO @GpoQueryParams
    if ($null -ne $Existing) {
        if (-not $Force) {
            Write-Host "[OK] GPO '$Name' already exists. Returning existing object." -ForegroundColor Green
        }
        return $Existing
    }

    if ($PSCmdlet.ShouldProcess("Domain '$ResolvedDomain'", "Create GPO '$Name'")) {
        try {
            $NewGpoParams = @{ Name = $Name; Comment = $Description; Domain = $ResolvedDomain; ErrorAction = 'Stop' }
            if ($Server) { $NewGpoParams['Server'] = $Server }
            $NewGpo = New-GPO @NewGpoParams
            Write-Host "[OK] GPO '$Name' created successfully." -ForegroundColor Green
            return $NewGpo
        } catch {
            Write-Host "[FAIL] Failed to create GPO '$Name': $_" -ForegroundColor Red
            return $null
        }
    }
    return $null
}

Function Set-GPORegistrySetting {
    <#
    .SYNOPSIS
        Applies a registry-backed policy setting to a named GPO.

    .DESCRIPTION
        Wraps Set-GPRegistryValue to apply a single registry-backed Administrative
        Template setting to the specified GPO. Supports -WhatIf and -Confirm.

    .PARAMETER GpoName
        Display name of the target GPO.

    .PARAMETER Key
        Full registry key path, e.g. "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters".

    .PARAMETER ValueName
        Name of the registry value to set.

    .PARAMETER Type
        Registry value type: String, ExpandString, Binary, DWord, MultiString, or QWord.

    .PARAMETER Value
        Value to write.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true on success.

    .EXAMPLE
        Set-GPORegistrySetting -GpoName "My-GPO" `
            -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
            -ValueName "RequireSecuritySignature" -Type DWord -Value 1
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$ValueName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')]
        [string]$Type,

        [Parameter(Mandatory=$true)]
        $Value,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if ($PSCmdlet.ShouldProcess("GPO '$GpoName'", "Set registry value '$ValueName' at '$Key'")) {
        try {
            Set-GPRegistryValue -Name $GpoName -Domain $ResolvedDomain `
                -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
            Write-Host "[OK] Set '$ValueName' = $Value ($Type) at '$Key' in GPO '$GpoName'." -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[FAIL] Failed to set registry value in GPO '$GpoName': $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

Function Set-GPOPermission {
    <#
    .SYNOPSIS
        Configures security filtering (permissions) on a named GPO.

    .DESCRIPTION
        Wraps Set-GPPermission to grant or modify a permission entry on a GPO.
        Supports -WhatIf and -Confirm.

    .PARAMETER GpoName
        Display name of the target GPO.

    .PARAMETER TargetName
        Name of the user, computer, or group to receive the permission.

    .PARAMETER TargetType
        Type of the target: User, Computer, or Group.

    .PARAMETER PermissionLevel
        Permission to assign: GpoRead, GpoApply, GpoEdit, GpoEditDeleteModifySecurity, or None.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true on success.

    .EXAMPLE
        Set-GPOPermission -GpoName "My-GPO" -TargetName "Domain Computers" `
            -TargetType Group -PermissionLevel GpoApply
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true)]
        [string]$TargetName,

        [Parameter(Mandatory=$true)]
        [ValidateSet('User','Computer','Group')]
        [string]$TargetType,

        [Parameter(Mandatory=$true)]
        [ValidateSet('GpoRead','GpoApply','GpoEdit','GpoEditDeleteModifySecurity','None')]
        [string]$PermissionLevel,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if ($PSCmdlet.ShouldProcess("GPO '$GpoName'", "Set $PermissionLevel permission for '$TargetName' ($TargetType)")) {
        try {
            Set-GPPermission -Name $GpoName -Domain $ResolvedDomain `
                -TargetName $TargetName -TargetType $TargetType `
                -PermissionLevel $PermissionLevel -ErrorAction Stop | Out-Null
            Write-Host "[OK] Set $PermissionLevel on GPO '$GpoName' for $TargetType '$TargetName'." -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[FAIL] Failed to set permission on GPO '$GpoName': $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

Function Set-GPOSecuritySetting {
    <#
    .SYNOPSIS
        Writes a security template setting into a Group Policy Object's GptTmpl.inf.

    .DESCRIPTION
        Sets a single key-value pair in the specified INF section of the named GPO's
        security template (GptTmpl.inf) on the domain SYSVOL. Creates the template
        and its directory if they do not yet exist. After writing, increments the
        machine-side version counter in gpt.ini and registers the Security
        Configuration Engine CSE GUID so Windows processes the template on the next
        Group Policy refresh.

        Use this function for settings in the Security Settings node of a GPO --
        account policy, lockout policy, security options -- that are stored in the
        security template rather than as registry values and therefore cannot be set
        with Set-GPORegistrySetting.

        Common sections:
          'System Access' -- password policy and lockout policy
          'Registry Values' -- security option registry values

        Common keys for 'System Access':
          MinimumPasswordLength, MaximumPasswordAge, MinimumPasswordAge,
          PasswordComplexity, PasswordHistorySize,
          LockoutBadCount, LockoutDuration, ResetLockoutCount

    .PARAMETER GpoName
        Display name of the GPO to modify.

    .PARAMETER Section
        The INF section name. For account and lockout policy use 'System Access'.

    .PARAMETER Key
        The setting key within the section.

    .PARAMETER Value
        The value to write. Always passed as a string; numeric policy values must
        be their decimal string representation (e.g. '14', '90', '1').

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true on success, $false on any failure.

    .EXAMPLE
        Set-GPOSecuritySetting -GpoName 'Default Domain Policy' `
            -Section 'System Access' -Key 'MinimumPasswordLength' -Value '14'
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true)]
        [string]$Section,

        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$Value,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    try {
        $Gpo = Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] GPO '$GpoName' not found in domain '$ResolvedDomain'." -ForegroundColor Red
        return $false
    }

    try {
        $DomainObj  = Get-ADDomain -Identity $ResolvedDomain -ErrorAction Stop
        $GpoIdStr   = $Gpo.Id.ToString('B').ToUpper()
        $PolicyDir  = "\\$($DomainObj.DNSRoot)\SYSVOL\$($DomainObj.DNSRoot)\Policies\$GpoIdStr"
        $SecEditDir = Join-Path $PolicyDir 'Machine\Microsoft\Windows NT\SecEdit'
        $InfPath    = Join-Path $SecEditDir 'GptTmpl.inf'
        $GptIniPath = Join-Path $PolicyDir 'gpt.ini'
    } catch {
        Write-Host "[FAIL] Could not determine SYSVOL path for GPO '$GpoName': $_" -ForegroundColor Red
        return $false
    }

    if (-not (Test-Path $SecEditDir)) {
        try {
            New-Item -Path $SecEditDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "[FAIL] Could not create SecEdit directory '$SecEditDir': $_" -ForegroundColor Red
            return $false
        }
    }

    $Sections = [ordered]@{}
    if (Test-Path $InfPath) {
        try {
            $Sections = ConvertFrom-IniString -Lines (Get-Content -Path $InfPath -Encoding Unicode -ErrorAction Stop)
        } catch {
            Write-Host "[WARN] Could not read existing GptTmpl.inf, creating new. $_" -ForegroundColor Yellow
        }
    }

    if (-not $Sections.Contains('Unicode'))  { $Sections['Unicode']  = [ordered]@{ 'Unicode'   = 'yes' } }
    if (-not $Sections.Contains('Version'))  { $Sections['Version']  = [ordered]@{ 'signature' = '"$CHICAGO$"'; 'Revision' = '1' } }
    if (-not $Sections.Contains($Section))   { $Sections[$Section]   = [ordered]@{} }
    $Sections[$Section][$Key] = $Value

    try {
        ConvertTo-IniLines -Sections $Sections |
            Out-File -FilePath $InfPath -Encoding Unicode -Force -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] Could not write GptTmpl.inf for GPO '$GpoName': $_" -ForegroundColor Red
        return $false
    }

    Update-GptIniVersion -GptIniPath $GptIniPath

    Write-Host "[OK] [$Section] $Key = $Value in GPO '$GpoName'." -ForegroundColor Green
    return $true
}

Function Set-GPOAdvancedAuditPolicy {
    <#
    .SYNOPSIS
        Writes Advanced Audit Policy subcategory settings to a GPO's audit.csv in SYSVOL.

    .DESCRIPTION
        Creates or overwrites the audit.csv file in the named GPO's SYSVOL path
        (Machine\Microsoft\Windows NT\Audit\audit.csv). This file is processed by the
        Security Configuration Engine on the next Group Policy refresh and applies
        Advanced Audit Policy subcategory settings to target computers.

        After writing, the machine-side version counter in gpt.ini is incremented and the
        Security Configuration Engine CSE GUID is registered so Windows processes the
        audit policy on the next Group Policy refresh.

        Each entry in AuditEntries must have three keys:
          Subcategory     -- display name, e.g. 'Logon'
          GUID            -- subcategory GUID, e.g. '{0CCE9215-69AE-11D9-BED3-505054503030}'
          InclusionSetting -- integer: 0=No Auditing, 1=Success, 2=Failure, 3=Success and Failure

    .PARAMETER GpoName
        Display name of the GPO to configure.

    .PARAMETER AuditEntries
        Array of hashtables. Each must contain Subcategory, GUID, and InclusionSetting.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true on success, $false on any failure.

    .EXAMPLE
        $Entries = @(
            @{ Subcategory = 'Logon'; GUID = '{0CCE9215-69AE-11D9-BED3-505054503030}'; InclusionSetting = 3 }
            @{ Subcategory = 'Logoff'; GUID = '{0CCE9216-69AE-11D9-BED3-505054503030}'; InclusionSetting = 1 }
        )
        Set-GPOAdvancedAuditPolicy -GpoName 'ADPA-AuditPolicy-DC' -AuditEntries $Entries
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true)]
        [hashtable[]]$AuditEntries,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    try {
        $Gpo = Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[FAIL] GPO '$GpoName' not found in domain '$ResolvedDomain'." -ForegroundColor Red
        return $false
    }

    try {
        $DomainObj  = Get-ADDomain -Identity $ResolvedDomain -ErrorAction Stop
        $GpoIdStr   = $Gpo.Id.ToString('B').ToUpper()
        $PolicyDir  = "\\$($DomainObj.DNSRoot)\SYSVOL\$($DomainObj.DNSRoot)\Policies\$GpoIdStr"
        $AuditDir   = Join-Path $PolicyDir 'Machine\Microsoft\Windows NT\Audit'
        $CsvPath    = Join-Path $AuditDir 'audit.csv'
        $GptIniPath = Join-Path $PolicyDir 'gpt.ini'
    } catch {
        Write-Host "[FAIL] Could not determine SYSVOL path for GPO '$GpoName': $_" -ForegroundColor Red
        return $false
    }

    if (-not (Test-Path $AuditDir)) {
        try {
            New-Item -Path $AuditDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "[FAIL] Could not create Audit directory '$AuditDir': $_" -ForegroundColor Red
            return $false
        }
    }

    # Windows audit.csv format (as generated by GPMC):
    #   Inclusion Setting = text label ("No Auditing", "Success", "Failure", "Success and Failure")
    #   Exclusion Setting = empty string (GPMC always leaves this blank)
    #   Setting Value     = uint32 integer (0, 1, 2, 3)
    #   Subcategory       = "Audit " prefix + display name (e.g. "Audit Credential Validation")
    #   Subcategory GUID  = lowercase GUID
    # The GPMC snapin calls Convert.ToUInt32() on Setting Value -- it must be a non-empty integer.
    $InclusionIntToText = @{
        0 = 'No Auditing'
        1 = 'Success'
        2 = 'Failure'
        3 = 'Success and Failure'
    }

    # Build a merged table: existing entries keyed by lowercase GUID, overwritten by incoming entries.
    $Merged = [ordered]@{}
    if (Test-Path $CsvPath) {
        try {
            $Existing = Import-Csv -Path $CsvPath -ErrorAction Stop
            foreach ($Row in $Existing) {
                $Guid = ($Row.'Subcategory GUID').ToLower()
                if ($Guid) { $Merged[$Guid] = $Row }
            }
        } catch {
            Write-Host "[WARN] Could not read existing audit.csv, overwriting. $_" -ForegroundColor Yellow
        }
    }

    foreach ($Entry in $AuditEntries) {
        $GuidLower      = $Entry.GUID.ToLower()
        $InclusionInt   = [int]$Entry.InclusionSetting
        $InclusionText  = if ($InclusionIntToText.ContainsKey($InclusionInt)) { $InclusionIntToText[$InclusionInt] } else { 'No Auditing' }
        $Merged[$GuidLower] = [PSCustomObject]@{
            'Machine Name'       = ''
            'Policy Target'      = 'System'
            'Subcategory'        = "Audit $($Entry.Subcategory)"
            'Subcategory GUID'   = $GuidLower
            'Inclusion Setting'  = $InclusionText
            'Exclusion Setting'  = ''
            'Setting Value'      = $InclusionInt
        }
    }

    # Write audit.csv as UTF-8 without BOM -- the encoding produced by the GPMC UI
    # and required by the Windows Security Configuration Engine. A BOM causes the SCE
    # to skip the file entirely because it cannot parse the byte-order-mark prefix.
    try {
        $Header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value'
        $Writer = [System.IO.StreamWriter]::new($CsvPath, $false, [System.Text.UTF8Encoding]::new($false))
        try {
            $Writer.WriteLine($Header)
            foreach ($Row in $Merged.Values) {
                $Writer.WriteLine("$($Row.'Machine Name'),$($Row.'Policy Target'),$($Row.'Subcategory'),$($Row.'Subcategory GUID'),$($Row.'Inclusion Setting'),$($Row.'Exclusion Setting'),$($Row.'Setting Value')")
            }
        } finally {
            $Writer.Dispose()
        }
    } catch {
        Write-Host "[FAIL] Could not write audit.csv for GPO '$GpoName': $_" -ForegroundColor Red
        return $false
    }

    # Register both the Security CSE (GptTmpl.inf) and the Audit Policy Configuration
    # CSE (audit.csv). Advanced Audit Policy requires its own dedicated CSE GUID
    # {F3CCC681-B74C-4060-9F26-CD84525DCA2A} in gPCMachineExtensionNames -- without it
    # the GP client never invokes the CSE and GPMC omits the section from the report.
    [string]$AuditPolicyCse = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    Update-GptIniVersion -GptIniPath $GptIniPath -ExtraCseBlocks @($AuditPolicyCse)
    Write-Host "[OK]  audit.csv written: $CsvPath ($($Merged.Count) subcategories, UTF-8 no BOM)." -ForegroundColor Green
    return $true
}

Function Add-GPOLink {
    <#
    .SYNOPSIS
        Links a GPO to an OU, domain, or site.

    .DESCRIPTION
        Validates that the target path exists in Active Directory before creating the link.
        Idempotent -- if the link already exists, calls Set-GPLink to enforce the desired
        LinkEnabled and Enforced state. Supports -WhatIf and -Confirm.

    .PARAMETER GpoName
        Display name of the GPO to link.

    .PARAMETER Target
        Distinguished name of the OU or domain, or site name to link to.

    .PARAMETER LinkEnabled
        Whether the link is enabled. Default 'Yes'.

    .PARAMETER Enforced
        Whether the link is enforced. Default 'No'.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if the link exists and is in the desired state after the call.

    .EXAMPLE
        Add-GPOLink -GpoName "My-GPO" -Target "OU=Servers,DC=corp,DC=local"

    .EXAMPLE
        Add-GPOLink -GpoName "My-GPO" -Target "OU=Servers,DC=corp,DC=local" -Enforced Yes
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$Target,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Yes','No')]
        [string]$LinkEnabled = 'Yes',

        [Parameter(Mandatory=$false)]
        [ValidateSet('Yes','No')]
        [string]$Enforced = 'No',

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    # Validate target exists in AD
    try {
        Get-ADObject -Identity $Target -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "[FAIL] Target '$Target' does not exist in Active Directory." -ForegroundColor Red
        return $false
    }

    # Check if link already exists
    $LinkExists = $false
    try {
        $Inheritance = Get-GPInheritance -Target $Target -Domain $ResolvedDomain -ErrorAction Stop
        $ExistingLink = $Inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
        if ($null -ne $ExistingLink) { $LinkExists = $true }
    } catch {
        # Target may be a site or root; proceed to create
    }

    if ($PSCmdlet.ShouldProcess("Target '$Target'", "Link GPO '$GpoName'")) {
        try {
            if ($LinkExists) {
                Set-GPLink -Name $GpoName -Target $Target -Domain $ResolvedDomain `
                    -LinkEnabled $LinkEnabled -Enforced $Enforced -ErrorAction Stop | Out-Null
                Write-Host "[OK] GPO '$GpoName' link to '$Target' updated (LinkEnabled=$LinkEnabled, Enforced=$Enforced)." -ForegroundColor Green
            } else {
                New-GPLink -Name $GpoName -Target $Target -Domain $ResolvedDomain `
                    -LinkEnabled $LinkEnabled -Enforced $Enforced -ErrorAction Stop | Out-Null
                Write-Host "[OK] GPO '$GpoName' linked to '$Target' (LinkEnabled=$LinkEnabled, Enforced=$Enforced)." -ForegroundColor Green
            }
            return $true
        } catch {
            Write-Host "[FAIL] Failed to link GPO '$GpoName' to '$Target': $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

Function Install-GPOBaseline {
    <#
    .SYNOPSIS
        Deploys a GPO from a declarative definition hashtable.

    .DESCRIPTION
        Primary inter-module API. Accepts a $GpoDefinition hashtable and idempotently
        creates, configures, and links the described GPO. The caller supplies the GPO
        name, description, target OUs, permissions, and registry settings. This module
        makes no decisions about GPO content.

        $GpoDefinition schema:
          Name             [string]       required
          Description      [string]       optional
          Links            [string[]]     optional -- OU/domain DNs
          Permissions      [hashtable[]]  optional -- each: @{TargetName;TargetType;PermissionLevel}
          RegistrySettings [hashtable[]]  optional -- each: @{Key;ValueName;Type;Value}

        Supports -WhatIf.

    .PARAMETER GpoDefinition
        Hashtable describing the GPO to deploy. See description for schema.

    .PARAMETER Force
        Suppresses the "GPO already exists" informational message.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject]@{
            GpoName  = [string]
            Exists   = [bool]
            Created  = [bool]
            Modified = [bool]
            Linked   = [bool]
            Links    = [string[]]
            Status   = 'Success'|'Partial'|'Failed'
            Errors   = [string[]]
        }

    .EXAMPLE
        $Definition = @{
            Name             = "Corp-SMB-Signing"
            Description      = "Enforces SMB signing on all servers."
            Links            = @("OU=Servers,DC=corp,DC=local")
            Permissions      = @(@{TargetName="Domain Computers";TargetType="Group";PermissionLevel="GpoApply"})
            RegistrySettings = @(
                @{Key="HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters";
                  ValueName="RequireSecuritySignature";Type="DWord";Value=1}
            )
        }
        $Result = Install-GPOBaseline -GpoDefinition $Definition
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [hashtable]$GpoDefinition,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    $Errors  = [System.Collections.Generic.List[string]]::new()
    $Created  = $false
    $Modified = $false
    $Linked   = $false
    $LinkedTargets = @()

    # Validate required fields
    if ([string]::IsNullOrWhiteSpace($GpoDefinition['Name'])) {
        return [PSCustomObject]@{
            GpoName  = ''; Exists = $false; Created = $false; Modified = $false
            Linked   = $false; Links = @(); Status = 'Failed'
            Errors   = @('GpoDefinition.Name is required and must not be empty.')
        }
    }

    $GpoName = $GpoDefinition['Name']
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if (-not (Test-GPOMgrPreFlight)) {
        return [PSCustomObject]@{
            GpoName  = $GpoName; Exists = $false; Created = $false; Modified = $false
            Linked   = $false; Links = @(); Status = 'Failed'
            Errors   = @('GroupPolicy module is not available. Install RSAT Group Policy Management Tools.')
        }
    }

    # Check existence before creating
    $Exists = $null -ne (Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction SilentlyContinue)

    # Create GPO
    $Description = if ($GpoDefinition.ContainsKey('Description')) { $GpoDefinition['Description'] } else { '' }
    $GpoObject = New-ADPAGPO -Name $GpoName -Description $Description -Domain $ResolvedDomain -Force:$Force
    if ($null -eq $GpoObject) {
        $Errors.Add("Failed to create or retrieve GPO '$GpoName'.")
        return [PSCustomObject]@{
            GpoName  = $GpoName; Exists = $Exists; Created = $false; Modified = $false
            Linked   = $false; Links = @(); Status = 'Failed'; Errors = $Errors.ToArray()
        }
    }
    $Created = -not $Exists

    # Apply registry settings
    if ($GpoDefinition.ContainsKey('RegistrySettings') -and $GpoDefinition['RegistrySettings'].Count -gt 0) {
        foreach ($Setting in $GpoDefinition['RegistrySettings']) {
            $Ok = Set-GPORegistrySetting -GpoName $GpoName -Domain $ResolvedDomain `
                -Key $Setting.Key -ValueName $Setting.ValueName `
                -Type $Setting.Type -Value $Setting.Value
            if ($Ok) { $Modified = $true } else { $Errors.Add("Failed to set registry value '$($Setting.ValueName)'.") }
        }
    }

    # Apply permissions
    if ($GpoDefinition.ContainsKey('Permissions') -and $GpoDefinition['Permissions'].Count -gt 0) {
        foreach ($Perm in $GpoDefinition['Permissions']) {
            $Ok = Set-GPOPermission -GpoName $GpoName -Domain $ResolvedDomain `
                -TargetName $Perm.TargetName -TargetType $Perm.TargetType `
                -PermissionLevel $Perm.PermissionLevel
            if ($Ok) { $Modified = $true } else { $Errors.Add("Failed to set permission for '$($Perm.TargetName)'.") }
        }
    }

    # Link to targets
    if ($GpoDefinition.ContainsKey('Links') -and $GpoDefinition['Links'].Count -gt 0) {
        foreach ($Target in $GpoDefinition['Links']) {
            $Ok = Add-GPOLink -GpoName $GpoName -Target $Target -Domain $ResolvedDomain
            if ($Ok) {
                $Linked = $true
                $LinkedTargets += $Target
            } else {
                $Errors.Add("Failed to link GPO to '$Target'.")
            }
        }
    }

    $Status = if ($Errors.Count -eq 0) { 'Success' } elseif ($Errors.Count -lt ($GpoDefinition['RegistrySettings'].Count + $GpoDefinition['Links'].Count)) { 'Partial' } else { 'Failed' }

    return [PSCustomObject]@{
        GpoName  = $GpoName
        Exists   = $Exists
        Created  = $Created
        Modified = $Modified
        Linked   = $Linked
        Links    = $LinkedTargets
        Status   = $Status
        Errors   = $Errors.ToArray()
    }
}

Function Backup-ADPAGPO {
    <#
    .SYNOPSIS
        Creates a backup of a single named Group Policy Object.

    .DESCRIPTION
        Backs up the named GPO to the AD-PowerAdmin GPOBackups directory under
        $global:ReportsPath. Each backup is stored in a GUID-named subfolder.
        Returns a structured result with the backup ID, path, and status.

    .PARAMETER GpoName
        Display name of the GPO to back up.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject]@{ GpoName; BackupId; BackupPath; Status; Errors }

    .EXAMPLE
        Backup-ADPAGPO -GpoName "Default Domain Policy"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) {
        return [PSCustomObject]@{
            GpoName    = $GpoName; BackupId = ''; BackupPath = ''
            Status     = 'Failed'
            Errors     = @('GroupPolicy module not available. Install RSAT Group Policy Management Tools.')
        }
    }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    try {
        Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "[FAIL] GPO '$GpoName' not found in domain '$ResolvedDomain'." -ForegroundColor Red
        return [PSCustomObject]@{
            GpoName    = $GpoName; BackupId = ''; BackupPath = ''
            Status     = 'Failed'
            Errors     = @("GPO '$GpoName' does not exist in domain '$ResolvedDomain'.")
        }
    }

    $BackupDir = Join-Path $global:ReportsPath 'GPOBackups'
    if (-not (Test-Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }

    try {
        $BackupResult = Backup-GPO -Name $GpoName -Path $BackupDir -Domain $ResolvedDomain -ErrorAction Stop
        $BackupId   = $BackupResult.Id.ToString()
        $BackupPath = $BackupResult.BackupDirectory
        Write-Host "[OK] GPO '$GpoName' backed up. ID: $BackupId" -ForegroundColor Green
        return [PSCustomObject]@{
            GpoName    = $GpoName
            BackupId   = $BackupId
            BackupPath = $BackupPath
            Status     = 'Success'
            Errors     = @()
        }
    } catch {
        Write-Host "[FAIL] Failed to back up GPO '$GpoName': $_" -ForegroundColor Red
        return [PSCustomObject]@{
            GpoName    = $GpoName; BackupId = ''; BackupPath = ''
            Status     = 'Failed'
            Errors     = @("Backup failed: $_")
        }
    }
}

Function Backup-AllGPOs {
    <#
    .SYNOPSIS
        Creates a backup of every Group Policy Object in the domain.

    .DESCRIPTION
        Backs up all GPOs to the AD-PowerAdmin GPOBackups directory under
        $global:ReportsPath. Returns a structured result with the backup path,
        count of GPOs backed up, and status.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject]@{ BackupPath; GpoCount; Status; Errors }

    .EXAMPLE
        Backup-AllGPOs
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) {
        return [PSCustomObject]@{
            BackupPath = ''; GpoCount = 0
            Status     = 'Failed'
            Errors     = @('GroupPolicy module not available. Install RSAT Group Policy Management Tools.')
        }
    }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    $BackupDir = Join-Path $global:ReportsPath 'GPOBackups'
    if (-not (Test-Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }

    Write-Host "[INFO] Backing up all GPOs in domain '$ResolvedDomain'. This may take a moment..." -ForegroundColor Cyan
    try {
        $BackupResults = @(Backup-GPO -All -Path $BackupDir -Domain $ResolvedDomain -ErrorAction Stop)
        $Count = $BackupResults.Count
        Write-Host "[OK] $Count GPO(s) backed up to '$BackupDir'." -ForegroundColor Green
        return [PSCustomObject]@{
            BackupPath = $BackupDir
            GpoCount   = $Count
            Status     = 'Success'
            Errors     = @()
        }
    } catch {
        Write-Host "[FAIL] Failed to back up all GPOs: $_" -ForegroundColor Red
        return [PSCustomObject]@{
            BackupPath = $BackupDir; GpoCount = 0
            Status     = 'Failed'
            Errors     = @("Backup-GPO -All failed: $_")
        }
    }
}

Function Restore-GPOBackup {
    <#
    .SYNOPSIS
        Restores a Group Policy Object from an available backup.

    .DESCRIPTION
        If -BackupId is not supplied, presents an interactive numbered list of all
        available backups using Show-Menu and prompts the user to select one.
        Requires explicit confirmation before overwriting the current GPO settings.
        Uses Restore-GPO to apply the selected backup.

    .PARAMETER BackupId
        Optional. GUID of the specific backup to restore. If omitted, an interactive
        picker is displayed.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject]@{ GpoName; BackupId; Status; Errors }

    .EXAMPLE
        Restore-GPOBackup

    .EXAMPLE
        Restore-GPOBackup -BackupId "{12345678-1234-1234-1234-123456789012}"
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$BackupId = '',

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) {
        return [PSCustomObject]@{
            GpoName  = ''; BackupId = $BackupId
            Status   = 'Failed'
            Errors   = @('GroupPolicy module not available. Install RSAT Group Policy Management Tools.')
        }
    }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain
    $BackupDir      = Join-Path $global:ReportsPath 'GPOBackups'
    $TargetBackup   = $null

    if (-not [string]::IsNullOrWhiteSpace($BackupId)) {
        $BackupList   = Get-GPOBackupList
        $TargetBackup = $BackupList | Where-Object { $_.BackupId -like "*$BackupId*" } | Select-Object -First 1
        if ($null -eq $TargetBackup) {
            Write-Host "[FAIL] No backup found with ID '$BackupId'." -ForegroundColor Red
            return [PSCustomObject]@{
                GpoName  = ''; BackupId = $BackupId
                Status   = 'Failed'
                Errors   = @("Backup ID '$BackupId' not found in '$BackupDir'.")
            }
        }
    } else {
        $BackupList = Get-GPOBackupList
        if ($BackupList.Count -eq 0) {
            return [PSCustomObject]@{
                GpoName  = ''; BackupId = ''
                Status   = 'Failed'
                Errors   = @('No backups available. Run Backup-ADPAGPO or Backup-AllGPOs first.')
            }
        }

        $MenuItems = @{}
        $LabelMap  = @{}
        $i = 1
        foreach ($B in $BackupList) {
            $Label           = "[$($B.BackupDate)]  $($B.GpoName)"
            $MenuItems[$i]   = $Label
            $LabelMap[$Label] = $B
            $i++
        }

        $SelectedLabel = Show-Menu -MenuName "Select Backup to Restore" -MenuItems $MenuItems
        if ([string]::IsNullOrEmpty($SelectedLabel)) {
            Write-Host "[INFO] Restore cancelled." -ForegroundColor Cyan
            return [PSCustomObject]@{
                GpoName  = ''; BackupId = ''
                Status   = 'Failed'
                Errors   = @('Restore cancelled by user.')
            }
        }

        $TargetBackup = $LabelMap[$SelectedLabel]
    }

    Write-Host ""
    Write-Host "[WARN] You are about to restore GPO '$($TargetBackup.GpoName)'." -ForegroundColor Yellow
    Write-Host "       Backup Date : $($TargetBackup.BackupDate)" -ForegroundColor Yellow
    Write-Host "       Backup ID   : $($TargetBackup.BackupId)" -ForegroundColor Yellow
    Write-Host "       This will OVERWRITE the current GPO settings." -ForegroundColor Yellow
    Write-Host ""
    $Confirm = Read-Host "Type YES to confirm restore"
    if ($Confirm -ne 'YES') {
        Write-Host "[INFO] Restore cancelled." -ForegroundColor Cyan
        return [PSCustomObject]@{
            GpoName  = $TargetBackup.GpoName; BackupId = $TargetBackup.BackupId
            Status   = 'Failed'
            Errors   = @('Restore cancelled by user.')
        }
    }

    try {
        Restore-GPO -BackupId $TargetBackup.BackupId -Path $BackupDir -Domain $ResolvedDomain -ErrorAction Stop | Out-Null
        Write-Host "[OK] GPO '$($TargetBackup.GpoName)' restored from backup $($TargetBackup.BackupId)." -ForegroundColor Green
        return [PSCustomObject]@{
            GpoName  = $TargetBackup.GpoName
            BackupId = $TargetBackup.BackupId
            Status   = 'Success'
            Errors   = @()
        }
    } catch {
        Write-Host "[FAIL] Restore failed: $_" -ForegroundColor Red
        return [PSCustomObject]@{
            GpoName  = $TargetBackup.GpoName
            BackupId = $TargetBackup.BackupId
            Status   = 'Failed'
            Errors   = @("Restore-GPO failed: $_")
        }
    }
}

Function Invoke-GPOModification {
    <#
    .SYNOPSIS
        Modifies an existing GPO with automatic pre-change backup.

    .DESCRIPTION
        Central wrapper for modifying existing Group Policy Objects safely.
        Before applying any changes, this function creates a full backup of the
        target GPO. If the backup fails the modification is aborted immediately --
        the function never silently continues after a failed backup.

        Use this function whenever an existing GPO needs to be modified. For new
        GPOs (which have no prior state to preserve) use New-ADPAGPO followed by
        Set-GPORegistrySetting directly.

    .PARAMETER GpoName
        Display name of the existing GPO to modify.

    .PARAMETER RegistrySettings
        Array of hashtables describing the registry-backed settings to apply.
        Each entry: @{Key='HKLM\...'; ValueName='...'; Type='DWord'; Value=1}

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [PSCustomObject]@{ GpoName; BackupId; BackupPath; Modified; Status; Errors }

    .EXAMPLE
        $Result = Invoke-GPOModification -GpoName "Default Domain Policy" `
            -RegistrySettings @(@{
                Key       = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
                ValueName = "NoLMHash"
                Type      = "DWord"
                Value     = 1
            })
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true)]
        [hashtable[]]$RegistrySettings,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    $Errors         = [System.Collections.Generic.List[string]]::new()
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if (-not (Test-GPOMgrPreFlight)) {
        return [PSCustomObject]@{
            GpoName    = $GpoName; BackupId = ''; BackupPath = ''; Modified = $false
            Status     = 'Failed'
            Errors     = @('GroupPolicy module not available. Install RSAT Group Policy Management Tools.')
        }
    }

    $Existing = Get-GPO -Name $GpoName -Domain $ResolvedDomain -ErrorAction SilentlyContinue
    if ($null -eq $Existing) {
        $Msg = "GPO '$GpoName' does not exist in domain '$ResolvedDomain'. Use New-ADPAGPO to create it first."
        Write-Host "[FAIL] $Msg" -ForegroundColor Red
        return [PSCustomObject]@{
            GpoName    = $GpoName; BackupId = ''; BackupPath = ''; Modified = $false
            Status     = 'Failed'
            Errors     = @($Msg)
        }
    }

    Write-Host "[INFO] Creating backup of GPO '$GpoName' before modification..." -ForegroundColor Cyan
    $BackupResult = Backup-ADPAGPO -GpoName $GpoName -Domain $ResolvedDomain
    if ($BackupResult.Status -ne 'Success') {
        $Msg = "Backup of GPO '$GpoName' failed. Modification aborted to protect current state."
        Write-Host "[FAIL] $Msg" -ForegroundColor Red
        return [PSCustomObject]@{
            GpoName    = $GpoName; BackupId = ''; BackupPath = ''; Modified = $false
            Status     = 'Failed'
            Errors     = (@($Msg) + $BackupResult.Errors)
        }
    }

    $Modified = $false
    foreach ($Setting in $RegistrySettings) {
        $Ok = Set-GPORegistrySetting -GpoName $GpoName -Domain $ResolvedDomain `
            -Key $Setting.Key -ValueName $Setting.ValueName `
            -Type $Setting.Type -Value $Setting.Value
        if ($Ok) {
            $Modified = $true
        } else {
            $Errors.Add("Failed to set registry value '$($Setting.ValueName)'.")
        }
    }

    $Status = if ($Errors.Count -eq 0) { 'Success' } elseif ($Modified) { 'Partial' } else { 'Failed' }

    return [PSCustomObject]@{
        GpoName    = $GpoName
        BackupId   = $BackupResult.BackupId
        BackupPath = $BackupResult.BackupPath
        Modified   = $Modified
        Status     = $Status
        Errors     = $Errors.ToArray()
    }
}



# ===========================================================================
# Removal Functions (Remove)
# ===========================================================================

Function Remove-GPORegistrySetting {
    <#
    .SYNOPSIS
        Removes a registry-backed policy setting from a named GPO.

    .DESCRIPTION
        Wraps Remove-GPRegistryValue. Idempotent -- returns $true if the setting is
        absent after the call whether or not it existed beforehand.
        Supports -WhatIf and -Confirm.

    .PARAMETER GpoName
        Display name of the target GPO.

    .PARAMETER Key
        Full registry key path.

    .PARAMETER ValueName
        Name of the registry value to remove.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if the setting is absent after the call.

    .EXAMPLE
        Remove-GPORegistrySetting -GpoName "My-GPO" `
            -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
            -ValueName "RequireSecuritySignature"
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [string]$ValueName,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if ($PSCmdlet.ShouldProcess("GPO '$GpoName'", "Remove registry value '$ValueName' at '$Key'")) {
        try {
            Remove-GPRegistryValue -Name $GpoName -Domain $ResolvedDomain `
                -Key $Key -ValueName $ValueName -ErrorAction Stop | Out-Null
            Write-Host "[OK] Removed '$ValueName' at '$Key' from GPO '$GpoName'." -ForegroundColor Green
            return $true
        } catch {
            # If the value was not present the cmdlet may throw; treat that as success.
            if ($_.Exception.Message -like "*not found*" -or $_.Exception.Message -like "*does not exist*") {
                Write-Host "[OK] Registry value '$ValueName' was not present in GPO '$GpoName' (nothing to remove)." -ForegroundColor Green
                return $true
            }
            Write-Host "[FAIL] Failed to remove registry value from GPO '$GpoName': $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

Function Remove-GPOLink {
    <#
    .SYNOPSIS
        Removes a GPO link from a target OU, domain, or site without deleting the GPO.

    .DESCRIPTION
        Idempotent -- returns $true if the link is absent after the call whether or not
        it existed beforehand. Supports -WhatIf and -Confirm.

    .PARAMETER GpoName
        Display name of the GPO whose link should be removed.

    .PARAMETER Target
        Distinguished name of the linked OU or domain, or site name.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if the link is absent after the call.

    .EXAMPLE
        Remove-GPOLink -GpoName "My-GPO" -Target "OU=Servers,DC=corp,DC=local"
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$GpoName,

        [Parameter(Mandatory=$true, Position=2)]
        [string]$Target,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    if ($PSCmdlet.ShouldProcess("Target '$Target'", "Remove link for GPO '$GpoName'")) {
        try {
            Remove-GPLink -Name $GpoName -Target $Target -Domain $ResolvedDomain -ErrorAction Stop | Out-Null
            Write-Host "[OK] Removed link of GPO '$GpoName' from '$Target'." -ForegroundColor Green
            return $true
        } catch {
            if ($_.Exception.Message -like "*not linked*" -or $_.Exception.Message -like "*does not exist*") {
                Write-Host "[OK] GPO '$GpoName' was not linked to '$Target' (nothing to remove)." -ForegroundColor Green
                return $true
            }
            Write-Host "[FAIL] Failed to remove link for GPO '$GpoName' from '$Target': $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

Function Remove-ADPAGPO {
    <#
    .SYNOPSIS
        Deletes a Group Policy Object using a safe confirmation workflow.

    .DESCRIPTION
        Before deleting, this function:
          1. Verifies the GPO exists.
          2. Counts and displays all active links.
          3. Refuses to delete a linked GPO unless -RemoveLinks is specified.
          4. Exports an HTML and XML report when -ExportBeforeDelete is set,
             or automatically when the GPO has active links.
          5. Removes links if -RemoveLinks is specified.
          6. Requires explicit confirmation before deletion.
        Supports -WhatIf and -Confirm.

    .PARAMETER Name
        Display name of the GPO to delete.

    .PARAMETER RemoveLinks
        If specified, all active links are removed before the GPO is deleted.

    .PARAMETER ExportBeforeDelete
        If specified, an HTML and XML report is exported before deletion.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if the GPO is absent after the call.

    .EXAMPLE
        Remove-ADPAGPO -Name "Old-Policy" -ExportBeforeDelete -Confirm:$true

    .EXAMPLE
        Remove-ADPAGPO -Name "Old-Policy" -RemoveLinks -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        [switch]$RemoveLinks,

        [Parameter(Mandatory=$false)]
        [switch]$ExportBeforeDelete,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if (-not (Test-GPOMgrPreFlight)) { return $false }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    # Verify existence
    try {
        $Gpo = Get-GPO -Name $Name -Domain $ResolvedDomain -ErrorAction Stop
    } catch {
        Write-Host "[OK] GPO '$Name' does not exist (nothing to delete)." -ForegroundColor Green
        return $true
    }

    # Find all links
    $LinkedTargets = @()
    try {
        $AllOUs = Get-ADOrganizationalUnit -Filter * -ErrorAction SilentlyContinue
        foreach ($OU in $AllOUs) {
            $Inheritance = Get-GPInheritance -Target $OU.DistinguishedName -Domain $ResolvedDomain -ErrorAction SilentlyContinue
            if ($null -ne $Inheritance) {
                $Match = $Inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $Name }
                if ($null -ne $Match) { $LinkedTargets += $OU.DistinguishedName }
            }
        }
    } catch { }

    if ($LinkedTargets.Count -gt 0) {
        Write-Host "[WARN] GPO '$Name' is linked to $($LinkedTargets.Count) location(s):" -ForegroundColor Yellow
        $LinkedTargets | ForEach-Object { Write-Host "       - $_" -ForegroundColor Yellow }

        if (-not $RemoveLinks) {
            Write-Host "[FAIL] Cannot delete a linked GPO without -RemoveLinks. Add the -RemoveLinks switch to remove all links before deletion." -ForegroundColor Red
            return $false
        }
    }

    # Export report if requested or if GPO has links
    if ($ExportBeforeDelete -or $LinkedTargets.Count -gt 0) {
        Write-Host "[INFO] Exporting GPO report before deletion..." -ForegroundColor Cyan
        Export-GPOReport -GpoName $Name -ReportType Both -Domain $ResolvedDomain | Out-Null
    }

    if ($PSCmdlet.ShouldProcess("Domain '$ResolvedDomain'", "Delete GPO '$Name'")) {
        # Remove links first if requested
        if ($RemoveLinks -and $LinkedTargets.Count -gt 0) {
            foreach ($Target in $LinkedTargets) {
                Remove-GPOLink -GpoName $Name -Target $Target -Domain $ResolvedDomain -Confirm:$false | Out-Null
            }
        }

        try {
            Remove-GPO -Guid $Gpo.Id -Domain $ResolvedDomain -Confirm:$false -ErrorAction Stop
            Write-Host "[OK] GPO '$Name' deleted." -ForegroundColor Green
            return $true
        } catch {
            Write-Host "[FAIL] Failed to delete GPO '$Name': $_" -ForegroundColor Red
            return $false
        }
    }
    return $false
}

Function Remove-GPOBaseline {
    <#
    .SYNOPSIS
        Removes a GPO that was deployed from a definition hashtable.

    .DESCRIPTION
        Extracts the GPO name from the supplied $GpoDefinition and delegates to
        Remove-ADPAGPO. Supports -WhatIf and -Confirm.

    .PARAMETER GpoDefinition
        The same hashtable that was passed to Install-GPOBaseline.
        Must contain a 'Name' key.

    .PARAMETER RemoveLinks
        If specified, all active links are removed before the GPO is deleted.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if the GPO is absent after the call.

    .EXAMPLE
        Remove-GPOBaseline -GpoDefinition $Definition -RemoveLinks
    #>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
    Param(
        [Parameter(Mandatory=$true, Position=1)]
        [hashtable]$GpoDefinition,

        [Parameter(Mandatory=$false)]
        [switch]$RemoveLinks,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )

    if ([string]::IsNullOrWhiteSpace($GpoDefinition['Name'])) {
        Write-Host "[FAIL] GpoDefinition.Name is required." -ForegroundColor Red
        return $false
    }

    return Remove-ADPAGPO -Name $GpoDefinition['Name'] -RemoveLinks:$RemoveLinks -Domain $Domain
}

Function Show-GPOMgrHelp {
    <#
    .SYNOPSIS
        Displays a plain-language guide to GPO backup and restore in this module.

    .DESCRIPTION
        Prints a formatted help screen explaining what GPO backups are, where they
        are stored, how to create and list them, how to restore, and how the
        automatic pre-modification backup safety contract works.

    .EXAMPLE
        Show-GPOMgrHelp
    #>
    [CmdletBinding()]
    Param()

    $Sep = '=' * 82

    Write-Host ""
    Write-Host $Sep -ForegroundColor Cyan
    Write-Host "  GPO MANAGER -- BACKUP AND RESTORE GUIDE" -ForegroundColor Cyan
    Write-Host $Sep -ForegroundColor Cyan
    Write-Host ""

    Write-Host "WHAT IS A GPO BACKUP?" -ForegroundColor Yellow
    Write-Host "  A GPO backup is a complete copy of a Group Policy Object saved to disk."
    Write-Host "  It captures all settings at the time of the backup so the GPO can be"
    Write-Host "  restored exactly as it was if settings are accidentally changed or deleted."
    Write-Host ""

    Write-Host "WHERE ARE BACKUPS STORED?" -ForegroundColor Yellow
    Write-Host "  All backups are saved in the AD-PowerAdmin Reports directory:"
    Write-Host "    $($global:ReportsPath)\GPOBackups\" -ForegroundColor Cyan
    Write-Host "  Each backup is a GUID-named subfolder containing the full GPO content."
    Write-Host ""

    Write-Host "HOW TO BACK UP" -ForegroundColor Yellow
    Write-Host "  Backup All GPOs  -- Creates a backup of every GPO in the domain at once."
    Write-Host "                      Use this before making any domain-wide policy changes."
    Write-Host ""
    Write-Host "  Backup a GPO     -- Prompts you to select a single GPO by name and backs"
    Write-Host "                      up only that one. Use this before editing a specific GPO."
    Write-Host ""

    Write-Host "HOW TO LIST AVAILABLE BACKUPS" -ForegroundColor Yellow
    Write-Host "  List GPO Backups -- Reads the backup directory and shows a table with:"
    Write-Host "    GpoName    - The display name of the backed-up GPO."
    Write-Host "    BackupDate - When the backup was taken."
    Write-Host "    BackupId   - The unique ID of this specific backup copy."
    Write-Host ""

    Write-Host "HOW TO RESTORE" -ForegroundColor Yellow
    Write-Host "  Restore a GPO    -- Shows a numbered list of all available backups."
    Write-Host "                      Select the one you want, then type YES to confirm."
    Write-Host "                      The selected backup overwrites the current GPO settings."
    Write-Host ""
    Write-Host "  IMPORTANT: Restore overwrites the current live GPO. The domain will apply"
    Write-Host "  the restored settings to all affected computers on the next Group Policy"
    Write-Host "  refresh (typically within 90 minutes, or immediately via gpupdate)."
    Write-Host ""

    Write-Host "AUTOMATIC BACKUPS" -ForegroundColor Yellow
    Write-Host "  When AD-PowerAdmin modules modify an existing GPO, a backup is created"
    Write-Host "  automatically before any change is applied. If the backup fails, the"
    Write-Host "  modification is cancelled -- your GPO is never changed without a restore"
    Write-Host "  point first."
    Write-Host ""

    Write-Host $Sep -ForegroundColor Cyan
    Write-Host ""
}

Initialize-Module
