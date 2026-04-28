#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory

Function Initialize-Module {
    <#
    .SYNOPSIS
        Satisfies the AD-PowerAdmin module load contract. Registers no menu items.

    .DESCRIPTION
        This module is a shared infrastructure library for other AD-PowerAdmin modules.
        It exposes no interactive menu entries. All functions are called programmatically
        by modules that require GPO management capabilities.

    .EXAMPLE
        Initialize-Module
    #>
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

Function Get-ResolvedDomain {
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )
    # Returns the caller-supplied domain, or falls back to the current user's domain.
    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        return $Domain
    }
    return $env:USERDNSDOMAIN
}

Function Get-GPOXmlReport {
    param(
        [Parameter(Mandatory=$true)]
        [string]$GpoName,

        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )
    # Generates an in-memory XML report for the named GPO.
    # Returns [xml] or $null if the GPO does not exist or the report fails.
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain
    $TempFile = [System.IO.Path]::GetTempFileName() + ".xml"
    try {
        Get-GPOReport -Name $GpoName -Domain $ResolvedDomain -ReportType Xml -Path $TempFile -ErrorAction Stop
        [xml]$Report = Get-Content -Path $TempFile -Raw -ErrorAction Stop
        return $Report
    } catch {
        return $null
    } finally {
        if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
    }
}

# ===========================================================================
# Public Exported Functions
# ===========================================================================

Function Find-ADPAGPO {
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
        Find-ADPAGPO -Name "My-GPO"

    .EXAMPLE
        Find-ADPAGPO -Pattern "*Signing*"
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

Function Test-ADPAGPO {
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
        Test-ADPAGPO -Name "My-GPO" -Links @("OU=Servers,DC=corp,DC=local")

    .EXAMPLE
        $ok = Test-ADPAGPO -Name "My-GPO" -Quiet
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

    # Check registry settings via XML report
    if ($RegistrySettings.Count -gt 0) {
        $XmlReport = Get-GPOXmlReport -GpoName $Name -Domain $ResolvedDomain
        if ($null -eq $XmlReport) {
            if (-not $Quiet) { Write-Host "[FAIL] Could not generate XML report for GPO '$Name'." -ForegroundColor Red }
            $AllPass = $false
        } else {
            $Ns = New-Object System.Xml.XmlNamespaceManager($XmlReport.NameTable)
            $Ns.AddNamespace("q", "http://www.microsoft.com/GroupPolicy/Settings/Registry")

            foreach ($Setting in $RegistrySettings) {
                $ExpectedKey   = $Setting.Key
                $ExpectedValue = $Setting.ValueName
                $Found = $false

                $RegNodes = $XmlReport.SelectNodes("//q:RegistrySetting", $Ns)
                if ($null -ne $RegNodes) {
                    foreach ($Node in $RegNodes) {
                        $KeyNode  = $Node.SelectSingleNode("q:KeyPath", $Ns)
                        $ValNode  = $Node.SelectSingleNode("q:ValueName", $Ns)
                        if ($null -ne $KeyNode -and $null -ne $ValNode) {
                            if ($KeyNode.InnerText -like "*$($ExpectedKey.TrimStart('HKLM\').TrimStart('HKCU\'))*" -and
                                $ValNode.InnerText -eq $ExpectedValue) {
                                $Found = $true
                                break
                            }
                        }
                    }
                }

                if ($Found) {
                    if (-not $Quiet) { Write-Host "[PASS] Registry setting '$ExpectedValue' found under '$ExpectedKey'." -ForegroundColor Green }
                } else {
                    if (-not $Quiet) { Write-Host "[FAIL] Registry setting '$ExpectedValue' under '$ExpectedKey' not found in GPO '$Name'." -ForegroundColor Red }
                    $AllPass = $false
                }
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

        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    if (-not (Test-GPOMgrPreFlight)) { return $null }
    $ResolvedDomain = Get-ResolvedDomain -Domain $Domain

    # Idempotency check
    $Existing = Get-GPO -Name $Name -Domain $ResolvedDomain -ErrorAction SilentlyContinue
    if ($null -ne $Existing) {
        if (-not $Force) {
            Write-Host "[OK] GPO '$Name' already exists. Returning existing object." -ForegroundColor Green
        }
        return $Existing
    }

    if ($PSCmdlet.ShouldProcess("Domain '$ResolvedDomain'", "Create GPO '$Name'")) {
        try {
            $NewGpo = New-GPO -Name $Name -Comment $Description -Domain $ResolvedDomain -ErrorAction Stop
            Write-Host "[OK] GPO '$Name' created successfully." -ForegroundColor Green
            return $NewGpo
        } catch {
            Write-Host "[FAIL] Failed to create GPO '$Name': $_" -ForegroundColor Red
            return $null
        }
    }
    return $null
}

Function Set-ADPAGPORegistrySetting {
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
        Set-ADPAGPORegistrySetting -GpoName "My-GPO" `
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

Function Remove-ADPAGPORegistrySetting {
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
        Remove-ADPAGPORegistrySetting -GpoName "My-GPO" `
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

Function Add-ADPAGPOLink {
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
        Add-ADPAGPOLink -GpoName "My-GPO" -Target "OU=Servers,DC=corp,DC=local"

    .EXAMPLE
        Add-ADPAGPOLink -GpoName "My-GPO" -Target "OU=Servers,DC=corp,DC=local" -Enforced Yes
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

Function Remove-ADPAGPOLink {
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
        Remove-ADPAGPOLink -GpoName "My-GPO" -Target "OU=Servers,DC=corp,DC=local"
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

Function Set-ADPAGPOPermission {
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
        Set-ADPAGPOPermission -GpoName "My-GPO" -TargetName "Domain Computers" `
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

Function Export-ADPAGPOReport {
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
        Export-ADPAGPOReport -GpoName "My-GPO"

    .EXAMPLE
        Export-ADPAGPOReport -GpoName "My-GPO" -ReportType Html
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
        Export-ADPAGPOReport -GpoName $Name -ReportType Both -Domain $ResolvedDomain | Out-Null
    }

    if ($PSCmdlet.ShouldProcess("Domain '$ResolvedDomain'", "Delete GPO '$Name'")) {
        # Remove links first if requested
        if ($RemoveLinks -and $LinkedTargets.Count -gt 0) {
            foreach ($Target in $LinkedTargets) {
                Remove-ADPAGPOLink -GpoName $Name -Target $Target -Domain $ResolvedDomain -Confirm:$false | Out-Null
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

Function Install-ADPAGPOBaseline {
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
        $Result = Install-ADPAGPOBaseline -GpoDefinition $Definition
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
            $Ok = Set-ADPAGPORegistrySetting -GpoName $GpoName -Domain $ResolvedDomain `
                -Key $Setting.Key -ValueName $Setting.ValueName `
                -Type $Setting.Type -Value $Setting.Value
            if ($Ok) { $Modified = $true } else { $Errors.Add("Failed to set registry value '$($Setting.ValueName)'.") }
        }
    }

    # Apply permissions
    if ($GpoDefinition.ContainsKey('Permissions') -and $GpoDefinition['Permissions'].Count -gt 0) {
        foreach ($Perm in $GpoDefinition['Permissions']) {
            $Ok = Set-ADPAGPOPermission -GpoName $GpoName -Domain $ResolvedDomain `
                -TargetName $Perm.TargetName -TargetType $Perm.TargetType `
                -PermissionLevel $Perm.PermissionLevel
            if ($Ok) { $Modified = $true } else { $Errors.Add("Failed to set permission for '$($Perm.TargetName)'.") }
        }
    }

    # Link to targets
    if ($GpoDefinition.ContainsKey('Links') -and $GpoDefinition['Links'].Count -gt 0) {
        foreach ($Target in $GpoDefinition['Links']) {
            $Ok = Add-ADPAGPOLink -GpoName $GpoName -Target $Target -Domain $ResolvedDomain
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

Function Remove-ADPAGPOBaseline {
    <#
    .SYNOPSIS
        Removes a GPO that was deployed from a definition hashtable.

    .DESCRIPTION
        Extracts the GPO name from the supplied $GpoDefinition and delegates to
        Remove-ADPAGPO. Supports -WhatIf and -Confirm.

    .PARAMETER GpoDefinition
        The same hashtable that was passed to Install-ADPAGPOBaseline.
        Must contain a 'Name' key.

    .PARAMETER RemoveLinks
        If specified, all active links are removed before the GPO is deleted.

    .PARAMETER Domain
        Target domain. Defaults to the current user's domain.

    .OUTPUTS
        [bool] -- $true if the GPO is absent after the call.

    .EXAMPLE
        Remove-ADPAGPOBaseline -GpoDefinition $Definition -RemoveLinks
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

Function Search-ADPAGPOSetting {
    <#
    .SYNOPSIS
        Scans GPOs in the domain for a specific registry key or value.

    .DESCRIPTION
        Iterates all GPOs (or a filtered subset) and parses each GPO's XML report to
        find registry-backed settings matching the supplied key and optional value name.

        Use this before deploying a new GPO to detect existing policies that already
        enforce the same registry setting, preventing duplicate or conflicting configurations.

        Note: scanning all GPOs via XML reports can be slow on large domains. A progress
        message is displayed before the scan begins.

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
        Search-ADPAGPOSetting -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
            -ValueName "RequireSecuritySignature"

    .EXAMPLE
        Search-ADPAGPOSetting -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" `
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

    # Normalize the key for comparison -- strip the hive prefix and backslash-normalize
    $NormalizedSearchKey = $Key.TrimStart('HKLM\').TrimStart('HKCU\').TrimStart('HKLM/').TrimStart('HKCU/').ToLower()

    $Results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Ns = New-Object System.Xml.XmlNamespaceManager([System.Xml.XmlNameTable](New-Object System.Xml.NameTable))
    $Ns.AddNamespace("q", "http://www.microsoft.com/GroupPolicy/Settings/Registry")

    foreach ($Gpo in $AllGpos) {
        if (-not $Force) {
            Write-Host "  Scanning: $($Gpo.DisplayName)" -ForegroundColor DarkGray
        }

        $TempFile = [System.IO.Path]::GetTempFileName() + ".xml"
        try {
            Get-GPOReport -Guid $Gpo.Id -Domain $ResolvedDomain -ReportType Xml -Path $TempFile -ErrorAction Stop
            [xml]$XmlReport = Get-Content -Path $TempFile -Raw -ErrorAction Stop
        } catch {
            continue
        } finally {
            if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
        }

        $RegNodes = $XmlReport.SelectNodes("//q:RegistrySetting", $Ns)
        if ($null -eq $RegNodes) { continue }

        foreach ($Node in $RegNodes) {
            $KeyNode   = $Node.SelectSingleNode("q:KeyPath", $Ns)
            $ValNode   = $Node.SelectSingleNode("q:ValueName", $Ns)
            $DataNode  = $Node.SelectSingleNode("q:Value/q:String", $Ns)
            if ($null -eq $DataNode) { $DataNode = $Node.SelectSingleNode("q:Value/q:Number", $Ns) }

            if ($null -eq $KeyNode) { continue }

            $NodeKey = $KeyNode.InnerText.ToLower()
            if ($NodeKey -notlike "*$NormalizedSearchKey*") { continue }

            $NodeValueName = if ($null -ne $ValNode) { $ValNode.InnerText } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($ValueName) -and $NodeValueName -ne $ValueName) { continue }

            $ActualValue = if ($null -ne $DataNode) { $DataNode.InnerText } else { $null }
            $Matches = if ($null -eq $ExpectedValue) { $true } else { $ActualValue -eq [string]$ExpectedValue }

            $Results.Add([PSCustomObject]@{
                GpoName     = $Gpo.DisplayName
                GpoId       = $Gpo.Id
                Key         = $KeyNode.InnerText
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

Initialize-Module
