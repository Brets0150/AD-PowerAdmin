#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    AD-PowerAdmin SMB Admin Share Audit module.
.DESCRIPTION
    Audits, detects, reports, and safely remediates SMB Windows administrative share abuse
    (ATT&CK T1021.002) in Active Directory environments.
    Checks: hidden share inventory, AutoShare registry policy, inbound SMB firewall exposure,
    local Administrator group membership, Windows LAPS coverage, and Security event log
    evidence of admin share access from unapproved sources.
    Includes a staged, confirmation-gated remediation workflow with JSON backup and rollback.
#>

##############################################################################
# Private helpers
##############################################################################

Function Get-SmbHostType {
    <#
    .SYNOPSIS
        Classify an AD computer as DomainController, Server, or Workstation.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ComputerName,
        [Parameter(Mandatory=$False)]
        [string]$OperatingSystem = '',
        [Parameter(Mandatory=$False)]
        [bool]$IsDC = $false
    )
    If ($IsDC) { Return 'DomainController' }
    If ($OperatingSystem -match 'Server') { Return 'Server' }
    Return 'Workstation'
}

Function New-SmbFinding {
    <#
    .SYNOPSIS
        Factory for a consistent SMB finding object.
    #>
    [CmdletBinding()]
    Param(
        [string]$ComputerName      = '',
        [string]$HostType          = '',
        [string]$FindingCategory   = '',
        [string]$Severity          = 'Informational',
        [string]$Evidence          = '',
        [string]$Risk              = '',
        [string]$Recommendation    = '',
        [string]$QueryStatus       = 'OK'
    )
    [PSCustomObject]@{
        ComputerName    = $ComputerName
        HostType        = $HostType
        FindingCategory = $FindingCategory
        Severity        = $Severity
        Evidence        = $Evidence
        Risk            = $Risk
        Recommendation  = $Recommendation
        QueryStatus     = $QueryStatus
    }
}

Function Save-SmbRemediationBackup {
    <#
    .SYNOPSIS
        Serialize pre-change state to a timestamped JSON file in ReportsPath.
        Returns the backup file path.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$StageNumber,
        [Parameter(Mandatory=$True)]
        [object[]]$Changes
    )
    $Timestamp  = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $BackupFile = Join-Path $global:ReportsPath "SmbAdminShare-Backup_Stage${StageNumber}_${Timestamp}.json"
    $Payload = [PSCustomObject]@{
        StageNumber = $StageNumber
        Timestamp   = $Timestamp
        Changes     = $Changes
    }
    $Payload | ConvertTo-Json -Depth 10 | Out-File -FilePath $BackupFile -Encoding UTF8 -Force
    Return $BackupFile
}

Function Write-SmbSectionHeader {
    <#
    .SYNOPSIS
        Print a formatted ASCII section header to the console.
    #>
    Param([string]$Title)
    $Line = '=' * 80
    Write-Host ''
    Write-Host $Line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $Line -ForegroundColor Cyan
}

Function Write-SmbFindingsSummary {
    <#
    .SYNOPSIS
        Print a standardized risk findings summary after one audit check.
    .DESCRIPTION
        Separates risk findings (non-Informational, successfully queried) from
        unreachable-host records and informational records. Prints a colour-coded
        result line and a findings table, then notes unreachable and informational
        counts. Call once at the end of each sub-audit function.
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [string]$CheckName,
        [Parameter(Mandatory=$True)]
        [AllowEmptyCollection()]
        [object[]]$Findings,
        [Parameter(Mandatory=$False)]
        [string[]]$DetailColumns = @('ComputerName','HostType','FindingCategory','Severity','Evidence')
    )

    $SevOrder     = @('Critical','High','Medium','Low')
    $RiskFindings = @($Findings | Where-Object {
        $_.QueryStatus -eq 'OK' -and
        $_.Severity -notin @('Informational',$null,'') -and
        -not [string]::IsNullOrWhiteSpace($_.FindingCategory)
    })
    $InfoCount   = @($Findings | Where-Object { $_.QueryStatus -eq 'OK' -and $_.Severity -eq 'Informational' }).Count
    $Unreachable = @($Findings | Where-Object { $_.QueryStatus -like 'UnableToQuery*' })

    $Parts = ForEach ($Sev in $SevOrder) {
        $n = @($RiskFindings | Where-Object { $_.Severity -eq $Sev }).Count
        If ($n -gt 0) { "$n $Sev" }
    }

    If ($RiskFindings.Count -gt 0) {
        $SevColor = If (@($RiskFindings | Where-Object { $_.Severity -eq 'Critical' }).Count -gt 0) {
            'Red'
        } ElseIf (@($RiskFindings | Where-Object { $_.Severity -eq 'High' }).Count -gt 0) {
            'Yellow'
        } Else { 'Cyan' }
        Write-Host "[RESULT] $CheckName -- $($Parts -join ', ')" -ForegroundColor $SevColor
        $RiskFindings | Sort-Object { $SevOrder.IndexOf($_.Severity) } |
            Format-Table $DetailColumns -AutoSize -Wrap
    } Else {
        Write-Host "[OK] $CheckName -- No risk findings on reachable hosts." -ForegroundColor Green
    }

    If ($Unreachable.Count -gt 0) {
        Write-Host "[INFO] $($Unreachable.Count) host(s) unreachable via WinRM -- connectivity gap, not a security finding." -ForegroundColor DarkYellow
    }
    If ($InfoCount -gt 0) {
        Write-Host "[INFO] $InfoCount Informational record(s) (no action required)." -ForegroundColor DarkGray
    }
    Write-Host ''
}

Function Get-SmbDcList {
    <#
    .SYNOPSIS
        Return a hashtable keyed by computer name for all DCs in the domain.
    #>
    $DcHash = @{}
    Try {
        Get-ADDomainController -Filter * -ErrorAction Stop | ForEach-Object {
            $DcHash[$_.Name.ToUpper()] = $true
        }
    } Catch {
        Write-Warning "[WARN] Could not enumerate domain controllers: $($_.Exception.Message)"
    }
    Return $DcHash
}

##############################################################################
# Initialize-Module
##############################################################################

Function Initialize-Module {
    $global:Menu.Remove('SmbAdminShareAuditMenu')
    $global:SubMenus.Remove('SmbAdminShareAuditMenu')
    $global:UnattendedJobs.Remove('SmbAdminShareDailyAudit')

    $global:SubMenus += @{
        'SmbAdminShareAuditMenu' = @{
            Title = 'SMB Admin Share Audit'
            Items = @{
                'SmbShareInventory' = @{
                    Title   = 'Share Inventory'
                    Label   = 'Enumerate hidden SMB administrative shares (ADMIN$, C$, IPC$) on all enabled AD computers via WinRM. Classifies each host as Workstation, Server, or DomainController.'
                    Command = 'Get-ADAdminShareInventory'
                }
                'SmbRegistryPolicy' = @{
                    Title   = 'AutoShare Registry'
                    Label   = 'Check AutoShareWks and AutoShareServer registry values on all computers. A missing value means default-enabled -- admin shares will recreate after a service restart.'
                    Command = 'Test-ADAdminShareRegistryPolicy'
                }
                'SmbFirewallExposure' = @{
                    Title   = 'Firewall Exposure'
                    Label   = 'Audit inbound SMB firewall rules (ports 445/139). Flags broad workstation access (High) and DC reachability from non-admin networks (Critical).'
                    Command = 'Test-ADSMBFirewallExposure'
                }
                'SmbLocalAdminExposure' = @{
                    Title   = 'Local Admin Exposure'
                    Label   = 'Enumerate local Administrators on all computers via WinRM. Flags Domain Users, broad domain groups, service accounts, and unapproved domain accounts.'
                    Command = 'Get-ADLocalAdminExposure'
                }
                'SmbLapsCoverage' = @{
                    Title   = 'LAPS Coverage'
                    Label   = 'Query AD for Windows LAPS and legacy LAPS attributes. Flags computers with no LAPS (High), stale passwords (Medium), or partial domain-wide coverage (Medium). No WinRM required.'
                    Command = 'Test-ADLAPSCoverage'
                }
                'SmbAccessEvents' = @{
                    Title   = 'Access Event Search'
                    Label   = 'Search Security event logs on DCs and servers for Event IDs 5140 and 5145. Flags admin share access from unapproved sources within the last 24 hours.'
                    Command = 'Search-ADAdminShareAccessEvents'
                }
                'SmbFullAudit' = @{
                    Title   = 'Full SMB Audit'
                    Label   = 'Run all six SMB admin share audit checks in sequence and export a consolidated findings CSV and text report.'
                    Command = 'Invoke-ADAdminShareExposureAudit'
                }
                'SmbRemediate' = @{
                    Title   = 'Safe Remediation'
                    Label   = 'Staged, confirmation-gated remediation: Stage 1 removes unapproved local admins (per-item), Stage 2 restricts firewall rules (CONFIRM), Stage 3 sets AutoShare registry to 0 (CONFIRM).'
                    Command = "Invoke-ADAdminShareSafeRemediation -Mode RemediateWithPrompt"
                }
                'SmbRollback' = @{
                    Title   = 'Rollback Changes'
                    Label   = 'Read a remediation backup JSON file and restore prior firewall rules, registry values, and local group membership. Shows a diff before restoring.'
                    Command = 'Restore-ADAdminShareRemediationBackup'
                }
            }
        }
    }

    $global:Menu += @{
        'SmbAdminShareAuditMenu' = @{
            Title    = 'SMB Admin Share Audit'
            Label    = 'Audit and remediate SMB administrative share abuse risks (ATT&CK T1021.002): share inventory, firewall exposure, LAPS coverage, local admin excess, and event log detection.'
            Module   = 'AD-PowerAdmin_SmbAdminShareAudit'
            Function = 'Enter-SubMenu'
            Command  = "Enter-SubMenu 'SmbAdminShareAuditMenu'"
        }
    }

    $global:UnattendedJobs += @{
        'SmbAdminShareDailyAudit' = @{
            Title    = 'SMB Admin Share Daily Audit'
            Label    = 'Daily unattended SMB admin share exposure audit. Controlled by SmbAdminShareAudit in AD-PowerAdmin_settings.ps1.'
            Module   = 'AD-PowerAdmin_SmbAdminShareAudit'
            Function = 'Invoke-ADAdminShareExposureAudit'
            Daily    = $global:SmbAdminShareAudit
            Command  = 'Invoke-ADAdminShareExposureAudit -Force'
        }
    }
}

Initialize-Module

##############################################################################
# Test-ADLAPSCoverage
##############################################################################

Function Test-ADLAPSCoverage {
    <#
    .SYNOPSIS
        Query AD for Windows LAPS and legacy LAPS attributes on all enabled computers.
    .DESCRIPTION
        Checks msLAPS-PasswordExpirationTime (Windows LAPS 2023+) and
        ms-Mcs-AdmPwdExpirationTime (legacy Microsoft LAPS) on every enabled
        computer object. Flags missing LAPS (High), stale expiration (Medium),
        and partial domain-wide deployment (Medium). No WinRM required.
    .PARAMETER StaleThresholdDays
        Days past expiration before a LAPS record is flagged stale. Defaults to
        the global SmbLapsExpiredDays setting.
    .PARAMETER Force
        Suppress the export confirmation prompt.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$StaleThresholdDays = $global:SmbLapsExpiredDays,
        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-SmbSectionHeader 'LAPS Coverage Audit'

    $Findings   = [System.Collections.Generic.List[object]]::new()
    $DcHash     = Get-SmbDcList
    $TotalCount = 0
    $CoveredCount = 0

    # Probe each LAPS attribute with a single-result test query. Get-ADComputer throws when
    # a requested property does not exist in the schema, so we must check before querying all.
    $SchemaWinLaps    = $false
    $SchemaLegacyLaps = $false
    $WinLapsAttr      = 'msLAPS-PasswordExpirationTime'
    $LegLapsAttr      = 'ms-Mcs-AdmPwdExpirationTime'

    Try {
        $null = Get-ADComputer -Filter 'Enabled -eq $true' -Properties $WinLapsAttr `
            -ResultSetSize 1 -ErrorAction Stop
        $SchemaWinLaps = $true
    } Catch { }

    Try {
        $null = Get-ADComputer -Filter 'Enabled -eq $true' -Properties $LegLapsAttr `
            -ResultSetSize 1 -ErrorAction Stop
        $SchemaLegacyLaps = $true
    } Catch { }

    # Build property list from what is actually present in the schema.
    $LapsQueryProps = @('Name', 'OperatingSystem')
    If ($SchemaWinLaps)    { $LapsQueryProps += $WinLapsAttr }
    If ($SchemaLegacyLaps) { $LapsQueryProps += $LegLapsAttr }

    Try {
        $Computers = Get-ADComputer -Filter 'Enabled -eq $true' `
            -Properties $LapsQueryProps -ErrorAction Stop
    } Catch {
        Write-Warning "[WARN] Could not query AD computers: $($_.Exception.Message)"
        Return $Findings
    }

    If (-not $SchemaWinLaps -and -not $SchemaLegacyLaps) {
        $Findings.Add((New-SmbFinding `
            -ComputerName  'DOMAIN' `
            -HostType       'Domain' `
            -FindingCategory 'LAPSNotDeployed' `
            -Severity       'Critical' `
            -Evidence       'Neither msLAPS-PasswordExpirationTime nor ms-Mcs-AdmPwdExpirationTime exists in the AD schema.' `
            -Risk           'No LAPS deployment means local administrator passwords are likely shared, reused, or unmanaged across all computers.' `
            -Recommendation 'Deploy Windows LAPS (built into Windows Server 2022 / Windows 11 22H2) or legacy Microsoft LAPS to all domain computers.'
        ))
        Write-Host '[FAIL] LAPS schema attributes not found. LAPS is not deployed.' -ForegroundColor Red
        If (-not $Force) {
            Export-AdPowerAdminData -Data $Findings -ReportName 'SMB-LAPSCoverage-Audit'
        } Else {
            Export-AdPowerAdminData -Data $Findings -ReportName 'SMB-LAPSCoverage-Audit' -Force
        }
        Return $Findings
    }

    $Now = Get-Date

    ForEach ($Computer in $Computers) {
        $TotalCount++
        $HostType = Get-SmbHostType -ComputerName $Computer.Name `
            -OperatingSystem $Computer.OperatingSystem `
            -IsDC ($DcHash.ContainsKey($Computer.Name.ToUpper()))

        # Prefer Windows LAPS attribute; fall back to legacy LAPS.
        $LapsValue     = $null
        $LapsAttrName  = ''
        $WinLapsVal    = $Computer.'msLAPS-PasswordExpirationTime'
        $LegacyLapsVal = $Computer.'ms-Mcs-AdmPwdExpirationTime'

        If ($null -ne $WinLapsVal -and $WinLapsVal -ne 0) {
            $LapsValue    = $WinLapsVal
            $LapsAttrName = 'msLAPS-PasswordExpirationTime'
        } ElseIf ($null -ne $LegacyLapsVal -and $LegacyLapsVal -ne 0) {
            $LapsValue    = $LegacyLapsVal
            $LapsAttrName = 'ms-Mcs-AdmPwdExpirationTime'
        }

        If ($null -eq $LapsValue -or $LapsValue -eq 0) {
            # Severity: High for workstations/servers; Medium for DCs (different local admin model).
            $Sev = If ($HostType -eq 'DomainController') { 'Medium' } Else { 'High' }
            $Findings.Add((New-SmbFinding `
                -ComputerName    $Computer.Name `
                -HostType        $HostType `
                -FindingCategory 'MissingLAPS' `
                -Severity        $Sev `
                -Evidence        'No LAPS expiration attribute found on this computer object.' `
                -Risk            'Local administrator password is likely shared or unmanaged. Pass-the-hash and credential reuse are viable lateral movement paths.' `
                -Recommendation  'Enroll this computer in Windows LAPS or legacy Microsoft LAPS.'
            ))
            Continue
        }

        # Convert to DateTime. Windows LAPS stores as a FileTime integer; legacy LAPS stores as DateTime.
        $ExpirationDate = $null
        Try {
            If ($LapsAttrName -eq 'msLAPS-PasswordExpirationTime') {
                $ExpirationDate = [datetime]::FromFileTime([long]$LapsValue)
            } Else {
                $ExpirationDate = [datetime]$LapsValue
            }
        } Catch {
            $Findings.Add((New-SmbFinding `
                -ComputerName    $Computer.Name `
                -HostType        $HostType `
                -FindingCategory 'LAPSParseError' `
                -Severity        'Medium' `
                -Evidence        "Could not parse LAPS expiration value '$LapsValue': $($_.Exception.Message)" `
                -Risk            'Unable to verify LAPS password age.' `
                -Recommendation  'Inspect LAPS attribute value manually and re-enroll if necessary.'
            ))
            Continue
        }

        $DaysPastExpiration = ($Now - $ExpirationDate).Days

        If ($DaysPastExpiration -gt $StaleThresholdDays) {
            $Findings.Add((New-SmbFinding `
                -ComputerName    $Computer.Name `
                -HostType        $HostType `
                -FindingCategory 'StaleLAPS' `
                -Severity        'Medium' `
                -Evidence        "LAPS expiration ($LapsAttrName): $($ExpirationDate.ToString('yyyy-MM-dd')). $DaysPastExpiration days past expiration (threshold: $StaleThresholdDays days)." `
                -Risk            'Stale LAPS password may no longer be unique or may have been compromised.' `
                -Recommendation  "Force a LAPS password rotation on $($Computer.Name)."
            ))
        } ElseIf ($DaysPastExpiration -gt 0) {
            $Findings.Add((New-SmbFinding `
                -ComputerName    $Computer.Name `
                -HostType        $HostType `
                -FindingCategory 'LAPSExpiredRecently' `
                -Severity        'Low' `
                -Evidence        "LAPS expiration ($LapsAttrName): $($ExpirationDate.ToString('yyyy-MM-dd')). Expired $DaysPastExpiration day(s) ago (within threshold)." `
                -Risk            'LAPS password has recently expired; rotation may be pending.' `
                -Recommendation  'Confirm LAPS client is running and will rotate the password soon.'
            ))
        } Else {
            $CoveredCount++
            # Informational -- LAPS is current; emit a record so the full report shows coverage.
            $Findings.Add((New-SmbFinding `
                -ComputerName    $Computer.Name `
                -HostType        $HostType `
                -FindingCategory 'LAPSCurrent' `
                -Severity        'Informational' `
                -Evidence        "LAPS expiration ($LapsAttrName): $($ExpirationDate.ToString('yyyy-MM-dd')). Password rotation is current." `
                -Risk            'None' `
                -Recommendation  'No action required.'
            ))
            Continue
        }

        $CoveredCount++
    }

    # Domain-level partial deployment check.
    If ($TotalCount -gt 0) {
        $CoveragePercent = [math]::Round(($CoveredCount / $TotalCount) * 100, 1)
        If ($CoveragePercent -lt 80) {
            $Findings.Add((New-SmbFinding `
                -ComputerName    'DOMAIN' `
                -HostType        'Domain' `
                -FindingCategory 'PartialLAPSDeployment' `
                -Severity        'Medium' `
                -Evidence        "LAPS attribute present on $CoveredCount of $TotalCount computers ($CoveragePercent%)." `
                -Risk            'Computers without LAPS have unmanaged local admin passwords. Partial deployment creates an uneven security posture.' `
                -Recommendation  'Extend LAPS enrollment to all domain-joined computers.'
            ))
        }
    }

    Write-Host "[INFO] LAPS audit: $TotalCount computers checked. $CoveredCount have a current LAPS attribute." -ForegroundColor Yellow
    Write-SmbFindingsSummary -CheckName 'LAPS Coverage' -Findings $Findings

    If (-not $Force) {
        Export-AdPowerAdminData -Data $Findings -ReportName 'SMB-LAPSCoverage-Audit'
    } Else {
        Export-AdPowerAdminData -Data $Findings -ReportName 'SMB-LAPSCoverage-Audit' -Force
    }

    Return $Findings
}

##############################################################################
# Get-ADAdminShareInventory
##############################################################################

Function Get-ADAdminShareInventory {
    <#
    .SYNOPSIS
        Enumerate hidden SMB administrative shares on all enabled AD computers.
    .DESCRIPTION
        Connects to each enabled computer via WinRM and retrieves shares whose
        name ends with '$'. Classifies each host as Workstation, Server, or
        DomainController. Unreachable systems are recorded as UnableToQuery.
    .PARAMETER ComputerNames
        Optional list of computer names to target. If omitted, all enabled AD
        computers are queried.
    .PARAMETER Force
        Suppress the export confirmation prompt.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$ComputerNames,
        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-SmbSectionHeader 'SMB Admin Share Inventory'

    $Results = [System.Collections.Generic.List[object]]::new()
    $DcHash  = Get-SmbDcList

    # Build an untyped array to avoid [string[]] coercion of PSCustomObjects.
    $ComputerData = @()
    If (-not $ComputerNames) {
        Try {
            $ComputerData = @(Get-ADComputer -Filter 'Enabled -eq $true' `
                -Properties Name, OperatingSystem -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{ Name = [string]$_.Name; OperatingSystem = [string]$_.OperatingSystem }
                })
        } Catch {
            Write-Warning "[WARN] Could not query AD computers: $($_.Exception.Message)"
            Return $Results
        }
    } Else {
        $ComputerData = @($ComputerNames | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_; OperatingSystem = '' }
        })
    }

    ForEach ($Comp in $ComputerData) {
        $HostType = Get-SmbHostType -ComputerName $Comp.Name `
            -OperatingSystem $Comp.OperatingSystem `
            -IsDC ($DcHash.ContainsKey($Comp.Name.ToUpper()))

        Try {
            $Shares = Invoke-Command -ComputerName $Comp.Name -ErrorAction Stop -ScriptBlock {
                Get-SmbShare -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '\$$' } |
                ForEach-Object {
                    @{
                        ComputerName = $env:COMPUTERNAME
                        ShareName    = $_.Name
                        SharePath    = $_.Path
                        ShareState   = $_.ShareState
                        Description  = $_.Description
                    }
                }
            }

            # Use Where-Object to strip null entries before counting (avoids @($null).Count=1 issue).
            $ShareArray = @($Shares | Where-Object { $null -ne $_ })
            If ($ShareArray.Count -eq 0) {
                $Results.Add([PSCustomObject]@{
                    ComputerName = $Comp.Name
                    HostType     = $HostType
                    ShareName    = ''
                    SharePath    = ''
                    ShareState   = ''
                    Description  = ''
                    QueryStatus  = 'NoAdminSharesFound'
                })
            } Else {
                ForEach ($Share in $ShareArray) {
                    $Results.Add([PSCustomObject]@{
                        ComputerName = $Comp.Name
                        HostType     = $HostType
                        ShareName    = [string]$Share['ShareName']
                        SharePath    = [string]$Share['SharePath']
                        ShareState   = [string]$Share['ShareState']
                        Description  = [string]$Share['Description']
                        QueryStatus  = 'OK'
                    })
                }
            }
        } Catch {
            $Results.Add([PSCustomObject]@{
                ComputerName = $Comp.Name
                HostType     = $HostType
                ShareName    = ''
                SharePath    = ''
                ShareState   = ''
                Description  = ''
                QueryStatus  = "UnableToQuery: $($_.Exception.Message)"
            })
        }
    }

    $Ok      = @($Results | Where-Object { $_.QueryStatus -eq 'OK' })
    $Failed  = @($Results | Where-Object { $_.QueryStatus -like 'UnableToQuery*' })
    Write-Host "[INFO] Share inventory complete. $($Ok.Count) shares found. $($Failed.Count) hosts unreachable." -ForegroundColor Yellow

    $Ok | Format-Table ComputerName, HostType, ShareName, SharePath -AutoSize

    If (-not $Force) {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-ShareInventory'
    } Else {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-ShareInventory' -Force
    }

    Return $Results
}

##############################################################################
# Test-ADAdminShareRegistryPolicy
##############################################################################

Function Test-ADAdminShareRegistryPolicy {
    <#
    .SYNOPSIS
        Check AutoShareWks and AutoShareServer registry values on all computers.
    .DESCRIPTION
        Reads HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
        remotely. A missing value means default-enabled. Severity: Medium for
        workstations, High for servers, Critical for domain controllers when the
        setting is absent or explicitly set to 1.
    .PARAMETER ComputerNames
        Optional list of computer names. If omitted, all enabled AD computers
        are queried.
    .PARAMETER Force
        Suppress the export confirmation prompt.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$ComputerNames,
        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-SmbSectionHeader 'AutoShare Registry Policy Audit'

    $Results = [System.Collections.Generic.List[object]]::new()
    $DcHash  = Get-SmbDcList

    # Build an untyped array to avoid [string[]] coercion of PSCustomObjects.
    $ComputerData = @()
    If (-not $ComputerNames) {
        Try {
            $ComputerData = @(Get-ADComputer -Filter 'Enabled -eq $true' `
                -Properties Name, OperatingSystem -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{ Name = [string]$_.Name; OperatingSystem = [string]$_.OperatingSystem }
                })
        } Catch {
            Write-Warning "[WARN] Could not query AD computers: $($_.Exception.Message)"
            Return $Results
        }
    } Else {
        $ComputerData = @($ComputerNames | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_; OperatingSystem = '' }
        })
    }

    $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

    ForEach ($Comp in $ComputerData) {
        $HostType = Get-SmbHostType -ComputerName $Comp.Name `
            -OperatingSystem $Comp.OperatingSystem `
            -IsDC ($DcHash.ContainsKey($Comp.Name.ToUpper()))

        Try {
            $RegData = Invoke-Command -ComputerName $Comp.Name -ErrorAction Stop `
                -ArgumentList $RegPath -ScriptBlock {
                Param($Path)
                $Props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
                @{
                    AutoShareWks    = $Props.AutoShareWks
                    AutoShareServer = $Props.AutoShareServer
                }
            }
        } Catch {
            $Results.Add([PSCustomObject]@{
                ComputerName    = $Comp.Name
                HostType        = $HostType
                ValueName       = ''
                ValueData       = ''
                Interpretation  = ''
                FindingCategory = 'WinRMQueryFailed'
                Severity        = 'Low'
                QueryStatus     = "UnableToQuery: $($_.Exception.Message)"
            })
            Continue
        }

        # Determine which value name and data to evaluate based on host type.
        $ValueName = If ($HostType -eq 'Workstation') { 'AutoShareWks' } Else { 'AutoShareServer' }
        $ValueData = $RegData[$ValueName]

        If ($null -eq $ValueData) {
            $Interpretation = 'Missing (default enabled)'
            $Severity = Switch ($HostType) {
                'DomainController' { 'Critical' }
                'Server'           { 'High' }
                Default            { 'Medium' }
            }
        } ElseIf ($ValueData -eq 0) {
            $Interpretation = 'Disabled'
            $Severity       = 'Informational'
        } Else {
            $Interpretation = 'Enabled'
            $Severity = Switch ($HostType) {
                'DomainController' { 'Critical' }
                'Server'           { 'High' }
                Default            { 'Medium' }
            }
        }

        $Results.Add([PSCustomObject]@{
            ComputerName    = $Comp.Name
            HostType        = $HostType
            ValueName       = $ValueName
            ValueData       = If ($null -eq $ValueData) { '(absent)' } Else { $ValueData }
            Interpretation  = $Interpretation
            FindingCategory = If ($Severity -eq 'Informational') { '' } Else { 'AutoShareNotRestricted' }
            Severity        = $Severity
            QueryStatus     = 'OK'
        })
    }

    Write-SmbFindingsSummary -CheckName 'AutoShare Registry Policy' -Findings $Results `
        -DetailColumns @('ComputerName','HostType','ValueName','ValueData','Interpretation','Severity')

    If (-not $Force) {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-AutoShareRegistry-Audit'
    } Else {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-AutoShareRegistry-Audit' -Force
    }

    Return $Results
}

##############################################################################
# Test-ADSMBFirewallExposure
##############################################################################

Function Test-ADSMBFirewallExposure {
    <#
    .SYNOPSIS
        Audit inbound SMB firewall rules on all computers for broad exposure.
    .DESCRIPTION
        Checks inbound Allow rules for TCP ports 445 and 139. Flags workstations
        with RemoteAddress=Any or broad subnets (High) and domain controllers
        reachable from sources not in ApprovedSmbAdminHosts (Critical).
    .PARAMETER ComputerNames
        Optional list of computer names. If omitted, all enabled AD computers
        are queried.
    .PARAMETER ApprovedAdminSources
        Approved host names or IPs. Defaults to $global:ApprovedSmbAdminHosts.
    .PARAMETER Force
        Suppress the export confirmation prompt.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$ComputerNames,
        [Parameter(Mandatory=$False)]
        [string[]]$ApprovedAdminSources = $global:ApprovedSmbAdminHosts,
        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-SmbSectionHeader 'SMB Firewall Exposure Audit'

    $Results = [System.Collections.Generic.List[object]]::new()
    $DcHash  = Get-SmbDcList

    # Build an untyped array to avoid [string[]] coercion of PSCustomObjects.
    $ComputerData = @()
    If (-not $ComputerNames) {
        Try {
            $ComputerData = @(Get-ADComputer -Filter 'Enabled -eq $true' `
                -Properties Name, OperatingSystem -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{ Name = [string]$_.Name; OperatingSystem = [string]$_.OperatingSystem }
                })
        } Catch {
            Write-Warning "[WARN] Could not query AD computers: $($_.Exception.Message)"
            Return $Results
        }
    } Else {
        $ComputerData = @($ComputerNames | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_; OperatingSystem = '' }
        })
    }

    ForEach ($Comp in $ComputerData) {
        $HostType = Get-SmbHostType -ComputerName $Comp.Name `
            -OperatingSystem $Comp.OperatingSystem `
            -IsDC ($DcHash.ContainsKey($Comp.Name.ToUpper()))

        Try {
            $RuleData = Invoke-Command -ComputerName $Comp.Name -ErrorAction Stop -ScriptBlock {
                $SmbRules = Get-NetFirewallRule -Direction Inbound -Enabled True `
                    -Action Allow -ErrorAction SilentlyContinue

                $Output = @()
                ForEach ($Rule in $SmbRules) {
                    $PortFilter = $Rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                    If ($null -eq $PortFilter) { Continue }
                    $Ports = @($PortFilter.LocalPort)
                    If ($Ports -notcontains '445' -and $Ports -notcontains '139' -and
                        $Ports -notcontains 'SMB') { Continue }

                    $AddrFilter = $Rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                    $Output += @{
                        RuleName      = $Rule.DisplayName
                        InstanceID    = $Rule.InstanceID
                        LocalPort     = ($Ports -join ',')
                        RemoteAddress = If ($AddrFilter) { ($AddrFilter.RemoteAddress -join ',') } Else { 'Unknown' }
                    }
                }
                $Output
            }
        } Catch {
            $Results.Add([PSCustomObject]@{
                ComputerName    = $Comp.Name
                HostType        = $HostType
                RuleName        = ''
                LocalPort       = ''
                RemoteAddress   = ''
                FindingCategory = 'WinRMQueryFailed'
                Severity        = 'Low'
                Evidence        = "WinRM query failed: $($_.Exception.Message)"
                QueryStatus     = 'UnableToQuery'
            })
            Continue
        }

        $RuleArray = @($RuleData | Where-Object { $null -ne $_ })
        If ($RuleArray.Count -eq 0) {
            $Results.Add([PSCustomObject]@{
                ComputerName  = $Comp.Name
                HostType      = $HostType
                RuleName      = ''
                LocalPort     = ''
                RemoteAddress = ''
                Severity      = 'Informational'
                Evidence      = 'No inbound SMB Allow rules found. SMB may be blocked by policy or default deny.'
                QueryStatus   = 'OK'
            })
            Continue
        }

        ForEach ($Rule in $RuleArray) {
            $RemoteAddr = $Rule.RemoteAddress
            $IsBroad    = ($RemoteAddr -eq 'Any' -or $RemoteAddr -eq 'LocalSubnet' -or
                          $RemoteAddr -match '^0\.0\.0\.0')
            $IsApproved = ($ApprovedAdminSources | Where-Object {
                $RemoteAddr -match [regex]::Escape($_)
            }).Count -gt 0

            If ($IsBroad -and -not $IsApproved) {
                $Severity = Switch ($HostType) {
                    'DomainController' { 'Critical' }
                    'Server'           { 'High' }
                    Default            { 'High' }
                }
                $Risk = Switch ($HostType) {
                    'DomainController' { 'Domain controllers with broad inbound SMB are at risk of credential database theft, SYSVOL manipulation, and direct DC compromise.' }
                    'Server'           { 'Servers with broad inbound SMB allow lateral movement, ransomware propagation, and remote payload staging.' }
                    Default            { 'Workstations with broad inbound SMB allow peer-to-peer lateral movement without needing a server-tier pivot.' }
                }
                $Evidence = "Rule '$($Rule.RuleName)' allows inbound SMB (port $($Rule.LocalPort)) from RemoteAddress: $RemoteAddr"
            } Else {
                $Severity = 'Informational'
                $Risk     = 'None'
                $Evidence = "Rule '$($Rule.RuleName)' port $($Rule.LocalPort) -- RemoteAddress: $RemoteAddr (restricted or approved)"
            }

            $Results.Add([PSCustomObject]@{
                ComputerName    = $Comp.Name
                HostType        = $HostType
                RuleName        = $Rule.RuleName
                LocalPort       = $Rule.LocalPort
                RemoteAddress   = $RemoteAddr
                FindingCategory = If ($Severity -eq 'Informational') { '' } Else { 'BroadSMBFirewallRule' }
                Severity        = $Severity
                Evidence        = $Evidence
                QueryStatus     = 'OK'
            })
        }
    }

    Write-SmbFindingsSummary -CheckName 'SMB Firewall Exposure' -Findings $Results `
        -DetailColumns @('ComputerName','HostType','Severity','RemoteAddress','RuleName','Evidence')

    If (-not $Force) {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-FirewallExposure-Audit'
    } Else {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-FirewallExposure-Audit' -Force
    }

    Return $Results
}

##############################################################################
# Get-ADLocalAdminExposure
##############################################################################

Function Get-ADLocalAdminExposure {
    <#
    .SYNOPSIS
        Enumerate local Administrators group on all computers and flag risky members.
    .DESCRIPTION
        Connects via WinRM to retrieve local Administrators membership. Flags:
        Domain Users in local Admins (Critical), broad domain groups (High),
        service accounts (Medium), and unapproved domain accounts (High).
        Post-collects disabled state via AD for flagged accounts.
    .PARAMETER ComputerNames
        Optional list of computer names. If omitted, all enabled AD computers
        are queried.
    .PARAMETER ApprovedLocalAdminGroups
        Optional list of approved domain group names to suppress from findings.
    .PARAMETER Force
        Suppress the export confirmation prompt.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$ComputerNames,
        [Parameter(Mandatory=$False)]
        [string[]]$ApprovedLocalAdminGroups = @(),
        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-SmbSectionHeader 'Local Administrator Exposure Audit'

    $Results = [System.Collections.Generic.List[object]]::new()
    $DcHash  = Get-SmbDcList

    # Build an untyped array to avoid [string[]] coercion of PSCustomObjects.
    $ComputerData = @()
    If (-not $ComputerNames) {
        Try {
            $ComputerData = @(Get-ADComputer -Filter 'Enabled -eq $true' `
                -Properties Name, OperatingSystem -ErrorAction Stop |
                ForEach-Object {
                    [PSCustomObject]@{ Name = [string]$_.Name; OperatingSystem = [string]$_.OperatingSystem }
                })
        } Catch {
            Write-Warning "[WARN] Could not query AD computers: $($_.Exception.Message)"
            Return $Results
        }
    } Else {
        $ComputerData = @($ComputerNames | ForEach-Object {
            [PSCustomObject]@{ Name = [string]$_; OperatingSystem = '' }
        })
    }

    # Broad-sounding group name patterns that warrant High severity.
    $BroadGroupPatterns = @('domain users','helpdesk','help desk','all users','everyone',
                             'authenticated users','it support','desktop support','tier 1',
                             'tier1','service desk')

    ForEach ($Comp in $ComputerData) {
        $HostType = Get-SmbHostType -ComputerName $Comp.Name `
            -OperatingSystem $Comp.OperatingSystem `
            -IsDC ($DcHash.ContainsKey($Comp.Name.ToUpper()))

        Try {
            $Members = Invoke-Command -ComputerName $Comp.Name -ErrorAction Stop -ScriptBlock {
                Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
                ForEach-Object {
                    @{
                        Name            = $_.Name
                        ObjectClass     = $_.ObjectClass
                        PrincipalSource = $_.PrincipalSource.ToString()
                        SID             = $_.SID.Value
                    }
                }
            }
        } Catch {
            $Results.Add([PSCustomObject]@{
                ComputerName    = $Comp.Name
                HostType        = $HostType
                MemberName      = ''
                ObjectClass     = ''
                PrincipalSource = ''
                FindingCategory = 'WinRMQueryFailed'
                Severity        = 'Low'
                IsDisabledInAD  = ''
                QueryStatus     = "UnableToQuery: $($_.Exception.Message)"
            })
            Continue
        }

        $MemberArray = @($Members | Where-Object { $null -ne $_ })
        If ($MemberArray.Count -eq 0) {
            Continue
        }

        ForEach ($Member in $MemberArray) {
            $ShortName     = ($Member.Name -split '\\')[-1]
            $IsDomainAcct  = ($Member.PrincipalSource -eq 'ActiveDirectory')
            $IsApproved    = ($ApprovedLocalAdminGroups | Where-Object {
                $_ -ieq $ShortName
            }).Count -gt 0

            $FindingCategory = 'LocalAdminMember'
            $Severity        = 'Informational'

            If ($IsDomainAcct) {
                $NameLower = $ShortName.ToLower()

                If ($NameLower -eq 'domain users') {
                    $FindingCategory = 'DomainUsersInLocalAdmins'
                    $Severity        = 'Critical'
                } ElseIf (($BroadGroupPatterns | Where-Object { $NameLower -match $_ }).Count -gt 0) {
                    $FindingCategory = 'BroadGroupInLocalAdmins'
                    $Severity        = 'High'
                } ElseIf ($ShortName -match '\$$') {
                    # Machine account ending in $ (not expected as local admin member).
                    $FindingCategory = 'ServiceAccountInLocalAdmins'
                    $Severity        = 'Medium'
                } ElseIf (-not $IsApproved -and $Member.ObjectClass -eq 'Group') {
                    $FindingCategory = 'UnapprovedDomainGroup'
                    $Severity        = 'High'
                } ElseIf (-not $IsApproved -and $Member.ObjectClass -eq 'User') {
                    $FindingCategory = 'UnapprovedDomainUser'
                    $Severity        = 'High'
                }
            }

            # Check if the AD account is disabled (only for domain accounts, best-effort).
            $IsDisabledInAD = ''
            If ($IsDomainAcct -and $Severity -ne 'Informational') {
                Try {
                    If ($Member.ObjectClass -eq 'User') {
                        $AdObj = Get-ADUser -Filter "SamAccountName -eq '$ShortName'" `
                            -Properties Enabled -ErrorAction SilentlyContinue
                        If ($null -ne $AdObj) { $IsDisabledInAD = (-not $AdObj.Enabled).ToString() }
                    } ElseIf ($Member.ObjectClass -eq 'Group') {
                        # Groups do not have an Enabled flag; leave blank.
                        $IsDisabledInAD = 'N/A'
                    }
                } Catch { }
            }

            $Results.Add([PSCustomObject]@{
                ComputerName    = $Comp.Name
                HostType        = $HostType
                MemberName      = $Member.Name
                ObjectClass     = $Member.ObjectClass
                PrincipalSource = $Member.PrincipalSource
                FindingCategory = $FindingCategory
                Severity        = $Severity
                IsDisabledInAD  = $IsDisabledInAD
                QueryStatus     = 'OK'
            })
        }
    }

    Write-SmbFindingsSummary -CheckName 'Local Admin Exposure' -Findings $Results `
        -DetailColumns @('ComputerName','HostType','MemberName','FindingCategory','Severity','IsDisabledInAD')

    If (-not $Force) {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-LocalAdminExposure-Audit'
    } Else {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-LocalAdminExposure-Audit' -Force
    }

    Return $Results
}

##############################################################################
# Search-ADAdminShareAccessEvents
##############################################################################

Function Search-ADAdminShareAccessEvents {
    <#
    .SYNOPSIS
        Search Security event logs on DCs and servers for admin share access events.
    .DESCRIPTION
        Queries Event IDs 5140 (share accessed) and 5145 (share object checked) on
        all domain controllers and enabled AD servers. Flags access to ADMIN$, C$,
        IPC$, or D$ from sources not in ApprovedSmbAdminHosts.
    .PARAMETER HoursBack
        How many hours back to search. Default is 24.
    .PARAMETER TargetShares
        Share names to flag. Defaults to ADMIN$, C$, IPC$, D$.
    .PARAMETER ApprovedSources
        Approved source hosts/IPs. Defaults to $global:ApprovedSmbAdminHosts.
    .PARAMETER Force
        Suppress the export confirmation prompt.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$HoursBack = 24,
        [Parameter(Mandatory=$False)]
        [string[]]$TargetShares = @('ADMIN$','C$','IPC$','D$'),
        [Parameter(Mandatory=$False)]
        [string[]]$ApprovedSources = $global:ApprovedSmbAdminHosts,
        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    Write-SmbSectionHeader 'Admin Share Access Event Search'

    $Results   = [System.Collections.Generic.List[object]]::new()
    $StartTime = (Get-Date).AddHours(-$HoursBack)
    $FilterHash = @{
        LogName   = 'Security'
        Id        = @(5140, 5145)
        StartTime = $StartTime
    }

    # Build target list: all DCs + enabled AD servers.
    $TargetHosts = [System.Collections.Generic.List[string]]::new()
    Try {
        Get-ADDomainController -Filter * -ErrorAction Stop |
            ForEach-Object { $TargetHosts.Add($_.Name) }
    } Catch {
        Write-Warning "[WARN] Could not enumerate DCs: $($_.Exception.Message)"
    }
    Try {
        Get-ADComputer -Filter 'Enabled -eq $true' -Properties OperatingSystem -ErrorAction Stop |
            Where-Object { $_.OperatingSystem -match 'Server' -and
                           $TargetHosts -notcontains $_.Name } |
            ForEach-Object { $TargetHosts.Add($_.Name) }
    } Catch {
        Write-Warning "[WARN] Could not enumerate AD servers: $($_.Exception.Message)"
    }

    $DcHash = Get-SmbDcList
    $MaxEventsPerHost = 10000

    ForEach ($TargetHost in $TargetHosts) {
        $HostType = Get-SmbHostType -ComputerName $TargetHost `
            -OperatingSystem '' `
            -IsDC ($DcHash.ContainsKey($TargetHost.ToUpper()))
        Try {
            $Events = Get-WinEvent -ComputerName $TargetHost `
                -FilterHashtable $FilterHash `
                -MaxEvents $MaxEventsPerHost `
                -ErrorAction Stop

            If (@($Events).Count -ge $MaxEventsPerHost) {
                Write-Warning "[WARN] Event cap ($MaxEventsPerHost) reached on $TargetHost. Results may be incomplete."
            }

            ForEach ($Evt in $Events) {
                Try {
                    [xml]$Xml     = $Evt.ToXml()
                    $EventData    = $Xml.Event.EventData.Data
                    $ShareName    = ($EventData | Where-Object { $_.Name -eq 'ShareName' }).'#text'
                    $AccountName  = ($EventData | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
                    $IpAddress    = ($EventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
                    $RelTarget    = ($EventData | Where-Object { $_.Name -eq 'RelativeTargetName' }).'#text'

                    # Filter: only flag target shares.
                    $ShareNameClean = If ($ShareName) { $ShareName.TrimEnd('\') } Else { '' }
                    If ($TargetShares -notcontains $ShareNameClean) { Continue }

                    $IsApproved = ($ApprovedSources | Where-Object {
                        $IpAddress -eq $_ -or $TargetHost -eq $_
                    }).Count -gt 0

                    $Severity = If (-not $IsApproved) {
                        If ($HostType -eq 'DomainController') { 'Critical' } Else { 'High' }
                    } Else { 'Informational' }

                    $Results.Add([PSCustomObject]@{
                        EventId              = $Evt.Id
                        TimeCreated          = $Evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        ComputerName         = $TargetHost
                        HostType             = $HostType
                        SubjectAccountName   = $AccountName
                        IpAddress            = $IpAddress
                        ShareName            = $ShareNameClean
                        RelativeTargetName   = $RelTarget
                        FindingCategory      = If ($IsApproved) { '' } Else { 'UnapprovedAdminShareAccess' }
                        Severity             = $Severity
                        IsApprovedSource     = $IsApproved
                        QueryStatus          = 'OK'
                    })
                } Catch {
                    # Skip unparseable events.
                }
            }
        } Catch {
            $Results.Add([PSCustomObject]@{
                EventId            = ''
                TimeCreated        = ''
                ComputerName       = $TargetHost
                HostType           = $HostType
                SubjectAccountName = ''
                IpAddress          = ''
                ShareName          = ''
                RelativeTargetName = ''
                FindingCategory    = 'EventLogQueryFailed'
                Severity           = 'Low'
                IsApprovedSource   = ''
                QueryStatus        = "UnableToQuery: $($_.Exception.Message)"
            })
        }
    }

    Write-SmbFindingsSummary -CheckName 'Admin Share Access Events' -Findings $Results `
        -DetailColumns @('TimeCreated','ComputerName','HostType','SubjectAccountName','IpAddress','ShareName','Severity')

    If (-not $Force) {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-AdminShareAccessEvents'
    } Else {
        Export-AdPowerAdminData -Data $Results -ReportName 'SMB-AdminShareAccessEvents' -Force
    }

    Return $Results
}

##############################################################################
# Invoke-ADAdminShareExposureAudit
##############################################################################

Function Invoke-ADAdminShareExposureAudit {
    <#
    .SYNOPSIS
        Run all six SMB admin share audit checks and export a consolidated report.
    .DESCRIPTION
        Calls Test-ADLAPSCoverage, Get-ADAdminShareInventory,
        Test-ADAdminShareRegistryPolicy, Test-ADSMBFirewallExposure,
        Get-ADLocalAdminExposure, and Search-ADAdminShareAccessEvents in sequence.
        Aggregates all findings, exports a timestamped CSV, and saves a plain ASCII
        text narrative report to the Reports directory.
    .PARAMETER Force
        Suppress export confirmation prompts from sub-functions.
    .PARAMETER EventLogHoursBack
        How far back to search event logs. Default is 24 hours.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$Force,
        [Parameter(Mandatory=$False)]
        [int]$EventLogHoursBack = 24
    )

    Write-SmbSectionHeader 'Full SMB Administrative Share Exposure Audit'
    Write-Host '[INFO] Starting full SMB admin share audit. This may take several minutes.' -ForegroundColor Yellow

    $AllFindings = [System.Collections.Generic.List[object]]::new()

    # 1. LAPS Coverage (no WinRM; fastest check)
    Try {
        Write-Host '[INFO] Step 1/6: Auditing LAPS coverage...' -ForegroundColor Cyan
        $LapsFindings = Test-ADLAPSCoverage -Force
        ForEach ($F in $LapsFindings) { $AllFindings.Add($F) }
    } Catch {
        Write-Warning "[WARN] LAPS coverage audit failed: $($_.Exception.Message)"
    }

    # 2. Share Inventory
    Try {
        Write-Host '[INFO] Step 2/6: Inventorying admin shares...' -ForegroundColor Cyan
        $ShareFindings = Get-ADAdminShareInventory -Force
        ForEach ($F in $ShareFindings) { $AllFindings.Add($F) }
    } Catch {
        Write-Warning "[WARN] Share inventory failed: $($_.Exception.Message)"
    }

    # 3. Registry Policy
    Try {
        Write-Host '[INFO] Step 3/6: Checking AutoShare registry policy...' -ForegroundColor Cyan
        $RegFindings = Test-ADAdminShareRegistryPolicy -Force
        ForEach ($F in $RegFindings) { $AllFindings.Add($F) }
    } Catch {
        Write-Warning "[WARN] Registry policy audit failed: $($_.Exception.Message)"
    }

    # 4. Firewall Exposure
    Try {
        Write-Host '[INFO] Step 4/6: Auditing SMB firewall exposure...' -ForegroundColor Cyan
        $FwFindings = Test-ADSMBFirewallExposure -Force
        ForEach ($F in $FwFindings) { $AllFindings.Add($F) }
    } Catch {
        Write-Warning "[WARN] Firewall exposure audit failed: $($_.Exception.Message)"
    }

    # 5. Local Admin Exposure
    Try {
        Write-Host '[INFO] Step 5/6: Auditing local administrator exposure...' -ForegroundColor Cyan
        $LocalAdminFindings = Get-ADLocalAdminExposure -Force
        ForEach ($F in $LocalAdminFindings) { $AllFindings.Add($F) }
    } Catch {
        Write-Warning "[WARN] Local admin exposure audit failed: $($_.Exception.Message)"
    }

    # 6. Event Log Search (slowest; run last)
    Try {
        Write-Host "[INFO] Step 6/6: Searching event logs (last $EventLogHoursBack hours)..." -ForegroundColor Cyan
        $EventFindings = Search-ADAdminShareAccessEvents -HoursBack $EventLogHoursBack -Force
        ForEach ($F in $EventFindings) { $AllFindings.Add($F) }
    } Catch {
        Write-Warning "[WARN] Event log search failed: $($_.Exception.Message)"
    }

    # Summary
    Write-SmbSectionHeader 'Audit Summary'
    $SeverityOrder = @('Critical','High','Medium','Low','Informational')
    $Summary = $AllFindings | Group-Object -Property Severity |
        Sort-Object { $SeverityOrder.IndexOf($_.Name) } |
        Select-Object @{N='Severity';E={$_.Name}}, @{N='Count';E={$_.Count}}
    $Summary | Format-Table -AutoSize

    $CritCount = @($AllFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $HighCount  = @($AllFindings | Where-Object { $_.Severity -eq 'High' }).Count
    If ($CritCount -gt 0) {
        Write-Host "[FAIL] $CritCount Critical finding(s) require immediate attention." -ForegroundColor Red
    }
    If ($HighCount -gt 0) {
        Write-Host "[WARN] $HighCount High finding(s) require attention." -ForegroundColor Yellow
    }

    # Show actual risk findings (Critical/High/Medium/Low) that were successfully queried.
    # UnableToQuery records are shown separately so they are not confused with real findings.
    $SevOrder    = @('Critical','High','Medium','Low','Informational')
    $RiskFindings = @($AllFindings | Where-Object {
        $_.Severity -notin @('Informational') -and
        $_.QueryStatus -eq 'OK' -and
        -not [string]::IsNullOrWhiteSpace($_.FindingCategory)
    })
    If ($RiskFindings.Count -gt 0) {
        Write-Host ''
        Write-Host "[INFO] Risk findings detail ($($RiskFindings.Count) non-Informational, successfully queried):" -ForegroundColor Cyan
        $RiskFindings |
            Sort-Object { $SevOrder.IndexOf($_.Severity) } |
            Format-Table ComputerName, HostType, FindingCategory, Severity, Evidence -AutoSize -Wrap
    } Else {
        Write-Host ''
        Write-Host '[OK] No risk findings on successfully queried hosts.' -ForegroundColor Green
    }

    # Unreachable hosts are an operational note, not a misconfiguration finding.
    $Unreachable = @($AllFindings | Where-Object { $_.QueryStatus -like 'UnableToQuery*' })
    If ($Unreachable.Count -gt 0) {
        Write-Host ''
        Write-Host "[INFO] $($Unreachable.Count) host(s) could not be reached via WinRM -- these are connectivity gaps, not security findings:" -ForegroundColor DarkYellow
        $Unreachable |
            Select-Object -Unique ComputerName, HostType, FindingCategory |
            Format-Table ComputerName, HostType, FindingCategory -AutoSize
    }

    # Export CSV
    $ExportData = $AllFindings | Select-Object ComputerName, HostType, FindingCategory,
        Severity, Evidence, Risk, Recommendation, QueryStatus,
        EventId, TimeCreated, SubjectAccountName, IpAddress, ShareName,
        MemberName, ObjectClass, PrincipalSource,
        ValueName, ValueData, Interpretation,
        RuleName, LocalPort, RemoteAddress

    If ($Force) {
        Export-AdPowerAdminData -Data $ExportData -ReportName 'SMB-AdminShare-FullAudit' -Force
    } Else {
        Export-AdPowerAdminData -Data $ExportData -ReportName 'SMB-AdminShare-FullAudit'
    }

    # Text narrative report
    $ReportFile = Join-Path $global:ReportsPath "SMB-AdminShare-FullAudit_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').txt"
    New-SmbAuditTextReport -Findings $AllFindings -OutputFile $ReportFile

    Write-Host "[INFO] Full audit complete. Reports saved to: $($global:ReportsPath)" -ForegroundColor Green

    Return $AllFindings
}

Function New-SmbAuditTextReport {
    <#
    .SYNOPSIS
        Write a plain ASCII text narrative report from aggregated SMB findings.
    #>
    Param(
        [Parameter(Mandatory=$True)]
        [object[]]$Findings,
        [Parameter(Mandatory=$True)]
        [string]$OutputFile
    )

    $Lines = [System.Collections.Generic.List[string]]::new()
    $Sep   = '=' * 80
    $Sub   = '-' * 80

    $Lines.Add($Sep)
    $Lines.Add('  AD-PowerAdmin -- SMB Administrative Share Exposure Audit Report')
    $Lines.Add("  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $Lines.Add($Sep)
    $Lines.Add('')

    $Lines.Add('EXECUTIVE SUMMARY')
    $Lines.Add($Sub)
    $Lines.Add('This report summarizes SMB administrative share exposure findings across the')
    $Lines.Add('Active Directory environment. Admin shares (ADMIN$, C$, IPC$) are a primary')
    $Lines.Add('lateral movement vector (ATT&CK T1021.002). Review Critical and High findings')
    $Lines.Add('immediately and follow the remediation guidance in each section.')
    $Lines.Add('')

    $SeverityOrder = @('Critical','High','Medium','Low','Informational')
    ForEach ($Sev in $SeverityOrder) {
        $Group = @($Findings | Where-Object { $_.Severity -eq $Sev })
        If ($Group.Count -eq 0) { Continue }
        $Lines.Add("  $Sev : $($Group.Count) finding(s)")
    }
    $Lines.Add('')

    # Section per finding category
    $Categories = $Findings | Group-Object -Property FindingCategory |
        Sort-Object { $SeverityOrder.IndexOf(($_.Group | Sort-Object Severity | Select-Object -First 1).Severity) }

    ForEach ($Cat in $Categories) {
        If ([string]::IsNullOrWhiteSpace($Cat.Name)) { Continue }
        $Lines.Add($Sep)
        $Lines.Add("  FINDING CATEGORY: $($Cat.Name)")
        $Lines.Add($Sub)
        $TopSev = ($Cat.Group | Sort-Object { $SeverityOrder.IndexOf($_.Severity) } | Select-Object -First 1).Severity
        $Lines.Add("  Severity: $TopSev   Count: $($Cat.Count)")
        $Lines.Add('')
        ForEach ($F in $Cat.Group | Select-Object -First 20) {
            $Lines.Add("  Computer : $($F.ComputerName)  ($($F.HostType))")
            If ($F.Evidence)       { $Lines.Add("  Evidence : $($F.Evidence)") }
            If ($F.Risk)           { $Lines.Add("  Risk     : $($F.Risk)") }
            If ($F.Recommendation) { $Lines.Add("  Action   : $($F.Recommendation)") }
            $Lines.Add('')
        }
        If ($Cat.Count -gt 20) {
            $Lines.Add("  ... and $($Cat.Count - 20) more. See the CSV export for full results.")
            $Lines.Add('')
        }
    }

    $Lines.Add($Sep)
    $Lines.Add('  REMEDIATION OVERVIEW')
    $Lines.Add($Sub)
    $Lines.Add('  1. Run Invoke-ADAdminShareSafeRemediation for guided, staged remediation.')
    $Lines.Add('  2. Review and extend Windows LAPS to all computers (Test-ADLAPSCoverage).')
    $Lines.Add('  3. Remove unapproved domain accounts from local Administrators.')
    $Lines.Add('  4. Restrict inbound SMB firewall rules to approved management hosts.')
    $Lines.Add('  5. Set AutoShareWks/AutoShareServer registry values to 0 where safe.')
    $Lines.Add('  6. Add approved admin hosts to ApprovedSmbAdminHosts in settings.')
    $Lines.Add($Sep)

    $Lines | Out-File -FilePath $OutputFile -Encoding ASCII -Force
    Write-Host "[INFO] Text report saved: $OutputFile" -ForegroundColor Green
}

##############################################################################
# Invoke-ADAdminShareSafeRemediation
##############################################################################

Function Invoke-ADAdminShareSafeRemediation {
    <#
    .SYNOPSIS
        Staged, confirmation-gated remediation for SMB admin share exposure findings.
    .DESCRIPTION
        Three stages:
          Stage 1 (Low risk, per-item y/N): Remove unapproved domain accounts from
            local Administrators.
          Stage 2 (Medium risk, CONFIRM gate): Restrict firewall RemoteAddress to
            approved sources.
          Stage 3 (High risk, CONFIRM gate + warning): Set AutoShareWks/AutoShareServer
            registry values to 0.
        Admin shares are NEVER disabled automatically. Every change creates a JSON
        backup in ReportsPath before it is applied.
    .PARAMETER Mode
        AuditOnly (default), RemediateWithPrompt, or Rollback.
    .PARAMETER Findings
        Optional pre-collected findings array. If omitted, a fresh audit is run.
    .PARAMETER WhatIf
        Describe proposed changes without applying them.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet('AuditOnly','RemediateWithPrompt','Rollback')]
        [string]$Mode = 'AuditOnly',
        [Parameter(Mandatory=$False)]
        [object[]]$Findings,
        [Parameter(Mandatory=$False)]
        [switch]$WhatIf
    )

    If ($Mode -eq 'Rollback') {
        Restore-ADAdminShareRemediationBackup
        Return
    }

    # Collect findings if not supplied.
    If (-not $Findings) {
        Write-Host '[INFO] Running fresh audit to identify remediation targets...' -ForegroundColor Yellow
        $Findings = Invoke-ADAdminShareExposureAudit -Force
    }

    If ($Mode -eq 'AuditOnly') {
        Write-Host '[INFO] AuditOnly mode -- no changes applied.' -ForegroundColor Cyan
        Return
    }

    # -----------------------------------------------------------------------
    # Stage 1: Remove unapproved domain accounts from local Administrators
    # -----------------------------------------------------------------------
    Write-SmbSectionHeader 'Remediation Stage 1: Local Administrator Cleanup'
    Write-Host '[INFO] Stage 1 removes unapproved domain accounts from local Administrators.' -ForegroundColor Yellow
    Write-Host '       Each removal requires individual y/N confirmation.' -ForegroundColor Yellow
    Write-Host ''

    $Stage1Targets = @($Findings | Where-Object {
        $_.FindingCategory -in @('DomainUsersInLocalAdmins','BroadGroupInLocalAdmins',
                                  'UnapprovedDomainGroup','UnapprovedDomainUser') -and
        $_.QueryStatus -eq 'OK' -and
        -not [string]::IsNullOrWhiteSpace($_.MemberName)
    })

    If ($Stage1Targets.Count -eq 0) {
        Write-Host '[OK] No Stage 1 targets identified.' -ForegroundColor Green
    } Else {
        $Stage1Changes = [System.Collections.Generic.List[object]]::new()

        ForEach ($Target in $Stage1Targets) {
            Write-Host "  Computer : $($Target.ComputerName)  ($($Target.HostType))"
            Write-Host "  Member   : $($Target.MemberName)  [$($Target.FindingCategory)]" -ForegroundColor Red
            Write-Host "  Severity : $($Target.Severity)"
            Write-Host ''

            If ($WhatIf) {
                Write-Host '  [WHATIF] Would remove from local Administrators.' -ForegroundColor Yellow
                Write-Host ''
                Continue
            }

            $Confirm = Read-Host "  Remove '$($Target.MemberName)' from Administrators on '$($Target.ComputerName)'? [y/N]"
            If ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
                Write-Host '  [SKIP] Skipped.' -ForegroundColor Yellow
                Write-Host ''
                Continue
            }

            # Backup current state (first time only, then append).
            $Stage1Changes.Add([PSCustomObject]@{
                ComputerName = $Target.ComputerName
                ChangeType   = 'LocalGroupMember'
                KeyOrPath    = 'Administrators'
                OldValue     = $Target.MemberName
                NewValue     = '(removed)'
            })

            Try {
                $MemberToRemove = $Target.MemberName
                Invoke-Command -ComputerName $Target.ComputerName -ErrorAction Stop `
                    -ArgumentList $MemberToRemove -ScriptBlock {
                    Param($Member)
                    Remove-LocalGroupMember -Group 'Administrators' -Member $Member -ErrorAction Stop
                }
                Write-Host "  [OK] Removed '$($Target.MemberName)' from Administrators on '$($Target.ComputerName)'." -ForegroundColor Green
            } Catch {
                Write-Warning "  [FAIL] Could not remove '$($Target.MemberName)' from '$($Target.ComputerName)': $($_.Exception.Message)"
                $Stage1Changes[-1] | Add-Member -NotePropertyName 'Error' `
                    -NotePropertyValue $_.Exception.Message -Force
            }
            Write-Host ''
        }

        If ($Stage1Changes.Count -gt 0) {
            $BackupPath = Save-SmbRemediationBackup -StageNumber 1 -Changes $Stage1Changes
            Write-Host "[INFO] Stage 1 backup saved: $BackupPath" -ForegroundColor Cyan
        }
    }

    # -----------------------------------------------------------------------
    # Stage 2: Restrict SMB firewall rules
    # -----------------------------------------------------------------------
    Write-SmbSectionHeader 'Remediation Stage 2: SMB Firewall Restriction'
    Write-Host '[INFO] Stage 2 restricts broad inbound SMB firewall rules.' -ForegroundColor Yellow
    Write-Host '       Requires typing CONFIRM to proceed.' -ForegroundColor Yellow
    Write-Host ''

    $Stage2Targets = @($Findings | Where-Object {
        $_.Severity -in @('High','Critical') -and
        $_.QueryStatus -eq 'OK' -and
        -not [string]::IsNullOrWhiteSpace($_.RuleName) -and
        -not [string]::IsNullOrWhiteSpace($_.ComputerName)
    })

    If ($Stage2Targets.Count -eq 0) {
        Write-Host '[OK] No Stage 2 firewall targets identified.' -ForegroundColor Green
    } ElseIf ([string]::IsNullOrWhiteSpace(($global:ApprovedSmbAdminHosts -join '').Trim())) {
        Write-Host '[WARN] ApprovedSmbAdminHosts is empty in settings. Stage 2 cannot restrict' -ForegroundColor Yellow
        Write-Host '       firewall rules to approved sources without a list of approved hosts.' -ForegroundColor Yellow
        Write-Host '       Add management host names or IPs to ApprovedSmbAdminHosts in' -ForegroundColor Yellow
        Write-Host '       AD-PowerAdmin_settings.ps1, then re-run.' -ForegroundColor Yellow
    } Else {
        Write-Host 'Proposed changes:' -ForegroundColor Yellow
        $Stage2Targets | Format-Table ComputerName, HostType, RuleName, RemoteAddress, Severity -AutoSize
        $NewRemoteAddress = $global:ApprovedSmbAdminHosts -join ','

        If ($WhatIf) {
            Write-Host "[WHATIF] Would restrict RemoteAddress to: $NewRemoteAddress" -ForegroundColor Yellow
        } Else {
            Write-Host "WARNING: This will restrict the listed firewall rules' RemoteAddress" -ForegroundColor Red
            Write-Host "         to: $NewRemoteAddress" -ForegroundColor Red
            Write-Host "         Ensure this list is complete before proceeding." -ForegroundColor Red
            Write-Host ''
            $Confirm = Read-Host 'Type CONFIRM to apply all Stage 2 firewall changes, or press Enter to skip'
            If ($Confirm -ne 'CONFIRM') {
                Write-Host '[SKIP] Stage 2 skipped.' -ForegroundColor Yellow
            } Else {
                $Stage2Changes = [System.Collections.Generic.List[object]]::new()

                ForEach ($Target in $Stage2Targets) {
                    $Stage2Changes.Add([PSCustomObject]@{
                        ComputerName = $Target.ComputerName
                        ChangeType   = 'FirewallRule'
                        KeyOrPath    = $Target.RuleName
                        OldValue     = $Target.RemoteAddress
                        NewValue     = $NewRemoteAddress
                    })

                    Try {
                        $RuleName     = $Target.RuleName
                        $NewAddr      = $NewRemoteAddress
                        Invoke-Command -ComputerName $Target.ComputerName -ErrorAction Stop `
                            -ArgumentList $RuleName, $NewAddr -ScriptBlock {
                            Param($Name, $Addr)
                            $Rule = Get-NetFirewallRule -DisplayName $Name -ErrorAction Stop
                            $Rule | Set-NetFirewallAddressFilter -RemoteAddress $Addr -ErrorAction Stop
                        }
                        Write-Host "[OK] Restricted '$($Target.RuleName)' on '$($Target.ComputerName)'." -ForegroundColor Green
                    } Catch {
                        Write-Warning "[FAIL] Could not restrict '$($Target.RuleName)' on '$($Target.ComputerName)': $($_.Exception.Message)"
                    }
                }

                If ($Stage2Changes.Count -gt 0) {
                    $BackupPath = Save-SmbRemediationBackup -StageNumber 2 -Changes $Stage2Changes
                    Write-Host "[INFO] Stage 2 backup saved: $BackupPath" -ForegroundColor Cyan
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # Stage 3: Set AutoShare registry values to 0
    # -----------------------------------------------------------------------
    Write-SmbSectionHeader 'Remediation Stage 3: AutoShare Registry Hardening'
    Write-Host '[INFO] Stage 3 sets AutoShareWks/AutoShareServer to 0 on flagged computers.' -ForegroundColor Yellow
    Write-Host '       This prevents admin shares from being auto-recreated after a service' -ForegroundColor Yellow
    Write-Host '       restart. It does NOT remove currently active shares.' -ForegroundColor Yellow
    Write-Host '       Requires typing CONFIRM to proceed.' -ForegroundColor Yellow
    Write-Host ''

    $Stage3Targets = @($Findings | Where-Object {
        $_.Severity -in @('High','Critical','Medium') -and
        $_.QueryStatus -eq 'OK' -and
        -not [string]::IsNullOrWhiteSpace($_.ValueName) -and
        $_.ValueData -ne '0'
    })

    If ($Stage3Targets.Count -eq 0) {
        Write-Host '[OK] No Stage 3 registry targets identified.' -ForegroundColor Green
    } Else {
        Write-Host 'WARNING: Disabling AutoShare prevents admin shares from auto-recreating.' -ForegroundColor Red
        Write-Host '         Test in a non-production environment first. Ensure backup, monitoring,' -ForegroundColor Red
        Write-Host '         and deployment tools do not require admin share access on these hosts.' -ForegroundColor Red
        Write-Host ''
        $Stage3Targets | Format-Table ComputerName, HostType, ValueName, ValueData, Severity -AutoSize

        If ($WhatIf) {
            Write-Host '[WHATIF] Would set AutoShareWks/AutoShareServer to 0 on listed computers.' -ForegroundColor Yellow
        } Else {
            $Confirm = Read-Host 'Type CONFIRM to apply all Stage 3 registry changes, or press Enter to skip'
            If ($Confirm -ne 'CONFIRM') {
                Write-Host '[SKIP] Stage 3 skipped.' -ForegroundColor Yellow
            } Else {
                $Stage3Changes = [System.Collections.Generic.List[object]]::new()
                $RegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

                ForEach ($Target in $Stage3Targets) {
                    $Stage3Changes.Add([PSCustomObject]@{
                        ComputerName = $Target.ComputerName
                        ChangeType   = 'RegistryValue'
                        KeyOrPath    = "$RegPath\$($Target.ValueName)"
                        OldValue     = $Target.ValueData
                        NewValue     = '0'
                    })

                    Try {
                        $ValName = $Target.ValueName
                        $Path    = $RegPath
                        Invoke-Command -ComputerName $Target.ComputerName -ErrorAction Stop `
                            -ArgumentList $Path, $ValName -ScriptBlock {
                            Param($RegPath, $ValueName)
                            Set-ItemProperty -Path $RegPath -Name $ValueName -Value 0 `
                                -Type DWord -Force -ErrorAction Stop
                        }
                        Write-Host "[OK] Set $($Target.ValueName) = 0 on '$($Target.ComputerName)'." -ForegroundColor Green
                    } Catch {
                        Write-Warning "[FAIL] Could not set $($Target.ValueName) on '$($Target.ComputerName)': $($_.Exception.Message)"
                    }
                }

                If ($Stage3Changes.Count -gt 0) {
                    $BackupPath = Save-SmbRemediationBackup -StageNumber 3 -Changes $Stage3Changes
                    Write-Host "[INFO] Stage 3 backup saved: $BackupPath" -ForegroundColor Cyan
                }
            }
        }
    }

    Write-Host ''
    Write-Host '[INFO] Remediation session complete. Use Restore-ADAdminShareRemediationBackup' -ForegroundColor Green
    Write-Host '       to roll back any stage if needed.' -ForegroundColor Green
}

##############################################################################
# Restore-ADAdminShareRemediationBackup
##############################################################################

Function Restore-ADAdminShareRemediationBackup {
    <#
    .SYNOPSIS
        Restore previous state from a remediation backup JSON file.
    .DESCRIPTION
        Lists available backup files in ReportsPath, prompts the user to select one,
        displays a diff of OldValue vs. CurrentValue for each item, and restores the
        prior configuration after CONFIRM input.
    .PARAMETER BackupFile
        Full path to a specific backup JSON file. If omitted, lists available backups
        from ReportsPath and prompts for selection.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$BackupFile
    )

    Write-SmbSectionHeader 'SMB Remediation Rollback'

    If ([string]::IsNullOrWhiteSpace($BackupFile)) {
        $Backups = @(Get-ChildItem -Path $global:ReportsPath `
            -Filter 'SmbAdminShare-Backup_*.json' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)

        If ($Backups.Count -eq 0) {
            Write-Host '[INFO] No SMB remediation backup files found in Reports directory.' -ForegroundColor Yellow
            Return
        }

        Write-Host 'Available backup files:'
        For ($i = 0; $i -lt $Backups.Count; $i++) {
            Write-Host "  [$($i+1)] $($Backups[$i].Name)  ($($Backups[$i].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))"
        }
        Write-Host ''
        $Selection = Read-Host 'Enter the number of the backup to restore, or press Enter to cancel'
        If ([string]::IsNullOrWhiteSpace($Selection)) {
            Write-Host '[INFO] Rollback cancelled.' -ForegroundColor Yellow
            Return
        }
        $Idx = [int]$Selection - 1
        If ($Idx -lt 0 -or $Idx -ge $Backups.Count) {
            Write-Warning '[WARN] Invalid selection.'
            Return
        }
        $BackupFile = $Backups[$Idx].FullName
    }

    If (-not (Test-Path $BackupFile)) {
        Write-Warning "[WARN] Backup file not found: $BackupFile"
        Return
    }

    Try {
        $Backup = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
    } Catch {
        Write-Warning "[WARN] Could not parse backup file: $($_.Exception.Message)"
        Return
    }

    Write-Host "Backup file  : $BackupFile"
    Write-Host "Stage        : $($Backup.StageNumber)"
    Write-Host "Recorded at  : $($Backup.Timestamp)"
    Write-Host ''
    Write-Host 'Changes to restore:'
    Write-Host ('-' * 80)

    ForEach ($Change in $Backup.Changes) {
        Write-Host "  Computer   : $($Change.ComputerName)"
        Write-Host "  Type       : $($Change.ChangeType)"
        Write-Host "  Key/Path   : $($Change.KeyOrPath)"
        Write-Host "  Restore to : $($Change.OldValue)  (was set to: $($Change.NewValue))"
        Write-Host ''
    }

    $Confirm = Read-Host 'Type CONFIRM to restore all items listed above, or press Enter to cancel'
    If ($Confirm -ne 'CONFIRM') {
        Write-Host '[INFO] Rollback cancelled.' -ForegroundColor Yellow
        Return
    }

    ForEach ($Change in $Backup.Changes) {
        Try {
            Switch ($Change.ChangeType) {
                'LocalGroupMember' {
                    $Member  = $Change.OldValue
                    $GrpName = $Change.KeyOrPath
                    Invoke-Command -ComputerName $Change.ComputerName -ErrorAction Stop `
                        -ArgumentList $GrpName, $Member -ScriptBlock {
                        Param($Group, $Member)
                        Add-LocalGroupMember -Group $Group -Member $Member -ErrorAction Stop
                    }
                    Write-Host "[OK] Restored '$Member' to '$($Change.KeyOrPath)' on '$($Change.ComputerName)'." -ForegroundColor Green
                }
                'FirewallRule' {
                    $RuleName   = $Change.KeyOrPath
                    $OldAddress = $Change.OldValue
                    Invoke-Command -ComputerName $Change.ComputerName -ErrorAction Stop `
                        -ArgumentList $RuleName, $OldAddress -ScriptBlock {
                        Param($Name, $Addr)
                        $Rule = Get-NetFirewallRule -DisplayName $Name -ErrorAction Stop
                        $Rule | Set-NetFirewallAddressFilter -RemoteAddress $Addr -ErrorAction Stop
                    }
                    Write-Host "[OK] Restored firewall rule '$RuleName' RemoteAddress to '$OldAddress' on '$($Change.ComputerName)'." -ForegroundColor Green
                }
                'RegistryValue' {
                    $OldVal = $Change.OldValue
                    $Path   = $Change.KeyOrPath -replace '\\[^\\]+$', ''
                    $ValName = $Change.KeyOrPath -replace '^.*\\', ''

                    If ($OldVal -eq '(absent)') {
                        Invoke-Command -ComputerName $Change.ComputerName -ErrorAction Stop `
                            -ArgumentList $Path, $ValName -ScriptBlock {
                            Param($RegPath, $ValueName)
                            Remove-ItemProperty -Path $RegPath -Name $ValueName `
                                -ErrorAction SilentlyContinue
                        }
                        Write-Host "[OK] Removed registry value '$ValName' on '$($Change.ComputerName)' (restoring absent state)." -ForegroundColor Green
                    } Else {
                        Invoke-Command -ComputerName $Change.ComputerName -ErrorAction Stop `
                            -ArgumentList $Path, $ValName, [int]$OldVal -ScriptBlock {
                            Param($RegPath, $ValueName, $Value)
                            Set-ItemProperty -Path $RegPath -Name $ValueName `
                                -Value $Value -Type DWord -Force -ErrorAction Stop
                        }
                        Write-Host "[OK] Restored '$ValName' to $OldVal on '$($Change.ComputerName)'." -ForegroundColor Green
                    }
                }
                Default {
                    Write-Warning "[WARN] Unknown ChangeType '$($Change.ChangeType)' -- skipping."
                }
            }
        } Catch {
            Write-Warning "[FAIL] Could not restore change for '$($Change.ComputerName)': $($_.Exception.Message)"
        }
    }

    Write-Host ''
    Write-Host '[INFO] Rollback complete.' -ForegroundColor Green
}
