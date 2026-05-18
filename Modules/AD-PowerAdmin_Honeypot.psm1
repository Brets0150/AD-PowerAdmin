#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory

Function Initialize-Module {
    <#
    .SYNOPSIS
        Initialize-Module

    .DESCRIPTION
        Initialize-Module

    .EXAMPLE
        Initialize-Module

    .NOTES
        Initialize-Module is called by AD-PowerAdmin_Main.ps1 to initialize the module.
    #>

    # Remove stale entries if module is reloaded.
    $global:Menu.Remove('HoneypotMenu')
    $global:SubMenus.Remove('HoneypotMenu')

    # Register the sub-menu items.
    $global:SubMenus += @{
        'HoneypotMenu' = @{
            Title       = "Honeytoken Account Management"
            HelpCommand = "Show-HoneypotHelp"
            Items = @{
                'HoneypotInstall' = @{
                    Title   = "Install Honeypot Account"
                    Label   = "Provision a hardened Active Directory honeytoken user account for password spray and brute-force detection."
                    Command = "Install-HoneypotAccount"
                }
                'HoneypotReport' = @{
                    Title   = "View Activity Report"
                    Label   = "Search domain controller security logs for authentication events against the honeytoken account and display a structured report."
                    Command = "Show-HoneypotReport"
                }
                'HoneypotSafetyCheck' = @{
                    Title   = "Verify Account Safety"
                    Label   = "Verify the honeytoken account has no privileged group memberships, SPNs, or delegation rights."
                    Command = "Test-HoneytokenUserSafety"
                }
                'HoneypotDetectionTest' = @{
                    Title   = "Test Detection System"
                    Label   = "Trigger controlled authentication events against the honeytoken account to verify that Security log detection and email alerting are working end to end."
                    Command = "Invoke-HoneypotDetectionTest"
                }
                'HoneypotRemove' = @{
                    Title   = "Remove Honeypot Account"
                    Label   = "Safely decommission the honeytoken account and remove the associated scheduled monitoring task."
                    Command = "Remove-HoneypotAccount"
                }
                'HoneypotDecentralizedInstall' = @{
                    Title   = "Deploy Decentralized Monitor"
                    Label   = "Install a lightweight local-only monitor on individual domain controllers. Each DC queries its own Security log and alerts independently -- eliminates RPC overhead for resource-constrained DCs. Requires the honeytoken account to be installed first."
                    Command = "Install-HoneypotDecentralized"
                }
                'HoneypotDecentralizedRemove' = @{
                    Title   = "Remove Decentralized Monitor"
                    Label   = "Remove the decentralized monitor deployment from selected domain controllers. Removes the scheduled task and optionally the deployment directory."
                    Command = "Remove-HoneypotDecentralized"
                }
            }
        }
    }

    # Register a single main menu entry that opens the sub-menu.
    $global:Menu += @{
        'HoneypotMenu' = @{
            Title    = "Honeytoken Management"
            Label    = "Deploy and monitor a honeytoken user account to detect password spray attacks and unauthorized credential use."
            Module   = "AD-PowerAdmin_Honeypot"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'HoneypotMenu'"
        }
    }

    # Register the hourly unattended monitoring job.
    # This job is triggered by the AD-PowerAdmin_HoneypotMonitor scheduled task, not the daily runner.
    $global:UnattendedJobs += @{
        'HoneypotHourlyMonitor' = @{
            Title    = 'Honeytoken Hourly Monitor'
            Label    = 'Search domain controller security logs for honeytoken authentication events in the past hour and send an alert if any are found.'
            Module   = 'AD-PowerAdmin_Honeypot'
            Function = 'Start-HoneypotMonitor'
            Daily    = $false
            Command  = 'Start-HoneypotMonitor'
        }
    }
}

Initialize-Module

# ===========================================================================
# Private Helpers (not exported; called only by public functions in this module)
# ===========================================================================

Function Get-HoneypotDefaultDenyGroup {
    # Returns the configured deny-logon group name, falling back to the default if not set.
    if (-not [string]::IsNullOrWhiteSpace($global:HoneypotDenyGroup)) {
        return $global:HoneypotDenyGroup
    }
    return 'GG_Honeytoken_DenyLogon'
}

Function Get-HoneypotEventsBatch {
    # Queries one DC for honeytoken authentication events in the given time window.
    # Enriches each matching event with Severity, DomainController, and HoneytokenAccount properties.
    #
    # Uses -FilterHashtable instead of -FilterXPath. -FilterHashtable accepts datetime objects
    # directly for StartTime/EndTime, letting PowerShell handle UTC conversion internally. This
    # avoids the class of failures where -FilterXPath with a manually-constructed UTC string
    # returns zero events on some Windows versions due to how the remote Event Log RPC service
    # evaluates the XPath TimeCreated predicate.
    #
    # Username filtering is done entirely client-side: the hashtable filter has no field for
    # EventData values, so all events matching EventID + time window are returned and then
    # filtered by TargetUserName / ServiceName in the loop below.
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][datetime]$StartTime,
        [Parameter(Mandatory=$true)][datetime]$EndTime
    )

    # Detect local machine to bypass RPC/DCOM (direct log file access).
    # Compare only the NetBIOS hostname portion: Get-ADDomainController returns FQDNs like
    # FL-222.tdcme.loc while $env:COMPUTERNAME is the short name FL-222. Without this
    # split, the IsLocal check always fails when running on the DC itself, causing a
    # remote self-query that may silently fail depending on firewall configuration.
    [string]$LocalNetBios = $env:COMPUTERNAME.ToUpper()
    [string]$QueryNetBios = $ComputerName.Split('.')[0].ToUpper()
    [bool]$IsLocal = ($QueryNetBios -eq $LocalNetBios) -or
                     ($ComputerName -eq 'localhost')   -or
                     ($ComputerName -eq '127.0.0.1')

    [hashtable]$Filter = @{
        LogName   = 'Security'
        Id        = @(4624, 4625, 4768, 4771, 4740)
        StartTime = $StartTime
        EndTime   = $EndTime
    }

    [datetime]$QueryStart = Get-Date
    try {
        if ($IsLocal) {
            $RawEvents = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue
        } else {
            $RawEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $Filter -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host ("    [DC-WARN] {0}: Security log query failed -- {1}" -f $ComputerName, $_) -ForegroundColor Yellow
        return @()
    }
    [double]$QuerySec = ((Get-Date) - $QueryStart).TotalSeconds

    [string]$QueryMode = if ($IsLocal) { 'local' } else { 'remote' }
    [int]$RawCount = if ($RawEvents) { $RawEvents.Count } else { 0 }
    Write-Host ("    [DC-DATA] {0}: {1} event(s) for '{2}' returned in {3:N1}s ({4} filter)" -f $ComputerName, $RawCount, $Username, $QuerySec, $QueryMode) -ForegroundColor DarkGray

    # Second query: Kerberos service ticket requests (Event 4769) when a bait SPN is configured.
    # Event 4769 identifies the target by ServiceName (= the honeytoken sAMAccountName),
    # not TargetUserName, so it requires a separate query.
    if (-not [string]::IsNullOrWhiteSpace($global:HoneypotSPN)) {
        [hashtable]$Filter4769 = @{
            LogName   = 'Security'
            Id        = @(4769)
            StartTime = $StartTime
            EndTime   = $EndTime
        }
        try {
            [array]$Kerberos4769 = if ($IsLocal) {
                Get-WinEvent -FilterHashtable $Filter4769 -ErrorAction SilentlyContinue
            } else {
                Get-WinEvent -ComputerName $ComputerName -FilterHashtable $Filter4769 -ErrorAction SilentlyContinue
            }
        } catch { $Kerberos4769 = @() }
        if ($Kerberos4769) { $RawEvents = @($RawEvents) + @($Kerberos4769) }
    }

    if (-not $RawEvents) { return @() }

    # Events are returned only when activity exists in the window -- parse and enrich them.
    [datetime]$ParseStart = Get-Date
    $Enriched = @()
    foreach ($Evt in $RawEvents) {
        # Flatten EventData XML fields onto the event object so callers can use dot notation.
        [xml]$Xml = $Evt.ToXml()
        $Xml.Event.EventData.Data | ForEach-Object {
            Add-Member -InputObject $Evt -MemberType NoteProperty -Name $_.Name -Value $_.'#text' -Force
        }

        # Client-side username filter.
        # Event 4769 stores the account name in ServiceName; all other events use TargetUserName.
        if ($Evt.Id -eq 4769) {
            $TargetUser = if ($Evt.ServiceName) { $Evt.ServiceName.Split('@')[0] } else { '' }
        } else {
            $TargetUser = if ($Evt.TargetUserName) { $Evt.TargetUserName.Split('@')[0] } else { '' }
        }
        if ($TargetUser -ne $Username) { continue }

        $Severity = if ($Evt.Id -eq 4624) { 'CRITICAL' } else { 'HIGH' }
        Add-Member -InputObject $Evt -MemberType NoteProperty -Name 'Severity'          -Value $Severity     -Force
        Add-Member -InputObject $Evt -MemberType NoteProperty -Name 'DomainController'  -Value $ComputerName -Force
        Add-Member -InputObject $Evt -MemberType NoteProperty -Name 'HoneytokenAccount' -Value $Username     -Force

        $Enriched += $Evt
    }
    Write-Host ("    [DC-PARSE] {0}: XML enrichment for {1} event(s) took {2:N1}s" -f $ComputerName, $RawCount, ((Get-Date) - $ParseStart).TotalSeconds) -ForegroundColor DarkGray

    return $Enriched
}

Function Get-HoneypotEvents {
    # Queries all domain controllers for honeytoken authentication events.
    param(
        [Parameter(Mandatory=$false)][datetime]$StartTime = (Get-Date).AddHours(-1),
        [Parameter(Mandatory=$false)][datetime]$EndTime   = (Get-Date),
        [Parameter(Mandatory=$false)][string]$Username    = $global:HoneypotUsername
    )

    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Host "Honeytoken username is not configured. Run 'Install Honeypot Account' first." -ForegroundColor Red
        return @()
    }

    if ($global:HoneypotMonitorMode -eq 'Decentralized') {
        $DomainControllers = @($env:COMPUTERNAME)
        Write-Host ("  [Decentralized] Querying local Security log only on: {0}" -f $env:COMPUTERNAME) -ForegroundColor Gray
    } else {
        try {
            $DomainControllers = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName)
        } catch {
            Write-Host "  [FAIL] Could not enumerate domain controllers: $_" -ForegroundColor Red
            return @()
        }
        Write-Host ("  [Centralized] Querying {0} domain controller(s) -- window: {1} to {2}" -f $DomainControllers.Count, $StartTime.ToString('HH:mm:ss'), $EndTime.ToString('HH:mm:ss')) -ForegroundColor Gray
    }

    [datetime]$QueryStart = Get-Date
    $AllEvents = @()
    foreach ($DC in $DomainControllers) {
        [datetime]$DCStart = Get-Date
        Write-Host ("  [{0}] Start  : {1}" -f $DCStart.ToString('HH:mm:ss'), $DC) -ForegroundColor Gray

        $DCEvents = Get-HoneypotEventsBatch -ComputerName $DC -Username $Username -StartTime $StartTime -EndTime $EndTime

        [datetime]$DCEnd     = Get-Date
        [double]$ElapsedSec  = ($DCEnd - $DCStart).TotalSeconds
        [int]$DCMatchCount   = if ($DCEvents) { $DCEvents.Count } else { 0 }
        Write-Host ("  [{0}] Finish : {1} -- {2} matching event(s) -- {3:N1}s" -f $DCEnd.ToString('HH:mm:ss'), $DC, $DCMatchCount, $ElapsedSec) -ForegroundColor Gray

        $AllEvents += $DCEvents
    }

    [double]$TotalSec = ((Get-Date) - $QueryStart).TotalSeconds
    Write-Host ("  Total: {0} DC(s) queried in {1:N1}s -- {2} matching event(s)" -f $DomainControllers.Count, $TotalSec, $AllEvents.Count) -ForegroundColor Gray

    return $AllEvents
}

Function New-HoneypotDenyGroup {
    # Creates the deny-logon security group if it does not already exist.
    param(
        [Parameter(Mandatory=$true)][string]$GroupName
    )

    $ExistingGroup = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
    if (-not $ExistingGroup) {
        Write-Host "  Creating deny-logon group '$GroupName' ..." -ForegroundColor White
        $Domain = Get-ADDomain
        try {
            New-ADGroup -Name $GroupName `
                        -GroupScope DomainLocal `
                        -GroupCategory Security `
                        -Description 'Deny-logon group for honeytoken accounts. Apply GPO user rights to block all logon types for this group.' `
                        -Path "CN=Users,$($Domain.DistinguishedName)" | Out-Null
            Write-Host "  [OK] Group '$GroupName' created." -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Could not create group '$GroupName': $_" -ForegroundColor Red
            return $null
        }
    } else {
        Write-Host "  [OK] Deny-logon group '$GroupName' already exists." -ForegroundColor Green
    }
    return Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue
}

Function New-HoneytokenUser {
    # Creates the honeytoken AD user account with hardened attributes.
    # $SpnValue: if non-empty, sets a Kerberoasting bait SPN on the account.
    # $EnableReversibleEncryption: if true, stores password with reversible encryption (DCSync bait).
    param(
        [Parameter(Mandatory=$true)][hashtable]$Profile,
        [Parameter(Mandatory=$true)][string]$OuDn,
        [Parameter(Mandatory=$true)][string]$DenyGroupName,
        [Parameter(Mandatory=$false)][string]$SpnValue = '',
        [Parameter(Mandatory=$false)][bool]$EnableReversibleEncryption = $false
    )

    [string]$SamAccountName = $Profile.SamAccountName

    # Check for an existing account.
    $Existing = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue
    if ($Existing) {
        Write-Host "  [WARN] Account '$SamAccountName' already exists in Active Directory." -ForegroundColor Yellow
        $Confirm = Read-Host "  Continue and reconfigure the existing account? (y/N)"
        if ($Confirm -notmatch '^[Yy]$') { return $false }
    }

    # Generate both forms of the password. The plain text is needed for the LDAP bind
    # that initializes lastLogonTimestamp (see below). It is cleared in a finally block
    # and never written to disk, the event log, or any persistent store.
    [string]$PlainPassword = New-RandomPassword -Length 32
    [securestring]$SecurePassword = ConvertTo-SecureString $PlainPassword -AsPlainText -Force

    Write-Host "  Creating honeytoken user '$SamAccountName' ..." -ForegroundColor White

    $NewUserParams = @{
        SamAccountName                  = $SamAccountName
        UserPrincipalName               = "$SamAccountName@$((Get-ADDomain).DNSRoot)"
        Name                            = $Profile.DisplayName
        DisplayName                     = $Profile.DisplayName
        GivenName                       = $Profile.GivenName
        Surname                         = $Profile.Surname
        Description                     = $Profile.Description
        Department                      = $Profile.Department
        Title                           = $Profile.Title
        AccountPassword                 = $SecurePassword
        Enabled                         = $true
        PasswordNeverExpires            = $true
        CannotChangePassword            = $true
        ChangePasswordAtLogon           = $false
        AllowReversiblePasswordEncryption = $EnableReversibleEncryption
        Path                            = $OuDn
    }

    try {
        if (-not $Existing) {
            New-ADUser @NewUserParams
        } else {
            # Reset the password when reconfiguring so the provisioning auth below has a known credential.
            Set-ADAccountPassword -Identity $SamAccountName -NewPassword $SecurePassword -Reset -ErrorAction Stop
            Set-ADUser -Identity $SamAccountName -AllowReversiblePasswordEncryption $EnableReversibleEncryption -ErrorAction Stop
        }
        # Disable all delegation regardless of whether the account is new or existing.
        Set-ADUser -Identity $SamAccountName -AccountNotDelegated $true
        Set-ADUser -Identity $SamAccountName -TrustedForDelegation $false
        Write-Host "  [OK] Account '$SamAccountName' provisioned with hardened attributes." -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Failed to create or configure honeytoken account: $_" -ForegroundColor Red
        $PlainPassword = $null
        return $false
    }

    # Initialize lastLogonTimestamp via a one-time LDAP bind.
    # The attribute is SAM-owned; direct LDAP writes are blocked even for Domain Admins.
    # A real Kerberos/NTLM authentication is the only deterministic path. We bind while
    # we still hold the plain-text password and before the deny-logon GPO has propagated
    # (fresh install) or before the account is known to be in the deny-logon group on
    # every DC (re-provisioning). The bind generates a controlled Event 4624 during
    # provisioning -- the monitor scheduled task is not yet running at this point.
    [string]$AuthDomain = (Get-ADDomain).DNSRoot
    [System.DirectoryServices.DirectoryEntry]$BindEntry = $null
    try {
        $BindEntry = [System.DirectoryServices.DirectoryEntry]::new(
            "LDAP://$AuthDomain",
            "$SamAccountName@$AuthDomain",
            $PlainPassword,
            [System.DirectoryServices.AuthenticationTypes]::Secure
        )
        $null = $BindEntry.distinguishedName
        Write-Host '  [OK] lastLogonTimestamp initialized via provisioning authentication.' -ForegroundColor Green
    } catch {
        Write-Host '  [INFO] Provisioning authentication was blocked (deny-logon policy may already be applied on the authenticating DC).' -ForegroundColor Cyan
        Write-Host '         lastLogonTimestamp will be set on the account''s first detected activity.' -ForegroundColor Gray
    } finally {
        if ($null -ne $BindEntry) { try { $BindEntry.Dispose() } catch {} }
        $BindEntry     = $null
        $PlainPassword = $null
    }

    # Set Kerberoasting bait SPN if requested.
    if (-not [string]::IsNullOrWhiteSpace($SpnValue)) {
        # Verify the SPN is not already registered on another account.
        $SpnConflict = Get-ADObject -Filter "servicePrincipalName -eq '$SpnValue'" -ErrorAction SilentlyContinue
        if ($SpnConflict -and $SpnConflict.DistinguishedName -ne (Get-ADUser -Identity $SamAccountName).DistinguishedName) {
            Write-Host "  [WARN] SPN '$SpnValue' is already registered on '$($SpnConflict.Name)'. Skipping SPN assignment." -ForegroundColor Yellow
        } else {
            try {
                Set-ADUser -Identity $SamAccountName -ServicePrincipalNames @{Add = $SpnValue} -ErrorAction Stop
                Write-Host "  [OK] Kerberoasting bait SPN set: $SpnValue" -ForegroundColor Green
            } catch {
                Write-Host "  [WARN] Could not set SPN '$SpnValue': $_" -ForegroundColor Yellow
            }
        }
    }

    if ($EnableReversibleEncryption) {
        Write-Host '  [OK] Reversible password encryption enabled (DCSync bait attribute).' -ForegroundColor Green
    }

    # Create or validate the deny-logon group and add the honeytoken user to it.
    $DenyGroupObj = New-HoneypotDenyGroup -GroupName $DenyGroupName
    if (-not $DenyGroupObj) { return $false }

    try {
        Add-ADGroupMember -Identity $DenyGroupObj -Members $SamAccountName -ErrorAction Stop
        Write-Host "  [OK] Added '$SamAccountName' to deny-logon group '$DenyGroupName'." -ForegroundColor Green
    } catch {
        if ($_.Exception.Message -match 'already a member') {
            Write-Host "  [OK] '$SamAccountName' is already a member of '$DenyGroupName'." -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Failed to add user to deny-logon group: $_" -ForegroundColor Red
        }
    }

    return $true
}

Function New-HoneypotScheduledTask {
    # Creates a Windows scheduled task that runs the honeytoken monitor via AD-PowerAdmin.
    # The repetition interval is driven by $global:HoneypotMonitorIntervalMinutes.
    param(
        [Parameter(Mandatory=$true)][string]$ScriptPath
    )

    [int]$IntervalMinutes = if ($global:HoneypotMonitorIntervalMinutes -gt 0) { $global:HoneypotMonitorIntervalMinutes } else { 60 }

    [string]$TaskName = 'AD-PowerAdmin_HoneypotMonitor'
    [string]$TaskDesc = "AD-PowerAdmin: Honeytoken authentication event monitor (every $IntervalMinutes min). Detects password spray and unauthorized access attempts against the configured honeytoken account."

    # Remove the task if it already exists so we can recreate it cleanly.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Write-Host "  Removing existing scheduled task '$TaskName' ..." -ForegroundColor White
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # First run is one interval from now; then repeats every interval indefinitely.
    [datetime]$FirstRun = (Get-Date).AddMinutes($IntervalMinutes)

    New-ADPAScheduledTask `
        -ActionString          'PowerShell.exe' `
        -ActionArguments       "-NonInteractive -NoProfile -File `"$ScriptPath`" -Unattended -JobName 'HoneypotHourlyMonitor'" `
        -ScheduleRunTime       $FirstRun `
        -Recurring             'Interval' `
        -RepeatIntervalMinutes $IntervalMinutes `
        -TaskName              $TaskName `
        -TaskDiscription       $TaskDesc
}

Function Remove-HoneypotScheduledTask {
    # Removes the AD-PowerAdmin_HoneypotMonitor scheduled task if it exists.
    [string]$TaskName = 'AD-PowerAdmin_HoneypotMonitor'
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "  [OK] Scheduled task '$TaskName' removed." -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Scheduled task '$TaskName' not found (already removed or never created)." -ForegroundColor Yellow
    }
}

Function Set-HoneypotSettings {
    # Updates honeytoken configuration variables in AD-PowerAdmin_settings.ps1 and syncs
    # them into the current session's global scope.
    # $IntervalMinutes = -1 (default) means leave the existing interval unchanged.
    # This is called only during install and removal -- not during normal operation.
    param(
        [Parameter(Mandatory=$true)][bool]$Audit,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Username,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$DenyGroup,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$OU,
        [Parameter(Mandatory=$false)][int]$IntervalMinutes = -1,
        [Parameter(Mandatory=$false)][AllowEmptyString()][string]$SPN = $null
    )

    [string]$SettingsFile = "$global:ThisScriptDir\AD-PowerAdmin_settings.ps1"
    if (-not (Test-Path $SettingsFile)) {
        Write-Host "  [FAIL] Settings file not found: $SettingsFile" -ForegroundColor Red
        return
    }

    [string]$Content = Get-Content $SettingsFile -Raw
    [string]$BoolStr = if ($Audit) { 'true' } else { 'false' }

    $Content = Set-SettingsFileValue -Content $Content -VarName 'HoneypotAudit'     -NewValue $BoolStr  -VarType 'bool'
    $Content = Set-SettingsFileValue -Content $Content -VarName 'HoneypotUsername'  -NewValue $Username  -VarType 'string-single'
    $Content = Set-SettingsFileValue -Content $Content -VarName 'HoneypotDenyGroup' -NewValue $DenyGroup -VarType 'string-single'
    $Content = Set-SettingsFileValue -Content $Content -VarName 'HoneypotOU'        -NewValue $OU        -VarType 'string-single'

    if ($IntervalMinutes -ge 1) {
        $Content = Set-SettingsFileValue -Content $Content -VarName 'HoneypotMonitorIntervalMinutes' -NewValue $IntervalMinutes -VarType 'int'
        $global:HoneypotMonitorIntervalMinutes = $IntervalMinutes
    }

    if ($null -ne $SPN) {
        $Content = Set-SettingsFileValue -Content $Content -VarName 'HoneypotSPN' -NewValue $SPN -VarType 'string-single'
        $global:HoneypotSPN = $SPN
    }

    [System.IO.File]::WriteAllText($SettingsFile, $Content, [System.Text.Encoding]::UTF8)

    # Sync the updated values into the running session so callers see the changes immediately.
    $global:HoneypotAudit     = $Audit
    $global:HoneypotUsername  = $Username
    $global:HoneypotDenyGroup = $DenyGroup
    $global:HoneypotOU        = $OU

    Write-Host "  [OK] Honeytoken settings written to settings file." -ForegroundColor Green
}

Function Get-HoneypotGPOName {
    # Returns the fixed GPO name used by the Honeypot module for the deny-logon policy.
    return 'ADPA__Honeytoken_DenyLogon'
}

Function Set-HoneypotGPOUserRights {
    # Writes the five deny-logon Privilege Rights for the specified group SID into the
    # GPO's GptTmpl.inf in SYSVOL, then increments the GPT.INI version counter and
    # updates the GPO's AD object so domain clients detect and apply the change.
    param(
        [Parameter(Mandatory=$true)][System.Guid]$GpoGuid,
        [Parameter(Mandatory=$true)][string]$GroupSid
    )

    try {
        $Domain = Get-ADDomain
    } catch {
        Write-Host "  [FAIL] Could not retrieve domain information: $_" -ForegroundColor Red
        return $false
    }

    # Build SYSVOL paths from the GPO GUID.
    [string]$GuidStr     = '{' + $GpoGuid.ToString().ToUpper() + '}'
    [string]$SysvolBase  = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\$GuidStr"
    [string]$GptTmplDir  = "$SysvolBase\Machine\Microsoft\Windows NT\SecEdit"
    [string]$GptTmplPath = "$GptTmplDir\GptTmpl.inf"
    [string]$GptIniPath  = "$SysvolBase\GPT.INI"

    # Ensure the SecEdit directory exists in SYSVOL.
    if (-not (Test-Path $GptTmplDir)) {
        try {
            New-Item -ItemType Directory -Path $GptTmplDir -Force | Out-Null
            Write-Host "  [OK] Created SYSVOL SecEdit directory." -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL] Could not create SYSVOL directory '$GptTmplDir': $_" -ForegroundColor Red
            return $false
        }
    }

    # Build the GptTmpl.inf content. The signature value '$CHICAGO$' cannot appear
    # in a double-quoted string without variable expansion swallowing it; use a
    # single-quoted intermediate variable so the here-string expands it correctly.
    [string]$Sig = 'signature="$CHICAGO$"'
    [string]$GptTmplContent = @"
[Unicode]
Unicode=yes
[Version]
$Sig
Revision=1
[Privilege Rights]
SeDenyInteractiveLogonRight = *$GroupSid
SeDenyRemoteInteractiveLogonRight = *$GroupSid
SeDenyBatchLogonRight = *$GroupSid
SeDenyServiceLogonRight = *$GroupSid
SeDenyNetworkLogonRight = *$GroupSid
"@

    # Write as UTF-16 LE (required by the Windows Security Configuration Engine).
    try {
        [System.IO.File]::WriteAllText($GptTmplPath, $GptTmplContent, [System.Text.Encoding]::Unicode)
        Write-Host "  [OK] Written GptTmpl.inf to SYSVOL." -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not write GptTmpl.inf: $_" -ForegroundColor Red
        return $false
    }

    # Read the current GPT.INI version counter.
    # The 32-bit version has high 16 bits = user config version and low 16 bits = computer config version.
    # Machine (computer) policy changes require incrementing the low 16 bits.
    [int]$CurrentVersion = 0
    try {
        [string]$GptIniContent = Get-Content $GptIniPath -Raw -ErrorAction Stop
        if ($GptIniContent -match 'Version=(\d+)') {
            $CurrentVersion = [int]$Matches[1]
        }
    } catch {
        Write-Host "  [WARN] Could not read GPT.INI (will create new version entry): $_" -ForegroundColor Yellow
        [string]$GptIniContent = "[General]`r`nVersion=0`r`n"
    }

    [int]$UserVer    = ($CurrentVersion -shr 16) -band 0xFFFF
    [int]$CompVer    = $CurrentVersion -band 0xFFFF
    [int]$NewVersion = ($UserVer -shl 16) -bor ($CompVer + 1)

    try {
        [string]$UpdatedIni = $GptIniContent -replace 'Version=\d+', "Version=$NewVersion"
        [System.IO.File]::WriteAllText($GptIniPath, $UpdatedIni, [System.Text.Encoding]::ASCII)
        Write-Host "  [OK] GPT.INI version incremented ($CurrentVersion -> $NewVersion)." -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not update GPT.INI: $_" -ForegroundColor Red
        return $false
    }

    # Update the GPO's AD object: versionNumber and gPCMachineExtensionNames.
    # Security Settings CSE GUID: {827D319E-6EAC-11D2-A4EA-00C04F79F83A}
    # Associated tool GUID:       {803E14A0-B4FB-11D0-A0D0-00A0C90F574B}
    #
    # New-GPO (called via Install-GPOBaseline) always writes to the PDC emulator.
    # Querying a different DC before replication completes causes "object not found".
    # Target the PDC emulator explicitly for both read and write to eliminate that race.
    [string]$PDC            = $Domain.PDCEmulator
    [string]$GpoDisplayName = Get-HoneypotGPOName
    [string]$PoliciesBase   = "CN=Policies,CN=System,$($Domain.DistinguishedName)"
    [string]$LdapFilter     = "(&(objectClass=groupPolicyContainer)(displayName=$GpoDisplayName))"
    [string]$SecExt         = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

    Write-Host ("  Locating GPO AD object on PDC emulator ({0}) ..." -f $PDC) -ForegroundColor Gray

    try {
        $GpoAdObj = Get-ADObject `
            -Server $PDC `
            -LDAPFilter $LdapFilter `
            -SearchBase $PoliciesBase `
            -Properties gPCMachineExtensionNames `
            -ErrorAction Stop
    } catch {
        Write-Host "  [FAIL] Error searching for GPO AD object on '$PDC': $_" -ForegroundColor Red
        return $false
    }

    if (-not $GpoAdObj) {
        Write-Host "  [FAIL] Could not locate GPO AD object for '$GpoDisplayName' on '$PDC'." -ForegroundColor Red
        Write-Host "  [DIAG] DC queried  : $PDC" -ForegroundColor Yellow
        Write-Host "  [DIAG] LDAP filter : $LdapFilter" -ForegroundColor Yellow
        Write-Host "  [DIAG] Search base : $PoliciesBase" -ForegroundColor Yellow
        Write-Host "  [DIAG] GPOs found in $PoliciesBase on $PDC :" -ForegroundColor Yellow
        try {
            $AllGpos = Get-ADObject -Server $PDC -SearchBase $PoliciesBase `
                -LDAPFilter '(objectClass=groupPolicyContainer)' `
                -Properties displayName -ErrorAction Stop
            if ($AllGpos) {
                $AllGpos | ForEach-Object {
                    Write-Host ("  [DIAG]   CN={0}  displayName={1}" -f $_.Name, $_.displayName) -ForegroundColor Yellow
                }
            } else {
                Write-Host "  [DIAG]   (none found -- GPO replication may still be in progress)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host ("  [DIAG]   Could not enumerate GPOs: {0}" -f $_) -ForegroundColor Yellow
        }
        return $false
    }

    [string]$GpoDn    = $GpoAdObj.DistinguishedName
    [string]$ExistExt = $GpoAdObj.gPCMachineExtensionNames

    if ([string]::IsNullOrWhiteSpace($ExistExt)) {
        [string]$NewExts = $SecExt
    } elseif ($ExistExt -notlike '*827D319E-6EAC-11D2-A4EA-00C04F79F83A*') {
        [string]$NewExts = $ExistExt + $SecExt
    } else {
        [string]$NewExts = $ExistExt
    }

    try {
        Set-ADObject -Server $PDC -Identity $GpoDn -Replace @{
            versionNumber            = $NewVersion
            gPCMachineExtensionNames = $NewExts
        }
        Write-Host ("  [OK] GPO AD object updated on {0} (versionNumber, gPCMachineExtensionNames)." -f $PDC) -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not update GPO AD object '$GpoDn' on '$PDC': $_" -ForegroundColor Red
        return $false
    }

    return $true
}

Function Install-HoneypotGPO {
    # Creates the honeytoken deny-logon GPO via GPOMgr, links it to the domain root,
    # and writes the Privilege Rights for the deny-logon group into SYSVOL GptTmpl.inf.
    param(
        [Parameter(Mandatory=$true)][string]$DenyGroupName
    )

    [string]$GpoName = Get-HoneypotGPOName

    try {
        $Domain = Get-ADDomain
    } catch {
        Write-Host "  [FAIL] Could not retrieve domain: $_" -ForegroundColor Red
        return $false
    }

    # Resolve the deny-logon group SID for GptTmpl.inf privilege rights.
    $DenyGroupObj = Get-ADGroup -Filter "Name -eq '$DenyGroupName'" -Properties SID -ErrorAction SilentlyContinue
    if (-not $DenyGroupObj) {
        Write-Host "  [FAIL] Deny-logon group '$DenyGroupName' not found. Create the group before installing the GPO." -ForegroundColor Red
        return $false
    }
    [string]$GroupSid = $DenyGroupObj.SID.Value

    Write-Host "  Creating GPO '$GpoName' ..." -ForegroundColor White

    # Create and link the GPO using GPOMgr's Install-GPOBaseline.
    $GpoDefinition = @{
        Name        = $GpoName
        Description = 'AD-PowerAdmin Honeypot Module: Denies all logon rights to the honeytoken deny-logon group. Managed by AD-PowerAdmin -- do not edit manually.'
        Links       = @($Domain.DistinguishedName)
    }

    try {
        $Result = Install-GPOBaseline -GpoDefinition $GpoDefinition
    } catch {
        Write-Host "  [FAIL] GPO baseline creation failed: $_" -ForegroundColor Red
        return $false
    }

    # Verify the GPO exists regardless of whether it was newly created or already present.
    $GpoCheck = Find-GPO -Name $GpoName
    if ($GpoCheck.Count -eq 0) {
        Write-Host "  [FAIL] GPO '$GpoName' was not found after creation attempt." -ForegroundColor Red
        if ($Result -and $Result.Errors) { $Result.Errors | ForEach-Object { Write-Host "    $_" -ForegroundColor Red } }
        return $false
    }

    Write-Host "  [OK] GPO '$GpoName' created and linked to domain root." -ForegroundColor Green

    # Retrieve the GPO GUID for SYSVOL path construction.
    try {
        $GpoObj  = Get-GPO -Name $GpoName -ErrorAction Stop
        $GpoGuid = $GpoObj.Id
    } catch {
        Write-Host "  [FAIL] Could not retrieve GPO GUID for '$GpoName': $_" -ForegroundColor Red
        return $false
    }

    # Write the deny-logon Privilege Rights into SYSVOL GptTmpl.inf.
    $RightsOk = Set-HoneypotGPOUserRights -GpoGuid $GpoGuid -GroupSid $GroupSid
    if (-not $RightsOk) {
        Write-Host "  [FAIL] Could not write User Rights Assignments to GptTmpl.inf." -ForegroundColor Red
        return $false
    }

    Write-Host "  [OK] GPO '$GpoName' fully configured with deny-logon User Rights Assignments." -ForegroundColor Green
    return $true
}

Function Remove-HoneypotGPO {
    # Removes the honeytoken deny-logon GPO and all its scope-of-management links.
    [string]$GpoName = Get-HoneypotGPOName

    $Existing = Find-GPO -Name $GpoName
    if ($Existing.Count -eq 0) {
        Write-Host "  [INFO] GPO '$GpoName' not found (may already have been removed)." -ForegroundColor Yellow
        return
    }

    Write-Host "  Removing GPO '$GpoName' ..." -ForegroundColor White
    try {
        Remove-ADPAGPO -Name $GpoName -RemoveLinks -Confirm:$false
        Write-Host "  [OK] GPO '$GpoName' removed." -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Could not remove GPO '$GpoName': $_" -ForegroundColor Red
    }
}

# ===========================================================================
# Public Functions (exported; called from menu/submenu or as unattended jobs)
# ===========================================================================

Function Install-HoneypotAccount {
    <#
    .SYNOPSIS
        Provisions a hardened Active Directory honeytoken user account for attack detection.

    .DESCRIPTION
        === Install Honeypot Account. ===
            This wizard creates a honeytoken user account that should never authenticate.
            Any authentication attempt against the account is treated as a high-confidence
            indicator of password spraying, brute-force activity, or credential testing.

            The wizard performs the following steps:
            1. Presents a curated list of realistic-looking service account usernames.
            2. Collects the target OU DistinguishedName for account placement.
            3. Prompts for the deny-logon group name and the monitoring check interval.
            4. Creates the AD user with hardened attributes: no SPNs, no delegation,
               PasswordNeverExpires, CannotChangePassword, long random password.
            5. Creates or validates the deny-logon security group and adds the account to it.
            6. Validates account safety (no privileged groups, no delegation).
            7. Creates and links the deny-logon GPO to the domain root and writes the
               five deny-logon Privilege Rights for the deny-logon group into SYSVOL.
            8. Writes all configuration (including the monitor interval) to AD-PowerAdmin_settings.ps1.
            9. Creates a Windows scheduled task using the configured monitor interval.

    .EXAMPLE
        Install-HoneypotAccount

    .INPUTS
        None. Interactive prompts guide the installation.

    .OUTPUTS
        None. Writes to Active Directory and the settings file.

    .NOTES
        Menu path: Honeytoken Management -> Install Honeypot Account.
    #>

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  Honeytoken Account Provisioning Wizard' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''

    # Warn if a honeytoken account is already configured.
    if (-not [string]::IsNullOrWhiteSpace($global:HoneypotUsername)) {
        Write-Host "WARNING: A honeytoken account is already configured: '$($global:HoneypotUsername)'" -ForegroundColor Yellow
        $OverwriteConfirm = Read-Host 'Replace the existing configuration? (y/N)'
        if ($OverwriteConfirm -notmatch '^[Yy]$') {
            Write-Host 'Installation cancelled.' -ForegroundColor White
            return
        }
    }

    # Curated list of realistic honeytoken profiles.
    $Profiles = @(
        @{ SamAccountName = 'svc_backup_sync';   DisplayName = 'Backup Sync Service';   GivenName = 'Backup';   Surname = 'Sync';        Description = 'Backup sync svc acct - temp pw: Backup@2024';          SpnService = 'MSExchangeMBx'; Department = 'Infrastructure';        Title = 'Service Account'        }
        @{ SamAccountName = 'svc_print_audit';   DisplayName = 'Print Audit Service';   GivenName = 'Print';    Surname = 'Audit';       Description = 'Print audit svc - default pwd: Print!Svc01';           SpnService = 'HTTP';          Department = 'IT Operations';          Title = 'Service Account'        }
        @{ SamAccountName = 'svc_file_index';    DisplayName = 'File Index Service';    GivenName = 'File';     Surname = 'Index';       Description = 'File indexer svc acct - temp: FileIdx@Corp';           SpnService = 'wsman';         Department = 'Infrastructure';        Title = 'Service Account'        }
        @{ SamAccountName = 'svc_report_reader'; DisplayName = 'Report Reader Service'; GivenName = 'Report';   Surname = 'Reader';      Description = 'Reports read-only acct - pw: R3port@ReadOnly';         SpnService = 'TERMSRV';       Department = 'Finance';               Title = 'Service Account'        }
        @{ SamAccountName = 'vpn.healthcheck';   DisplayName = 'VPN Health Check';      GivenName = 'VPN';      Surname = 'HealthCheck'; Description = 'VPN monitor - vendor default creds: Netw0rk!Mon';      SpnService = 'HTTP';          Department = 'Network Operations';    Title = 'Service Account'        }
        @{ SamAccountName = 'adm_helpdesk_temp'; DisplayName = 'Helpdesk Admin Temp';   GivenName = 'Helpdesk'; Surname = 'Admin';       Description = 'Temp helpdesk elevated acct - reset pw: H3lpD3sk@Tmp'; SpnService = 'WSMAN';         Department = 'IT Support';            Title = 'Helpdesk Administrator' }
        @{ SamAccountName = 'sql_report_reader'; DisplayName = 'SQL Report Reader';     GivenName = 'SQL';      Surname = 'Reports';     Description = 'SQL reports svc - default install pw: SqlR3p0rt!';     SpnService = 'MSSQLSvc';      Department = 'Business Intelligence'; Title = 'Service Account'        }
    )

    Write-Host 'Select a honeytoken username from the list below.' -ForegroundColor White
    Write-Host 'Choose a name that blends naturally with your environment.' -ForegroundColor Gray
    Write-Host ''
    for ($i = 0; $i -lt $Profiles.Count; $i++) {
        $P = $Profiles[$i]
        Write-Host ("  [{0}] {1,-24}  {2}" -f ($i + 1), $P.SamAccountName, $P.DisplayName) -ForegroundColor White
    }
    Write-Host ''

    [int]$Selection = 0
    do {
        $Raw = Read-Host "Enter selection (1-$($Profiles.Count))"
        if ($Raw -match '^\d+$') { [int]$Selection = [int]$Raw }
        if ($Selection -lt 1 -or $Selection -gt $Profiles.Count) {
            Write-Host "  Invalid selection. Enter a number between 1 and $($Profiles.Count)." -ForegroundColor Red
            $Selection = 0
        }
    } until ($Selection -ge 1 -and $Selection -le $Profiles.Count)

    $ChosenProfile = $Profiles[$Selection - 1]
    Write-Host ''
    Write-Host "  Selected: $($ChosenProfile.SamAccountName)  ($($ChosenProfile.DisplayName))" -ForegroundColor Green
    Write-Host ''

    # Collect the target OU using the interactive browser.
    Write-Host 'Select the OU where the honeytoken account should be created:' -ForegroundColor White
    [string]$OuDn = Get-AdOuSearch
    if ([string]::IsNullOrWhiteSpace($OuDn)) {
        Write-Host '  [INFO] Installation cancelled.' -ForegroundColor Cyan
        return
    }

    # Allow the admin to customise the deny-logon group name.
    [string]$DenyGroup = Get-HoneypotDefaultDenyGroup
    Write-Host ''
    Write-Host "Deny-logon group: $DenyGroup" -ForegroundColor White
    $CustomGroup = Read-Host 'Press ENTER to accept or type a different group name'
    if (-not [string]::IsNullOrWhiteSpace($CustomGroup)) { $DenyGroup = $CustomGroup.Trim() }

    # Kerberoasting bait SPN (optional).
    # Adding an SPN makes the account a Kerberoastable target; any service ticket request
    # (Event 4769) against it is an attack indicator. The suggested SPN is based on the account's
    # service class and the domain FQDN -- it does not need to resolve to a real host.
    Write-Host ''
    Write-Host 'Kerberoasting bait SPN (optional):' -ForegroundColor White
    Write-Host '  Adding an SPN makes this account targetable by Kerberoasting tools.' -ForegroundColor Gray
    Write-Host '  Any Kerberos service ticket request (Event 4769) becomes an attack indicator.' -ForegroundColor Gray
    [string]$DomainFqdn    = (Get-ADDomain).DNSRoot
    [string]$SpnHostname   = ($ChosenProfile.SamAccountName -replace '[_.]', '-') + '.' + $DomainFqdn
    [string]$SuggestedSpn  = if ($ChosenProfile.SpnService -eq 'MSSQLSvc') {
        "$($ChosenProfile.SpnService)/$($SpnHostname):1433"
    } else {
        "$($ChosenProfile.SpnService)/$SpnHostname"
    }
    Write-Host ("  Suggested: {0}" -f $SuggestedSpn) -ForegroundColor Cyan
    [string]$SpnInput = Read-Host '  Press ENTER to use suggestion, type a custom SPN, or type N to skip'
    [string]$SpnValue = ''
    if ($SpnInput.Trim().ToUpper() -ne 'N') {
        $SpnValue = if ([string]::IsNullOrWhiteSpace($SpnInput)) { $SuggestedSpn } else { $SpnInput.Trim() }
    }

    # Reversible encryption (optional).
    # Enabling this stores the password in a recoverable form in AD, making the account a
    # higher-priority target for operators with DCSync rights. Since the password is a
    # cryptographically random 32-char string the harvested value is useless to an attacker,
    # but the attribute increases the account's attractiveness as a target.
    Write-Host ''
    Write-Host 'Reversible password encryption (optional):' -ForegroundColor White
    Write-Host '  Marks the account as a DCSync high-value target without real credential risk.' -ForegroundColor Gray
    [string]$RevEncInput = Read-Host '  Enable reversible encryption? (y/N)'
    [bool]$EnableReversibleEncryption = ($RevEncInput.Trim().ToUpper() -eq 'Y')

    # Collect the monitoring check interval.
    Write-Host ''
    Write-Host 'How often should the monitor check Security logs for honeytoken activity?' -ForegroundColor White
    Write-Host 'This sets both the scheduled task interval and the log lookback window (interval + 1 min).' -ForegroundColor Gray
    [int]$MonitorInterval = 15
    $RawInterval = Read-Host 'Check interval in minutes (press ENTER for default: 15)'
    if (-not [string]::IsNullOrWhiteSpace($RawInterval)) {
        [int]$ParsedInterval = 0
        if ([int]::TryParse($RawInterval.Trim(), [ref]$ParsedInterval) -and $ParsedInterval -gt 0) {
            $MonitorInterval = $ParsedInterval
        } else {
            Write-Host "  Invalid value. Using default of 15 minutes." -ForegroundColor Yellow
        }
    }

    # Show summary and ask for final confirmation.
    Write-Host ''
    Write-Host 'Summary:' -ForegroundColor White
    Write-Host ("  Username              : {0}" -f $ChosenProfile.SamAccountName) -ForegroundColor White
    Write-Host ("  Display Name          : {0}" -f $ChosenProfile.DisplayName)     -ForegroundColor White
    Write-Host ("  OU                    : {0}" -f $OuDn)                          -ForegroundColor White
    Write-Host ("  Deny Group            : {0}" -f $DenyGroup)                     -ForegroundColor White
    Write-Host ("  Kerberoasting SPN     : {0}" -f $(if ([string]::IsNullOrWhiteSpace($SpnValue)) { '(none)' } else { $SpnValue })) -ForegroundColor White
    Write-Host ("  Reversible Encryption : {0}" -f $(if ($EnableReversibleEncryption) { 'Enabled' } else { 'Disabled' })) -ForegroundColor White
    Write-Host ("  Monitor Interval      : {0} minutes" -f $MonitorInterval)       -ForegroundColor White
    Write-Host ''

    $FinalConfirm = Read-Host 'Proceed with account creation? (y/N)'
    if ($FinalConfirm -notmatch '^[Yy]$') {
        Write-Host 'Installation cancelled.' -ForegroundColor White
        return
    }

    Write-Host ''
    Write-Host 'Provisioning honeytoken account ...' -ForegroundColor White

    $Created = New-HoneytokenUser -Profile $ChosenProfile -OuDn $OuDn -DenyGroupName $DenyGroup `
        -SpnValue $SpnValue -EnableReversibleEncryption $EnableReversibleEncryption
    if (-not $Created) {
        Write-Host '[FAIL] Account provisioning failed. Installation aborted.' -ForegroundColor Red
        return
    }

    # Sync the SPN into the session so Set-HoneypotSettings and the safety check
    # both see the correct value without an extra Get-ADDomain round-trip.
    $global:HoneypotSPN = $SpnValue

    Write-Host ''
    Write-Host 'Creating deny-logon Group Policy Object ...' -ForegroundColor White
    $GpoOk = Install-HoneypotGPO -DenyGroupName $DenyGroup
    if (-not $GpoOk) {
        Write-Host '[WARN] GPO creation failed. The account is provisioned but deny-logon policy was not applied automatically.' -ForegroundColor Yellow
        Write-Host '       Resolve the GPO error and re-run the install wizard, or configure the GPO manually.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host 'Writing configuration to settings file ...' -ForegroundColor White
    Set-HoneypotSettings -Audit $true -Username $ChosenProfile.SamAccountName -DenyGroup $DenyGroup -OU $OuDn -IntervalMinutes $MonitorInterval -SPN $SpnValue

    Write-Host ''
    Write-Host "Creating monitoring scheduled task (every $MonitorInterval minutes) ..." -ForegroundColor White
    New-HoneypotScheduledTask -ScriptPath $global:ThisScript

    Write-Host ''
    Write-Host 'Running safety validation ...' -ForegroundColor White
    Test-HoneytokenUserSafety -SamAccountName $ChosenProfile.SamAccountName

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Green
    Write-Host '  Honeytoken account provisioning complete.' -ForegroundColor Green
    Write-Host ('=' * 70) -ForegroundColor Green
    Write-Host ''
    Write-Host 'Recommended follow-up:' -ForegroundColor Yellow
    Write-Host "  1. Allow 5-10 minutes for Group Policy to propagate to all domain controllers." -ForegroundColor Yellow
    Write-Host "  2. Confirm scheduled task 'AD-PowerAdmin_HoneypotMonitor' appears in Task Scheduler." -ForegroundColor Yellow
    Write-Host ''
}

Function Test-HoneytokenUserSafety {
    <#
    .SYNOPSIS
        Validates the honeytoken account has no dangerous privileges, SPNs, or delegation rights.

    .DESCRIPTION
        === Verify Honeytoken Account Safety. ===
            Inspects the configured honeytoken account and reports pass or fail for each
            of the following safety criteria:

            - Account is enabled (must be enabled to generate detection events)
            - No Service Principal Names configured (prevents Kerberoasting)
            - Not trusted for unconstrained Kerberos delegation
            - AccountNotDelegated flag is set
            - Account is a member of the deny-logon group
            - Account has no membership in privileged groups

    .EXAMPLE
        Test-HoneytokenUserSafety
        Test-HoneytokenUserSafety -SamAccountName 'svc_backup_sync'

    .INPUTS
        Optional SamAccountName. Uses the configured honeytoken account by default.

    .OUTPUTS
        Console safety report. Returns $true if all checks pass, $false otherwise.

    .NOTES
        Menu path: Honeytoken Management -> Verify Account Safety.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)][string]$SamAccountName = $global:HoneypotUsername
    )

    if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
        Write-Host 'No honeytoken account configured. Run Install Honeypot Account first.' -ForegroundColor Red
        return $false
    }

    $User = Get-ADUser -Identity $SamAccountName `
        -Properties MemberOf, ServicePrincipalNames, TrustedForDelegation, AccountNotDelegated, Enabled `
        -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Host "  [FAIL] Account '$SamAccountName' not found in Active Directory." -ForegroundColor Red
        return $false
    }

    [bool]$AllPassed = $true
    [string]$Divider = '-' * 60

    Write-Host ''
    Write-Host "Honeytoken Safety Report: $SamAccountName" -ForegroundColor White
    Write-Host $Divider -ForegroundColor White

    # Enabled status.
    if ($User.Enabled) {
        Write-Host '  [OK]   Account is enabled (required for detection events).' -ForegroundColor Green
    } else {
        Write-Host '  [WARN] Account is disabled and will not generate detection events.' -ForegroundColor Yellow
    }

    # SPNs -- treat the configured Kerberoasting bait SPN as intentional; flag unexpected ones.
    [string]$ConfiguredSpn = $global:HoneypotSPN
    if ([string]::IsNullOrWhiteSpace($ConfiguredSpn)) {
        # No intentional SPN configured -- any SPN is unexpected and a hardening failure.
        if ($User.ServicePrincipalNames.Count -eq 0) {
            Write-Host '  [OK]   No Service Principal Names (SPNs) configured.' -ForegroundColor Green
        } else {
            Write-Host '  [FAIL] Account has unexpected SPNs (Kerberoasting risk):' -ForegroundColor Red
            $User.ServicePrincipalNames | ForEach-Object { Write-Host "           $_" -ForegroundColor Red }
            $AllPassed = $false
        }
    } else {
        # Intentional Kerberoasting bait SPN -- validate it is present and no extras exist.
        [bool]$HasExpected = $User.ServicePrincipalNames -contains $ConfiguredSpn
        [array]$ExtraSpns  = @($User.ServicePrincipalNames | Where-Object { $_ -ne $ConfiguredSpn })
        if ($HasExpected) {
            Write-Host ("  [OK]   Kerberoasting bait SPN is set: {0}" -f $ConfiguredSpn) -ForegroundColor Green
        } else {
            Write-Host ("  [WARN] Expected Kerberoasting bait SPN is missing: {0}" -f $ConfiguredSpn) -ForegroundColor Yellow
        }
        if ($ExtraSpns.Count -gt 0) {
            Write-Host '  [FAIL] Unexpected additional SPNs detected (not the configured bait SPN):' -ForegroundColor Red
            $ExtraSpns | ForEach-Object { Write-Host "           $_" -ForegroundColor Red }
            $AllPassed = $false
        }
    }

    # Unconstrained delegation.
    if ($User.TrustedForDelegation -eq $true) {
        Write-Host '  [FAIL] Account is trusted for unconstrained Kerberos delegation.' -ForegroundColor Red
        $AllPassed = $false
    } else {
        Write-Host '  [OK]   Not trusted for unconstrained delegation.' -ForegroundColor Green
    }

    # AccountNotDelegated flag.
    if ($User.AccountNotDelegated -eq $true) {
        Write-Host '  [OK]   AccountNotDelegated flag is set.' -ForegroundColor Green
    } else {
        Write-Host '  [WARN] AccountNotDelegated flag is not set. Remediate with: Set-ADUser -Identity <name> -AccountNotDelegated $true' -ForegroundColor Yellow
    }

    # Deny-logon group membership.
    [string]$DenyGroup = Get-HoneypotDefaultDenyGroup
    $DenyGroupObj = Get-ADGroup -Filter "Name -eq '$DenyGroup'" -ErrorAction SilentlyContinue
    if ($DenyGroupObj) {
        if ($User.MemberOf -contains $DenyGroupObj.DistinguishedName) {
            Write-Host "  [OK]   Account is a member of deny-logon group '$DenyGroup'." -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Account is NOT a member of deny-logon group '$DenyGroup'." -ForegroundColor Red
            $AllPassed = $false
        }
    } else {
        Write-Host "  [WARN] Deny-logon group '$DenyGroup' not found. Run the install wizard to create it." -ForegroundColor Yellow
    }

    # Deny-logon GPO existence and domain-root link check.
    [string]$GpoName  = Get-HoneypotGPOName
    $GpoFound         = Find-GPO -Name $GpoName
    if ($GpoFound.Count -eq 0) {
        Write-Host "  [FAIL] Deny-logon GPO '$GpoName' does not exist. Run the install wizard to create it." -ForegroundColor Red
        $AllPassed = $false
    } else {
        [string]$DomainDn = (Get-ADDomain).DistinguishedName
        [bool]$GpoLinked  = Test-GPO -Name $GpoName -Links @($DomainDn) -Quiet
        if ($GpoLinked) {
            Write-Host "  [OK]   Deny-logon GPO '$GpoName' exists and is linked to domain root." -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Deny-logon GPO '$GpoName' exists but is not linked to the domain root." -ForegroundColor Red
            $AllPassed = $false
        }
    }

    # Scheduled task interval vs configured setting.
    [string]$MonitorTaskName    = 'AD-PowerAdmin_HoneypotMonitor'
    [int]$ConfiguredMinutes     = if ($global:HoneypotMonitorIntervalMinutes -gt 0) { $global:HoneypotMonitorIntervalMinutes } else { 15 }
    $MonitorTask = Get-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue
    if (-not $MonitorTask) {
        Write-Host "  [FAIL] Scheduled task '$MonitorTaskName' not found. Run the install wizard to create it." -ForegroundColor Red
        $AllPassed = $false
    } else {
        [int]$TaskMinutes    = 0
        $TaskTrigger = $MonitorTask.Triggers | Select-Object -First 1
        if ($TaskTrigger -and $TaskTrigger.Repetition -and $TaskTrigger.Repetition.Interval) {
            [string]$IsoInterval = $TaskTrigger.Repetition.Interval
            if      ($IsoInterval -match '^PT(\d+)H$')      { $TaskMinutes = [int]$Matches[1] * 60 }
            elseif  ($IsoInterval -match '^PT(\d+)M$')      { $TaskMinutes = [int]$Matches[1] }
            elseif  ($IsoInterval -match '^PT(\d+)H(\d+)M$'){ $TaskMinutes = ([int]$Matches[1] * 60) + [int]$Matches[2] }
        }
        if ($TaskMinutes -gt 0 -and $TaskMinutes -eq $ConfiguredMinutes) {
            Write-Host "  [OK]   Monitor task interval ($TaskMinutes min) matches configured setting." -ForegroundColor Green
        } elseif ($TaskMinutes -gt 0) {
            Write-Host "  [FAIL] Monitor task interval ($TaskMinutes min) does not match setting ($ConfiguredMinutes min). Re-run the install wizard to sync." -ForegroundColor Red
            $AllPassed = $false
        } else {
            Write-Host "  [WARN] Could not parse scheduled task repetition interval '$($TaskTrigger.Repetition.Interval)'." -ForegroundColor Yellow
        }
    }

    # Privileged group membership.
    [string[]]$PrivGroups = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Backup Operators', 'Account Operators', 'Server Operators',
        'Print Operators', 'Replicator', 'Enterprise Key Admins', 'Key Admins'
    )
    $UserGroupNames = $User.MemberOf | ForEach-Object { (Get-ADGroup -Identity $_).Name }
    $PrivFound      = $UserGroupNames | Where-Object { $PrivGroups -contains $_ }

    if ($PrivFound) {
        Write-Host '  [FAIL] Account has privileged group memberships:' -ForegroundColor Red
        $PrivFound | ForEach-Object { Write-Host "           $_" -ForegroundColor Red }
        $AllPassed = $false
    } else {
        Write-Host '  [OK]   No privileged group memberships detected.' -ForegroundColor Green
    }

    Write-Host $Divider -ForegroundColor White
    if ($AllPassed) {
        Write-Host '  RESULT: All safety checks passed.' -ForegroundColor Green
    } else {
        Write-Host '  RESULT: One or more safety checks FAILED. Review and remediate.' -ForegroundColor Red
    }
    Write-Host ''

    return $AllPassed
}

Function Start-HoneypotMonitor {
    <#
    .SYNOPSIS
        Hourly unattended monitor that searches for honeytoken authentication events and alerts on activity.

    .DESCRIPTION
        === Honeytoken Hourly Monitor (Unattended). ===
            Executed by the AD-PowerAdmin_HoneypotMonitor Windows scheduled task every hour.
            Queries all domain controllers for Security log events 4624, 4625, 4768, 4771,
            and 4740 involving the configured honeytoken account in the past hour.

            If any events are detected:
            - Classifies events by severity: CRITICAL (4624 successful logon), HIGH (all others).
            - Builds a structured alert and emails it to the configured administrator address.
            - Exports full event details to a timestamped CSV file in the Reports directory.

            Controlled by $global:HoneypotAudit in AD-PowerAdmin_settings.ps1.

    .EXAMPLE
        Start-HoneypotMonitor

    .INPUTS
        None. Reads configuration from global settings.

    .OUTPUTS
        None on no activity. On detection: email alert and CSV export.

    .NOTES
        Triggered by: AD-PowerAdmin.ps1 -Unattended -JobName 'HoneypotHourlyMonitor'
        Requires $global:HoneypotAudit = $true and $global:HoneypotUsername to be set.
    #>

    if ($global:HoneypotAudit -ne $true) {
        Write-Host 'Honeytoken monitoring is disabled (HoneypotAudit = false). No action taken.' -ForegroundColor Yellow
        return
    }

    if ([string]::IsNullOrWhiteSpace($global:HoneypotUsername)) {
        Write-Host 'HoneypotUsername is not configured. Run the install wizard first.' -ForegroundColor Red
        return
    }

    [int]$IntervalMinutes = if ($global:HoneypotMonitorIntervalMinutes -gt 0) { $global:HoneypotMonitorIntervalMinutes } else { 60 }
    [int]$LookbackMinutes = $IntervalMinutes + 1

    [datetime]$StartTime = (Get-Date).AddMinutes(-$LookbackMinutes)
    [datetime]$EndTime   = Get-Date
    [string]$ReportDate  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    [string]$Username    = $global:HoneypotUsername

    Write-Host "Honeytoken monitor: checking for activity against '$Username' since $StartTime (lookback: $LookbackMinutes min)" -ForegroundColor White

    $Events = Get-HoneypotEvents -StartTime $StartTime -EndTime $EndTime -Username $Username

    if (-not $Events -or $Events.Count -eq 0) {
        Write-Host "No honeytoken authentication events detected in the past $LookbackMinutes minutes." -ForegroundColor Green
        return
    }

    # Events detected -- build and send an alert.
    [int]$EventCount    = $Events.Count
    [int]$CriticalCount = ($Events | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    [string]$Subject    = "ADPowerAdmin: ALERT - Honeytoken Activity Detected ($EventCount events, $CriticalCount CRITICAL)"

    [string]$Divider = ('-' * 70) + "`r`n"
    [string]$Body    = "AD-PowerAdmin: Honeytoken Authentication Alert`r`n"
    $Body           += "Report Generated   : $ReportDate`r`n"
    $Body           += "Honeytoken Account : $Username`r`n"
    $Body           += "Period             : $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))`r`n"
    $Body           += "Total Events       : $EventCount`r`n"
    $Body           += "CRITICAL (Successful Logon) : $CriticalCount`r`n"
    $Body           += "`r`n"
    $Body           += "Any use of a honeytoken account is a high-confidence indicator of:`r`n"
    $Body           += "  - Password spray or brute-force attack`r`n"
    $Body           += "  - Credential stuffing or replay`r`n"
    $Body           += "  - Attacker reconnaissance or validation`r`n"
    $Body           += "  - Leaked or compromised credentials in use`r`n"
    if (-not [string]::IsNullOrWhiteSpace($global:HoneypotSPN)) {
        $Body       += "  - Kerberoasting attack (Event 4769: service ticket requested for bait SPN '$($global:HoneypotSPN)')`r`n"
    }
    $Body           += "`r`n$Divider"
    $Body           += "Event Details:`r`n$Divider"

    $Events | ForEach-Object {
        $Body += "Severity         : $($_.Severity)`r`n"
        $Body += "Timestamp        : $($_.TimeCreated)`r`n"
        $Body += "Domain Controller: $($_.DomainController)`r`n"
        $Body += "Event ID         : $($_.Id)`r`n"
        $Body += "Target Account   : $($_.TargetUserName)`r`n"
        $Body += "Source IP        : $($_.IpAddress)`r`n"
        $Body += "Workstation      : $($_.WorkstationName)`r`n"
        $Body += "Logon Type       : $($_.LogonType)`r`n"
        $Body += "Auth Package     : $($_.AuthenticationPackageName)`r`n"
        $Body += "Process Name     : $($_.ProcessName)`r`n"
        if ($_.Id -eq 4769) {
            $Body += "Service Name     : $($_.ServiceName)`r`n"
            $Body += "Ticket Options   : $($_.TicketOptions)`r`n"
        }
        $Body += $Divider
    }

    $Body += "`r`nRecommended Immediate Actions:`r`n"
    $Body += "  1. Identify the source IP and workstation listed in the event details.`r`n"
    $Body += "  2. Determine if the same source attempted other accounts.`r`n"
    $Body += "  3. Check whether any successful logons occurred from the same source.`r`n"
    $Body += "  4. Isolate or block the source if internal; block at perimeter if external.`r`n"
    $Body += "  5. Reset passwords for any accounts targeted by the same source.`r`n"
    $Body += "  6. Review MFA, lockout policy, and conditional access controls.`r`n"
    $Body += "`r`nFull event export: $global:ReportsPath`r`n"

    # Export full event details to CSV.
    [string]$ReportName = "HoneytokenAlert_$($Username)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Export-AdPowerAdminData -Data $Events -ReportName $ReportName -Force

    if ([string]::IsNullOrWhiteSpace($global:ADAdminEmail) -or [string]::IsNullOrWhiteSpace($global:SMTPServer)) {
        Write-Host "  [SKIP] Alert email not sent: ADAdminEmail or SMTPServer is not configured in AD-PowerAdmin_settings.ps1." -ForegroundColor Yellow
        Write-Host "         $EventCount event(s) detected. Report exported to '$global:ReportsPath'." -ForegroundColor Yellow
    } else {
        Send-Email -ToEmail   $global:ADAdminEmail `
                   -FromEmail $global:FromEmail `
                   -Subject   $Subject `
                   -Body      $Body
        Write-Host "Alert sent to $global:ADAdminEmail. $EventCount event(s) detected. Report exported to '$global:ReportsPath'." -ForegroundColor Yellow
    }
}

Function Show-HoneypotReport {
    <#
    .SYNOPSIS
        Searches domain controller security logs for honeytoken activity and displays a structured report.

    .DESCRIPTION
        === View Honeytoken Activity Report. ===
            Queries all domain controllers for authentication events (4624, 4625, 4768,
            4771, 4740) targeting the configured honeytoken account over a user-selected
            time range.

            Events are classified by severity:
            - CRITICAL: Successful logon (ID 4624). The account was accessed.
            - HIGH:     All other authentication attempts.

            Displays a summary table and optionally exports full details to a CSV file.

    .EXAMPLE
        Show-HoneypotReport

    .INPUTS
        None. Interactive prompts guide the time range selection.

    .OUTPUTS
        Console report. Optional CSV export to $global:ReportsPath.

    .NOTES
        Menu path: Honeytoken Management -> View Activity Report.
    #>

    if ([string]::IsNullOrWhiteSpace($global:HoneypotUsername)) {
        Write-Host 'No honeytoken account configured. Run Install Honeypot Account first.' -ForegroundColor Red
        return
    }

    [string]$Username = $global:HoneypotUsername

    Write-Host ''
    Write-Host "Honeytoken Activity Report  --  Account: $Username" -ForegroundColor White
    Write-Host ''
    Write-Host 'NOTE: This report queries the Windows Security Event Log on every domain' -ForegroundColor Yellow
    Write-Host 'controller in the domain over the network. Longer time ranges return more' -ForegroundColor Yellow
    Write-Host 'raw events, which significantly increases retrieval time. This is a' -ForegroundColor Yellow
    Write-Host 'limitation of how Windows transfers event logs between systems, not a' -ForegroundColor Yellow
    Write-Host 'limitation of this script. For large or busy domains, prefer shorter ranges.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  (1) 15 minutes  [default]'
    Write-Host '  (2) 1 hour'
    Write-Host '  (3) 24 hours'
    Write-Host '  (4) 7 days'
    Write-Host '  (5) Custom date/time range'
    Write-Host '  (6) Custom minutes back from now'
    Write-Host ''
    $Range = Read-Host 'Selection [default: 1]'

    [datetime]$StartTime = (Get-Date).AddMinutes(-15)
    [datetime]$EndTime   = Get-Date

    switch ($Range.Trim()) {
        '1' { $StartTime = (Get-Date).AddMinutes(-15) }
        '2' { $StartTime = (Get-Date).AddHours(-1)    }
        '3' { $StartTime = (Get-Date).AddHours(-24)   }
        '4' { $StartTime = (Get-Date).AddDays(-7)     }
        '5' {
            Write-Host 'Enter start date/time (e.g. 2026-04-20 08:00:00):' -ForegroundColor White
            [string]$StartRaw = Read-Host
            Write-Host 'Enter end date/time (leave blank for now):' -ForegroundColor White
            [string]$EndRaw   = Read-Host
            try {
                $StartTime = [datetime]::Parse($StartRaw)
                if (-not [string]::IsNullOrWhiteSpace($EndRaw)) {
                    $EndTime = [datetime]::Parse($EndRaw)
                }
            } catch {
                Write-Host 'Invalid date format. Defaulting to past 15 minutes.' -ForegroundColor Yellow
                $StartTime = (Get-Date).AddMinutes(-15)
            }
        }
        '6' {
            Write-Host 'Enter number of minutes to look back from now:' -ForegroundColor White
            [string]$MinRaw = Read-Host
            [int]$MinBack   = 0
            if ([int]::TryParse($MinRaw.Trim(), [ref]$MinBack) -and $MinBack -gt 0) {
                $StartTime = (Get-Date).AddMinutes(-$MinBack)
            } else {
                Write-Host 'Invalid value. Defaulting to past 15 minutes.' -ForegroundColor Yellow
                $StartTime = (Get-Date).AddMinutes(-15)
            }
        }
        default { $StartTime = (Get-Date).AddMinutes(-15) }
    }

    Write-Host ''
    Write-Host "Searching $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $($EndTime.ToString('yyyy-MM-dd HH:mm:ss')) ..." -ForegroundColor White

    $Events = Get-HoneypotEvents -StartTime $StartTime -EndTime $EndTime -Username $Username

    if (-not $Events -or $Events.Count -eq 0) {
        Write-Host ''
        Write-Host 'No honeytoken authentication events found in the selected time range.' -ForegroundColor Green
        Write-Host 'This is the expected result when the account has not been targeted.' -ForegroundColor Green
        Write-Host ''
        return
    }

    [int]$Total    = $Events.Count
    [int]$Critical = ($Events | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    [int]$High     = $Total - $Critical
    [string]$SummaryColor = if ($Critical -gt 0) { 'Red' } else { 'Yellow' }

    Write-Host ''
    Write-Host ("Total: {0}  |  CRITICAL: {1}  |  HIGH: {2}" -f $Total, $Critical, $High) -ForegroundColor $SummaryColor
    Write-Host ''

    $Events | Select-Object `
        @{N='Severity';        E={$_.Severity}},
        @{N='Time';            E={$_.TimeCreated}},
        @{N='EventID';         E={$_.Id}},
        @{N='DomainController';E={$_.DomainController}},
        @{N='SourceIP';        E={$_.IpAddress}},
        @{N='Workstation';     E={$_.WorkstationName}},
        @{N='LogonType';       E={$_.LogonType}},
        @{N='AuthPackage';     E={$_.AuthenticationPackageName}} |
    Format-Table -AutoSize

    $ExportPrompt = Read-Host 'Export full event details to CSV? (y/N)'
    if ($ExportPrompt -match '^[Yy]$') {
        [string]$ReportName = "HoneytokenReport_$($Username)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Export-AdPowerAdminData -Data $Events -ReportName $ReportName -Force
        Write-Host "Report exported to '$global:ReportsPath'." -ForegroundColor Green
    }

    Write-Host ''
}

Function Remove-HoneypotAccount {
    <#
    .SYNOPSIS
        Safely decommissions the honeytoken account and removes the monitoring scheduled task.

    .DESCRIPTION
        === Remove Honeytoken Account. ===
            Performs a complete, reversible decommissioning of the honeytoken account:

            Step 1: Removes the AD-PowerAdmin_HoneypotMonitor scheduled task.
            Step 2: Removes the account from the deny-logon group.
            Step 3: Disables the AD account.
            Step 4: Optionally deletes the account permanently (explicit confirmation required).
            Step 5: Optionally removes the deny-logon group if it has no remaining members.
            Step 6: Optionally removes the deny-logon GPO (ADPA__Honeytoken_DenyLogon).
            Step 7: Clears the honeytoken configuration from AD-PowerAdmin_settings.ps1.

            Each destructive step is confirmed interactively before execution.

    .EXAMPLE
        Remove-HoneypotAccount

    .INPUTS
        None. Interactive prompts guide the removal.

    .OUTPUTS
        None. Modifies Active Directory and the settings file.

    .NOTES
        Menu path: Honeytoken Management -> Remove Honeypot Account.
    #>

    [string]$Username  = $global:HoneypotUsername
    [string]$DenyGroup = Get-HoneypotDefaultDenyGroup

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Yellow
    Write-Host '  Honeytoken Account Removal' -ForegroundColor Yellow
    Write-Host ('=' * 70) -ForegroundColor Yellow
    Write-Host ''

    # Allow manually specifying the account name if settings were cleared already.
    if ([string]::IsNullOrWhiteSpace($Username)) {
        Write-Host 'No honeytoken account is recorded in settings.' -ForegroundColor Yellow
        $ManualName = Read-Host 'Enter the sAMAccountName of the account to remove (or ENTER to cancel)'
        if ([string]::IsNullOrWhiteSpace($ManualName)) {
            Write-Host 'Removal cancelled.' -ForegroundColor White
            return
        }
        $Username = $ManualName.Trim()
    }

    $Confirm = Read-Host "This will decommission honeytoken account '$Username'. Continue? (y/N)"
    if ($Confirm -notmatch '^[Yy]$') {
        Write-Host 'Removal cancelled.' -ForegroundColor White
        return
    }
    Write-Host ''

    # Step 1: Remove the scheduled task.
    Write-Host 'Step 1: Removing monitoring scheduled task ...' -ForegroundColor White
    Remove-HoneypotScheduledTask
    Write-Host ''

    # Step 2: Remove account from deny-logon group.
    Write-Host "Step 2: Removing account from deny-logon group '$DenyGroup' ..." -ForegroundColor White
    $DenyGroupObj = Get-ADGroup -Filter "Name -eq '$DenyGroup'" -ErrorAction SilentlyContinue
    if ($DenyGroupObj) {
        try {
            Remove-ADGroupMember -Identity $DenyGroupObj -Members $Username -Confirm:$false -ErrorAction Stop
            Write-Host "  [OK] Removed '$Username' from '$DenyGroup'." -ForegroundColor Green
        } catch {
            Write-Host "  [WARN] Could not remove from deny-logon group: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [INFO] Group '$DenyGroup' not found (may already have been removed)." -ForegroundColor Yellow
    }
    Write-Host ''

    # Step 3: Disable the account.
    Write-Host "Step 3: Disabling account '$Username' ..." -ForegroundColor White
    $UserObj = Get-ADUser -Filter "SamAccountName -eq '$Username'" -ErrorAction SilentlyContinue
    if ($UserObj) {
        Disable-ADAccount -Identity $Username
        Write-Host "  [OK] Account '$Username' disabled." -ForegroundColor Green
    } else {
        Write-Host "  [INFO] Account '$Username' not found in AD." -ForegroundColor Yellow
    }
    Write-Host ''

    # Step 4: Optional permanent deletion.
    Write-Host 'Step 4: Permanent deletion (optional).' -ForegroundColor White
    $DeleteConfirm = Read-Host "Permanently DELETE AD account '$Username'? This cannot be undone. (y/N)"
    if ($DeleteConfirm -match '^[Yy]$') {
        if ($UserObj) {
            try {
                Remove-ADUser -Identity $Username -Confirm:$false
                Write-Host "  [OK] Account '$Username' permanently deleted." -ForegroundColor Green
            } catch {
                Write-Host "  [FAIL] Failed to delete account: $_" -ForegroundColor Red
            }
        } else {
            Write-Host '  [INFO] Account was not found in AD; nothing to delete.' -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Account '$Username' left in disabled state (not deleted)." -ForegroundColor White
    }
    Write-Host ''

    # Step 5: Optional deny-logon group removal.
    if ($DenyGroupObj) {
        Write-Host 'Step 5: Deny-logon group cleanup (optional).' -ForegroundColor White
        $DenyGroupObjRefreshed = Get-ADGroup -Filter "Name -eq '$DenyGroup'" -ErrorAction SilentlyContinue
        if ($DenyGroupObjRefreshed) {
            $Members = Get-ADGroupMember -Identity $DenyGroupObjRefreshed -ErrorAction SilentlyContinue
            if (-not $Members -or $Members.Count -eq 0) {
                $RemoveGroup = Read-Host "  Group '$DenyGroup' has no remaining members. Remove the group? (y/N)"
                if ($RemoveGroup -match '^[Yy]$') {
                    try {
                        Remove-ADGroup -Identity $DenyGroupObjRefreshed -Confirm:$false
                        Write-Host "  [OK] Group '$DenyGroup' removed." -ForegroundColor Green
                    } catch {
                        Write-Host "  [FAIL] Failed to remove group: $_" -ForegroundColor Red
                    }
                }
            } else {
                Write-Host "  Group '$DenyGroup' has $($Members.Count) member(s); leaving it in place." -ForegroundColor White
            }
        }
        Write-Host ''
    }

    # Step 6: Optional GPO removal.
    Write-Host 'Step 6: Removing deny-logon Group Policy Object (optional).' -ForegroundColor White
    [string]$HoneypotGpoName = Get-HoneypotGPOName
    $GpoExists = Find-GPO -Name $HoneypotGpoName
    if ($GpoExists.Count -gt 0) {
        $RemoveGpo = Read-Host "  Remove GPO '$HoneypotGpoName'? (y/N)"
        if ($RemoveGpo -match '^[Yy]$') {
            Remove-HoneypotGPO
        } else {
            Write-Host "  GPO '$HoneypotGpoName' left in place." -ForegroundColor White
        }
    } else {
        Write-Host "  [INFO] GPO '$HoneypotGpoName' not found (may already have been removed)." -ForegroundColor Yellow
    }
    Write-Host ''

    # Step 7: Clear settings.
    Write-Host 'Step 7: Clearing honeytoken configuration from settings file ...' -ForegroundColor White
    Set-HoneypotSettings -Audit $false -Username '' -DenyGroup 'GG_Honeytoken_DenyLogon' -OU ''

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Green
    Write-Host '  Honeytoken account removal complete.' -ForegroundColor Green
    Write-Host ('=' * 70) -ForegroundColor Green
    Write-Host ''
}

Function New-HoneypotLiteSettingsContent {
    # Generates the text of a minimal AD-PowerAdmin_settings.ps1 for a decentralized DC
    # deployment. Contains only the variables required for the monitor and email alert.
    # $DeployPath is the root directory on the target DC (e.g. C:\Scripts\AD-PowerAdmin).
    param(
        [Parameter(Mandatory=$true)][string]$DeployPath
    )

    [string]$ReportsPath   = "$DeployPath\Reports"
    [string]$AuditBool     = if ($global:HoneypotAudit) { '$true' } else { '$false' }
    [string]$SmtpSslBool   = if ($global:SmtpEnableSSL) { '$true' } else { '$false' }
    [string]$DebugBool      = '$false'
    [int]$Interval          = if ($global:HoneypotMonitorIntervalMinutes) { $global:HoneypotMonitorIntervalMinutes } else { 15 }

    # Build the content with only the variables the monitor and email functions require.
    # HoneypotMonitorMode is hardcoded to Decentralized so the local copy queries only
    # the local Security log without any AD or network dependency.
    [string]$Content = @"
# AD-PowerAdmin lite settings -- auto-generated for decentralized honeytoken monitor.
# This file is managed by Install-HoneypotDecentralized. Do not edit manually.

[bool]`$global:HoneypotAudit                       = $AuditBool
[int]`$global:HoneypotMonitorIntervalMinutes        = $Interval
[string]`$global:HoneypotUsername                  = '$($global:HoneypotUsername)'
[string]`$global:HoneypotDenyGroup                 = '$($global:HoneypotDenyGroup)'
[string]`$global:HoneypotOU                        = '$($global:HoneypotOU)'
[string]`$global:HoneypotSPN                       = '$($global:HoneypotSPN)'
[string]`$global:HoneypotMonitorMode               = 'Decentralized'

[string]`$global:ADAdminEmail                      = '$($global:ADAdminEmail)'
[string]`$global:FromEmail                         = '$($global:FromEmail)'

[string]`$global:SMTPServer                        = '$($global:SMTPServer)'
[int]`$global:SMTPPort                             = $($global:SMTPPort)
[string]`$global:SMTPUsername                      = '$($global:SMTPUsername)'
[string]`$global:SMTPPassword                      = '$($global:SMTPPassword)'
[bool]`$global:SmtpEnableSSL                       = $SmtpSslBool

[string]`$global:ReportsPath                       = '$ReportsPath'
[bool]`$global:Debug                               = $DebugBool
[string]`$global:MsaAccountName                    = ''
"@

    return $Content
}

Function New-HoneypotDCTaskGPOContent {
    # Generates the GPP ScheduledTasks.xml content for the decentralized DC monitor task.
    # The fixed uid ensures re-running the install updates the same GPP entry, not a duplicate.
    # action="R" (Replace) creates the task on first GP apply and replaces it on subsequent applies.
    param(
        [Parameter(Mandatory=$true)][string]$DeployPath,
        [Parameter(Mandatory=$true)][int]$IntervalMinutes
    )

    [string]$Timestamp  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    [string]$TaskUid    = '{AD50FADE-ADPA-4D43-ABCD-ADB0DE123456}'
    [string]$ScriptFile = "$DeployPath\AD-PowerAdmin.ps1"
    [string]$Interval   = "PT${IntervalMinutes}M"

    [string]$Xml = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A0CE60735378}">
  <TaskV2 clsid="{D8896631-B747-47a7-84A6-C155337F3BC8}" name="AD-PowerAdmin_HoneypotMonitor" image="0" changed="$Timestamp" uid="$TaskUid">
    <Properties action="R" name="AD-PowerAdmin_HoneypotMonitor" runAs="NT AUTHORITY\System" logonType="S4U">
      <Task version="1.3">
        <RegistrationInfo>
          <Author>AD-PowerAdmin</Author>
          <Description>Honeytoken account monitor -- queries the local Security Event Log for authentication events against the honeytoken account and sends an email alert if any are found.</Description>
        </RegistrationInfo>
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\System</UserId>
            <LogonType>S4U</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Settings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>false</AllowHardTerminate>
          <StartWhenAvailable>true</StartWhenAvailable>
          <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>false</Hidden>
          <RunOnlyIfIdle>false</RunOnlyIfIdle>
          <WakeToRun>false</WakeToRun>
          <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
          <Priority>7</Priority>
        </Settings>
        <Triggers>
          <TimeTrigger>
            <Repetition>
              <Interval>$Interval</Interval>
              <StopAtDurationEnd>false</StopAtDurationEnd>
            </Repetition>
            <StartBoundary>2000-01-01T00:00:00</StartBoundary>
            <Enabled>true</Enabled>
          </TimeTrigger>
        </Triggers>
        <Actions Context="Author">
          <Exec>
            <Command>PowerShell.exe</Command>
            <Arguments>-NonInteractive -NoProfile -File &quot;$ScriptFile&quot; -Unattended -JobName 'HoneypotHourlyMonitor'</Arguments>
            <WorkingDirectory>$DeployPath</WorkingDirectory>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </TaskV2>
</ScheduledTasks>
"@

    return $Xml
}

Function Install-HoneypotDCTaskGPO {
    # Creates (or updates) the AD-PowerAdmin_HoneypotDCMonitor GPO, links it to the Domain
    # Controllers OU, and writes the GPP ScheduledTasks.xml to SYSVOL. Group Policy then
    # deploys the AD-PowerAdmin_HoneypotMonitor scheduled task to every DC automatically --
    # no PSRemoting or WinRM required.
    param(
        [Parameter(Mandatory=$true)][string]$DeployPath,
        [Parameter(Mandatory=$true)][int]$IntervalMinutes
    )

    [string]$GpoName = 'AD-PowerAdmin_HoneypotDCMonitor'

    try {
        $Domain = Get-ADDomain
    } catch {
        Write-Host ("  [FAIL] Could not retrieve domain information: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    # Step 1: Create the GPO and link it to the Domain Controllers OU via GPOMgr.
    Write-Host ("  Creating/updating GPO '{0}' ..." -f $GpoName) -ForegroundColor Gray
    $GpoDef = @{
        Name        = $GpoName
        Description = 'AD-PowerAdmin: deploys the honeytoken monitor scheduled task to all domain controllers via Group Policy Preferences. The task queries only the local Security Event Log (no RPC) and emails an alert on any authentication event against the honeytoken account.'
        Links       = @($Domain.DomainControllersContainer)
    }
    Install-GPOBaseline -GpoDefinition $GpoDef | Out-Null

    # Step 2: Retrieve the GPO GUID (required for SYSVOL path construction).
    try {
        $Gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    } catch {
        Write-Host ("  [FAIL] Could not retrieve GPO '{0}' after creation: {1}" -f $GpoName, $_) -ForegroundColor Red
        return $false
    }
    [string]$GuidStr    = '{' + $Gpo.Id.ToString().ToUpper() + '}'
    [string]$SysvolBase = "\\$($Domain.DNSRoot)\SYSVOL\$($Domain.DNSRoot)\Policies\$GuidStr"
    [string]$PrefDir    = "$SysvolBase\Machine\Preferences\ScheduledTasks"
    [string]$XmlPath    = "$PrefDir\ScheduledTasks.xml"
    [string]$GptIniPath = "$SysvolBase\GPT.INI"

    Write-Host ("  [OK] GPO '{0}' ready (GUID: {1})." -f $GpoName, $GuidStr) -ForegroundColor Green

    # Step 3: Create the Preferences\ScheduledTasks directory in SYSVOL.
    try {
        New-Item -Path $PrefDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Write-Host ("  [OK] SYSVOL preferences directory ready.") -ForegroundColor Green
    } catch {
        Write-Host ("  [FAIL] Could not create SYSVOL directory '{0}': {1}" -f $PrefDir, $_) -ForegroundColor Red
        return $false
    }

    # Step 4: Write the GPP ScheduledTasks.xml.
    try {
        [string]$XmlContent = New-HoneypotDCTaskGPOContent -DeployPath $DeployPath -IntervalMinutes $IntervalMinutes
        [System.IO.File]::WriteAllText($XmlPath, $XmlContent, [System.Text.Encoding]::UTF8)
        Write-Host ("  [OK] Written ScheduledTasks.xml to SYSVOL.") -ForegroundColor Green
    } catch {
        Write-Host ("  [FAIL] Could not write ScheduledTasks.xml: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    # Step 5: Increment the GPT.INI computer version counter so DCs detect the policy change.
    # The 32-bit version packs user config (high 16 bits) and computer config (low 16 bits).
    [int]$CurrentVersion = 0
    try {
        [string]$GptIniContent = Get-Content $GptIniPath -Raw -ErrorAction Stop
        if ($GptIniContent -match 'Version=(\d+)') {
            $CurrentVersion = [int]$Matches[1]
        }
    } catch {
        Write-Host "  [WARN] Could not read GPT.INI (will create new version entry): $_" -ForegroundColor Yellow
        [string]$GptIniContent = "[General]`r`nVersion=0`r`n"
    }

    [int]$UserVer    = ($CurrentVersion -shr 16) -band 0xFFFF
    [int]$CompVer    = $CurrentVersion -band 0xFFFF
    [int]$NewVersion = ($UserVer -shl 16) -bor ($CompVer + 1)

    try {
        [string]$UpdatedIni = $GptIniContent -replace 'Version=\d+', "Version=$NewVersion"
        [System.IO.File]::WriteAllText($GptIniPath, $UpdatedIni, [System.Text.Encoding]::ASCII)
        Write-Host ("  [OK] GPT.INI version incremented ($CurrentVersion -> $NewVersion).") -ForegroundColor Green
    } catch {
        Write-Host ("  [FAIL] Could not update GPT.INI: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    # Step 6: Update the GPO AD object with the GPP Scheduled Tasks extension GUIDs and new version.
    # GPP Scheduled Tasks CSE GUID:  {AADCED64-746C-4633-A97C-D61349046527}
    # GPP Scheduled Tasks Tool GUID: {CAB54552-DEEA-4691-817E-ED4A4D1AFC72}
    # New-GPO (via Install-GPOBaseline) writes to the PDC emulator; target it explicitly
    # to avoid a replication-lag race where a different DC has not yet received the new GPO.
    [string]$PDC          = $Domain.PDCEmulator
    [string]$PoliciesBase = "CN=Policies,CN=System,$($Domain.DistinguishedName)"
    [string]$LdapFilter   = "(&(objectClass=groupPolicyContainer)(displayName=$GpoName))"
    [string]$GppSchedExt  = '[{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]'

    Write-Host ("  Locating GPO AD object on PDC emulator ({0}) ..." -f $PDC) -ForegroundColor Gray

    try {
        $GpoAdObj = Get-ADObject `
            -Server     $PDC `
            -LDAPFilter $LdapFilter `
            -SearchBase $PoliciesBase `
            -Properties gPCMachineExtensionNames `
            -ErrorAction Stop
    } catch {
        Write-Host ("  [FAIL] Error searching for GPO AD object on '{0}': {1}" -f $PDC, $_) -ForegroundColor Red
        return $false
    }

    if (-not $GpoAdObj) {
        Write-Host ("  [FAIL] Could not locate GPO AD object for '{0}' on '{1}'." -f $GpoName, $PDC) -ForegroundColor Red
        return $false
    }

    [string]$GpoDn    = $GpoAdObj.DistinguishedName
    [string]$ExistExt = $GpoAdObj.gPCMachineExtensionNames

    if ([string]::IsNullOrWhiteSpace($ExistExt)) {
        [string]$NewExts = $GppSchedExt
    } elseif ($ExistExt -notlike '*AADCED64-746C-4633-A97C-D61349046527*') {
        [string]$NewExts = $ExistExt + $GppSchedExt
    } else {
        [string]$NewExts = $ExistExt
    }

    try {
        Set-ADObject -Server $PDC -Identity $GpoDn -Replace @{
            versionNumber            = $NewVersion
            gPCMachineExtensionNames = $NewExts
        }
        Write-Host ("  [OK] GPO AD object updated on {0} (versionNumber, gPCMachineExtensionNames)." -f $PDC) -ForegroundColor Green
    } catch {
        Write-Host ("  [FAIL] Could not update GPO AD object on '{0}': {1}" -f $PDC, $_) -ForegroundColor Red
        return $false
    }

    return $true
}

Function Invoke-HoneypotDCDeploy {
    # Copies the minimal file set to one domain controller via UNC admin share.
    # The scheduled task is NOT created here -- it is deployed domain-wide via the
    # AD-PowerAdmin_HoneypotDCMonitor GPO after all file copies complete.
    # Returns $true on successful file copy, $false if any step fails.
    param(
        [Parameter(Mandatory=$true)][string]$DCHostname,
        [Parameter(Mandatory=$true)][string]$DeployPath
    )

    # Build the UNC root path (e.g. C:\Scripts\AD-PowerAdmin -> \\DC\C$\Scripts\AD-PowerAdmin).
    [string]$UncRoot    = '\\' + $DCHostname + '\' + ($DeployPath -replace '^([A-Za-z]):\\', '$1$\')
    [string]$UncModules = "$UncRoot\Modules"
    [string]$UncReports = "$UncRoot\Reports"

    Write-Host ("  [DC] {0} -- Deploy path: {1}" -f $DCHostname, $DeployPath) -ForegroundColor Cyan

    # Step 1: Create root directory via UNC admin share.
    try {
        if (-not (Test-Path $UncRoot)) {
            New-Item -Path $UncRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Write-Host ("    [OK] Root directory ready: {0}" -f $UncRoot) -ForegroundColor Green
    } catch {
        Write-Host ("    [FAIL] Could not create root directory: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    # Step 2: Lock down the root directory ACL before writing any files.
    # Remove inherited permissions and grant only SYSTEM and Administrators full control.
    # Any files and subdirectories created below will inherit this ACL, ensuring no
    # non-administrative account (including regular domain users or an attacker with standard
    # access) can read or modify the scripts that run as SYSTEM via the scheduled task.
    try {
        $NewAcl = New-Object System.Security.AccessControl.DirectorySecurity
        # Disable inheritance and discard all inherited ACEs (start with a clean ACL).
        $NewAcl.SetAccessRuleProtection($true, $false)

        [System.Security.AccessControl.FileSystemAccessRule]$SystemAce = `
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                ([System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        $NewAcl.AddAccessRule($SystemAce)

        [System.Security.AccessControl.FileSystemAccessRule]$AdminAce = `
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                ([System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'),
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        $NewAcl.AddAccessRule($AdminAce)

        Set-Acl -Path $UncRoot -AclObject $NewAcl -ErrorAction Stop
        Write-Host ("    [OK] ACL set: SYSTEM + Administrators only (inheritance disabled).") -ForegroundColor Green
    } catch {
        Write-Host ("    [FAIL] Could not set directory ACL on '{0}': {1}" -f $UncRoot, $_) -ForegroundColor Red
        return $false
    }

    # Step 3: Create subdirectories (inherit the restricted ACL from the root).
    try {
        foreach ($Dir in @($UncModules, $UncReports)) {
            if (-not (Test-Path $Dir)) {
                New-Item -Path $Dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
        }
        Write-Host ("    [OK] Subdirectory structure created.") -ForegroundColor Green
    } catch {
        Write-Host ("    [FAIL] Could not create subdirectories: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    # Step 4: Copy main entry point.
    try {
        Copy-Item -Path "$global:ThisScriptDir\AD-PowerAdmin.ps1" -Destination "$UncRoot\AD-PowerAdmin.ps1" -Force -ErrorAction Stop
        Write-Host ("    [OK] Copied AD-PowerAdmin.ps1") -ForegroundColor Green
    } catch {
        Write-Host ("    [FAIL] Could not copy AD-PowerAdmin.ps1: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    # Step 3: Copy required module files.
    [string[]]$ModuleFiles = @(
        'AD-PowerAdmin_Honeypot.psm1',
        'AD-PowerAdmin_Honeypot.psd1',
        'AD-PowerAdmin_Utils.psm1',
        'AD-PowerAdmin_Utils.psd1'
    )
    foreach ($ModFile in $ModuleFiles) {
        [string]$Src = "$global:ModulesPath\$ModFile"
        [string]$Dst = "$UncModules\$ModFile"
        try {
            if (-not (Test-Path $Src)) {
                Write-Host ("    [FAIL] Module file not found: {0}" -f $Src) -ForegroundColor Red
                return $false
            }
            Copy-Item -Path $Src -Destination $Dst -Force -ErrorAction Stop
            Write-Host ("    [OK] Copied Modules\{0}" -f $ModFile) -ForegroundColor Green
        } catch {
            Write-Host ("    [FAIL] Could not copy {0}: {1}" -f $ModFile, $_) -ForegroundColor Red
            return $false
        }
    }

    # Step 4: Write the generated lite settings file.
    try {
        [string]$LiteSettings = New-HoneypotLiteSettingsContent -DeployPath $DeployPath
        [string]$SettingsDst  = "$UncRoot\AD-PowerAdmin_settings.ps1"
        [System.IO.File]::WriteAllText($SettingsDst, $LiteSettings, [System.Text.Encoding]::UTF8)
        Write-Host ("    [OK] Wrote lite settings file") -ForegroundColor Green
    } catch {
        Write-Host ("    [FAIL] Could not write settings file: {0}" -f $_) -ForegroundColor Red
        return $false
    }

    return $true
}

Function Install-HoneypotDecentralized {
    <#
    .SYNOPSIS
        Deploys a lightweight honeytoken monitor to individual domain controllers.

    .DESCRIPTION
        Copies the minimum required files (AD-PowerAdmin.ps1, the Honeypot and Utils modules,
        and a generated lite settings file) to each selected domain controller via the UNC
        admin share (\\DC\C$). After the file copy, creates or updates the
        AD-PowerAdmin_HoneypotDCMonitor Group Policy Object and links it to the Domain
        Controllers OU. Group Policy then deploys the AD-PowerAdmin_HoneypotMonitor scheduled
        task (running as NT AUTHORITY\System) to every DC without any PSRemoting or WinRM
        dependency. Each DC queries only its own local Security log -- eliminating the RPC
        overhead of the centralized mode -- and sends its own email alert if honeytoken
        activity is detected.

        Prerequisites:
          - The honeytoken account must already be provisioned (run Install Honeypot Account first).
          - The executing account must have write access to the DC admin shares (\\DC\C$).
          - No PSRemoting or WinRM required.

        Use this mode when the centralized monitor is too slow due to resource-constrained DCs
        that take excessive time to respond to remote Security Event Log queries.
    #>

    if ([string]::IsNullOrWhiteSpace($global:HoneypotUsername)) {
        Write-Host ''
        Write-Host '  [FAIL] No honeytoken account is configured.' -ForegroundColor Red
        Write-Host '  Run "Install Honeypot Account" from the Honeytoken menu first.' -ForegroundColor Red
        Write-Host ''
        return
    }

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  Deploy Decentralized Honeytoken Monitor' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''
    Write-Host ('  Honeytoken account : {0}' -f $global:HoneypotUsername) -ForegroundColor White
    Write-Host ('  Monitor interval   : {0} minutes' -f $global:HoneypotMonitorIntervalMinutes) -ForegroundColor White
    Write-Host ''

    # Enumerate DCs and present a numbered list.
    try {
        $AllDCs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Sort-Object)
    } catch {
        Write-Host ("  [FAIL] Could not enumerate domain controllers: {0}" -f $_) -ForegroundColor Red
        return
    }

    Write-Host '  Domain Controllers:' -ForegroundColor White
    for ([int]$i = 0; $i -lt $AllDCs.Count; $i++) {
        Write-Host ("    [{0}] {1}" -f ($i + 1), $AllDCs[$i]) -ForegroundColor Gray
    }
    Write-Host ''

    [string]$DCSelection = Read-Host '  Enter DC numbers (comma-separated) or A for all'
    if ([string]::IsNullOrWhiteSpace($DCSelection)) {
        Write-Host '  No selection made. Exiting.' -ForegroundColor Yellow
        return
    }

    [string[]]$SelectedDCs = @()
    if ($DCSelection.Trim().ToUpper() -eq 'A') {
        $SelectedDCs = $AllDCs
    } else {
        foreach ($Token in ($DCSelection -split ',')) {
            [string]$Trimmed = $Token.Trim()
            [int]$Idx = 0
            if ([int]::TryParse($Trimmed, [ref]$Idx) -and $Idx -ge 1 -and $Idx -le $AllDCs.Count) {
                $SelectedDCs += $AllDCs[$Idx - 1]
            } else {
                Write-Host ("  [WARN] Invalid selection '{0}' -- skipped." -f $Trimmed) -ForegroundColor Yellow
            }
        }
    }

    if ($SelectedDCs.Count -eq 0) {
        Write-Host '  No valid DCs selected. Exiting.' -ForegroundColor Yellow
        return
    }

    # Deployment path on each DC.
    [string]$DefaultPath = 'C:\Scripts\AD-PowerAdmin'
    [string]$PathInput   = Read-Host ("  Deployment path on each DC [default: {0}]" -f $DefaultPath)
    [string]$DeployPath  = if ([string]::IsNullOrWhiteSpace($PathInput)) { $DefaultPath } else { $PathInput.Trim() }

    # Summary and confirmation.
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor White
    Write-Host '  Deployment Summary' -ForegroundColor White
    Write-Host ('=' * 70) -ForegroundColor White
    Write-Host ('  Target DC(s)     : {0}' -f ($SelectedDCs -join ', ')) -ForegroundColor White
    Write-Host ('  Deploy path      : {0}' -f $DeployPath) -ForegroundColor White
    Write-Host ('  Scheduled task   : NT AUTHORITY\System via GPO (AD-PowerAdmin_HoneypotDCMonitor)') -ForegroundColor White
    Write-Host ('  Monitor interval : {0} minutes' -f $global:HoneypotMonitorIntervalMinutes) -ForegroundColor White
    Write-Host ''
    [string]$Confirm = Read-Host '  Proceed? (y/N)'
    if ($Confirm.Trim().ToUpper() -ne 'Y') {
        Write-Host '  Cancelled.' -ForegroundColor Yellow
        return
    }

    # Deploy files to each selected DC via UNC admin share.
    Write-Host ''
    [int]$Succeeded = 0
    [int]$Failed    = 0
    foreach ($DC in $SelectedDCs) {
        [bool]$Result = Invoke-HoneypotDCDeploy -DCHostname $DC -DeployPath $DeployPath
        if ($Result) { $Succeeded++ } else { $Failed++ }
        Write-Host ''
    }

    Write-Host ('  File deployment complete: {0} succeeded, {1} failed.' -f $Succeeded, $Failed) -ForegroundColor Cyan
    Write-Host ''

    # Create or update the GPO that delivers the scheduled task to all DCs via Group Policy.
    # This runs once after all file copies; the GPO applies to the entire Domain Controllers OU.
    Write-Host ('=' * 70) -ForegroundColor White
    Write-Host '  Configuring Group Policy scheduled task delivery ...' -ForegroundColor White
    Write-Host ('=' * 70) -ForegroundColor White
    [int]$Interval = if ($global:HoneypotMonitorIntervalMinutes) { $global:HoneypotMonitorIntervalMinutes } else { 15 }
    [bool]$GpoOk   = Install-HoneypotDCTaskGPO -DeployPath $DeployPath -IntervalMinutes $Interval
    Write-Host ''

    Write-Host ('=' * 70) -ForegroundColor Cyan
    if ($GpoOk) {
        Write-Host '  [OK] GPO created and linked to the Domain Controllers OU.' -ForegroundColor Cyan
        Write-Host '  Group Policy will deploy the task on the next GP refresh (up to ~90 min).' -ForegroundColor Gray
        Write-Host '  Run "gpupdate /force" on each DC to apply immediately.' -ForegroundColor Gray
    } else {
        Write-Host '  [FAIL] GPO creation failed. Scheduled task will not be deployed until' -ForegroundColor Red
        Write-Host '         the GPO issue is resolved. File copies above may still be valid.' -ForegroundColor Red
    }
    if ($Succeeded -gt 0) {
        Write-Host ''
        Write-Host '  NOTE: The central AD-PowerAdmin settings file still has HoneypotMonitorMode' -ForegroundColor Yellow
        Write-Host '        set to Centralized. To disable centralized querying and rely solely' -ForegroundColor Yellow
        Write-Host '        on the decentralized tasks, set HoneypotMonitorMode = Decentralized' -ForegroundColor Yellow
        Write-Host '        in AD-PowerAdmin_settings.ps1 on the central server.' -ForegroundColor Yellow
    }
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''
}

Function Remove-HoneypotDecentralized {
    <#
    .SYNOPSIS
        Removes the decentralized honeytoken monitor deployment from domain controllers.

    .DESCRIPTION
        Removes the AD-PowerAdmin_HoneypotDCMonitor GPO (which removes the scheduled task from
        all DCs on the next Group Policy refresh) and optionally deletes the deployment directory
        from selected DCs via UNC admin share. Does not affect the central AD-PowerAdmin
        installation or the honeytoken account itself. No PSRemoting or WinRM required.
    #>

    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  Remove Decentralized Honeytoken Monitor' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''

    # Ask what to remove.
    Write-Host '  What would you like to remove?' -ForegroundColor White
    Write-Host ''
    [string]$RemoveGpoInput = Read-Host '  Remove the AD-PowerAdmin_HoneypotDCMonitor GPO? Removes the scheduled task from ALL DCs on next GP refresh. (y/N)'
    [bool]$RemoveGpo        = ($RemoveGpoInput.Trim().ToUpper() -eq 'Y')

    [string]$RemoveDirInput = Read-Host '  Remove deployment directories from specific DCs? (y/N)'
    [bool]$RemoveDir        = ($RemoveDirInput.Trim().ToUpper() -eq 'Y')

    if (-not $RemoveGpo -and -not $RemoveDir) {
        Write-Host '  Nothing selected. Exiting.' -ForegroundColor Yellow
        return
    }

    # If removing directories, enumerate DCs and let user select which ones.
    [string[]]$SelectedDCs = @()
    [string]$DeployPath    = ''
    if ($RemoveDir) {
        try {
            $AllDCs = @(Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Sort-Object)
        } catch {
            Write-Host ("  [FAIL] Could not enumerate domain controllers: {0}" -f $_) -ForegroundColor Red
            return
        }

        Write-Host ''
        Write-Host '  Domain Controllers:' -ForegroundColor White
        for ([int]$i = 0; $i -lt $AllDCs.Count; $i++) {
            Write-Host ("    [{0}] {1}" -f ($i + 1), $AllDCs[$i]) -ForegroundColor Gray
        }
        Write-Host ''

        [string]$DCSelection = Read-Host '  Enter DC numbers to remove directories from (comma-separated) or A for all'
        if ([string]::IsNullOrWhiteSpace($DCSelection)) {
            Write-Host '  No selection made. Directory removal skipped.' -ForegroundColor Yellow
            $RemoveDir = $false
        } else {
            if ($DCSelection.Trim().ToUpper() -eq 'A') {
                $SelectedDCs = $AllDCs
            } else {
                foreach ($Token in ($DCSelection -split ',')) {
                    [string]$Trimmed = $Token.Trim()
                    [int]$Idx = 0
                    if ([int]::TryParse($Trimmed, [ref]$Idx) -and $Idx -ge 1 -and $Idx -le $AllDCs.Count) {
                        $SelectedDCs += $AllDCs[$Idx - 1]
                    } else {
                        Write-Host ("  [WARN] Invalid selection '{0}' -- skipped." -f $Trimmed) -ForegroundColor Yellow
                    }
                }
            }

            if ($SelectedDCs.Count -eq 0) {
                Write-Host '  No valid DCs selected. Directory removal skipped.' -ForegroundColor Yellow
                $RemoveDir = $false
            } else {
                [string]$DefaultPath = 'C:\Scripts\AD-PowerAdmin'
                [string]$PathInput   = Read-Host ("  Deployment path to remove [default: {0}]" -f $DefaultPath)
                $DeployPath          = if ([string]::IsNullOrWhiteSpace($PathInput)) { $DefaultPath } else { $PathInput.Trim() }
            }
        }
    }

    # Confirm before proceeding.
    Write-Host ''
    Write-Host ('  Remove GPO (AD-PowerAdmin_HoneypotDCMonitor) : {0}' -f $(if ($RemoveGpo) { 'Yes -- affects all DCs' } else { 'No' })) -ForegroundColor White
    if ($RemoveDir -and $SelectedDCs.Count -gt 0) {
        Write-Host ('  Remove directory ({0}) from : {1}' -f $DeployPath, ($SelectedDCs -join ', ')) -ForegroundColor White
    }
    Write-Host ''
    [string]$Confirm = Read-Host '  Proceed? (y/N)'
    if ($Confirm.Trim().ToUpper() -ne 'Y') {
        Write-Host '  Cancelled.' -ForegroundColor Yellow
        return
    }

    Write-Host ''

    # Remove the GPO (removes scheduled task from all DCs via GP).
    if ($RemoveGpo) {
        Write-Host '  Removing GPO AD-PowerAdmin_HoneypotDCMonitor ...' -ForegroundColor White
        try {
            [bool]$GpoRemoved = Remove-ADPAGPO -Name 'AD-PowerAdmin_HoneypotDCMonitor' -RemoveLinks
            if ($GpoRemoved) {
                Write-Host '  [OK] GPO removed. Task will be deleted from DCs on next GP refresh.' -ForegroundColor Green
                Write-Host '  Run "gpupdate /force" on each DC to apply immediately.' -ForegroundColor Gray
            } else {
                Write-Host '  [FAIL] GPO removal reported failure. Check GPMC for residual objects.' -ForegroundColor Red
            }
        } catch {
            Write-Host ("  [FAIL] GPO removal error: {0}" -f $_) -ForegroundColor Red
        }
        Write-Host ''
    }

    # Remove deployment directories via UNC admin share (no PSRemoting required).
    if ($RemoveDir -and $SelectedDCs.Count -gt 0) {
        Write-Host '  Removing deployment directories ...' -ForegroundColor White
        foreach ($DC in $SelectedDCs) {
            [string]$UncDeploy = '\\' + $DC + '\' + ($DeployPath -replace '^([A-Za-z]):\\', '$1$\')
            Write-Host ("  [DC] {0}" -f $DC) -ForegroundColor Cyan
            try {
                if (Test-Path $UncDeploy) {
                    Remove-Item -Path $UncDeploy -Recurse -Force -ErrorAction Stop
                    Write-Host ("    [OK] Removed: {0}" -f $UncDeploy) -ForegroundColor Green
                } else {
                    Write-Host ("    [INFO] Path not found (already removed or not deployed): {0}" -f $UncDeploy) -ForegroundColor Gray
                }
            } catch {
                Write-Host ("    [FAIL] Could not remove '{0}': {1}" -f $UncDeploy, $_) -ForegroundColor Red
            }
        }
        Write-Host ''
    }

    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host '  Decentralized monitor removal complete.' -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host ''
}

Function Test-HoneypotAuditPolicy {
    # Checks whether the local DC is configured to log the Security events the honeytoken
    # monitor searches for. Uses auditpol subcategory GUIDs (language-independent lookup).
    # Returns $true if all four required subcategories are logging; $false otherwise.
    #
    # Uses the plain-text auditpol output (no /r CSV flag). The /r CSV path depends on
    # column position and header-line detection, both of which vary across Windows versions
    # and produce silent 'Unknown' results when the format differs from expectations.
    # The plain-text output always places the effective setting at the end of the subcategory
    # line; pattern-matching against the four known English setting strings is simpler and
    # more reliable than CSV field indexing.
    # Check order: 'Success and Failure' must be tested before 'Success' or 'Failure' alone
    # to avoid a substring false match.
    [hashtable[]]$Checks = @(
        @{ Guid = '{0cce9215-69ae-11d9-bed3-505054503030}'; Name = 'Logon';                               Events = '4624, 4625' }
        @{ Guid = '{0cce9217-69ae-11d9-bed3-505054503030}'; Name = 'Account Lockout';                    Events = '4740'       }
        @{ Guid = '{0cce9242-69ae-11d9-bed3-505054503030}'; Name = 'Kerberos Authentication Service';    Events = '4768, 4771' }
        @{ Guid = '{0cce9240-69ae-11d9-bed3-505054503030}'; Name = 'Kerberos Service Ticket Operations'; Events = '4769'       }
    )
    [bool]$AllGood = $true
    foreach ($Check in $Checks) {
        [string]$Setting = 'Unknown'
        try {
            [string[]]$Lines = & auditpol.exe /get /subcategory:"$($Check.Guid)" 2>&1
            foreach ($Line in $Lines) {
                if ($Line -match 'No Auditing')        { $Setting = 'No Auditing';        break }
                if ($Line -match 'Success and Failure') { $Setting = 'Success and Failure'; break }
                if ($Line -match '\bSuccess\b')         { $Setting = 'Success';             break }
                if ($Line -match '\bFailure\b')         { $Setting = 'Failure';             break }
            }
        } catch {}
        if ($Setting -eq 'No Auditing' -or $Setting -eq 'Unknown') {
            Write-Host ("  [WARN] {0} ({1}): {2} -- these events will NOT be logged" -f $Check.Name, $Check.Events, $Setting) -ForegroundColor Yellow
            Write-Host ("         Fix: auditpol /set /subcategory:`"{0}`" /success:enable /failure:enable" -f $Check.Name) -ForegroundColor DarkGray
            $AllGood = $false
        } else {
            Write-Host ("  [OK]   {0} ({1}): {2}" -f $Check.Name, $Check.Events, $Setting) -ForegroundColor Green
        }
    }
    return $AllGood
}

Function Invoke-HoneypotTestAuthAttempt {
    # Sends two deliberate failed authentication attempts against the honeytoken account:
    # one using Kerberos (AuthType::Negotiate) and one using explicit NTLM (AuthType::Ntlm).
    # Negotiate selects Kerberos when the DC supports GSSAPI, which generates Event 4771
    # (Kerberos pre-auth failure) but NOT 4625. The second NTLM bind forces the NTLM path,
    # which generates Event 4625 (failed logon) on the DC.
    # Both binds use the same randomly generated wrong password.
    [string]$SamAccountName = $global:HoneypotUsername
    [string]$DomainFqdn     = (Get-ADDomain).DNSRoot
    [string]$WrongPassword  = 'Tw!' + [System.Guid]::NewGuid().ToString('N').Substring(0, 20)

    Add-Type -AssemblyName System.DirectoryServices.Protocols

    [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]$Id   = $null
    [System.Net.NetworkCredential]$Cred                                = $null
    [System.DirectoryServices.Protocols.LdapConnection]$Conn          = $null

    try {
        $Id   = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($DomainFqdn, 389)
        $Cred = [System.Net.NetworkCredential]::new($SamAccountName, $WrongPassword, $DomainFqdn)

        # Kerberos bind: AuthType::Negotiate selects Kerberos when the DC advertises GSSAPI.
        # Generates Event 4771 (Kerberos pre-authentication failure).
        Write-Host ("  [1/2] Kerberos bind as '{0}' (Negotiate -> Kerberos)..." -f $SamAccountName) -ForegroundColor White
        try {
            $Conn = [System.DirectoryServices.Protocols.LdapConnection]::new(
                $Id, $Cred, [System.DirectoryServices.Protocols.AuthType]::Negotiate
            )
            $Conn.SessionOptions.ProtocolVersion = 3
            $Conn.AutoBind = $false
            $Conn.Bind($Cred)
            Write-Host '  [CRITICAL] Kerberos bind SUCCEEDED -- honeytoken account is not protected!' -ForegroundColor Red
            Write-Host '             The deny-logon GPO is not applied or has not yet propagated to this DC.' -ForegroundColor Red
            Write-Host '             Run Test-HoneytokenUserSafety to diagnose the GPO configuration.' -ForegroundColor Red
        } catch {
            Write-Host '  [OK] Kerberos bind rejected as expected. Expected event: 4771.' -ForegroundColor Green
        } finally {
            if ($null -ne $Conn) { try { $Conn.Dispose() } catch {} }
            $Conn = $null
        }

        # NTLM bind: AuthType::Ntlm forces NTLM regardless of Kerberos availability.
        # Generates Event 4625 (An account failed to log on) on the DC.
        Write-Host ("  [2/2] NTLM bind as '{0}'..." -f $SamAccountName) -ForegroundColor White
        try {
            $Conn = [System.DirectoryServices.Protocols.LdapConnection]::new(
                $Id, $Cred, [System.DirectoryServices.Protocols.AuthType]::Ntlm
            )
            $Conn.SessionOptions.ProtocolVersion = 3
            $Conn.AutoBind = $false
            $Conn.Bind($Cred)
            Write-Host '  [CRITICAL] NTLM bind SUCCEEDED -- honeytoken account is not protected!' -ForegroundColor Red
            Write-Host '             The deny-logon GPO is not applied or has not yet propagated to this DC.' -ForegroundColor Red
            Write-Host '             Run Test-HoneytokenUserSafety to diagnose the GPO configuration.' -ForegroundColor Red
        } catch {
            Write-Host '  [OK] NTLM bind rejected as expected. Expected event: 4625.' -ForegroundColor Green
        } finally {
            if ($null -ne $Conn) { try { $Conn.Dispose() } catch {} }
            $Conn = $null
        }
    } finally {
        $WrongPassword = $null
        $Cred          = $null
        $Id            = $null
    }
}

Function Invoke-HoneypotTestServiceTicket {
    # Requests a Kerberos service ticket for the honeytoken's bait SPN using the current
    # user's existing TGT. This is the exact request a Kerberoasting tool makes.
    # Generates Event 4769 on the domain controller.
    # Does nothing if no bait SPN is configured.
    [string]$SpnValue       = $global:HoneypotSPN
    [string]$SamAccountName = $global:HoneypotUsername

    if ([string]::IsNullOrWhiteSpace($SpnValue)) {
        Write-Host '  [SKIP] No bait SPN configured (HoneypotSPN is empty).' -ForegroundColor Yellow
        Write-Host '         Assign a Kerberoasting bait SPN during account provisioning to enable 4769 detection.' -ForegroundColor Gray
        return
    }

    # Verify the SPN is actually registered in AD before calling klist.
    # If the SPN exists in settings but was never written to the AD account (or was cleared),
    # the KDC returns KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN and no 4769 event is logged.
    Write-Host ("  Verifying SPN '{0}' is registered on '{1}' in AD..." -f $SpnValue, $SamAccountName) -ForegroundColor DarkGray
    try {
        $AdAccount = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" `
                                -Properties servicePrincipalName -ErrorAction Stop
    } catch {
        Write-Host ("  [FAIL] Could not query AD account '{0}': {1}" -f $SamAccountName, $_) -ForegroundColor Red
        return
    }
    if (-not $AdAccount) {
        Write-Host ("  [FAIL] Account '{0}' not found in AD." -f $SamAccountName) -ForegroundColor Red
        return
    }
    if ($AdAccount.servicePrincipalName -notcontains $SpnValue) {
        Write-Host ("  [FAIL] SPN '{0}' is NOT registered on '{1}' in AD." -f $SpnValue, $SamAccountName) -ForegroundColor Red
        Write-Host "         The KDC cannot issue a service ticket for an unregistered SPN -- no 4769 will be logged." -ForegroundColor Yellow
        if ($AdAccount.servicePrincipalName) {
            Write-Host "         SPNs currently on account:" -ForegroundColor Gray
            $AdAccount.servicePrincipalName | ForEach-Object { Write-Host ("           {0}" -f $_) -ForegroundColor DarkGray }
        } else {
            Write-Host "         No SPNs are registered on this account." -ForegroundColor Gray
        }
        Write-Host ("         Fix: Set-ADUser -Identity '{0}' -Add @{{servicePrincipalName='{1}'}}" -f $SamAccountName, $SpnValue) -ForegroundColor DarkGray
        return
    }
    Write-Host ("  [OK] SPN confirmed in AD." -f $SpnValue) -ForegroundColor Green

    Write-Host ("  Requesting Kerberos service ticket for SPN '{0}'..." -f $SpnValue) -ForegroundColor White
    Write-Host '  (Uses the current user''s TGT -- no honeytoken credentials required.)' -ForegroundColor Gray

    [string]$KlistExe = Join-Path $env:SystemRoot 'System32\klist.exe'
    if (-not (Test-Path $KlistExe)) {
        Write-Host '  [WARN] klist.exe not found. Cannot request service ticket.' -ForegroundColor Yellow
        return
    }

    try {
        [string[]]$KlistOut = & $KlistExe get "$SpnValue" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host '  [OK] Service ticket requested successfully. Expected event: 4769.' -ForegroundColor Green
        } else {
            Write-Host ('  [FAIL] klist exited with code {0}. The KDC rejected the ticket request.' -f $LASTEXITCODE) -ForegroundColor Red
            Write-Host '         klist output:' -ForegroundColor Gray
            $KlistOut | ForEach-Object { Write-Host ("           {0}" -f $_) -ForegroundColor DarkGray }
        }
    } catch {
        Write-Host ("  [WARN] klist.exe failed: {0}" -f $_) -ForegroundColor Yellow
    }
}

Function Invoke-HoneypotDetectionTest {
    <#
    .SYNOPSIS
        Triggers controlled authentication events to test the honeytoken detection pipeline.

    .DESCRIPTION
        === Honeytoken Detection System Test. ===
            Generates real Windows Security Event Log entries against the configured honeytoken
            account so you can verify that event detection, alert building, and email delivery
            are working end to end.

            Available tests:
            [1] Authentication attempt  -- Sends two failed LDAP binds using a random wrong
                password: one with AuthType::Negotiate (selects Kerberos, generates 4771)
                and one with AuthType::Ntlm (forces NTLM, generates 4625) on the DC.
            [2] Kerberos service ticket -- Uses the current user's TGT to request a service
                ticket for the bait SPN. Generates Event 4769. Requires a bait SPN configured.
            [3] Both tests together
            [4] Run monitor check now  -- Immediately runs Start-HoneypotMonitor to search
                for events and send an alert email if any are found.

            After triggering test events, you will be offered the option to run the monitor
            check immediately so you can confirm the full pipeline in one step.

    .EXAMPLE
        Invoke-HoneypotDetectionTest

    .NOTES
        Menu path: Honeytoken Management -> Test Detection System.
    #>

    if ([string]::IsNullOrWhiteSpace($global:HoneypotUsername)) {
        Write-Host 'No honeytoken account configured. Run Install Honeypot Account first.' -ForegroundColor Red
        return
    }

    # Verify audit policy prerequisites once on entry so the admin sees any gaps before testing.
    Write-Host ''
    Write-Host '  Checking Security audit policy on this DC...' -ForegroundColor DarkGray
    [bool]$AuditReady = Test-HoneypotAuditPolicy
    if (-not $AuditReady) {
        Write-Host ''
        Write-Host '  One or more subcategories are disabled. Tests will still run but the monitor' -ForegroundColor Yellow
        Write-Host '  may find 0 events until the audit policy is corrected.' -ForegroundColor Yellow
    }

    while ($true) {
        [string]$SpnLabel = if ([string]::IsNullOrWhiteSpace($global:HoneypotSPN)) { '(not configured)' } else { $global:HoneypotSPN }

        Write-Host ''
        Write-Host ('=' * 70) -ForegroundColor White
        Write-Host '  Honeytoken Detection Test' -ForegroundColor White
        Write-Host ('=' * 70) -ForegroundColor White
        Write-Host ("  Account : {0}" -f $global:HoneypotUsername) -ForegroundColor Gray
        Write-Host ("  SPN     : {0}" -f $SpnLabel) -ForegroundColor Gray
        Write-Host ("  Monitor : {0}" -f $(if ($global:HoneypotAudit) { 'Enabled' } else { 'DISABLED -- monitor will not send alerts' })) -ForegroundColor $(if ($global:HoneypotAudit) { 'Gray' } else { 'Yellow' })
        Write-Host ''
        Write-Host '  [1] Authentication attempt  -- Events 4771 (Kerberos) + 4625 (NTLM)' -ForegroundColor White
        Write-Host '  [2] Kerberos service ticket -- Event 4769  (requires bait SPN)' -ForegroundColor White
        Write-Host '  [3] Both tests' -ForegroundColor White
        Write-Host '  [4] Run monitor check now   -- process Security log and send alert email' -ForegroundColor White
        Write-Host '  [Q] Back' -ForegroundColor White
        Write-Host ''

        [string]$Choice = (Read-Host 'Select').Trim().ToUpper()

        if ($Choice -eq 'Q') { return }

        if ($Choice -eq '1' -or $Choice -eq '3') {
            Write-Host ''
            Invoke-HoneypotTestAuthAttempt
        }

        if ($Choice -eq '2' -or $Choice -eq '3') {
            Write-Host ''
            Invoke-HoneypotTestServiceTicket
        }

        if ($Choice -eq '1' -or $Choice -eq '2' -or $Choice -eq '3') {
            Write-Host ''
            [string]$RunMonitor = (Read-Host '  Run monitor check now to detect these events and send alert email? (y/N)').Trim().ToUpper()
            if ($RunMonitor -eq 'Y') {
                Write-Host '  Waiting 3 seconds for events to be written to the Security log ...' -ForegroundColor Gray
                Start-Sleep -Seconds 3
                Write-Host ''
                Start-HoneypotMonitor
            }
            continue
        }

        if ($Choice -eq '4') {
            Write-Host ''
            Start-HoneypotMonitor
            continue
        }

        Write-Host '  Invalid selection. Enter 1, 2, 3, 4, or Q.' -ForegroundColor Yellow
    }
}

Function Show-HoneypotHelp {
    <#
    .SYNOPSIS
        Display the Honeytoken system deployment guide.
    .DESCRIPTION
        Prints the correct installation order and removal procedure for the Honeytoken
        detection system, covering both Centralized and Decentralized monitor modes.
    #>

    Write-Host ''
    Write-Host '  HONEYTOKEN SYSTEM -- DEPLOYMENT GUIDE' -ForegroundColor Cyan
    Write-Host ('=' * 70)
    Write-Host ''
    Write-Host '  OVERVIEW' -ForegroundColor Yellow
    Write-Host '  The Honeytoken system has two independent layers:'
    Write-Host '    1. A hardened AD account that should never be used. Any authentication'
    Write-Host '       attempt against it is a high-confidence indicator of an attack.'
    Write-Host '    2. A monitor that queries all DC Security Event Logs on a configurable'
    Write-Host '       interval and emails an alert on any detection.'
    Write-Host ''
    Write-Host '  The monitor runs in one of two modes:'
    Write-Host '    Centralized (default) -- one central AD-PowerAdmin installation queries'
    Write-Host '       all DCs remotely. No additional deployment required.'
    Write-Host '    Decentralized         -- a lightweight copy runs locally on each DC.'
    Write-Host '       Use this if centralized mode is too slow on resource-constrained DCs.'
    Write-Host ''
    Write-Host ('=' * 70)
    Write-Host ''
    Write-Host '  INSTALLATION ORDER' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Step 1 -- Install Honeypot Account' -ForegroundColor Green
    Write-Host '    Select "Install Honeypot Account" from this menu.'
    Write-Host '    The wizard provisions the honeytoken account, creates the deny-logon'
    Write-Host '    security group, creates and links the ADPA__Honeytoken_DenyLogon'
    Write-Host '    GPO at the domain root, and creates the central monitoring scheduled task.'
    Write-Host '    No manual GPMC steps are required -- the GPO is fully automated.'
    Write-Host ''
    Write-Host '  Step 2 -- Allow Group Policy to propagate' -ForegroundColor Green
    Write-Host '    Wait 5-10 minutes, or run "gpupdate /force" on each domain controller.'
    Write-Host '    The deny-logon rights assignment must be in effect on all DCs before the'
    Write-Host '    account is considered live. Until then, a 4624 (Successful Logon) could'
    Write-Host '    be a false positive from a DC that has not yet applied the policy.'
    Write-Host ''
    Write-Host '  Step 3 -- Verify Account Safety' -ForegroundColor Green
    Write-Host '    Select "Verify Account Safety" from this menu.'
    Write-Host '    Confirms the account has no dangerous attributes: no SPNs, no delegation,'
    Write-Host '    no privileged group memberships, deny-logon group membership intact.'
    Write-Host ''
    Write-Host '  Step 4 -- (Optional) Deploy Decentralized Monitor' -ForegroundColor Green
    Write-Host '    Only needed if centralized mode is too slow (80+ seconds per DC).'
    Write-Host '    Select "Deploy Decentralized Monitor" from this menu.'
    Write-Host '    Files are copied to each selected DC via UNC admin share (no WinRM).'
    Write-Host '    The AD-PowerAdmin_HoneypotDCMonitor GPO is linked to the Domain'
    Write-Host '    Controllers OU and delivers the monitoring scheduled task via GP.'
    Write-Host '    Run "gpupdate /force" on each DC to apply immediately.'
    Write-Host '    To stop the central sweep, set HoneypotMonitorMode = Decentralized'
    Write-Host '    in the central AD-PowerAdmin_settings.ps1.'
    Write-Host ''
    Write-Host ('=' * 70)
    Write-Host ''
    Write-Host '  REMOVAL ORDER' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Step 1 -- (If applicable) Remove Decentralized Monitor first' -ForegroundColor Green
    Write-Host '    Select "Remove Decentralized Monitor" from this menu.'
    Write-Host '    Removes the AD-PowerAdmin_HoneypotDCMonitor GPO (the scheduled task is'
    Write-Host '    removed from all DCs on the next GP refresh) and optionally removes the'
    Write-Host '    deployment directory from selected DCs via UNC admin share.'
    Write-Host '    Run "gpupdate /force" on each DC to apply immediately.'
    Write-Host ''
    Write-Host '  Step 2 -- Remove Honeypot Account' -ForegroundColor Green
    Write-Host '    Select "Remove Honeypot Account" from this menu.'
    Write-Host '    Removes the central monitoring scheduled task, removes the account from'
    Write-Host '    the deny-logon group, disables or deletes the AD account, removes the'
    Write-Host '    deny-logon group (if empty), removes the ADPA__Honeytoken_DenyLogon'
    Write-Host '    GPO, and clears all configuration from the settings file.'
    Write-Host '    Each destructive step requires explicit confirmation before proceeding.'
    Write-Host ''
    Write-Host ('=' * 70)
    Write-Host ''
    Write-Host '  NOTES' -ForegroundColor Yellow
    Write-Host '    - Alerts are emailed to the address in $global:ADAdminEmail.'
    Write-Host '    - A 4624 (Successful Logon) is always CRITICAL. The deny-logon GPO must'
    Write-Host '      block all logon types. If a 4624 occurs, escalate immediately and verify'
    Write-Host '      the ADPA__Honeytoken_DenyLogon GPO is linked and enforced.'
    Write-Host '    - The account username must never appear in any service, scheduled task,'
    Write-Host '      application configuration, or legitimate logon process.'
    Write-Host '    - Run "Verify Account Safety" periodically to confirm no privileges have'
    Write-Host '      accumulated on the honeytoken account since deployment.'
    Write-Host ''
}
