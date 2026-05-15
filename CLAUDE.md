# AD-PowerAdmin -- Project Guide for Claude

## Project Overview

**AD-PowerAdmin** is a modular PowerShell framework for Active Directory administrators. It is built around two core goals:

1. **Audit and maintain Active Directory security** -- identify misconfigurations, weak credentials, stale accounts, excessive privileges, and known attack vectors before adversaries exploit them.
2. **Automate day-to-day administrative tasks securely and consistently** -- remove human variability from sensitive operations by encoding best practices directly into scripts.

Automation here is not simply about saving time. It is about enforcing secure, repeatable processes every single time. A manually run offboarding checklist gets skipped or done inconsistently. A scripted user decommissioning workflow disables the account, revokes group memberships, resets the password, and archives the mailbox in the same order, with the same checks, without exception. The script is the policy.

- **Author:** Bret.s (CyberGladius)
- **License:** MIT
- **Repo:** https://github.com/Brets0150/AD-PowerAdmin
- **Current Script Version:** 1.2.0

---

## Documentation Model

### README.md -- High-Level Summary Only

`README.md` is the public face of the project. It contains:

- Project purpose and what problem it solves
- Feature overview (one line per feature, user-facing language)
- Quick-start and installation instructions

`README.md` does **not** contain implementation details, architectural explanations, or methodology writeups. Keep it oriented toward a reader deciding whether to adopt the tool.

**Features in README.md must describe Active Directory capabilities and outcomes only.** Internal framework mechanics -- menu structure, sub-menu architecture, modular design, scheduled job infrastructure, or any other implementation detail -- must not appear in the Features list. Those topics belong exclusively in `AD-PowerAdmin.wiki/`. Every bullet in Features answers the question "what does this do for Active Directory?" not "how is the tool structured?"

**README must be updated with every change.** Whenever a function, feature, or module is added, modified, or removed:

- **New AD feature or function:** add a bullet to the Features list in plain, user-facing terms describing the AD capability.
- **Modified feature:** update the existing description if behavior, scope, or name changed.
- **Removed feature:** remove the corresponding bullet.
- **New module:** if it introduces a user-visible AD capability, it earns a Features entry. Framework-only modules (utilities, infrastructure) do not.

```
# AD-PowerAdmin Overview   <- project summary, do not change
# Features                 <- bulleted list, update here for every change
# Installation             <- do not change unless install process changes
```

### AD-PowerAdmin.wiki/ -- All Detailed Documentation

Everything beyond the high-level summary belongs in the wiki. The wiki has two distinct purposes:

**`AD-PowerAdmin.wiki/Vulnerabilities/`** contains generalized dossiers on known Active Directory vulnerabilities -- what the vulnerability is, how it works, why it matters, and what mitigations exist. These dossiers are reference material independent of this project's implementation. Examples: Kerberoasting, Pass-the-Hash, DCSync, AS-REP Roasting, KRBTGT compromise.

**The rest of `AD-PowerAdmin.wiki/`** documents AD-PowerAdmin-specific content:
- Module methodologies and implementation rationale
- Audit design and what each audit detects
- Automation workflows and the best practices they enforce
- Architectural decisions and the reasoning behind them
- Operational guidance for administrators running the tool

The wiki is the authoritative source for "why does this exist and how does it work."

### CHANGELOG.md -- Version History and Change Record

`CHANGELOG.md` is the authoritative record of every meaningful change to the project. It exists to give contributors and operators a clear, chronological account of what changed, why it changed, and what effect it had.

**CHANGELOG.md must be updated for every code change** -- including new features, new functions, modifications to existing behavior, bug fixes, refactors, and architectural changes. This is mandatory alongside wiki and README updates; it is not optional.

Each entry must include:

- **What changed** -- the function, module, or system component that was affected, and a precise description of the addition, modification, fix, or removal.
- **Why it changed** -- the purpose of the change: the threat it addresses, the bug it resolves, the operational need it fulfills, or the improvement it makes.
- **Impact** -- what effect the change has on behavior, security posture, or compatibility.

**Entry format by change type:**

```
### [Module or Component Name]

**Added:**
- `Function-Name` -- what it does and why it was introduced.

**Changed:**
- `Function-Name` -- what changed and what problem it solves.

**Fixed:**
- `Function-Name` -- what was broken and how it was corrected.

**Removed:**
- `Function-Name` -- what was removed and why.
```

A code change without a CHANGELOG entry is an incomplete change.

---

## Feature Justification Policy

Every audit, test, automation, and feature in AD-PowerAdmin must be grounded in at least one of the following:

- A known Active Directory vulnerability
- A known weakness or misconfiguration pattern
- An operational best practice
- An administrative security requirement

**This is not optional.** AD-PowerAdmin exists to address real threats. A feature that cannot be traced to one of the above has no place in the project.

### Documentation Requirements for Every Change

When adding or changing any audit, test, automation, or feature, all three of the following documentation updates are mandatory. A code change is not complete until all three are done.

**1. Update CHANGELOG.md**

Add an entry describing what changed, why it changed, and what its impact is. See the CHANGELOG.md section in the Documentation Model above for the required format and entry types (Added / Changed / Fixed / Removed).

**2. Create or update the wiki page**

The wiki page must answer:

- **What was built or changed** -- a clear description of the functionality.
- **Why it was built** -- the threat, weakness, operational need, or best practice that motivated it.
- **Which vulnerability, weakness, operational need, or best practice it addresses** -- link to the relevant `Vulnerabilities/` dossier if applicable.
- **How it integrates with the broader AD-PowerAdmin framework** -- which module it lives in, how it appears in the menu or scheduler, and any dependencies on other modules.

**3. Update README.md** (if the change introduces or removes a user-visible AD capability)

Add, update, or remove the corresponding bullet in the Features list following the README rules defined in the Documentation Model above.

---

## Project Structure

```
AD-PowerAdmin/
|-- AD-PowerAdmin.ps1              # Main entry point (menu, module loader, scheduler)
|-- AD-PowerAdmin_settings.ps1     # All global configuration variables
|-- README.md                      # High-level summary only
|-- CHANGELOG.md                   # Mandatory change record; updated with every code change
|-- .gitignore
|-- Modules/                       # All production modules go here
|   |-- AD-PowerAdmin_Utils.psm1/.psd1
|   |-- AD-PowerAdmin_LogMgr.psm1/.psd1
|   |-- AD-PowerAdmin_Installer.psm1/.psd1
|   |-- AD-PowerAdmin_Audits.psm1/.psd1
|   |-- AD-PowerAdmin_PasswordsCtl.psm1/.psd1
|   `-- AD-PowerAdmin_AdAccessRights.psm1/.psd1
|-- Modules_Examples/              # Reference/template module
|   |-- AD-PowerAdmin_Example.psm1
|   `-- AD-PowerAdmin_Example.psd1
|-- AD-PowerAdmin.wiki/            # All detailed documentation
|   |-- Vulnerabilities/           # Generalized AD vulnerability dossiers
|   `-- ...                        # AD-PowerAdmin methodology, architecture, operational docs
`-- Reports/                       # Auto-created; holds CSV exports and debug log
```

---

## Requirements

```powershell
#Requires -RunAsAdministrator
#Requires -Version 5
#Requires -Modules ActiveDirectory
```

The main script detects the running PowerShell version at startup. If a module's manifest declares a minimum `PowerShellVersion` that exceeds the current session, that module is silently skipped and listed in a warning banner. No automatic re-launch occurs; to access PS7-only modules, run AD-PowerAdmin directly from a PowerShell 7 console.

---

## Global Variables (Set by Main Script)

| Variable | Type | Purpose |
|---|---|---|
| `$global:ThisScript` | string | Full path to AD-PowerAdmin.ps1 |
| `$global:ThisScriptDir` | string | Directory containing main script |
| `$global:ThisScriptsName` | string | Script filename |
| `$global:ModulesPath` | string | Path to Modules/ folder |
| `$global:ReportsPath` | string | Path to Reports/ folder |
| `$global:Version` | System.Version | Script version (1.2.0) |
| `$global:OptionsMaxTextLength` | int | Menu display width (82 chars) |
| `$global:Menu` | PSCustomObject | Hashtable of all menu items (populated by modules) |
| `$global:UnattendedJobs` | PSCustomObject | Hashtable of all scheduled jobs (populated by modules) |
| `$global:SubMenus` | hashtable | Hashtable of submenus contributed by modules; dispatched by `Enter-SubMenu` |

Settings from `AD-PowerAdmin_settings.ps1` are sourced into additional `$global:*` variables.

---

## AD-PowerAdmin.ps1 -- The Orchestrator

`AD-PowerAdmin.ps1` is not a library of AD functions. It is the **orchestration shell** -- it owns the startup sequence, the menu system, the unattended job dispatcher, and the global state that every module writes into. It contains no AD business logic of its own. All AD functionality lives in the modules.

### What the Main Script Does NOT Contain

- No AD audit logic
- No password management logic
- No event log searching logic
- No installation logic

All of that lives exclusively in the modules. The main script's only job is to load modules, build the menu from what they register, and dispatch commands.

### Startup Sequence (exact order)

```
AD-PowerAdmin.ps1 is executed
|
|-- 1. Global variables declared at script scope
|     $global:ThisScript, $global:ThisScriptDir, $global:ModulesPath,
|     $global:ReportsPath, $global:Version, $global:OptionsMaxTextLength
|     $global:Menu = @{}            <- empty hashtable, modules will fill this
|     $global:UnattendedJobs = @{}  <- empty hashtable, modules will fill this
|
|-- 2. Get-IncompatibleModules (called by Initialize-AllModules)
|     Reads each .psd1 manifest in Modules/ and compares its PowerShellVersion
|     field against $PSVersionTable.PSVersion. Any module requiring a higher
|     version than the running session is recorded in $global:IncompatibleModules
|     and excluded from loading. No re-launch occurs. If incompatible modules
|     exist, a yellow warning banner is shown in the interactive menu listing
|     which modules were skipped and why.
|
|-- 3. Initialize-ADPowerAdmin
|     |-- Validates prerequisites (script path, settings file exists)
|     |-- dot-sources AD-PowerAdmin_settings.ps1
|     |     -> populates all $global:* config variables
|     |-- Creates Reports/ directory if missing
|     |-- Initialize-Debug  (starts transcript if $global:Debug = $true)
|     `-- Initialize-AllModules
|           Get-ChildItem Modules\ -Filter *.psd1 | ForEach-Object {
|               Import-Module <module.psd1> -Force -Verbose
|           }
|           v for each .psd1 PowerShell also loads its RootModule (.psm1)
|           v the .psm1 calls Initialize-Module at the bottom of the file
|           v Initialize-Module adds entries to $global:Menu and $global:UnattendedJobs
|
`-- 4. Branch on -Unattended parameter
      |-- -Unattended present -> Start-Automation  (scheduled/headless path)
      `-- -Unattended absent  -> Enter-MainMenu    (interactive path)
```

### How Dynamic Module Loading Works

`Initialize-AllModules` (lines 445-458 of AD-PowerAdmin.ps1) does exactly this:

```powershell
Get-ChildItem -Path $global:ModulesPath -Filter *.psd1 | ForEach-Object {
    Import-Module "$global:ModulesPath\$($_.Name)" -Force -Verbose
}
```

- It scans `Modules/` for every `.psd1` file -- **no hardcoded list, no registration required**.
- Importing a `.psd1` manifest causes PowerShell to load the `.psm1` named in `RootModule`.
- When the `.psm1` is loaded, its top-level code runs. Every module ends with a bare call to `Initialize-Module`, so that function runs immediately on import.
- `Initialize-Module` writes into `$global:Menu` and `$global:UnattendedJobs`.

After `Initialize-AllModules` returns, those two global hashtables contain every menu item and every scheduled job contributed by every module. The main script then uses those hashtables -- it never needs to know which modules exist.

**Consequence:** dropping a valid `.psm1`/`.psd1` pair into `Modules/` is sufficient to add new functionality. No changes to `AD-PowerAdmin.ps1` are ever needed.

### How the Interactive Menu Is Built (Enter-MainMenu)

`Enter-MainMenu` (lines 613-758) reads `$global:Menu` at runtime -- it does not have a hardcoded list of options:

1. Iterates `$global:Menu.GetEnumerator()` sorted by `Title`.
2. Assigns sequential numbers (`MenuIndex`) to each entry.
3. Formats `Title` and `Label` to fit the 82-character terminal width (`$global:OptionsMaxTextLength`).
4. Displays the numbered list and waits for input with `Read-Host`.
5. When the user enters a number, retrieves the matching `Command` string and executes it:
   ```powershell
   Invoke-Expression "$SelectedOption"
   ```
6. After the command returns, calls itself recursively to redisplay the menu.

The menu is entirely data-driven from the modules. Adding a module entry = a new numbered line appears. Removing a module file = that line disappears. The main script has no opinion about what items exist.

Special menu inputs: `q` = quit, `h` = show help for a function (calls `Get-Help`), `d` = show diagnostics.

### How the Unattended Job Dispatcher Works (Start-Automation)

`Start-Automation` (lines 524-611) reads `$global:UnattendedJobs` the same way:

1. Flattens the hashtable into an array of objects.
2. If `-JobName 'Daily'`: iterates all jobs where `Daily = $true` and calls `Invoke-Expression` on each `Command`.
3. If `-JobName '<specific key>'`: finds the matching entry, optionally appends `-JobVar1 "<value>"` to the command string, then calls `Invoke-Expression`.

The `$JobVar1` substitution allows parameterized jobs -- e.g., passing a username for a password follow-up check without changing the module code.

### Execution Modes

```powershell
# Interactive menu (default)
.\AD-PowerAdmin.ps1

# Unattended -- run a specific registered job
.\AD-PowerAdmin.ps1 -Unattended -JobName 'krbtgt-RotateKey'

# Unattended -- run a job with a parameter
.\AD-PowerAdmin.ps1 -Unattended -JobName 'PwUserFollowup' -JobVar1 'jsmith'

# Unattended -- run ALL jobs flagged Daily = $true
.\AD-PowerAdmin.ps1 -Unattended -JobName 'Daily'
```

---

## Module Architecture

Every module consists of exactly two files:

| File | Purpose |
|---|---|
| `AD-PowerAdmin_<Name>.psm1` | Implementation -- functions + `Initialize-Module` |
| `AD-PowerAdmin_<Name>.psd1` | Manifest -- metadata, exports, channel designation |

The main script discovers and imports **all `.psd1` files** in `Modules/` at startup. No wiring in the main script is needed for new modules.

### Module Load Sequence (detailed)

```
Import-Module AD-PowerAdmin_MyModule.psd1
  `-- PowerShell reads RootModule = 'AD-PowerAdmin_MyModule.psm1'
       `-- Loads and executes the .psm1 top-level code
            `-- Initialize-Module is called (bare call at bottom of file)
                 |-- Writes to $global:Menu           -> appears in interactive menu
                 `-- Writes to $global:UnattendedJobs -> available as scheduled job
```

The `.psm1` must call `Initialize-Module` at module scope (outside any function) so it runs automatically on import. This is what connects the module's functions to the main script's menu and job systems.

### Framework Consistency Requirement

All new functions, audits, modules, and automations must conform to the existing project infrastructure:

- **Menu methodology** -- register items in `$global:Menu` using the established key/Title/Label/Command structure.
- **Sub-menu architecture** -- when a module exposes multiple user actions, use `$global:SubMenus` and `Enter-SubMenu` rather than cluttering the main menu.
- **Testing patterns** -- test scripts go in `temp/`, follow `test_<topic>.ps1` naming, and use the remote test runner for Windows AD validation.
- **Configuration handling** -- all tunable values belong in `AD-PowerAdmin_settings.ps1` as `$global:*` variables; modules read but never write them.
- **Coding conventions** -- `Verb-Noun` PascalCase functions, ASCII-only source files, comment-based help on every exported function, `$global:ReportsPath` for all output.
- **Module organization** -- one `.psm1`/`.psd1` pair per functional area; no business logic in the main script.

After any architectural change, both `CLAUDE.md` and relevant wiki pages must be reviewed and updated to reflect the new state.

---

## Module Implementation Pattern (.psm1)

```powershell
Function Initialize-Module {
    # Remove stale entries if module is reloaded
    $global:Menu.Remove('OldKey')

    # Register interactive menu items
    $global:Menu += @{
        'UniqueKey' = @{
            Title    = "Short Title"           # ~20 chars; shown in menu
            Label    = "Longer description."   # ~150-250 chars; shown below title
            Module   = "AD-PowerAdmin_MyModule"
            Function = "My-MainFunction"
            Command  = "My-MainFunction"       # Executed via Invoke-Expression
        }
    }

    # Register a submenu (use when the module has multiple user actions).
    # ONE main-menu entry points to Enter-SubMenu; all sub-actions go in $global:SubMenus.
    $global:SubMenus += @{
        'MyModuleMenu' = @{
            Title = "My Module Actions"
            Items = @{
                'Action1' = @{
                    Title   = "Do Thing One"
                    Label   = "Description of the first action."
                    Command = "My-MainFunction"
                }
                'Action2' = @{
                    Title   = "Do Thing Two"
                    Label   = "Description of the second action."
                    Command = "My-OtherFunction"
                }
            }
        }
    }
    # The main menu entry that opens the submenu:
    $global:Menu += @{
        'MyModuleEntry' = @{
            Title    = "My Module"
            Label    = "Manage things provided by My Module."
            Module   = "AD-PowerAdmin_MyModule"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'MyModuleMenu'"
        }
    }

    # Register unattended/scheduled jobs (optional)
    $global:UnattendedJobs += @{
        'MyDailyJob' = @{
            Title    = "My Daily Job"
            Label    = "Runs automatically each day."
            Module   = "AD-PowerAdmin_MyModule"
            Function = "Start-MyDailyJob"
            Daily    = $true           # $true = included in "Daily" run
            Command  = "Start-MyDailyJob"
        }
        'MyParameterizedJob' = @{
            Title    = "My Parameterized Job"
            Label    = "Runs with a supplied value."
            Module   = "AD-PowerAdmin_MyModule"
            Function = "Start-MyParamJob"
            Daily    = $false
            Command  = 'Start-MyParamJob -User $JobVar1'  # $JobVar1 from -JobVar1 arg
        }
    }
}

Initialize-Module   # MUST be called at module load time

Function My-MainFunction {
    <#
    .SYNOPSIS Short description.
    .DESCRIPTION Longer description.
    #>
    # Implementation
}

Function Start-MyDailyJob {
    # Implementation for scheduled use
}
```

---

## Module Manifest Pattern (.psd1)

```powershell
@{
    RootModule        = 'AD-PowerAdmin_MyModule.psm1'
    ModuleVersion     = '1.0'
    GUID              = '<generate with New-Guid>'
    Author            = 'CyberGladius'
    Description       = 'What this module does.'
    FunctionsToExport = @(
        'Initialize-Module',
        'My-MainFunction',
        'Start-MyDailyJob'
    )
    PrivateData = @{
        PSData = @{
            Channel      = 'Production'    # Alpha | Beta | Production
            ProjectUri   = 'https://github.com/Brets0150/AD-PowerAdmin'
            ReleaseNotes = 'Initial release.'
        }
    }
}
```

**Critical:** Any function not listed in `FunctionsToExport` is invisible to the main script.

---

## Naming Conventions

| Element | Convention | Examples |
|---|---|---|
| Module files | `AD-PowerAdmin_<Area>.psm1/.psd1` | `AD-PowerAdmin_Audits.psm1` |
| Functions | `Verb-Noun` PascalCase | `Get-ADAdminAudit`, `Search-InactiveUsers` |
| Global variables | `$global:<Name>` | `$global:InactiveDays` |
| Menu keys | Descriptive string | `'ADAdminAudit'`, `'KRBTGTRotate'` |
| Job keys | Descriptive string | `'Daily'`, `'PwUserFollowup'` |

---

## Settings File (AD-PowerAdmin_settings.ps1)

All configuration lives here. Modules read these as `$global:*` variables -- never write to them from a module.

Key settings groups:

| Group | Variables |
|---|---|
| Identity | `$global:ADAdminEmail`, `$global:FromEmail`, `$global:MsaAccountName` |
| Install | `$global:InstallDirectory` |
| SMTP | `$global:SMTPServer`, `$global:SMTPPort`, `$global:SMTPUsername`, `$global:SMTPPassword` |
| Feature flags | `$global:KerberosKRBTGTAudit`, `$global:InactiveComputerAudit`, `$global:InactiveUserAudit`, `$global:WeakPasswordAudit` |
| Inactive accounts | `$global:InactiveDays`, `$global:InactiveComputersLocations[]`, `$global:InactiveUsersLocations[]` |
| Password audit | `$global:NtlmHashDataFile`, `$global:WeakPassDictFile`, `$global:PwAuditPwChangeGracePeriod` |
| Debug | `$global:Debug` (bool) -- if true, transcript written to Reports/ |

---

## Production Modules Reference

### AD-PowerAdmin_Utils (v1.1, Production)
Shared utilities used by all other modules.

Key exports: `Get-DownloadFile`, `New-ADPAScheduledTask`, `Send-Email`, `Send-EmailTest`, `Get-DateFromCalendar`, `Export-AdPowerAdminData`, `Search-SingleAdObject`, `Show-Menu`

### AD-PowerAdmin_LogMgr (v1.0, Beta)
Windows Security Event Log searching -- lockout events (4740) and failed logons (4625).

Key exports: `Show-ADUserLockouts`, `Get-CurrentLockedoutUsers`, `Show-AdUserFailedLoginEvents`, `Get-FailedLoginEvents`

### AD-PowerAdmin_Installer (v1.0, Production)
Installs/uninstalls AD-PowerAdmin as a scheduled service using an sMSA account.

Key exports: `Install-ADPowerAdmin`, `Remove-ADPowerAdmin`, `Test-ADPowerAdminInstall`, `Install-PowerShell7`, `Install-DSInternals`

### AD-PowerAdmin_Audits (v1.1, Production)
AD security audits and account lifecycle management.

Key exports: `Get-ADAdminAudit`, `Get-ADUserAudit`, `Search-MultipleInactiveComputers`, `Search-MultipleInactiveUsers`, `Search-AD`, `Test-ADSecurityBestPractices`, `Start-DailyInactiveUserAudit`, `Start-DailyInactiveComputerAudit`

High-privilege groups checked: Domain Admins, Enterprise Admins, Schema Admins, Administrators, Backup Operators, Account Operators, Server Operators, Domain Controllers, Print Operators, Replicator, Enterprise Key Admins, Key Admins.

### AD-PowerAdmin_PasswordsCtl (v1.0, Production)
Password management, KRBTGT rotation, and breach detection via DSInternals + HIBP hash file.

Key exports: `Update-KRBTGTPassword`, `Get-PasswordAuditAdminReport`, `Test-PwUserFollowup`, `Start-MonthlyPasswordAudit`, `New-RandomPassword`

Scheduled jobs: `Test-krbtgtPwdAge` (daily), `krbtgt-RotateKey`, `PwUserFollowup`, `Start-MonthlyPasswordAudit`

### AD-PowerAdmin_AdAccessRights (v1.0, Production)
Audits Active Directory ACLs and permissions; identifies DCSync and delegation risks.

Key exports: `Get-AdAcl`, `Get-ExtendedAcl`, `Get-AdGuids`, `Search-DcSyncRisk`, `Search-HighRiskAdAce`, `Out-AclDetails`, `Out-AclDetailsLite`

---

## How to Create a New Module

Building a new module is the standard way to extend AD-PowerAdmin. The framework is designed so that a valid `.psm1`/`.psd1` pair dropped into `Modules/` is all that is needed -- no changes to the main script are required.

### Step 1 -- Copy the example files

```
Modules_Examples/AD-PowerAdmin_Example.psm1  ->  Modules/AD-PowerAdmin_<Name>.psm1
Modules_Examples/AD-PowerAdmin_Example.psd1  ->  Modules/AD-PowerAdmin_<Name>.psd1
```

### Step 2 -- Update the manifest (.psd1)

- Generate a new GUID with `New-Guid`.
- Set `RootModule` to the correct `.psm1` filename.
- List all exported functions in `FunctionsToExport`.
- Set `Channel` to `Alpha`, `Beta`, or `Production`.

### Step 3 -- Implement the module (.psm1)

- Write `Initialize-Module` to add menu and/or job entries.
- Call `Initialize-Module` at the **bottom of the file** (not inside a function).
- Implement all exported functions with comment-based help.
- Abstract any logic used in more than one place (or likely to be reused) into a dedicated helper function -- see Code Reusability Standards below.
- **If this module depends on another AD-PowerAdmin module**, declare and enforce the dependency -- see Inter-Module Dependencies below.

### Inter-Module Dependencies

`Initialize-AllModules` loads modules in filesystem order (alphabetical by `.psd1` filename). If
your module calls functions exported by another AD-PowerAdmin module, that other module may not be
loaded yet when `Initialize-Module` runs. You must declare and enforce the dependency explicitly.

**Convention -- two locations:**

**1. In the `.psd1` manifest** (documentation + future tooling hook):
```powershell
PrivateData = @{
    PSData = @{
        RequiredADPAModules = @('AD-PowerAdmin_GPOMgr')
        # ...
    }
}
```

**2. At the top of `Initialize-Module` in the `.psm1`** (runtime enforcement):
```powershell
Function Initialize-Module {
    # Bootstrap Utils if this module loads alphabetically before it (e.g. any module
    # with a name that sorts before 'AD-PowerAdmin_Utils'). Assert-ADPAModuleDependency
    # lives in Utils and cannot be called until Utils is imported.
    if (-not (Get-Module -Name 'AD-PowerAdmin_Utils')) {
        $UtilsPath = Join-Path $global:ModulesPath 'AD-PowerAdmin_Utils.psd1'
        if (Test-Path $UtilsPath) {
            try { Import-Module $UtilsPath -Force -ErrorAction Stop } catch { }
        }
    }
    if (-not (Assert-ADPAModuleDependency -RequiredModules @('AD-PowerAdmin_GPOMgr'))) {
        Write-Host "[WARN] MyModule was not registered: required module AD-PowerAdmin_GPOMgr is unavailable." -ForegroundColor Yellow
        return
    }
    # ... rest of menu registration
}
```

`Assert-ADPAModuleDependency` (from `AD-PowerAdmin_Utils`) checks whether each named module is
loaded, attempts to import it from `$global:ModulesPath` if not, and returns `$false` with a
`[FAIL]` message if it still cannot be loaded. If it returns `$false`, `Initialize-Module`
must `return` immediately without registering any menu entries -- the module simply will not
appear in the menu rather than registering broken entries that fail silently at invocation.

**Load-order note:** `Initialize-AllModules` loads `.psd1` files in alphabetical order. Because
`AD-PowerAdmin_Utils` sorts after most module names, any module whose filename sorts before
`AD-PowerAdmin_Utils` must include the Utils bootstrap block shown above. Without it,
`Assert-ADPAModuleDependency` will throw "not recognized" at `Initialize-Module` call time.

### Step 4 -- Create or update the wiki page

Before the module is considered complete, create a wiki page that covers:

1. What the module does
2. Why it was built -- the vulnerability, weakness, operational need, or best practice it addresses
3. Which `Vulnerabilities/` dossier is relevant (if any)
4. How it integrates with the rest of the framework

### Step 5 -- Update CHANGELOG.md

Add an entry under the appropriate headings (Added / Changed / Fixed / Removed) for every function and behavior introduced by the new module. Include what it does and why it was built.

### Step 6 -- Test

```powershell
.\AD-PowerAdmin.ps1                                     # Verify menu item appears
.\AD-PowerAdmin.ps1 -Unattended -JobName 'MyJobKey'    # Verify job runs
```

### Step 7 -- Update README.md

Add a bullet to the Features list for every user-visible AD capability the new module introduces.

---

## Version System

Overall version is computed dynamically:

- Base: script version `1.2.0`
- Minor component sums all module `ModuleVersion` minor numbers
- Patch component sums all module `ModuleVersion` patch numbers
- Channel = lowest across all modules: `Alpha < Beta < Production`

```powershell
Get-ADPAVersion           # Summary version
Get-ADPAVersion -Detailed # Per-module breakdown table
```

Adding a new module will increment the computed version automatically.

---

## Key Design Rules

1. **Modules are self-registering.** `Initialize-Module` + `Initialize-AllModules` in the main script -- no manual wiring.

2. **`$global:Menu`, `$global:UnattendedJobs`, and `$global:SubMenus` are the integration points.** Everything a module exposes goes through these three hashtables.

3. **`Invoke-Expression` executes commands.** The `Command` string in a menu/job entry is passed directly; it can contain PowerShell expressions.

4. **Settings are read-only from modules.** Modules only read `$global:` settings; they never write to them.

5. **Export every public function.** Missing from `FunctionsToExport` = invisible.

6. **Use `$global:ReportsPath` for output.** Never hardcode paths.

7. **Check `$global:Debug`** for conditional verbose or transcript output.

8. **Email uses `Send-Email` from the Utils module.** Parameters first, global settings as fallback.

9. **Never use non-ASCII or multi-byte Unicode characters in any `.ps1` or `.psm1` file.** Characters such as Unicode checkmarks, cross marks, emoji, smart quotes, or any symbol outside the standard ASCII range (0x00-0x7F) cause encoding-related parse failures in the PowerShell interpreter, especially when scripts are transferred between machines or executed in environments with different default encodings. Use only plain ASCII text -- replace Unicode symbols with ASCII equivalents such as `[OK]` and `[FAIL]`.

10. **Use submenus to keep the main menu uncluttered.** When a module has multiple user-facing actions, register ONE entry in `$global:Menu` with `Command = "Enter-SubMenu 'MyKey'"` and register all sub-actions in `$global:SubMenus['MyKey'].Items`. `Enter-SubMenu` in `AD-PowerAdmin.ps1` handles display and dispatch with consistent styling.

11. **Every feature must have a justification.** No audit, test, automation, or feature is added without a clear link to a known vulnerability, weakness, operational best practice, or security requirement. That justification is documented in the wiki.

12. **After any architectural change, update both `CLAUDE.md` and the relevant wiki pages.** These documents are the authoritative reference for contributors and must stay current.

---

## Code Reusability Standards

AD-PowerAdmin is a framework shared across modules. Redundant code fragments the codebase, increases maintenance burden, and creates inconsistency in behavior.

**Rules:**

- If logic is used in more than one place, abstract it into a dedicated function.
- If logic is likely to be reused by another module or future feature, abstract it.
- Shared utility functions belong in `AD-PowerAdmin_Utils.psm1` unless they are tightly scoped to a single module's domain.
- Helper functions within a module that are not part of the public interface should be kept private (omit from `FunctionsToExport`).

The test for whether to abstract: if you copy-paste a block from one function to another, stop and write a function instead.

---

## .gitignore Highlights

These are intentionally excluded:

- `Reports/` -- runtime output, not source
- `Modules/AD-PowerAdmin_Azure.*` -- Alpha, not ready
- `AD-PowerAdmin_Debug.log` -- debug transcript
- `junk.ps1` -- scratch file
- `temp/` -- throwaway and diagnostic scripts

---

## Development Procedures

### Test Scripts Must Live in a Dedicated Temp Directory

When test or scratch scripts need to be created during development or debugging, they must **never** be placed in the project root or any existing project directory.

**Required location:**

```
AD-PowerAdmin/
`-- temp/          <- create this directory if it does not exist; place all test scripts here
    `-- test_*.ps1
```

**Rules:**
- Always use `temp/` as the directory for any throwaway, diagnostic, or exploratory script.
- Name test files descriptively: `test_<what_is_being_tested>.ps1`.
- The `temp/` directory is covered by `.gitignore` and must not be committed.
- Never leave test scripts in the project root, `Modules/`, or `Reports/`.

---

## Remote Windows Test Runner

This project includes a narrow wrapper for executing approved PowerShell scripts on the Windows AD test server over PowerShell remoting.

**Test runner location:** `.claude/tools/run-win-test.ps1`
**Allow-list:** `.claude/tools/allowed-tests.json`

### How to run a remote test

```bash
pwsh -File ./.claude/tools/run-win-test.ps1 -TestName <TestName>
```

Valid test names are the keys in `.claude/tools/allowed-tests.json`. Check that file first.

### Mandatory rules

1. **Always use the wrapper.** Never run `Enter-PSSession`, `New-PSSession`, `Invoke-Command`, or any ad-hoc remoting command directly. The wrapper is the only approved execution path.

2. **Never use `pwsh -Command`.** The only approved invocation form is `pwsh -File ./.claude/tools/run-win-test.ps1 -TestName <name>`. `pwsh -Command` and `pwsh -c` are explicitly denied by `settings.local.json`.

3. **Never touch the Windows password.** Do not request, print, store, or log it. The password lives exclusively in the SecretManagement vault under the secret name `WinTestPassword`. The wrapper retrieves it silently.

4. **Only use approved test names.** Names must exist as keys in `.claude/tools/allowed-tests.json`. Never construct or guess a remote path.

5. **If a needed test is missing from the allow-list**, say so and ask the user to add an entry before proceeding:
   ```json
   "My-TestName": "C:\\ApprovedTests\\My-TestName.ps1"
   ```

### After a test runs

Summarize results: test name, target server, exit code (0 = success), any errors, and recommended next steps.

### One-time setup (run by the user, not Claude)

```powershell
Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force
Register-SecretVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore
Set-Secret -Name WinTestPassword -Secret (Read-Host -AsSecureString 'Windows password')
```

Also edit the configuration block near the top of `run-win-test.ps1` to set the correct `$TargetServer` and `$ServiceAccount` values before first use.
