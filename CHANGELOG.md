# AD-PowerAdmin — Changelog

## Unpushed Changes (since last `git push`)

**2 commits ahead of `origin/main` as of 2026-04-04.**
**Plus additional unstaged working-directory modifications across all modules.**

---

### Commits Not Yet Pushed

| Commit | Date | Summary |
|---|---|---|
| `e1d12a8` | 2025-08-18 | Added diagnostics output option; began PS7 install/upgrade function for Azure CLI work |
| `2eab2b3` | 2025-08-18 | Updated `Search-MultipleInactiveComputers` function |

---

## Changes by File

---

### Modules/AD-PowerAdmin_HIBP_PwndPwMgr.psm1 and AD-PowerAdmin_HIBP_PwndPwMgr.psd1 -- Embedded Pure-PS Downloader

**Architectural change:** Replaced the .NET SDK + `haveibeenpwned-downloader.exe` toolchain with a pure PowerShell 5.1 downloader embedded directly in the module. No external installs, no runtime dependencies, and no subprocess invocations.

**Added:**
- `Start-HibpDownload` -- Full-featured NTLM hash downloader. Supports directory mode (ETag-based incremental updates via ~1 million range files) and single-file mode (monolithic sorted flat file). Parallel `Start-Job` workers for concurrent range downloads; `.part`-file safety pattern; per-prefix retry logic with configurable count and timeout; failure log written to `$global:ReportsPath`. Parameters: `-OutputFile`, `-Parallelism` (0 = auto-detect), `-Overwrite`, `-Single`, `-Ntlm`, `-Update`, `-VerifyOnly`, `-Prefix`, `-RequestTimeoutSeconds`, `-Retries`, `-ContinueOnError`.
- `Initialize-HibpTls12` (private) -- Forces TLS 1.2 for `System.Net.HttpWebRequest` in the current session.
- `Resolve-HibpLocalPath` (private) -- Resolves PowerShell provider paths to filesystem absolute paths.
- `ConvertTo-HibpPrefix` (private) -- Normalizes and validates a single 5-character hex prefix value.
- `Expand-HibpPrefixes` (private) -- Expands a prefix list or range specifier to a full `[string[]]` of 5-character hex prefixes.
- `Get-HibpRangeUri` (private) -- Builds the HIBP API URL for a given prefix and hash mode.
- `Get-HibpHeaderValue` (private) -- Safely reads a single HTTP response header without throwing on missing keys.
- `Invoke-HibpRangeDownload` (private) -- Downloads a single prefix range to a `.part` file with retry logic; renames to final filename only after validation succeeds.
- `Test-HibpRangeFile` (private) -- Validates that a downloaded range file contains valid `SUFFIX:count` lines.
- `Import-HibpManifest` (private) -- Reads the manifest TSV into a hashtable keyed by prefix, tracking ETag and modification timestamp per range.
- `Export-HibpManifest` (private) -- Writes the manifest hashtable to TSV atomically via a `.part` file.
- `Split-HibpPrefixBuckets` (private) -- Distributes a prefix list evenly across a set of parallel worker buckets.
- `Invoke-HibpDirectoryDownload` (private) -- Orchestrates parallel `Start-Job` workers for directory mode; contains a self-contained `$workerScript` scriptblock that re-declares all required helpers with a `Local` suffix because `Start-Job` spawns new PS processes that do not inherit module functions.
- `Invoke-HibpSingleFileDownload` (private) -- Sequential single-file download with a streaming `StreamWriter`; no parallel workers needed for monolithic output.

**Removed:**
- `Test-DotnetInstalled` -- No .NET runtime check needed; the downloader is pure PowerShell.
- `Install-DotnetSdk` -- No .NET SDK installation required.
- `Install-HibpHashDownloader` -- No external executable to install.
- `Uninstall-DotnetSdk` -- No SDK to remove.

**Changed:**
- `Get-HibpPasswordHashesFiles` -- Rewritten as a thin settings-aware wrapper around `Start-HibpDownload`. Reads `$global:NtlmHashDataDir` to select directory vs single-file mode. Detects first run via manifest file presence. Passes `-ContinueOnError` and checks `$stats.Failed` to allow partial success on the ~1 million prefix download. Retains disk-space display and confirmation prompt. Calls `Get-WeakPasswordsList` after the hash download completes.
- `Test-HibpToolsInstalled` -- Rewritten. Now performs an HTTP connectivity check against `api.pwnedpasswords.com/range/00000?mode=ntlm` via `HttpWebRequest` and reports whether local hash data (file or directory) has been downloaded. Returns `$true` if the API is reachable; data presence is informational.
- `Uninstall-HibpTools` -- .NET artifact removal eliminated. Now identifies the configured hash data (file or directory), displays approximate size, prompts for confirmation, and deletes it.
- `Show-HibpTroubleshootingGuide` -- Fully rewritten for the pure-PS architecture. All .NET SDK content removed. New sections: CloudFlare rate limiting, network timeout handling, partial-download resume, `.part`-file safety pattern, and single-file vs directory mode rationale.
- `Initialize-Module` -- Removed `HibpInstall` submenu item. Updated `HibpTest` label to "Test HIBP Readiness". Updated `HibpUninstall` label to "Remove HIBP Hash Data". Submenu is now 5 items instead of 6.

**Why it changed:**
The prior architecture required a two-step install (dotnet SDK + tool install), created environment variable dependencies (`DOTNET_ROOT`, `PATH`), and used a subprocess call to invoke the downloader -- all sources of failure that appeared in routine use. The pure PowerShell replacement eliminates every external dependency. Because v3.4 of the research script uses `throw` instead of `exit`, its functions can be called directly in the current session without spawning a subprocess, which is required for embedding in a module. ETag-based incremental updates in directory mode are the primary operational improvement: after the ~70 GB first run, weekly refreshes download only changed ranges (typically a few hundred MB).

**Impact:**
- No .NET SDK or tool install step required before using the HIBP sub-menu.
- `.gitignore` entries for `Modules/haveibeenpwned-downloader.exe`, `Modules/.dotnet`, and `Modules/.store` have been removed.
- `FunctionsToExport` in the `.psd1` updated: removed `Install-HibpHashDownloader`, `Install-DotnetSdk`, `Test-DotnetInstalled`, `Uninstall-DotnetSdk`; added `Start-HibpDownload`.
- No changes to `AD-PowerAdmin_settings.ps1` or the password audit module (`AD-PowerAdmin_PasswordsCtl`) are required.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 and AD-PowerAdmin_GPOMgr.psd1 -- New Module

**Added:**
- `Initialize-Module` -- Satisfies the AD-PowerAdmin module load contract. Registers no menu items or unattended jobs. This module is a shared infrastructure library; all functions are called programmatically by other modules.
- `Find-ADPAGPO` -- Searches for Group Policy Objects by exact name (`-Name`) or wildcard pattern (`-Pattern`). Always returns an array so callers can check `.Count -eq 0` for "not found" without null guards. Wraps `Get-GPO -Name` for exact matches and `Get-GPO -All | Where-Object` for pattern searches.
- `Test-ADPAGPO` -- Validates that a named GPO exists, is enabled (not AllSettingsDisabled), and optionally contains expected registry settings and links. Registry settings are verified by parsing the GPO's XML report. Links are verified via `Get-GPInheritance`. Writes `[PASS]` / `[FAIL]` per check unless `-Quiet` is specified. Returns `[bool]`. Intended for use by other modules to verify their GPO is still in the expected state.
- `New-ADPAGPO` -- Idempotently creates a GPO by name. If a GPO with the given name already exists, returns the existing object and writes an `[OK]` message without modifying anything. Supports `-WhatIf`. Returns the GPO object or `$null` on failure.
- `Set-ADPAGPORegistrySetting` -- Applies a single registry-backed Administrative Template setting to a named GPO via `Set-GPRegistryValue`. Accepts `-Key`, `-ValueName`, `-Type` (String/ExpandString/Binary/DWord/MultiString/QWord), and `-Value`. Supports `-WhatIf` and `-Confirm`.
- `Remove-ADPAGPORegistrySetting` -- Removes a specific registry-backed setting from a named GPO via `Remove-GPRegistryValue`. Idempotent -- returns `$true` if the setting is absent after the call. Treats "value not found" errors from the cmdlet as success. Supports `-WhatIf` and `-Confirm`.
- `Add-ADPAGPOLink` -- Links a GPO to an OU, domain, or site. Validates the target distinguished name exists in Active Directory before linking. Idempotent -- if the link already exists, calls `Set-GPLink` to enforce the desired `LinkEnabled` and `Enforced` state. Supports `-WhatIf` and `-Confirm`.
- `Remove-ADPAGPOLink` -- Removes a GPO link from a target without deleting the GPO. Idempotent -- returns `$true` if the link is absent after the call. Supports `-WhatIf` and `-Confirm`.
- `Set-ADPAGPOPermission` -- Configures a security filtering entry on a named GPO via `Set-GPPermission`. Accepts `-TargetName`, `-TargetType` (User/Computer/Group), and `-PermissionLevel` (GpoRead/GpoApply/GpoEdit/GpoEditDeleteModifySecurity/None). Supports `-WhatIf` and `-Confirm`.
- `Export-ADPAGPOReport` -- Generates HTML and/or XML audit reports for a named GPO via `Get-GPOReport`. Saves files to `$global:ReportsPath` with a sanitized GPO name and timestamp in the filename. Returns a `[PSCustomObject]` with `HtmlPath` and `XmlPath` properties.
- `Remove-ADPAGPO` -- Deletes a GPO using a multi-step safe workflow: verifies the GPO exists, counts and displays all active links, refuses to delete a linked GPO unless `-RemoveLinks` is specified, exports reports when `-ExportBeforeDelete` is set or when the GPO has active links, removes links if `-RemoveLinks` is specified, then deletes after explicit confirmation. Supports `-WhatIf` and `-Confirm` with `ConfirmImpact=High`.
- `Install-ADPAGPOBaseline` -- Primary inter-module API. Accepts a declarative `$GpoDefinition` hashtable (Name, Description, Links, Permissions, RegistrySettings) and idempotently creates, configures, and links the described GPO by orchestrating `New-ADPAGPO`, `Set-ADPAGPORegistrySetting`, `Set-ADPAGPOPermission`, and `Add-ADPAGPOLink`. Returns a structured result object with GpoName, Exists, Created, Modified, Linked, Links, Status, and Errors fields. The caller determines all GPO content; this module makes no policy decisions. Supports `-WhatIf`.
- `Remove-ADPAGPOBaseline` -- Removes a GPO that was deployed from a definition hashtable by extracting `Name` from the definition and delegating to `Remove-ADPAGPO`. Supports `-RemoveLinks`, `-WhatIf`, and `-Confirm`.
- `Search-ADPAGPOSetting` -- Scans all GPOs in the domain for a specific registry key and optional value name by parsing each GPO's XML report. Accepts `-Key`, `-ValueName`, `-ExpectedValue`, and `-Force` (suppresses progress output for programmatic use). Returns an array of result objects (GpoName, GpoId, Key, ValueName, ActualValue, Matches). Used by other modules to detect existing policies before deploying a new GPO for the same setting, preventing duplicate or conflicting configurations.

**Why it was built:**
Multiple planned AD-PowerAdmin security features require Group Policy as their enforcement mechanism. Without a shared module, each feature would implement its own GPO creation, configuration, and lifecycle management -- fragmenting maintenance and making it impossible to detect when two modules create conflicting GPOs targeting the same registry keys on overlapping OUs. The GPOMgr module centralizes GPO mechanics into a single tested infrastructure layer and provides a declarative API (`Install-ADPAGPOBaseline`) that consuming modules call instead of reimplementing GPO plumbing. The module is intentionally neutral: it enforces no naming conventions and defines no security standards. Policy decisions belong entirely to the modules that use this infrastructure.

**Impact:**
- Establishes `Install-ADPAGPOBaseline` and `Search-ADPAGPOSetting` as the shared GPO infrastructure API for all future modules requiring GPO deployment.
- No interactive menu entries, no unattended jobs, and no changes to `AD-PowerAdmin_settings.ps1`.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 and AD-PowerAdmin_Honeypot.psd1 -- New Module

**Added:**
- `Install-HoneypotAccount` -- Interactive provisioning wizard. Presents a curated list of seven realistic-looking service account usernames, collects the target OU, generates a 32-character cryptographically random password, creates the AD user with hardened attributes (PasswordNeverExpires, CannotChangePassword, no delegation, no SPNs), creates or validates the GG_Honeytoken_DenyLogon security group, adds the account to the deny-logon group, runs the safety validation, writes all configuration to the settings file, and creates the hourly Windows scheduled task. Displays GPO guidance for deny-logon user rights after provisioning.
- `Test-HoneytokenUserSafety` -- Validates the honeytoken account against six safety criteria: account is enabled, no SPNs configured, not trusted for unconstrained delegation, AccountNotDelegated flag is set, membership in the deny-logon group is intact, and no privileged group memberships (Domain Admins, Enterprise Admins, Schema Admins, Administrators, Backup Operators, Account Operators, Server Operators, Print Operators, Replicator, Enterprise Key Admins, Key Admins). Returns $true if all checks pass. Callable from the menu or from Install-HoneypotAccount during provisioning.
- `Start-HoneypotMonitor` -- Unattended hourly monitor executed via the AD-PowerAdmin_HoneypotMonitor scheduled task. Queries all domain controllers for Security log events 4624 (successful logon), 4625 (failed logon), 4768 (Kerberos TGT request), 4771 (Kerberos pre-auth failure), and 4740 (account lockout) targeting the configured honeytoken account in the past hour. Classifies 4624 as CRITICAL and all others as HIGH. On detection, builds a structured alert email with event details and recommended response actions, sends it via Send-Email, and exports a timestamped CSV to the Reports directory. No action taken when no events are found. Controlled by $global:HoneypotAudit.
- `Show-HoneypotReport` -- Interactive log review. Prompts for a time range (1 hour, 24 hours, 7 days, or custom), queries all DCs for honeytoken events, displays a severity-classified summary table, and offers CSV export.
- `Remove-HoneypotAccount` -- Six-step reversible decommissioning: removes the scheduled task, removes the account from the deny-logon group, disables the AD account, optionally permanently deletes the account, optionally removes the deny-logon group if empty, and clears all honeytoken configuration from the settings file. Each destructive step requires explicit confirmation.
- `Initialize-Module` -- Registers the HoneypotMenu submenu (Install, View Report, Verify Safety, Remove), a single main menu entry, and the HoneypotHourlyMonitor unattended job entry (Daily = $false; triggered by its own scheduled task, not the daily runner).
- Private helpers: `Get-HoneypotEventsBatch`, `Get-HoneypotEvents`, `New-HoneytokenUser`, `New-HoneypotDenyGroup`, `New-HoneypotScheduledTask`, `Remove-HoneypotScheduledTask`, `Set-HoneypotSettings`, `New-HoneypotRandomPassword`, `Get-HoneypotDefaultDenyGroup`. Not exported; called only by the public functions above.

**Why it was built:**
Password spraying against Active Directory is a leading initial-access technique. Attackers enumerate valid usernames and attempt a single password guess per account to stay below lockout thresholds, making the attack nearly invisible in volume-based alerting. A honeytoken account -- one that looks legitimate but should never authenticate -- creates a zero-false-positive detection signal: any authentication attempt against the account is unambiguous evidence of enumeration or spraying activity. This module provides the complete lifecycle for that detection capability.

**Impact:**
- Adds a new Honeytoken Management submenu to the interactive menu.
- Adds the HoneypotHourlyMonitor unattended job to $global:UnattendedJobs.
- Adds four new configuration variables to AD-PowerAdmin_settings.ps1: $global:HoneypotAudit, $global:HoneypotUsername, $global:HoneypotDenyGroup, $global:HoneypotOU.
- Creates a Windows scheduled task named AD-PowerAdmin_HoneypotMonitor when installed.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- GPO Automation Enhancement

**Changed:**
- `Install-HoneypotAccount` -- The provisioning wizard now automatically creates, configures, and links the deny-logon GPO (`AD-PowerAdmin_HoneypotDenyLogon`) to the domain root as step 6 of the wizard. The previous manual GPO configuration instruction block displayed after provisioning has been removed. The post-completion message now states that Group Policy propagation typically takes 5-10 minutes rather than directing the administrator to configure a GPO manually.
- `Test-HoneytokenUserSafety` -- Added two new safety checks: GPO existence (verifies `AD-PowerAdmin_HoneypotDenyLogon` is present in the domain) and domain-root link validation (verifies the GPO is actively linked to the domain root). Both checks write `[OK]` or `[FAIL]` with explanatory messages. Either failure sets `$AllPassed = $false` and contributes to the overall RESULT.
- `Remove-HoneypotAccount` -- Added Step 6 (optional GPO removal) between the deny-logon group cleanup and the settings-clear step. If the GPO `AD-PowerAdmin_HoneypotDenyLogon` exists, the administrator is offered the option to remove it; otherwise the step is skipped with an informational message. The original settings-clear step is now Step 7. The `.DESCRIPTION` docblock is updated to reflect seven steps.
- `New-HoneytokenUser` -- Removed the block of Yellow-colored output lines that displayed manual GPO configuration guidance. This guidance is now obsolete because the wizard automates GPO creation.

**Added (private helpers):**
- `Get-HoneypotGPOName` -- Returns the fixed GPO name `'AD-PowerAdmin_HoneypotDenyLogon'` used consistently by all GPO-related functions.
- `Set-HoneypotGPOUserRights` -- Writes the five deny-logon Privilege Rights (`SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`, `SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`, `SeDenyNetworkLogonRight`) for a given group SID directly into the GPO's `GptTmpl.inf` in SYSVOL as UTF-16 LE. Also increments the computer-policy version in `GPT.INI` (low 16 bits of the 32-bit version counter) and updates the GPO's AD object (`versionNumber` and `gPCMachineExtensionNames`) to register the Security Settings CSE GUID `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` with tool `{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}` so domain clients recognize and apply the change.
- `Install-HoneypotGPO` -- Orchestrates GPO deployment: calls `Install-ADPAGPOBaseline` from the GPOMgr module to create and link the GPO, retrieves the GPO GUID via `Get-GPO`, and delegates to `Set-HoneypotGPOUserRights` to write the Privilege Rights into SYSVOL.
- `Remove-HoneypotGPO` -- Calls `Remove-ADPAGPO -RemoveLinks` to delete the honeytoken GPO and all its links. Idempotent -- writes an informational message if the GPO is already absent.

**Why this changed:**
The original installation required administrators to manually create a GPO and configure five User Rights Assignments for the deny-logon group. This manual step was error-prone, frequently skipped during testing, and undermined the goal of a single-wizard deployment. The deny-logon restriction is the safety mechanism that prevents the honeytoken account from being used even if the password is guessed; without it, a successful credential guess could result in an actual compromise. Automating the GPO ensures the restriction is always in place and consistent.

**Impact:**
- The installation wizard is now fully automated: no post-wizard manual steps are required.
- `Test-HoneytokenUserSafety` now reports on GPO health in addition to account attributes, providing a complete picture of the detection configuration.
- The removal workflow now offers GPO cleanup, preventing orphaned GPOs from accumulating in environments where the honeytoken is reinstalled with a different deny-group name.
- The GPOMgr module (`Install-ADPAGPOBaseline`, `Find-ADPAGPO`, `Remove-ADPAGPO`, `Test-ADPAGPO`) is now a runtime dependency of the Honeypot module; both modules must be present in `Modules/` for the Honeypot module to function.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 and AD-PowerAdmin_settings.ps1 -- Configurable Monitor Interval

**Added:**
- `$global:HoneypotMonitorIntervalMinutes` (settings file) -- New integer variable that controls both how often the honeytoken monitor scheduled task fires and how far back the Security log search looks. The lookback window is this value plus one additional minute to prevent timing gaps between consecutive executions. Default is 60 (minutes). Example: setting 15 runs the task every 15 minutes and reviews the past 16 minutes of logs.

**Changed:**
- `New-HoneypotScheduledTask` -- The task repetition interval is now read from `$global:HoneypotMonitorIntervalMinutes` (falling back to 60 if the value is absent or zero) rather than being hardcoded to 1 hour. The trigger's first-run time is set to now plus one interval rather than snapping to the next whole hour, ensuring the task fires promptly regardless of the configured interval. Task description and success message now report the actual interval value.
- `Start-HoneypotMonitor` -- The lookback window (`$StartTime`) is now `$global:HoneypotMonitorIntervalMinutes + 1` minutes rather than a fixed 1 hour. Log messages report the actual lookback duration.

**Why this changed:**
A 60-minute detection window is adequate for overnight monitoring but too coarse for high-security environments where a password spray could produce dozens of attempts within a few minutes. Configuring a 15-minute interval reduces the maximum time between an event occurring and the administrator receiving an alert from up to 60 minutes to up to 15 minutes. The one-minute buffer prevents the gap that would otherwise exist if a task runs at exactly the same second each cycle and the prior cycle missed events logged in the final second of its window.

**Impact:**
- Environments that do not change the setting retain the existing 60-minute behavior; no operational change.
- Setting `$global:HoneypotMonitorIntervalMinutes = 15` and re-running the install wizard (which recreates the scheduled task) applies the new interval immediately.
- The setting does not affect `Show-HoneypotReport`; that function always prompts for an explicit time range.

---

### AD-PowerAdmin.ps1 (Main Script)

**Added:**
- `Test-PowerShellVersion` — checks if running under PS7+; if not, automatically re-launches the entire script under `pwsh.exe` with admin privileges preserved. Searches common install paths and PATH for `pwsh.exe`, verifies the found binary is actually version 7+, and exits the current session cleanly after re-launch.
- `Show-Diagnostics` — outputs system diagnostic info (PS version, OS, user, paths, all loaded modules with versions/channels). Accessible from the main menu by pressing `d`.
- `Get-ADPAVersion` — dynamic version computation: sums `ModuleVersion` values from all `.psd1` files and adds them to the base script version; determines overall channel as the lowest across all modules (Alpha < Beta < Production). Supports a `-Detailed` flag for a per-module breakdown table.

**Changed:**
- Main execution flow now calls `Test-PowerShellVersion` as the very first step before any initialization.
- Version string in logo now calls `Get-ADPAVersion` dynamically rather than displaying a static value.

---

### Modules/AD-PowerAdmin_Installer.psm1 — Major Additions

The Installer module received significant new functionality. The following functions were added:

| Function | Status | Description |
|---|---|---|
| `Install-PowerShell7` | **Complete** | Installs PS7 system-wide via `winget`; checks if already installed first; verifies install succeeded via `Test-PowerShell7-Installed` |
| `New-ADPowerAdminSmsaAccount` | **Complete** | Creates the standalone Managed Service Account (sMSA) for the scheduled task; adds it to Domain Admins |
| `New-ADPowerAdminScheduledTask` | **Complete** | Creates the `AD-PowerAdmin_Daily` scheduled task; prompts before overwriting an existing task |
| `New-ADPowerAdminHomeFolder` | **Complete** | Creates install directory; sets owner to Domain Admins; removes all other ACL entries; configures folder audit policy for Everyone Success+Failure |
| `Enable-AuditLogging` | **Complete** | Enables system-level audit policies via `auditpol.exe` |
| `Copy-AdPowerAdmin` | **Complete** | Copies all project files to the install directory if not already running from there; skips if source and destination already match |
| `Set-ADPowerAdminGPO` | **Complete** | Modifies the Default Domain Controllers Policy GPO to grant the sMSA "Log on as a service" right; supports `-Install` and `-Uninstall` switches |
| `Test-PowerShell7-Installed` | **Complete** | Tests whether `pwsh` is reachable on PATH and returns true/false |
| `Test-ADPowerAdminInstall` | **Complete** | Full install verification: checks home folder, sMSA account, scheduled task, PS7, DSInternals, and GPO |
| `Test-SystemAuditPolicy` | **Complete** | Validates a specific `auditpol.exe` subcategory is set to the expected Success/Failure state |
| `Test-FolderAuditPolicy` | **Complete** | Validates the ACL audit rules on a folder against expected settings |
| `Remove-AdPowerAdmin` | **Complete** | Removes scheduled task, sMSA account, GPO modification, and optionally the install directory |

---

### Modules/AD-PowerAdmin_Audits.psm1

**Changed:**
- `Search-MultipleInactiveComputers` — updated to accept an array of `@{SearchOUbase; DisabledOULocal}` hashtables (driven by `$global:InactiveComputersLocations`), iterating each OU pair. Previously handled a single OU.
- Menu registrations updated: now exposes two separate menu items for the inactive computer scan — one in report-only mode (`-ReportOnly $true`) and one in enforce mode (`-ReportOnly $false`).

---

### .gitignore

**Added:**
- `Modules/AD-PowerAdmin_Azure.psd1`
- `Modules/AD-PowerAdmin_Azure.psm1`

This indicates an Azure module is planned but not yet started or is too early to publish.

---

## Known Issues & Incomplete Work

### INCOMPLETE — Azure CLI Installer Module

**Commit message `e1d12a8` states:** *"Working on PS7 Install/Upgrade function, for Azure Cli."*

The `.gitignore` now includes `Modules/AD-PowerAdmin_Azure.*`, indicating an Azure module was planned. However:
- No `AD-PowerAdmin_Azure.psm1` or `.psd1` file exists yet.
- No Azure CLI installation function exists anywhere in the current codebase.

**Status:** Not started / placeholder only.

---

### TEST SCRIPT IN ROOT DIRECTORY — `test_pwsh_version.ps1`

`test_pwsh_version.ps1` is sitting untracked in the project root. Per the project's development procedures, test scripts must be moved to `temp/`. This file should be relocated to `temp/test_pwsh_version.ps1` and the `temp/` directory added to `.gitignore` if not already covered.

---

## Summary: Function Completion Status

### AD-PowerAdmin.ps1
| Function | Status |
|---|---|
| `Test-PowerShellVersion` | Complete |
| `Show-Logo` | Complete |
| `Initialize-Debug` | Complete |
| `Get-ADPAVersion` | Complete |
| `Show-Diagnostics` | Complete |
| `Stop-AllTranscripts` | Complete |
| `Initialize-AllModules` | Complete |
| `Initialize-ADPowerAdmin` | Complete |
| `Start-Automation` | Complete |
| `Enter-MainMenu` | Complete |

### AD-PowerAdmin_Installer
| Function | Status |
|---|---|
| `Install-ADPowerAdmin` | Complete |
| `Install-DSInternals` | Complete |
| `Install-PowerShell7` | Complete |
| `New-ADPowerAdminSmsaAccount` | Complete |
| `New-ADPowerAdminScheduledTask` | Complete |
| `New-ADPowerAdminHomeFolder` | Complete |
| `Enable-AuditLogging` | Complete |
| `Copy-AdPowerAdmin` | Complete |
| `Set-ADPowerAdminGPO` | Complete |
| `Test-PowerShell7-Installed` | Complete |
| `Test-ADPowerAdminInstall` | Complete |
| `Test-SystemAuditPolicy` | Complete |
| `Test-FolderAuditPolicy` | Complete |
| `Remove-AdPowerAdmin` | Complete |
| Azure CLI installer | **Not started** |

### AD-PowerAdmin_Audits
| Function | Status |
|---|---|
| `Get-ADAdminAudit` | Complete |
| `Get-ADUserAudit` | Complete |
| `Search-MultipleInactiveComputers` | Complete (updated) |
| `Search-MultipleInactiveUsers` | Complete |
| `Search-AD` | Complete |
| `Test-ADSecurityBestPractices` | Complete |
| `Start-DailyInactiveUserAudit` | Complete |
| `Start-DailyInactiveComputerAudit` | Complete |

### AD-PowerAdmin_PasswordsCtl
| Function | Status |
|---|---|
| `Update-KRBTGTPassword` | Complete |
| `Get-PasswordAuditAdminReport` | Complete |
| `Test-PwUserFollowup` | Complete |
| `Start-MonthlyPasswordAudit` | Complete |
| `New-RandomPassword` | Complete |

### AD-PowerAdmin_LogMgr
| Function | Status |
|---|---|
| `Show-ADUserLockouts` | Complete |
| `Get-CurrentLockedoutUsers` | Complete |
| `Show-AdUserFailedLoginEvents` | Complete |
| `Get-FailedLoginEvents` | Complete |

### AD-PowerAdmin_AdAccessRights
| Function | Status |
|---|---|
| `Get-AdAcl` | Complete |
| `Get-ExtendedAcl` | Complete |
| `Get-AdGuids` | Complete |
| `Search-DcSyncRisk` | Complete |
| `Search-HighRiskAdAce` | Complete |
| `Out-AclDetails` | Complete |
| `Out-AclDetailsLite` | Complete |

### AD-PowerAdmin_Utils
| Function | Status |
|---|---|
| `Get-DownloadFile` | Complete |
| `New-ScheduledTask` | Complete |
| `Send-Email` | Complete |
| `Send-EmailTest` | Complete |
| `Get-DateFromCalendar` | Complete |
| `Get-DatePickerGui` | Complete |
| `Export-AdPowerAdminData` | Complete |
| `Convert-TimeDurationString` | Complete |
| `Search-SingleAdObject` | Complete |
| `Enable-OldWindowsTLS12` | Complete |
| `Show-Menu` | Complete |

---

## Planned / In-Progress (Not Yet Implemented)

| Feature | Notes |
|---|---|
| Azure CLI installer module | `.gitignore` entry added for `AD-PowerAdmin_Azure.*`; commit `e1d12a8` references it; no code exists yet |
| PS7 upgrade function (as distinct from install) | Commit message referenced "PS7 Install/**Upgrade**"; current `Install-PowerShell7` only installs, does not upgrade an existing PS7 to a newer version |
