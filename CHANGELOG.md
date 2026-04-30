# AD-PowerAdmin — Changelog

## Unpushed Changes (since last `git push`)

**2 commits ahead of `origin/main` as of 2026-04-04.**
**Plus additional unstaged working-directory modifications across all modules.**

---

### Modules/AD-PowerAdmin_HIBP_PwndPwMgr.psd1 -- Promoted to Production

**Changed:**
- Module channel promoted from `Beta` to `Production`. The embedded pure PowerShell HIBP downloader has been exercised through real-world full and incremental downloads and is stable for production use.
- `ModuleVersion` bumped from `1.0` to `1.1` to align the manifest version field with the v1.1 architectural release documented in the existing release notes.

**Why it changed:** The v1.1 architecture replaced the previous .NET SDK + `haveibeenpwned-downloader.exe` toolchain with a fully self-contained pure PowerShell 5.1 implementation requiring no external installs or runtime dependencies. That implementation has been validated and there are no known issues. Promoting to Production makes it eligible for default installations and removes the Beta-channel caveat from operator tooling.

**Impact:** The HIBP database management submenu is now Production-channel. The overall channel reported by `Get-ADPAVersion` will increase if this was the only non-Production module in the load set.

---

### Modules/AD-PowerAdmin_Installer.psm1 and AD-PowerAdmin_Installer.psd1 -- Module Update Feature

**Added:**
- `Update-ADPowerAdminModules` -- Downloads the latest `.psm1` and `.psd1` files from the
  AD-PowerAdmin GitHub repository and replaces local copies. Before overwriting, each changed
  file is backed up to a timestamped folder under `$global:ReportsPath\ModuleBackups\`. Files
  already matching the remote copy are left untouched. Files with no remote counterpart
  (local-only modules) are skipped gracefully. Addresses the operational need to keep security
  audit modules current without manual file replacement.
- `Get-ADPowerAdminLatestReleaseTag` (private) -- Queries the GitHub Releases API
  (`api.github.com/repos/Brets0150/AD-PowerAdmin/releases/latest`) and returns the latest
  release tag string. Used by `Update-ADPowerAdminModules` when the Release channel is active.

**Changed:**
- `Initialize-Module` -- Added "Update Modules" item to the AD-PowerAdmin Management submenu,
  pointing to `Update-ADPowerAdminModules`.

### AD-PowerAdmin_settings.ps1 -- UpdateChannel Setting

**Added:**
- `$global:UpdateChannel` -- Controls the update source used by `Update-ADPowerAdminModules`.
  `'Release'` (default) fetches the latest officially tagged GitHub release; `'Development'`
  fetches the live main branch. This allows administrators running development builds to receive
  in-progress fixes without waiting for a release.

---

### Modules/AD-PowerAdmin_PasswordsCtl.psm1 -- HIBP directory mode missing from scheduled audit

**Fixed:**
- `Start-MonthlyPasswordAudit` -- Added the missing `-NtlmHashDataDir $global:NtlmHashDataDir` argument to its internal `Get-PasswordAudit` call. Without this, the scheduled daily/monthly audit silently skipped the entire HIBP range-file directory check: `Get-PasswordAudit` received an empty `$NtlmHashDataDir`, the guard at line 317 evaluated false, and `Test-NtlmHashesInDirectory` was never called. The audit produced results with no breached-password detection when directory mode was configured.

**Why it changed:** `Get-PasswordAuditAdminReport` and `Invoke-WeakPwdProcess` both pass `-NtlmHashDataDir` correctly; only the scheduled-job entry point `Start-MonthlyPasswordAudit` omitted the parameter. The bug meant that directory-mode HIBP checking worked correctly when run interactively from the menu but was completely bypassed during automated daily and monthly runs.

**Impact:** Scheduled password audits now correctly evaluate all AD account NT hashes against the HIBP range-file directory. No other logic changed.

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

### Modules/AD-PowerAdmin_Honeypot.psm1 -- GPO AD Object PDC Emulator Targeting Fix

**Fixed:**
- `Set-HoneypotGPOUserRights` -- `Get-ADObject` and `Set-ADObject` now explicitly target the PDC emulator (`$Domain.PDCEmulator`) when locating and updating the GPO's AD object. Previously, both calls queried the nearest available DC, which may not yet have received the GPO via replication. Because `New-GPO` (called via `Install-ADPAGPOBaseline`) always writes to the PDC emulator, the GPO was invisible on other DCs until replication completed, causing `Get-ADObject` to return nothing and the function to fail with "Could not locate GPO AD object".

**Changed:**
- `Set-HoneypotGPOUserRights` -- Added a status line showing which PDC emulator is being queried before the `Get-ADObject` call. On failure to locate the GPO AD object, the function now emits `[DIAG]` lines reporting: the DC queried, the LDAP filter used, the search base, and a list of every `groupPolicyContainer` object found on that DC -- or an explicit "(none found)" notice if replication is still in progress. Success messages now include the PDC emulator hostname to confirm the correct DC was targeted.

**Why it changed:**
`New-GPO` always writes to the PDC emulator, but `Get-ADObject` without an explicit `-Server` resolves to the nearest DC (site-local) which may not have received the new object yet. This race is reliable on multi-DC domains: the window between GPO creation and full replication is typically 15-60 seconds. Targeting the PDC emulator explicitly for both the read and write eliminates the race. The added diagnostic output allows an administrator to diagnose any future failure by showing exactly what the query found on the authoritative DC, distinguishing between a missing GPO, a naming mismatch, and a replication problem.

**Impact:**
- GPO AD object updates no longer fail due to DC replication lag in multi-DC environments.
- If the GPO still cannot be located on the PDC emulator, the diagnostic output lists all GPOs visible to that DC, enabling immediate root-cause identification without manual AD browsing.

---

### Modules/AD-PowerAdmin_SysvolAudit.psm1 -- External Path GPO Name and GUID Split

**Fixed:**
- `Search-GpoExternalScriptPaths` -- `$GpoMap` was declared as `@{}`, which uses a case-sensitive string comparer. On Windows, the path stored as a key (`$OutFile`) and the path returned by `Get-ChildItem` (`$XmlFile.FullName`) are identical in content but may differ in case depending on path resolution. This caused the lookup to silently return `$null`, triggering the fallback. The fallback set `SourceGPOName` to `$XmlFile.BaseName` (the raw filename, which includes both the GUID and sanitized display name as a single string) and `SourceGPOGuid` to an empty string. `Show-AuditReport` skips empty fields, so only "Source GPO" appeared in output showing the combined `{guid}_{name}` value rather than the two separate labeled lines the HeaderFields were designed to produce.
- `Search-GpoExternalScriptPaths` -- Even when the lookup fails, the fallback now correctly parses `SourceGPOName` and `SourceGPOGuid` as separate values from the filename (format: `{guid}_{safename}`), so both fields are populated and display on separate lines in all cases.

**Changed:**
- `$GpoMap` declaration changed from `@{}` to `[System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)` to prevent case-mismatch lookup failures.
- Fallback parsing now uses the regex `^([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})_(.+)$` to extract the GUID (group 1) and sanitized display name (group 2) separately from the filename, rather than using the full basename as a single string.

**Impact:** The terminal report now shows GPO Name and GPO GUID on separate labeled lines (`Source GPO` and `Source GPO GUID`) for every external path finding, both when the GpoMap lookup succeeds and when it falls back to filename parsing.

---

### Modules/AD-PowerAdmin_SysvolAudit.psm1 -- GpoCustom False-Positive Filter and Display Fix

**Fixed:**
- `Search-GpoDelegation` -- `CustomRights` field was absent from the `Show-AuditReport` call on the results path. The field was correctly added to the empty-results path in a prior change but was omitted from the matching call that renders actual findings. Result: the resolved raw AD rights were never displayed in the terminal report even when findings were present.
- `Search-GpoDelegation` -- `GpoCustom` findings were not filtered by the resolved rights level. A trustee holding only `ReadProperty`/`ReadControl`/`ListChildren` (the standard read-only delegation used for deny-apply targeting) resolved as `GpoCustom` and was flagged High. Read-only `GpoCustom` ACEs are not delegation risks; only write-level ACEs (`WriteProperty`, `CreateChild`, `DeleteChild`, `DeleteTree`, `GenericAll`, `GenericWrite`) represent exploitable permissions.

**Changed:**
- `Search-GpoDelegation` -- After `Get-GpoCustomRights` resolves the raw rights for a `GpoCustom` finding, the code now checks whether any write-level indicator appears in the resolved string. If resolution succeeded and no write-level right is present, the finding is skipped. If resolution failed (diagnostic message returned), the finding is retained because the risk level cannot be determined. If write-level rights are confirmed, the finding is retained as before.

**Why it changed:** Testing revealed that a security group holding "Read + Deny Apply Group Policy" on a GPO -- a standard exclusion pattern used to prevent a GPO from applying to specific users or computers -- produced a spurious High finding. The group's permission did not map to a standard GPMC level and was therefore classified `GpoCustom`, but its actual AD rights were entirely read-level. The filter eliminates this category of false positive without masking genuinely dangerous custom delegations.

**Impact:** Legitimate read-only `GpoCustom` ACEs (deny-apply targeting, WMI filter evaluation) no longer appear as delegation findings. Write-level `GpoCustom` ACEs continue to be flagged. When the `CustomRights` field could not be resolved, the finding is still reported so it can be investigated manually.

---

### Modules/AD-PowerAdmin_SysvolAudit.psm1 -- Email Alerts Removed

**Removed:**
- Email alert from `Start-SysvolAudit` -- the block that built an audit-summary email body and called `Send-Email` when Critical or High findings were present has been removed. The function now prints the console summary table and writes the consolidated report file; no external communication occurs.
- Email alert from `Start-SysvolGppCpasswordCheck` -- the block that called `Send-Email` when cpassword values were found has been removed. A `Write-Host` `[CRITICAL]` line is written to the console instead.

**Changed:**
- `Start-SysvolGppCpasswordCheck` -- now writes `"[CRITICAL] N GPP cpassword value(s) found in SYSVOL. Review the CSV report in the Reports directory."` when findings are present, rather than constructing and sending an email.
- Submenu label for `SysvolFullAudit` updated to remove "Emails Critical findings to the administrator."
- Unattended job label for `SysvolGppCpasswordCheck` updated to remove "Emails the administrator immediately if any are found."
- DESCRIPTION docstrings in both functions updated to remove email references.

---

### Modules/AD-PowerAdmin_SysvolAudit.psm1 -- GpoCustom Permission Expansion

**Changed:**
- `Search-GpoDelegation` -- When a trustee holds `GpoCustom` permission, the audit now reads the raw Active Directory security descriptor of the GPO object (`CN={GUID},CN=Policies,CN=System,<DomainDN>`) via `Get-Acl` and enumerates every Allow ACE for that trustee's SID. The resolved rights are surfaced in a new `CustomRights` header field (visible only on `GpoCustom` findings -- the field is skipped for all other permission types). The resolved rights are also incorporated into the `VulnerabilityDetail` narrative so the explanation states the exact rights granted rather than the generic "custom permission set" description. If the AD ACL cannot be read (permissions error, offline DC, domain DN unavailable), the field reports the specific failure reason rather than failing silently. `$DomainDn` is now declared before the try/catch block so it remains accessible for ACL lookups even when Tier-0 link enrichment partially fails.

**Added:**
- `Get-GpoCustomRights` (private helper) -- Given a GPO GUID, a trustee SID, and the domain DN, opens `AD:\CN={GUID},CN=Policies,CN=System,<DomainDN>` via `Get-Acl` and collects every Allow ACE for the specified trustee. For ACEs with a non-null `ObjectType`, it resolves the GUID against a table of known GPO extended rights (Apply Group Policy, Update Group Policy, and common property set GUIDs). Returns a semicolon-separated string of right descriptions; returns a diagnostic message if no matching ACEs are found or the ACL is unreadable. Trustee matching uses SID comparison as primary with identity-reference name substring as fallback for accounts whose SIDs cannot be translated.

**Why:** Test results showed `GpoCustom` in the Permission column with no explanation of what rights were actually granted. An administrator cannot determine from "GpoCustom" alone whether the delegation is intentional (e.g., read-only with Apply Group Policy) or dangerous (e.g., write-property on all attributes). The resolved rights make that determination possible directly from the report.

---

### Modules/AD-PowerAdmin_SysvolAudit.psm1 -- Post-Testing Refinements

**Changed:**
- `Search-SysvolSecrets` renamed to `Search-SysvolScriptRisks`. The previous name described only one dimension of the scan; the function detects both embedded credentials (passwords, tokens, API keys) and high-risk execution patterns (IEX, encoded commands, WebClient, RunAs, net use, sqlcmd). The function's SYNOPSIS, DESCRIPTION, report file name (`SysvolAudit-ScriptRisks`), and report title (`SYSVOL Credential & Risk Pattern Scan`) have been updated to match. The submenu entry title is now "Credential & Risk Pattern Scan" and the label describes both credential indicators and dangerous patterns. The `Start-SysvolAudit` summary line, email body, and consolidated report file all use "Credential & Risk Scan" as the label. `FunctionsToExport` in the `.psd1` updated accordingly.

- `Search-GpoDelegation` -- Each finding now includes three narrative explanation fields generated by the new private helper `Get-DelegationExplanation`: `VulnerabilityDetail` (which identity holds which specific permission on which GPO, whether the GPO covers Tier-0 scope, and why the delegation is anomalous), `Impact` (what an attacker who compromises the trustee identity can do -- script injection, registry policy modification, software deployment, persistence installation -- and whether the scope leads to full domain compromise or limited lateral movement), and `Remediation` (step-by-step GPMC instructions to locate the delegation, remove or reduce it, and verify the result with gpresult). The `Show-AuditReport` call updated to render these as wrapped detail paragraphs. The `GPOGuid` field is now shown in the terminal report header alongside `GPOName`.

- `Search-GpoExternalScriptPaths` -- Four refinements applied:
  1. **Drive-map filter**: Lines where `ScriptType = 'Unknown'` and the UNC appears in an XML `path=` attribute (the format used by drive-mapping GPO preferences) are now skipped. Mounting a shared folder is not a script execution risk and was generating noise.
  2. **GPO traceability on permission findings**: Every entry in the permissions report now carries `SourceGPOName`, `SourceGPOGuid`, and `GPOSetting` fields. These are resolved from a path-to-GPO map built after the XML scan phase. If multiple GPOs reference the same external path, all GPO names and GUIDs are listed semicolon-separated. `GPOSetting` reports the script type (e.g., "PowerShell Script Reference"). Unreachable-path entries receive the same traceability fields.
  3. **Grouped permissions display**: The terminal report now shows one card per external path (previously one card per ACE). Each card's `IdentitiesAndRights` field lists every matching ACE as "Identity: Rights [RiskLevel]" separated by pipe characters, so all exposure is visible at a glance. The `RiskLevel` of the card is the highest severity among all ACEs for that path. The CSV export retains individual ACE rows for forensic completeness.
  4. **GPOGuid in paths header**: The `GPOGuid` field is now shown in the "External GPO Script Paths" terminal report header alongside `GPOName`, so each path reference can be traced to a specific GPO without opening GPMC.

**Added:**
- `Get-DelegationExplanation` (private helper) -- Generates `VulnerabilityDetail`, `Impact`, and `Remediation` text for a GPO delegation finding based on: GPO name, trustee name, trustee type, permission type, Tier-0 link status, and GPO status. Called by `Search-GpoDelegation` for every finding.

**Why these changes:** Initial test results showed findings that stated a problem existed without explaining what the problem was, what its impact would be, or how to fix it. Administrators who lack deep Group Policy security knowledge need narrative context to act on findings. The drive-map filter reduced false-positive volume in the external paths report. The grouped permissions display eliminated duplicate path entries that made the report harder to read.

---

### Modules/AD-PowerAdmin_SysvolAudit.psm1 and AD-PowerAdmin_SysvolAudit.psd1 -- New Module

SYSVOL is replicated to every domain controller and is universally readable by all authenticated domain users. Scripts and Group Policy Preference XML files stored in SYSVOL and NETLOGON frequently contain plaintext credentials, misconfigured write permissions, excessive GPO delegation, or references to external shares with weak access controls. Each condition is a documented attack vector: credential theft, startup-script hijacking, GPP cpassword decryption (MS14-025), and lateral movement through writable external shares. The module implements all five audit categories as a self-contained AD-PowerAdmin module with interactive menus, CSV export, and scheduled job support.

**Added:**
- `Get-SysvolScriptInventory` -- Enumerates all script and configuration files (.ps1, .bat, .cmd, .vbs, .js, .wsf, .hta, .xml, .ini, .config, .txt) across SYSVOL and NETLOGON via recursive `Get-ChildItem`. Produces a timestamped CSV to `$global:ReportsPath` and a formatted terminal report. Provides an inventory baseline for identifying orphaned, unexpected, or recently modified scripts.
- `Search-SysvolSecrets` -- Multi-pattern scan of all SYSVOL/NETLOGON script files for embedded credentials and dangerous execution behavior. Critical-severity regex patterns cover password assignments, PSCredential construction, and `/user:` flags. High-severity literal patterns cover credential indicators (credential, creds, token, apikey, api_key, client_secret, net use, runas, sqlcmd) and dangerous execution patterns (IEX, Invoke-Expression, DownloadString, WebClient, Invoke-WebRequest, ExecutionPolicy Bypass, -EncodedCommand). All matches exported without filtering -- LineContent provides full context for human triage.
- `Search-SysvolGppCpassword` -- Targeted scan of the six known GPP XML file types (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml, Drives.xml, Printers.xml) in SYSVOL for cpassword values. Distinguishes Critical findings (non-empty encrypted value -- decryptable with the publicly known AES-256 key from MS14-025) from Info findings (empty cpassword attribute -- not currently exploitable but should be cleaned up). Effectively zero false-positive rate.
- `Search-SysvolPermissions` -- Audits SYSVOL file and folder ACLs for write, modify, or FullControl rights granted to broad or risky principals: Everyone, Authenticated Users, Domain Users, Domain Computers, BUILTIN\Users. Risk classification: Critical for script-extension files (.ps1, .bat, .cmd, .vbs, .js, .wsf, .hta) writable by the broadest principals; High for other script-file write access or any folder with write access; Medium for non-script files (.xml, .ini, .config, .txt).
- `Search-GpoDelegation` -- Enumerates all GPOs and identifies GpoEdit, GpoEditDeleteModifySecurity, or GpoCustom rights assigned to principals outside the expected Tier-0 set (Domain Admins, Enterprise Admins, SYSTEM, CREATOR OWNER, NT AUTHORITY\SYSTEM, Group Policy Creator Owners, Administrator). Enriches each finding with Tier-0 link status by calling `Get-GPInheritance` against the domain root and DC OU; GPOs linked to those targets are classified Critical, all others High. Requires the GroupPolicy module (RSAT-GPMC); prints a warning and returns without results if absent.
- `Search-GpoExternalScriptPaths` -- Exports all GPO definitions to a temporary XML directory under `$global:ReportsPath`, searches for UNC path references that resolve outside SYSVOL or NETLOGON, and classifies each as High (server does not match the domain FQDN) or Medium (domain share but outside SYSVOL/NETLOGON). For each distinct external UNC root, attempts `Get-Acl` and classifies ACEs for broad principals using the same risky-rights regex as the permission scan. ACE findings include four narrative explanation fields per finding (SecurityImpact, ExploitScenario, AccessRequired, LeastPrivDev). Unreachable paths are recorded as Info with a note for decommissioned-server investigation. Temp directory is always cleaned up in a finally block. Requires the GroupPolicy module.
- `Start-SysvolAudit` -- Full-audit wrapper that calls all six scan functions in sequence, passing a shared report file path so each function appends its output to a single consolidated `.txt` report. After all scans complete, prints a summary table with per-category Critical/High counts and totals. Sends an alert email to `$global:ADAdminEmail` if any Critical or High findings are present.
- `Start-SysvolGppCpasswordCheck` -- Lightweight daily scheduled entry point for the GPP cpassword scan. Respects the `$global:SysvolGppCpasswordAudit` toggle -- returns silently if `$false`. If findings are present, sends an immediate alert email; returns silently with no email if the scan is clean.
- `Initialize-Module` -- Registers the SysvolAuditMenu submenu (seven items: Script Inventory, Secret Scan, GPP cpassword Scan, Permission Scan, GPO Delegation Audit, External Script Paths, Full SYSVOL Audit), a single main-menu entry pointing to the submenu, and two unattended job entries: `SysvolGppCpasswordCheck` (Daily = $true, guarded by the toggle) and `SysvolFullAudit` (Daily = $false, on-demand only). Stale entries are removed before re-registration to allow safe module reloads.
- Private helpers `Get-SysvolRoots`, `Get-SysvolScriptFiles`, and `Get-AceExplanation` are not exported. `Get-SysvolRoots` resolves the SYSVOL and NETLOGON UNC roots from `$env:USERDNSDOMAIN`. `Get-SysvolScriptFiles` returns a typed list of file objects with the Location field set. `Get-AceExplanation` builds the four narrative explanation fields for external-path ACE findings based on object type, extension, identity, and rights.

**Why it was built:** SYSVOL is the most broadly readable share in an Active Directory environment -- every authenticated user has read access by design. Credentials stored in scripts or GPP XML, weak write permissions on SYSVOL content, excessive GPO delegation, and external script references are all documented attack vectors that appear routinely in penetration test findings and incident reports. Because any authenticated user can read SYSVOL, a single exposed credential or writable script path can be the entry point for privilege escalation to Domain Admin without requiring any special access.

**Impact:**
- Adds one main-menu entry (`SYSVOL Security Audit`) and a seven-item submenu.
- Adds two unattended job keys: `SysvolGppCpasswordCheck` (daily, toggle-controlled) and `SysvolFullAudit` (on-demand).
- Adds `$global:SysvolGppCpasswordAudit = $false` to `AD-PowerAdmin_settings.ps1`.
- Produces up to seven timestamped CSV reports per full-audit run: Inventory, Secrets, GppCpassword, Permissions, GpoDelegation, ExternalPaths, ExternalPathPermissions.
- The full audit additionally produces a single consolidated plain-text report (`SysvolAudit-FullReport_<timestamp>.txt`) containing all section outputs in sequence.
- Module channel: Beta.

---

### Modules/AD-PowerAdmin_Utils.psm1 -- Show-AuditReport

**Added:**
- `Show-AuditReport` -- Renders an array of PSCustomObject findings as a structured, color-coded terminal report and optionally writes the same content as plain text to a file. Accepts `HeaderFields` (compact key/value pairs), `DetailFields` (wrapped multi-line paragraphs), `RiskField` (used for severity grouping and color coding -- Critical = Red, High = Yellow, Medium = Cyan, Info = DarkGray), and `FieldLabels` (overrides for display names). When `RiskField` is empty, grouping is disabled and all items display in order without severity badges, suitable for inventory-style output. Output is built as a parallel list of text/color pairs so the terminal receives colored output and the file receives identical plain text from one pass through the data. Designed for use by any audit module that produces structured findings. Adds entries to the built-in label map covering all SysvolAudit field names (ExternalPath, ObjectPath, FilePath, FileSystemRights, AccessControlType, SecurityImpact, ExploitScenario, AccessRequired, LeastPrivDev, GPOName, GPOGuid, GPOStatus, MatchedPattern, LineContent, LineNumber, ReferencedShare, LinkedToTier0, TrusteeType, TrusteeSid, GppFileType, LastWriteTime, SizeBytes).

**Why it was built:** The SysvolAudit module produces findings across seven distinct report types with varying field sets, severity classifications, and long-form narrative explanation fields. Implementing a consistent terminal rendering function in the Utils module avoids duplicating formatting logic across modules and ensures that future audit modules can produce the same structured, color-coded output by calling a shared utility.

**Impact:** `Show-AuditReport` is exported and available to all modules that import Utils. No changes to existing callers.

**Changed (post-testing refinement):**
- `Show-AuditReport` built-in label map extended with seven new field names introduced by the SysvolAudit post-testing refinements: `VulnerabilityDetail` -> 'Vulnerability', `Impact` -> 'Impact', `Remediation` -> 'Remediation', `IdentitiesAndRights` -> 'Identities & Rights', `SourceGPOName` -> 'Source GPO', `SourceGPOGuid` -> 'Source GPO GUID', `GPOSetting` -> 'GPO Setting'. Additionally: `CustomRights` -> 'Custom Rights Detail' (for the GpoCustom permission expansion).

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
| `Show-AuditReport` | Complete |

### AD-PowerAdmin_SysvolAudit
| Function | Status |
|---|---|
| `Get-SysvolScriptInventory` | Complete |
| `Search-SysvolSecrets` | Complete |
| `Search-SysvolGppCpassword` | Complete |
| `Search-SysvolPermissions` | Complete |
| `Search-GpoDelegation` | Complete |
| `Search-GpoExternalScriptPaths` | Complete |
| `Start-SysvolAudit` | Complete |
| `Start-SysvolGppCpasswordCheck` | Complete |

---

## Planned / In-Progress (Not Yet Implemented)

| Feature | Notes |
|---|---|
| Azure CLI installer module | `.gitignore` entry added for `AD-PowerAdmin_Azure.*`; commit `e1d12a8` references it; no code exists yet |
| PS7 upgrade function (as distinct from install) | Commit message referenced "PS7 Install/**Upgrade**"; current `Install-PowerShell7` only installs, does not upgrade an existing PS7 to a newer version |
