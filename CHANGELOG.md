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
