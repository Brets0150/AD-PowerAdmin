# AD-PowerAdmin — Changelog

## Unpushed Changes (since last `git push`)

---

### [AD-PowerAdmin — Unattended Job Log Concurrency Fix]

**Fixed:**
- `Initialize-UnattendedLog` -- Replaced the static `AD-PowerAdmin_Unattended.log` transcript
  path with an optional `[string]$LogPath` parameter (default retains the static fallback for
  backward compatibility). Replaced the `Get-Transcript`-based idempotency guard with a
  script-scope variable `$script:UnattendedLogPath`; `Get-Transcript` does not exist in Windows
  PowerShell 5.1 and always throws, so the old guard was never True and every call restarted the
  transcript, splitting each run into two separate transcript sections.
- `Start-Automation` -- Computes a per-invocation unique log path
  (`Reports\UnattendedJobLogs\AD-PowerAdmin_Unattended_<JobName>_<JobVar1>_<timestamp>_<PID>.log`)
  and passes it to all three `Initialize-UnattendedLog` call sites. The `UnattendedJobLogs`
  subdirectory is created automatically if absent. Previously, all concurrent unattended processes
  wrote to the same static file; when multiple follow-up tasks fired simultaneously (e.g., all
  `PwUserFollowup` tasks scheduled at the same time), only the process that won the file-lock race
  produced a complete transcript -- the rest recorded only the "End" marker or nothing.

---

### [AD-PowerAdmin_PasswordsCtl — PwUserFollowup Job Fix]

**Fixed:**
- `Initialize-Module` (PwUserFollowup job) -- Removed `-JobVar1 $JobVar1` from the Command
  template. `Start-Automation` appends `-JobVar1 "value"` to the command string at dispatch
  time; having it in the template as well caused "Cannot bind parameter because parameter
  'JobVar1' is specified more than once", which prevented the follow-up password-change check
  from executing. Command template corrected to `'Test-PwUserFollowup'` so the dispatcher is
  the sole injection point.
- `Get-ADUserPasswordAge` -- Replaced `DayOfYear` subtraction with proper DateTime arithmetic
  (`((Get-Date) - $PasswordLastSet).TotalDays`). The old calculation produced a negative result
  whenever the password was last set on a calendar day later in the year than the current day
  (e.g., set on day 200 of a prior year, checked on day 139 of the current year gives -61).
  A negative age is never greater than the grace period, so `ChangePasswordAtLogon` was silently
  skipped for all such users. Also added a null guard: if `PasswordLastSet` is null or
  `DateTime::MinValue` (account created with "must change at next logon", or password never set),
  the function now returns `[int]::MaxValue` so the flag is always applied.
- `Test-UserUpdatedPassword` -- Added `Write-Host` diagnostic output showing the username being
  checked, the calculated password age vs. the grace period, and whether `ChangePasswordAtLogon`
  was set or the password was found to be current. Previously the function ran silently with no
  transcript visibility, making it impossible to diagnose failures from unattended job logs.
- `Update-KRBTGTPassword` -- Replaced the post-rotation success check from
  `PasswordLastSet.DayOfYear -eq (Get-Date).DayOfYear` to
  `PasswordLastSet -ge (Get-Date).Date`. The DayOfYear comparison fails at year rollover: if
  rotation runs at 11:59 PM on Dec 31 and any delay pushes the check past midnight, DayOfYear
  returns 1 while PasswordLastSet is still 365, causing the function to report failure and skip
  scheduling the mandatory second rotation. The new check compares against midnight of the
  current day and is immune to year boundaries.

---

### [Security Compliance — Offensive Tool Name Removal]

**Changed:**
- Source comments and wiki documentation -- replaced all references to specific offensive tool
  names (credential dumping tools, AD attack path enumeration tools, commercial C2 frameworks,
  open-source attack frameworks, network attack tools) with generic category-level descriptions.
  Affected files: `Modules/AD-PowerAdmin_GPOBestPracticesDeployer.psm1`,
  `AD-PowerAdmin.wiki/Modules/AD-AccessControlRights.md`,
  `AD-PowerAdmin.wiki/Modules/SYSVOL-Audit-Module.md`,
  `AD-PowerAdmin.wiki/Modules/Exchange-AD-Security-Audit.md`,
  `AD-PowerAdmin.wiki/Research/AD_Empty_Password_PasswordNotRequired_Audit_Remediation.md`,
  `AD-PowerAdmin.wiki/Research/exchange_ad_permission_escalation.md`,
  `AD-PowerAdmin.wiki/Vulnerabilities/SMB-Admin-Shares-Abuse.md`,
  `AD-PowerAdmin.wiki/Vulnerabilities/LM-Hash-Storage.md`.
  Specific tool names in comments and documentation triggered signature-based false-positive
  alerts in endpoint security products (Arctic Wolf, SentinelOne), causing the script to be
  blocked. All security meaning is preserved; no logic, functions, or settings were changed.

---

### [AD-PowerAdmin_Honeypot — Configuration Wizard and SPN Bug Fixes]

**Fixed:**
- `Remove-HoneypotAccount` -- `HoneypotSPN` was not cleared from `AD-PowerAdmin_settings.ps1`
  when the account was removed. `Set-HoneypotSettings` was called without `-SPN ''`, so the
  old SPN value persisted in the settings file after decommissioning. Fixed by passing `-SPN ''`
  explicitly in the removal step.
- `Set-HoneypotSettings` -- Added post-write verification: after writing the settings file the
  function re-reads it and checks that `HoneypotSPN` contains the expected value. A mismatch
  (silent regex-replacement failure) now prints a `[WARN]` with the expected vs. actual value so
  administrators can identify and manually correct the problem instead of running with stale config.

**Added:**
- `Edit-HoneypotSettings` -- Interactive post-install configuration wizard. Allows changing
  four settings without removing and reinstalling the account: `HoneypotAudit` (toggle
  monitoring on/off), `HoneypotMonitorIntervalMinutes` (change the check interval with
  automatic scheduled task recreation), `HoneypotSPN` (add, change, or remove the
  Kerberoasting bait SPN with the corresponding AD `ServicePrincipalNames` update), and
  `HoneypotMonitorMode` (switch between Centralized and Decentralized). Settings that require
  account recreation (username, OU, deny-logon group) are intentionally excluded with a
  note to remove and reinstall. Registered in the Honeytoken Management submenu as
  "Configure Settings."
- `Set-HoneypotSettings` -- Added optional `MonitorMode` parameter (`[string]`, default
  `$null` = leave unchanged) to support persisting `HoneypotMonitorMode` changes from the
  configuration wizard without a separate file write.

---

### [AD-PowerAdmin_GPOMgr — Generalized GPO Content Search]

**Added:**
- `Search-GPOContent` -- domain-wide GPO content scanner supporting three content types
  via a single unified interface: `Registry` (reads registry settings via
  Get-GPRegistryValue), `SecurityTemplate` (reads GptTmpl.inf INI settings from SYSVOL),
  and `AdvancedAuditPolicy` (reads audit.csv Advanced Audit Policy entries from SYSVOL).
  All result objects share a common envelope (GpoName, GpoId, ContentType) with
  type-specific data in a `Details` PSCustomObject. The `switch` on ContentType means new
  content types can be added without changing the calling interface. The existing
  `Search-GPOSetting` and `Search-GPOSecuritySetting` are unchanged and continue to serve
  existing callers; this function is the generalized form for new code.

### [AD-PowerAdmin_AuditPolicy — Competing GPO Detection in Compliance Scan]

**Changed:**
- `Show-ADPAuditFindings` -- added optional `$GpoConflicts` parameter (PSCustomObject[]
  from Search-GPOContent). When populated, displays competing GPO names and configured
  values beneath each non-compliant `Audit Subcategory` finding. If no GPO configures the
  subcategory, displays an advisory pointing to GPO link, security filter, or WMI filter
  as likely causes.
- `Start-ADPAuditPolicyCheck` -- after collecting findings, calls
  `Search-GPOContent -ContentType AdvancedAuditPolicy` when at least one non-compliant
  `Audit Subcategory` finding is present, then passes the results to Show-ADPAuditFindings.
  Fully-compliant systems skip the GPO scan entirely to avoid unnecessary overhead.

---

### [AD-PowerAdmin_HIBP_PwndPwMgr — Weak Password Download TLS Fix]

**Fixed:**
- `Get-WeakPasswordsList` -- replaced the call to `Enable-OldWindowsTLS12` (a function from
  `AD-PowerAdmin_Utils`) with the module-local `Initialize-HibpTls12`. The Utils function was
  never guaranteed to be loaded when `Get-WeakPasswordsList` runs, causing a "not recognized"
  error that silently aborted the download. The HIBP module already contains `Initialize-HibpTls12`
  for this exact purpose; using it eliminates the cross-module dependency and matches how the
  HIBP downloader itself enables TLS 1.2 in all other paths.

---

### [AD-PowerAdmin_GPOBestPracticesDeployer — NTLM Variant Redesign, Help Section, and Coverage-Check Ordering]

**Changed:**
- `DisableNTLMProtocols` (best-practice definition) -- redesigned from three variants to two.
  The previous options mixed "Disable" and "Restrict" terminology inconsistently and left a gap:
  no option blocked all NTLM at the machine level. The new variants follow a consistent language
  framework (outbound = "disable"; inbound = "deny") and cover two distinct hardening levels.
  Variant 1 (`CorpSec-Disable-NTLMv1-LM`) sets `LmCompatibilityLevel=5` to disable NTLMv1 and
  LM outbound on all machines and deny NTLMv1/LM inbound at DCs, while NTLMv2 remains allowed.
  Variant 2 (`CorpSec-Disable-All-NTLM`) adds `RestrictSendingNTLMTraffic=2`,
  `RestrictReceivingNTLMTraffic=2`, and `RestrictNTLMInDomain=7` to disable all NTLM outbound
  and deny all NTLM inbound on every machine and at DCs -- NTLMv2 is also blocked. Variant 2
  carries an AUDIT FIRST warning and should only be applied after reviewing logs with the
  Enable NTLM Audit Policy GPO.
- `DisableNTLMProtocols` (best-practice definition) -- added `SelectionGuide` field. This
  new field provides a concise decision guide explaining when to choose Option 1 vs Option 2,
  what prerequisites each requires, and what breakage risk each carries. The guide is displayed
  before the variant selection prompt so administrators have full context before choosing.
- `Invoke-GPOBestPracticeDeployment` -- redesigned the deployment workflow display order.
  The function now follows: help section (AppliesTo, Description, settings summary or
  SelectionGuide, Note) -> coverage scan -> variant selection (if applicable) -> application
  mode. For variant entries the coverage scan now collects all registry settings across all
  variants (deduplicated by Key and ValueName) and scans the entire set before the variant
  selection prompt appears, giving administrators a complete picture of what already exists
  in the domain before they choose an option. Previously the scan ran after variant selection,
  leaving no domain-state visibility at decision time.

---

### [AD-PowerAdmin_LogMgr — NTLM Auth Reporting]

**Changed:**
- `Show-NTLMAuthEvents` -- when no events are found, the console message now reports NTLMv1 and
  NTLMv2 status on separate lines (`[OK] NTLMv1 : No events detected` / `[OK] NTLMv2 : No events
  detected`) instead of a single generic "no NTLM authentication events found" line. This makes
  it explicit which NTLM versions were audited and found clear, which is important when validating
  that both protocol versions have been eliminated from the environment.
- `Start-DailyNTLMAuthReport` -- when no events are found, the email subject now reads
  `No NTLMv1 or NTLMv2 Detected` and the body lists NTLMv1 and NTLMv2 status on separate lines,
  matching the interactive display change above.
- `Start-DailyNTLMAuthReport` -- when events are found, the email subject now includes per-version
  status (e.g., `NTLMv1: 3 DETECTED | NTLMv2: 47`) so the security posture is visible from the
  inbox without opening the message.
- `Start-DailyNTLMAuthReport` -- the email body NTLMv1 and NTLMv2 count lines now append
  `[NOT DETECTED]` when a version's count is zero, providing an explicit clear status rather than
  a bare zero.

---

### [AD-PowerAdmin.ps1 — Diagnostics]

**Changed:**
- `Show-Diagnostics` -- added a "Registered Unattended Jobs" section at the end of the `d`
  (diagnostics) display. For each entry in `$global:UnattendedJobs` the section shows the job
  key, title, sourcing module, and whether it is flagged as a Daily job. Entries are sorted
  first by module name then by job key, making it straightforward to identify which module
  contributes each scheduled job and whether any expected jobs failed to register.

---

### [AD-PowerAdmin.ps1 — Module Loading]

**Changed:**
- `Initialize-AllModules` -- added per-module diagnostic output captured by the debug transcript.
  The function now logs the module path, how many `.psd1` files `Get-ChildItem` found, and an
  `[OK]` / `[FAIL]` / `[SKIP]` result for each manifest import. If `Get-ChildItem` returns zero
  files (the symptom when the sMSA lacks read access to the Modules folder), a `[FAIL]` message
  is written and the function returns immediately instead of silently proceeding with no modules.
  Previously, `Import-Module` was called with `-Verbose` (noisy) and the loop was wrapped in a
  single `try/catch` that couldn't distinguish which module failed; changed to per-module
  `try/catch` with `-ErrorAction Stop`. Removed `-Verbose` flag.

---

### [AD-PowerAdmin.ps1 — Unattended Run Logging]

**Changed:**
- `Start-Automation` -- added diagnostic output to the unattended log so every run now records:
  (1) a registration summary listing every job name, module, and whether it is flagged `[Daily]`;
  (2) a count of Daily jobs selected for the current run with a `[WARN]` if none are registered;
  (3) a timestamped start line before each job showing its name, module, and resolved command;
  (4) a timestamped end line after each job showing whether it completed normally or with an error;
  (5) full exception message and stack trace if a job throws an unhandled error (previously
  swallowed silently by `Invoke-Expression`). For single named jobs, a `[WARN]` is now printed
  if no job with that name exists in the registered list, along with the list of known job names.
  These changes allow log-only diagnosis of why daily jobs are or are not executing without
  requiring interactive access to the server.

---

### [AD-PowerAdmin.ps1 — Transcript Management]

**Fixed:**
- `Stop-AllTranscripts` -- the function used `Stop-Transcript -ErrorAction Stop` inside a
  `while($true)` loop to detect when all transcripts were drained. `Stop` converts the
  non-terminating "not currently transcribing" error into a terminating error, which PowerShell's
  Script Block Logging records as a Warning event before the `catch` block suppresses it. Every
  scheduled task invocation generated this spurious warning because the session starts with no
  active transcript. Changed to `-ErrorAction SilentlyContinue` with `$?` as the loop-exit
  condition. `SilentlyContinue` suppresses the error before logging occurs; `$?` is `$false`
  when `Stop-Transcript` fails, providing the same reliable exit signal without the event log
  noise.

- `Initialize-UnattendedLog` -- relied on `Get-Transcript` to detect a running transcript before
  stopping it. `Get-Transcript` was added in PowerShell 7 and does not exist in PS 5.1
  (the version used by the scheduled task). On PS 5.1 the call always threw, leaving
  `$currentTranscript` as `$null`, so the `if ($currentTranscript) { Stop-AllTranscripts }`
  guard never fired. When `Start-Transcript -Force` was then called for the unattended log, the
  debug log (started by `Initialize-ADPowerAdmin`) was already active, and PS 5.1 does not allow
  `-Force` to override an already-active transcript. The unattended log silently failed to start,
  and all scheduled-run output was routed to the debug log instead. Fixed by removing the
  conditional guard and always calling `Stop-AllTranscripts` before starting the unattended log.
  The fixed `Stop-AllTranscripts` (above) is a silent no-op when nothing is running, making the
  unconditional call safe.

- `Start-Automation` -- `Initialize-Debug` was called immediately after `Initialize-UnattendedLog`
  at both the start and end of the function. `Initialize-Debug` is correct as a fallback when
  `$global:UnattendedLog` is disabled, but when the unattended log is active, calling it
  caused transcript competition: because `Get-Transcript` is absent in PS 5.1, `Initialize-Debug`
  always believed no transcript was running and attempted `Start-Transcript -Force` for the debug
  log, which either silently failed or stopped the just-started unattended log. All three
  `Initialize-Debug` calls inside `Start-Automation` are now wrapped with
  `if (-not $global:UnattendedLog)` so the debug log is only used as a fallback when the
  dedicated unattended log is disabled.

---

### [AD-PowerAdmin_Installer Module]

**Changed:**
- `New-ADPowerAdminScheduledTask` -- the daily scheduled task was created with action arguments
  `"$ScriptPath -Unattended -JobName 'Daily'"`, missing the `-File`, `-NonInteractive`, and
  `-NoProfile` flags. This matched neither PowerShell best practice nor the pattern already
  used by the Honeypot task. Updated to
  `"-NonInteractive -NoProfile -File \"$ScriptPath\" -Unattended -JobName 'Daily'"`.
  `-File` ensures correct parameter binding and a clean exit code. `-NonInteractive` prevents
  the task from hanging on `Read-Host` prompts if any are inadvertently reached. `-NoProfile`
  eliminates profile-loading side effects that could alter the module path or variable state.
  Note: Existing installed tasks must be recreated (via "Install AD-PowerAdmin" or
  "Diagnose Scheduled Task") for this change to take effect.

**Added:**
- `Invoke-ScheduledTaskDiagnostic` -- new function accessible from the AD-PowerAdmin Management
  submenu. Triggers the `AD-PowerAdmin_Daily` scheduled task, waits for it to complete (180 s
  timeout), then collects evidence from four sources: (1) Task Scheduler Operational event log,
  (2) Microsoft-Windows-PowerShell/Operational log, (3) classic Windows PowerShell log
  (errors/warnings only), and (4) the transcript log files (`AD-PowerAdmin_Debug.log` and
  `AD-PowerAdmin_Unattended.log`). Displays a colour-coded console report and offers to export
  the full findings to `Reports\AD-PowerAdmin_TaskDiag_<timestamp>.txt`. Addresses the
  operational need to diagnose why the daily scheduled task fails silently -- no logs, no emails,
  no errors visible -- without manually hunting through multiple event log sources.

**Added:**
- `Set-ReportsFolderAcl` -- private helper that stamps two explicit sMSA ACEs on every Step 6
  run: (1) `ReadAndExecute` with `ContainerInherit + ObjectInherit` on `$global:InstallDirectory`,
  propagating to `Modules/` and all subdirectories so the sMSA's scheduled-task process can read
  and load modules; (2) `Modify` with `ObjectInherit` on `$global:ReportsPath` so the sMSA can
  write transcript logs and CSV exports. Both ACEs are necessary because the sMSA's Domain Admins
  group membership is not reliably evaluated for filesystem ACLs in a scheduled-task token context;
  explicit ACEs remove that dependency. Previously only granted Modify on the Reports folder, which
  allowed the unattended log to be created but left modules unreadable, resulting in zero registered
  jobs on every scheduled run.

**Changed:**
- `Install-ADPowerAdmin` -- `New-ADPowerAdminHomeFolder` (install directory ACL setup) was
  previously bundled inside the `if ($CopyRequired)` conditional, so ACLs were never checked or
  repaired when the install directory matched the running directory. Moved to a dedicated Step 1
  that always runs. `Set-ReportsFolderAcl` promoted from a post-install note to numbered Step 6.
  Step labels updated from `/5` to `/6`. Permission setup (install directory and Reports folder)
  now runs unconditionally on every installer invocation.
- `Test-ADPowerAdminInstall` -- added three new checks: (8) sMSA has an explicit `ReadData` ACE
  on the install directory (absence causes zero modules to load in unattended mode); (9) Reports
  folder exists at `$global:ReportsPath`; (10) sMSA has an explicit `WriteData` ACE on the Reports
  folder. These checks surface the permission gaps that caused modules to not load and the
  unattended log to be missing on every scheduled run.

**Changed:**
- `Show-InstallHelp` -- updated to match the current six-step installer structure and to add a
  complete troubleshooting section based on root causes discovered during scheduled task
  diagnostics. Changes: (1) Updated topic list from three parts to four; (2) "Confirm
  Installation Directory" redesignated from Step 1 to an "Initial Confirmation" section, keeping
  it as a pre-step before the six numbered steps; (3) Remaining steps renumbered: old Steps 2-6
  are now Steps 1-5; (4) Added new Step 6 description for `Set-ReportsFolderAcl`, explaining the
  two explicit sMSA ACEs (ReadAndExecute on install directory; Modify on Reports folder), why
  explicit ACEs are required in a scheduled-task token context, and what silently fails without
  each ACE; (5) `Install DSInternals` promoted from Step 7 (numbered) to a post-install section
  header to match the installer's actual structure; (6) Post-installation checks section expanded
  from six to ten checks, adding: sMSA has explicit ReadData on install directory, Reports folder
  exists, sMSA has explicit WriteData on Reports folder; (7) Added Part 4 -- Troubleshooting with
  four sections: "Symptom: Unattended Log Not Created" (sMSA write permission, Modify ACE fix),
  "Symptom: Task Runs but No Jobs Execute" (sMSA read permission, ReadAndExecute ACE fix),
  "Symptom: Stop-Transcript Warnings in the Event Log" (PS 5.1 transcript conflict, cosmetic when
  alone), "Diagnostic Tool: Diagnose Scheduled Task" (what it triggers, what it collects, how to
  read the output), and "Reading Module Load Status in the Unattended Log" (explaining [OK]/[SKIP]/
  [FAIL] codes and the '.psd1 files found : 0' signal that indicates missing read permissions).

**Fixed:**
- `Invoke-ScheduledTaskDiagnostic` -- four problems caused the function to flood the console
  with errors and scroll endlessly through event log output: (1) `Get-WinEvent` queries had no
  `EndTime` bound, so any event written after the task finished (from unrelated processes) was
  included; (2) no `-MaxEvents` cap meant the PowerShell Operational log (which Script Block
  Logging fills with hundreds of entries per AD-PowerAdmin run) could load thousands of records;
  (3) the PS/Operational filter used `Where-Object { $_.Message -like "*AD-PowerAdmin*" }` which
  matches every logged script block from the entire AD-PowerAdmin session -- not just errors --
  defeating its purpose as a selector; (4) all matched events were written to the console with no
  limit. Fixed by adding `EndTime = $DiagEnd.AddSeconds(30)` and `-MaxEvents 200` to every
  `Get-WinEvent` call; changing the PS/Operational section to filter by `Level = @(1, 2, 3)`
  (errors and warnings only) instead of message text; and capping console display to 15 events
  per section with a "(N more -- see export file)" summary for overflow. The export file still
  receives the full untruncated event list. Added progress dots to the wait loop so the operator
  can see the tool is actively waiting for the task to finish.

---

### [AD-PowerAdmin_Utils Module]

**Changed:**
- `New-ScheduledTask` renamed to `New-ADPAScheduledTask` to eliminate a name collision with
  the PowerShell built-in `ScheduledTasks\New-ScheduledTask` cmdlet. The collision caused
  callers to bind to the built-in instead of the custom wrapper, producing "A parameter cannot
  be found that matches parameter name 'ActionString'" at runtime. All callers across
  `AD-PowerAdmin_Installer`, `AD-PowerAdmin_PasswordsCtl`, and `AD-PowerAdmin_Honeypot`
  updated accordingly. `FunctionsToExport` in the manifest updated to match.
- `New-ADPAScheduledTask` extended with a new optional `-RepeatIntervalMinutes [int]` parameter
  and a new `"Interval"` value in the `-Recurring` ValidateSet. When `Recurring = 'Interval'`,
  the trigger fires once at the specified time and then repeats every `-RepeatIntervalMinutes`
  minutes indefinitely. This replaces the equivalent logic that was previously duplicated inside
  `New-HoneypotScheduledTask`.
- `New-ADPAScheduledTask` principal selection now includes sMSA-with-current-user fallback.
  If the configured sMSA account is not found in AD, the task is registered under the current
  interactive user with a `[WARN]` message, rather than silently producing a malformed principal.

**Fixed:**
- `New-ScheduledTask` -- `Get-ADDomain` was called without `-ErrorAction Stop` inside the
  `try` block, so a non-terminating error left `$DomainNameShort` as `$null`, producing a
  UserID of `\AccountName$` (no domain prefix). Task Scheduler silently accepted the malformed
  principal and stored just `AccountName$`, causing the scheduled task to fail at runtime
  because the sMSA could not be resolved without the domain qualifier. Additionally, the code
  used `.Name` (the first DNS label, e.g. "contoso" from "contoso.com") instead of
  `.NetBIOSName` (e.g. "CONTOSO"), which is the format required by Task Scheduler for
  `DOMAIN\AccountName$` sMSA principals. Fixed by replacing the pipeline with
  `(Get-ADDomain -ErrorAction Stop).NetBIOSName`, which retrieves the correct NetBIOS name
  and causes any failure to propagate cleanly to the `catch` block.

---

### [AD-PowerAdmin_PasswordsCtl Module]

**Fixed:**
- `Get-PasswordAudit` -- after DSInternals `Get-ADReplAccount` replicates all AD accounts,
  the large account data set was held in memory until PowerShell's garbage collector ran
  automatically. If the caller followed up with an SMTP email (as `Get-PasswordAuditAdminReport
  -EmailReport` does), the TLS handshake could fail under memory pressure with "Server does not
  support secure connections." Fixed by explicitly nulling `$AllAdAccountData` and calling
  `[System.GC]::Collect()` and `[System.GC]::WaitForPendingFinalizers()` before returning,
  ensuring memory is freed before the SMTP connection is attempted.

---

### [AD-PowerAdmin_Honeypot Module]

**Changed:**
- `New-HoneypotScheduledTask` -- rewritten to call `New-ADPAScheduledTask` (the Utils wrapper)
  instead of directly invoking the low-level built-in task cmdlets. The function retains its
  Honeypot-specific logic (removing any pre-existing task, computing the first-run datetime from
  the configured interval). Principal selection, trigger construction, action construction,
  settings, and registration are now handled by the shared wrapper, keeping all scheduled task
  creation consistent across modules.

---

### [AD-PowerAdmin_Installer Module]

**Added:**
- `Get-ADPowerAdminRemoteModuleList` (private) -- queries the GitHub Contents API
  (`https://api.github.com/repos/Brets0150/AD-PowerAdmin/contents/Modules?ref=<GitRef>`)
  and returns the list of .psm1/.psd1 file names present in the remote Modules directory.
  Returns $null on failure. Private helper for `Update-ADPowerAdminModules`.

**Fixed:**
- `Update-ADPowerAdminModules` -- the function previously iterated only over locally
  present files, so any new module added to the GitHub repository after the user's last
  install was never discovered or downloaded. Fixed by calling `Get-ADPowerAdminRemoteModuleList`
  to obtain the full remote file list, comparing it against local files, and downloading any
  GitHub-only files directly to the Modules directory with a [NEW] status line. If the
  GitHub Contents API is unavailable, the function falls back to local-only update behavior
  with a warning. The restart-required notice now triggers for new modules as well as updated ones.

---

### [Modules/standalone_scripts/New-ReleasePackage.ps1]

**Added:**
- `New-ReleasePackage.ps1` -- standalone script that calculates the current AD-PowerAdmin
  version using the same algorithm as `Get-ADPAVersion` (summing module `.psd1` versions,
  applying the Alpha/Beta/Production channel hierarchy) and packages a release zip named
  `ADPowerAdmin_V<version>.zip` into a `Releases\` folder at the project root. The zip
  contains `AD-PowerAdmin.ps1`, `AD-PowerAdmin_settings.ps1`, `README.md`, and all direct
  files in `Modules\` (no subdirectories). A `MANIFEST.txt` of SHA256 hashes for every
  included file is generated and added to the zip, enabling post-download integrity
  verification via `sha256sum -c` on Linux/macOS. The script prompts before overwriting an
  existing zip of the same version. Purpose: replace the manual release packaging process
  with a deterministic, repeatable script that produces a consistent artifact for GitHub
  distribution.

---

### [AD-PowerAdmin.ps1 -- Main Script]

**Changed:**
- `Show-Diagnostics` -- expanded the debug diagnostics screen (main menu option `D`) to include a
  full readout of every global configuration variable loaded from `AD-PowerAdmin_settings.ps1`.
  Settings are grouped into labeled sections (Core, Daily Audit Flags, KRBTGT, Inactive Accounts,
  Password Quality, Email/SMTP, Honeytoken, Exchange, SMB) and formatted with aligned columns
  matching the style used in the installer's settings confirmation wizard. Sensitive values such
  as `SMTPPassword` are shown as `(configured)` rather than the raw value. Array settings
  (`InactiveComputersLocations`, `InactiveUsersLocations`, `ExchangeGroupsToAudit`,
  `ApprovedSmbAdminHosts`) are expanded entry by entry. Aids rapid on-screen verification of
  loaded settings without opening the settings file.

---

### [AD-PowerAdmin_Utils Module]

**Fixed:**
- `Set-SettingsFileValue` -- the `bool` VarType regex never matched any settings file line.
  The pattern contained a spurious `\` before the second `` `$ `` (`` \`\$ `` instead of `` \`$ ``).
  In a PowerShell double-quoted string, `` \`$ `` produces `\$` in the pattern string — the
  correct regex escape for a literal dollar sign. The extra `\` produced either `\\$` (two
  backslashes + end-of-string anchor) or a literal-backtick match depending on PS 5.1 string
  processing, neither of which matched the `$true`/`$false` in the settings file. Result: every
  call to `Set-SettingsFileValue -VarType 'bool'` was silently a no-op. Only settings where the
  new value happened to equal the old value (user pressed Enter keeping the default) were
  unaffected in practice; any intentional change from `$true` to `$false` or vice versa was lost.
- `New-ScheduledTask` -- removed erroneous `-Password ""` from `Register-ScheduledTask`.
  PowerShell validates that the Password parameter cannot be an empty string, causing immediate
  failure. For sMSA/gMSA accounts the parameter must be omitted entirely; the OS retrieves the
  account password from Active Directory automatically when it recognizes the trailing `$` in
  the account name.
- `New-ScheduledTask` -- replaced `Write-Output $_` with `Write-Host` and `break` with `throw`
  in the catch block. `Write-Output $_` sent error details to the success stream where they were
  discarded; `break` outside a loop has undefined propagation and swallowed the exception before
  the caller's catch could see it. The fix surfaces the actual error message and re-throws so
  callers can handle it.

---

### [AD-PowerAdmin_Installer Module]

**Added:**
- `Show-InstallHelp` -- prints a section-by-section guide to every action performed by
  `Install-ADPowerAdmin`. Covers all seven installation steps in order: install directory
  confirmation, directory creation and ACL/audit hardening, production file deployment, sMSA
  account creation and local installation, Default Domain Controllers Policy GPO modification
  (SeServiceLogonRight), scheduled task registration, and DSInternals module installation.
  Each section identifies what is created vs. modified, explains why the step exists, and
  includes post-install verification details. Available as "Installation Guide" in the
  AD-PowerAdmin Management submenu.
- `Confirm-InstallDirectory` (private) -- prompts the administrator to confirm or change the
  install directory before `Install-ADPowerAdmin` makes any system changes. Displays the current
  `InstallDirectory` setting, asks for confirmation, and if a new path is entered validates that
  it is an absolute path, writes it back to `AD-PowerAdmin_settings.ps1` via
  `Set-SettingsFileValue`, and updates `$global:InstallDirectory` in memory. Returns `$false`
  and aborts the install if the user cancels. Prevents silent installs to a misconfigured or
  unintended directory.
- `Update-ADPowerAdminMainScript` -- downloads and applies the latest AD-PowerAdmin.ps1 from
  GitHub. Supports Release and Development update channels. Displays current vs. available
  version before prompting for confirmation. Creates a timestamped, read-only backup under
  `Reports\MainScriptBackups\` before replacing the local file. Closes the gap where the main
  script was the only component without an automated update path.
- `Set-BackupFileProtection` (private) -- marks a backup file read-only after creation.
  Called by all backup-creation sites to prevent accidental modification or re-execution of
  an archived file.
- `Write-FileUtf8Crlf` (private) -- centralizes every settings and script file write in the
  installer. Clears the read-only attribute on the target file if set, normalizes all line
  endings to CRLF, then writes UTF-8 without BOM. Replaces direct
  `[System.IO.File]::WriteAllText()` calls at all four write sites. Required because
  `WriteAllText` fails with "Access denied" when the target carries the read-only attribute
  applied by `Set-BackupFileProtection`, and because files downloaded from GitHub use LF
  endings which Windows Notepad renders as a single continuous line.

**Added:**
- `Get-SettingsFileValues` (private) -- extracts every typed `$global:*` variable value from a
  settings file content string. Returns a list of `{Name, Value, VarType}` objects compatible
  with `Set-SettingsFileValue`. Handles bool, int, single-quoted string, double-quoted string,
  and multi-line array declarations. Bare `$global:` reference values are skipped so the new
  file's formula is preserved for those variables.

**Changed:**
- `Update-ADPowerAdminSettingsFile` -- completely redesigned. Previous behavior appended missing
  variables from the new file to the old file, resulting in a hybrid document. New behavior
  downloads the latest settings file, extracts all configured values from the old file, and
  transplants those values into the new file's structure. The result is a clean adoption of the
  new file layout with all user settings preserved. Variables removed from the new version are
  dropped; new variables keep their defaults. The migration plan (counts of migrated, new-default,
  and removed variables) is displayed before the user confirms.

**Removed:**
- `Get-SettingsMigrationContent` -- no longer needed. The new migration approach operates on
  extracted values (via `Get-SettingsFileValues`) applied to the new file's content directly,
  rather than building an append block from the remote file's text.

**Fixed:**
- `Get-SettingsMigrationContent` -- added `[AllowEmptyString()]` to the `$Lines` parameter.
  PowerShell 5.1 mandatory validation for `[string[]]` rejects the array if any element is an
  empty string, which is always the case when a text file ending with a newline is split on
  `\r?\n` (the last element is `""`). The function's internal logic already handled empty lines
  correctly; the fix prevents the parameter binding from blocking execution before the function
  body runs.

**Changed:**
- `Update-ADPowerAdminModules` -- backup files are now stored with a `.txt` extension appended
  (e.g. `AD-PowerAdmin_Installer.psm1.txt`) and marked read-only via `Set-BackupFileProtection`.
  Prevents execution or re-import of a backed-up file that may contain a known-vulnerable version.
- `Update-ADPowerAdminSettingsFile` -- backup now stored as `AD-PowerAdmin_settings.ps1.txt`
  (read-only) instead of `.bak`. Consistent with the new backup security model.
- `Start-SettingsWizard` -- backup now stored as `AD-PowerAdmin_settings.ps1.txt` (read-only)
  instead of `.bak`. Consistent with the new backup security model.
- `New-ADPowerAdminScheduledTask` -- the catch block now prints the underlying exception message
  alongside the generic failure notice. Previously only "The AD-PowerAdmin schedule task failed
  to be created." was shown, hiding the root cause.
- `New-ADPowerAdminSmsaAccount` -- the "account already exists" branch now calls
  `Test-ADServiceAccount` to check whether the sMSA is installed on the local computer. If not
  installed (re-install or new server where the account pre-exists in AD), it calls
  `Add-ADComputerServiceAccount` and `Install-ADServiceAccount` before continuing. Previously
  the branch returned immediately without installing, so `Register-ScheduledTask` could not
  verify the account credentials and failed.
- `New-ADPowerAdminHomeFolder` -- ACL on the install directory did not propagate to files or
  subdirectories. The previous code used the 3-parameter `FileSystemAccessRule` constructor
  which defaults `InheritanceFlags` to `None`, making the Domain Admins FullControl ACE apply
  only to the directory container itself. Files copied into the directory by `Copy-AdPowerAdmin`
  received no inherited ACE and were accessible only to their original creator. Any administrator
  who opened the tool in a new session received "Access denied" when writing the settings file.
  Fixed by using the 5-parameter constructor with `ContainerInherit | ObjectInherit` so the ACE
  propagates to all child files and subdirectories. Added BUILTIN\Administrators and
  NT AUTHORITY\SYSTEM as explicit FullControl entries with the same inheritance so local
  administrators and Windows system processes have the access they require.
- `Start-SettingsWizard` -- the file-write call had no error handling. When the target settings
  file carried the read-only attribute (set by the backup step), the `[System.IO.File]::WriteAllText()`
  .NET call threw a non-terminating exception that was invisible to the caller, so execution
  continued past the failure and printed "Settings written to:" success messages despite nothing
  being written. Replaced with `Write-FileUtf8Crlf` inside a `try/catch` that prints an error
  and returns on failure, preventing false success feedback.
- `Confirm-InstallDirectory`, `Update-ADPowerAdminMainScript`, `Update-ADPowerAdminSettingsFile`
  -- all file-write calls now route through `Write-FileUtf8Crlf`. Files written with direct
  `[System.IO.File]::WriteAllText()` calls used whatever line endings were in the source string
  (LF from GitHub downloads), which Windows Notepad rendered as a single unbroken line. The new
  helper normalizes to CRLF before writing.
- `Copy-AdPowerAdmin` -- redesigned from a destructive `Move-Item` of the entire source directory
  to a selective `Copy-Item` of exactly four production items: `AD-PowerAdmin.ps1`, 
  `AD-PowerAdmin_settings.ps1`, `Modules\`, and `README.md`. Development artefacts (.git,
  Reports, temp, test scripts, hash lists, etc.) are intentionally excluded. After copying,
  the function verifies that the three critical items (main script, settings file, Modules
  directory) are present in the install directory and reports per-item `[OK]`, `[SKIP]`, or
  `[FAIL]` status. Eliminates the risk of deploying development-only content into a scheduled-
  task installation directory.

---

### [AD-PowerAdmin_settings.ps1]

**Changed:**
- Settings file reorganized for clarity. All daily-task enable/disable booleans
  (`SysvolGppCpasswordAudit`, `ExchangeADSecurityAudit`, `SmbAdminShareAudit`,
  `AuditPolicyDailyCheck`) are now consolidated into the existing "Daily Task Enable / Disable"
  block alongside the original eight flags, giving administrators a single location to toggle
  scheduled jobs. The standalone SYSVOL and Audit Policy sections, which contained only their
  respective boolean, were removed. SMB admin share settings (`ApprovedSmbAdminHosts`,
  `SmbLapsExpiredDays`) are now fully contiguous; the Audit Policy section no longer interrupts
  them. `HoneypotAudit` was intentionally left in the Honeytoken section because the honeytoken
  monitor runs on its own dedicated scheduled task, not the daily job. No variable names, default
  values, or runtime behavior changed.

---

### AD-PowerAdmin_GPOBestPracticesDeployer (v1.4) -- Promoted to Production

**Changed:**
- `Channel` promoted from `Beta` to `Production`. Module has completed Beta validation and
  passed pre-production review (reusability audit, ADPA naming review, verb-group ordering
  compliance).
- Function order refactored for verb-group compliance. `Resolve-ConfigurableSettings` moved
  from before `Show-BPCoverageReport` to after all `Select-*` functions, placing it correctly
  within the retrieval group (Show -> Select -> Resolve). All `Invoke-*` functions are now
  together in the modification group (private helpers before public dispatcher). Section
  comments updated to reflect verb-group organization (`Retrieval Functions`,
  `Modification Functions`); the `Private Helpers` / `Public Exported Functions` split
  removed -- public vs private distinction is tracked in the manifest `FunctionsToExport`.
  No logic changes.

---

### AD-PowerAdmin_GPOBestPracticesDeployer (v1.3) + AD-PowerAdmin_LogMgr (v1.2) -- NTLM Audit and Remediation

**Added to GPOBestPracticesDeployer (v1.3):**
- `EnableNTLMAuditPolicy` best practice entry -- enables NTLM authentication auditing on domain
  controllers by configuring `AuditNTLMInDomain` (Netlogon\Parameters) and
  `AuditReceivingNTLMTraffic` (Lsa\MSV1_0). Populates the Microsoft-Windows-NTLM/Operational
  log with per-authentication records needed to identify legacy NTLM consumers before enforcing
  blocks. `AuditNTLMInDomain` is configurable (default 7 = Enable all).
  Addresses: credential capture and relay risk from undetected NTLM usage.
- `DisableNTLMProtocols` best practice entry -- consolidated NTLM disable policy with three
  variants selected at deployment time: (1) Disable LM and NTLMv1 only (LmCompatibilityLevel=5,
  clients send NTLMv2 only, DCs refuse LM and NTLM); (2) Restrict all domain NTLM authentication
  (RestrictNTLMInDomain, configurable level 1-7); (3) Both controls combined.
  Addresses: NTLMv1 offline cracking, pass-the-hash, and domain NTLM relay attack paths.
- `Variants` field support for `$script:GPOBestPractices` entries -- when a best practice defines
  a `Variants` array, `Invoke-GPOBestPracticeDeployment` presents a numbered choice list, then
  merges the selected variant's `RegistrySettings`, `DefaultGpoName`, and `GpoDescription` into
  the deployment path before running coverage checks and the DDP/New GPO flow. All existing
  entries without `Variants` are unchanged.
- `Select-BestPracticeVariant` private helper -- presents the variant list and returns the
  selected hashtable or null on cancel. Used exclusively by the Variants code path in
  `Invoke-GPOBestPracticeDeployment`.

**Added to LogMgr (v1.2):**
- `Show-NTLMAuthEvents` -- interactive search of NTLM v1 and v2 authentication events across all
  domain controllers. Queries the Microsoft-Windows-NTLM/Operational log, parses event XML into
  structured records (DomainController, TimeCreated, EventId, UserName, DomainName, SourceComputer,
  SourceIpAddress, TargetServer, NTLMVersion, LogonType, ProcessName), displays a summary and
  per-event list grouped by version (NTLMv1 first as higher risk), and offers CSV export.
  Requires the NTLM Audit Policy GPO applied to DCs before events appear.
- `Start-DailyNTLMAuthReport` -- automated daily scheduled report. Queries all DCs for 24-hour
  NTLM events, groups by NTLMv1/v2 with per-user/source counts and first/last seen, exports CSV,
  and emails summary to `$global:ADAdminEmail`. NTLMv1 is flagged explicitly in subject and body.
  Controlled by `$global:NTLMAuthDailyReport = $true` in settings.
- `Get-NTLMAuthEvents` private helper -- enumerates all DCs via `Get-ADDomainController`,
  queries the NTLM Operational log with a StartTime/EndTime window, parses event XML data nodes
  into normalized PSCustomObjects, and returns the full array. Warns per DC if the log is
  inaccessible (audit policy not yet applied).
- `NTLMAuthDailySummary` scheduled job registration in `Initialize-Module` (Daily = $true).
- `SearchNTLMAuthEvents` submenu item registration in `Initialize-Module` under `LogMgrMenu`.

**Changed in settings (AD-PowerAdmin_settings.ps1):**
- Added `$global:NTLMAuthDailyReport = $false` feature flag. Set to `$true` to enable the daily
  NTLM authentication summary email report.

**Documentation:**
- Created `AD-PowerAdmin.wiki/Vulnerabilities/NTLMv1_NTLMv2_Authentication_Risks.md` -- generalized
  vulnerability dossier covering NTLM credential capture, offline cracking, pass-the-hash, relay
  attacks, downgrade risk, audit event log guidance, and remediation controls.
- Created `AD-PowerAdmin.wiki/LogMgr-NTLM-Authentication-Audit.md` -- module wiki page covering
  feature description, prerequisite GPO requirement, daily report configuration, recommended
  workflow (audit -> remediate -> restrict), and framework integration details.

---

### Modules/AD-PowerAdmin_GPOMgr.psd1 -- Promoted to Production

**Changed:**
- `Channel` set to `'Production'`. The module has completed Beta validation across Honeypot,
  AuditPolicy, and BestPracticesDeployer integration, passed pre-production review (naming reform,
  verb-group reorder, Utils migration), and has no known issues.

---

### Multiple Modules -- GPOMgr Pre-Production Refactor + Inter-Module Dependency Framework

**Added to Utils (v1.4):**
- `Assert-ADPAModuleDependency` -- Framework-wide helper for inter-module dependency enforcement.
  Called from `Initialize-Module` of any module that depends on another AD-PowerAdmin module.
  Checks whether the required module is loaded, attempts to import it from `$global:ModulesPath`
  if not, and returns `$false` with a `[FAIL]` message if it cannot be loaded. When it returns
  `$false`, `Initialize-Module` must return immediately without registering menu entries.
- `Get-ResolvedDomain` -- Resolves the current AD domain name from an optional parameter or
  the session default (`$env:USERDNSDOMAIN`). Migrated from `AD-PowerAdmin_GPOMgr` (was private
  there) to make domain resolution available framework-wide.
- Replaced wildcard `FunctionsToExport = @("*")` with an explicit list for performance and
  predictability (v1.4).

**Changed in GPOMgr (v3.0) -- breaking rename of public API:**
- Renamed 19 public functions by removing the `ADPA` abbreviation where no native GroupPolicy
  cmdlet conflict exists. Three names retained ADPA to avoid collision with native cmdlets:
  - `New-ADPAGPO` (native `New-GPO` exists)
  - `Remove-ADPAGPO` (native `Remove-GPO` exists)
  - `Backup-ADPAGPO` (native `Backup-GPO` exists)
- Complete rename map (old -> new):
  - `Find-ADPAGPO` -> `Find-GPO`
  - `Test-ADPAGPO` -> `Test-GPO`
  - `Set-ADPAGPORegistrySetting` -> `Set-GPORegistrySetting`
  - `Remove-ADPAGPORegistrySetting` -> `Remove-GPORegistrySetting`
  - `Add-ADPAGPOLink` -> `Add-GPOLink`
  - `Remove-ADPAGPOLink` -> `Remove-GPOLink`
  - `Set-ADPAGPOPermission` -> `Set-GPOPermission`
  - `Export-ADPAGPOReport` -> `Export-GPOReport`
  - `Install-ADPAGPOBaseline` -> `Install-GPOBaseline`
  - `Remove-ADPAGPOBaseline` -> `Remove-GPOBaseline`
  - `Search-ADPAGPOSetting` -> `Search-GPOSetting`
  - `Backup-AllADPAGPOs` -> `Backup-AllGPOs`
  - `Get-ADPAGPOBackupList` -> `Get-GPOBackupList`
  - `Restore-ADPAGPOBackup` -> `Restore-GPOBackup`
  - `Invoke-ADPAGPOModification` -> `Invoke-GPOModification`
  - `Search-ADPAGPOSecuritySetting` -> `Search-GPOSecuritySetting`
  - `Set-ADPAGPOSecuritySetting` -> `Set-GPOSecuritySetting`
  - `Set-ADPAGPOAdvancedAuditPolicy` -> `Set-GPOAdvancedAuditPolicy`
  - `Get-ADPAGPOAdvancedAuditPolicy` -> `Get-GPOAdvancedAuditPolicy`
- Reordered all functions into framework-standard verb groups: Retrieval (Find, Test, Export,
  Get, Search), Modification (New, Set, Add, Install, Backup, Restore, Invoke), Removal (Remove).
- Removed `Get-ResolvedDomain` (private) -- migrated to `AD-PowerAdmin_Utils` as a shared utility.

**Changed in GPOBestPracticesDeployer (v1.3):**
- Added `Assert-ADPAModuleDependency` check at the top of `Initialize-Module`. If
  `AD-PowerAdmin_GPOMgr` cannot be loaded, the module does not register menu entries and prints
  a `[WARN]` message instead of silently registering broken entries.
- Added `RequiredADPAModules = @('AD-PowerAdmin_GPOMgr')` to `PrivateData.PSData` in the
  manifest as the documentation-level dependency declaration.
- Updated all 7 GPOMgr call sites to use the v3.0 renamed function names.

**Changed in AuditPolicy + Honeypot:**
- Updated all call sites to use the renamed GPOMgr v3.0 function names.

**Changed in CLAUDE.md:**
- Added "Inter-Module Dependencies" subsection under "How to Create a New Module" documenting
  the `Assert-ADPAModuleDependency` pattern, the `RequiredADPAModules` convention, and the
  requirement that `Initialize-Module` return early if dependency check fails.

---

### Modules/AD-PowerAdmin_Utils.psm1 -- Remove Dead Code

**Removed:**
- `Send-EmailTest` -- Removed. This interactive SMTP tester was never registered in any menu
  and had no call sites anywhere in the codebase. Its functionality is fully covered by
  `Test-EmailConfiguration` in `AD-PowerAdmin_Installer`, which is registered in the main menu
  and maintained alongside the current `Send-Email` implementation.

---

### Multiple Modules -- Promote Shared Utilities to Utils (v1.3)

**Added to Utils (v1.3):**
- `Test-PasswordIsComplex` -- Promoted from `AD-PowerAdmin_PasswordsCtl` where it was private.
  Tests whether a string meets Windows default password complexity requirements (upper, lower,
  digit, symbol from at least three categories, minimum eight characters). Now available to
  any module that generates or validates passwords.
- `New-RandomPassword` -- Promoted from `AD-PowerAdmin_PasswordsCtl` where it was exported but
  effectively only used within that module. Rewrote with a `-Length` parameter (default 64) and
  an `-AsSecureString` switch. Uses unbiased byte-rejection sampling via RNGCryptoServiceProvider
  across the full printable-ASCII range (33-126); retries until `Test-PasswordIsComplex` passes.
  Returning a SecureString directly avoids callers having to wrap the result themselves.
- `Set-SettingsFileValue` -- Promoted from `AD-PowerAdmin_Installer` where it was private.
  Applies a targeted regex replacement for one `$global:*` variable in the settings file content
  string. Supports six declaration styles: `bool`, `int`, `string-single`, `string-double`,
  `string-varref`, `array-ou-locations`. Returns the modified content; the caller writes the file.
  Now available to any module that needs to persist configuration changes to the settings file.

**Removed from PasswordsCtl:**
- `New-RandomPassword` -- Removed from the module; now provided by Utils. Removed from
  `FunctionsToExport`. Internal callers (`Update-KRBTGTPassword`) resolve it from Utils after
  all modules load.
- `Test-PasswordIsComplex` -- Removed from the module; now provided by Utils. Was private
  (not in `FunctionsToExport`); `New-RandomPassword` in Utils calls it from Utils.

**Removed from Installer:**
- `Set-SettingsFileValue` -- Removed from the module; now provided by Utils. Was private
  (not in `FunctionsToExport`). The one call site in `Start-SettingsWizard` resolves it
  from Utils after all modules load.

**Changed in Honeypot:**
- `New-HoneypotRandomPassword` -- Removed. This function was dead code: it was defined but
  never called. Password generation was already being done inline inside `New-HoneytokenUser`.
- `New-HoneytokenUser` -- Replaced the six-line inline RNGCryptoServiceProvider block (with
  modulo-biased charset sampling) with a single `New-RandomPassword -Length 32` call from Utils.
  The Utils version uses unbiased rejection sampling and validates complexity.
- `Set-HoneypotSettings` -- Replaced six hand-coded `$Content -replace` regex expressions with
  equivalent `Set-SettingsFileValue` calls from Utils. Behavior is identical; duplication is
  eliminated.

**Why:** Three functions in the codebase were duplicating logic that is useful across modules.
  `New-RandomPassword` and `Test-PasswordIsComplex` are needed wherever passwords are generated
  or validated. `Set-SettingsFileValue` is needed wherever a module must persist configuration
  to the settings file. Centralizing them in Utils removes duplication, ensures consistent
  behavior, and makes the functions available to future modules without reimplementation.

---

### Modules/AD-PowerAdmin_Honeypot.psd1 -- Promote to Production

**Changed:**
- `Channel` -- Promoted from `Beta` to `Production` after successful end-to-end validation:
  authentication test events (4771, 4625) confirmed generated and detected, audit policy
  pre-checks reporting correctly, email pre-flight guard handling unconfigured settings
  cleanly, and unattended scheduled task running and logging correctly under Windows Task
  Scheduler on Server 2016 (PS 5.1.14393).

---

### AD-PowerAdmin_settings.ps1 + Multiple Modules -- Settings File Cleanup

**Changed:**
- `$global:ReportsEmailFrom` -- Removed. This variable was always set to `$global:FromEmail` and served only as a redundant alias. All callers in `AD-PowerAdmin_PasswordsCtl`, `AD-PowerAdmin_LogMgr`, `AD-PowerAdmin_Honeypot`, and `AD-PowerAdmin_ExchangeAdSecurity` now reference `$global:FromEmail` directly. The Installer settings wizard prompt for this variable has been removed accordingly.
- `$global:ReportAdminEmailTo` -- Removed. This variable was always set to `$global:ADAdminEmail` and served only as a redundant alias. All callers in `AD-PowerAdmin_PasswordsCtl` now reference `$global:ADAdminEmail` directly. The Installer settings wizard prompt for this variable has been removed accordingly.
- `$global:SMTPPort` -- Changed type declaration from `[string]` to `[int]` and value from `'25'` to `25`. The port is used as a number and the string type was a mismatch. The Installer wizard now uses `Read-SettingInt` and `VarType = 'int'` when writing this value back to the settings file.

**Fixed:**
- Duplicate `# EXAMPLE: [string]$global:SMTPServer = ''` comment line in `AD-PowerAdmin_settings.ps1` -- one instance removed.
- Incorrect variable names `$global:ReportEmailFrom` referenced in two comment lines -- corrected as part of the surrounding block removal.
- `Send-Email` credential fallback in `AD-PowerAdmin_Utils.psm1` -- line 235 referenced `$global:SMTPUser` (undefined), which silently skipped credential injection even when `$global:SMTPUsername` and `$global:SMTPPassword` were configured. Corrected to `$global:SMTPUsername`.
- Decentralized honeypot settings template in `AD-PowerAdmin_Honeypot.psm1` -- removed the line that emitted `$global:ReportsEmailFrom` into the generated settings snippet, since that variable no longer exists.

**Impact:** No change in email sending behavior. The removed variables were always equal to the variables they referenced. The `SMTPUsername` credential bug fix means SMTP authentication will now work correctly when credentials are configured.

---

### Modules/AD-PowerAdmin_Installer.psm1 + .psd1 -- Email Configuration Diagnostic Test

**Added:**
- `Test-EmailConfiguration` -- Multi-stage SMTP diagnostic function accessible from the
  AD-PowerAdmin Management submenu. Performs four sequential stages:
  1. **Settings validation** -- confirms `SMTPServer`, `FromEmail`, and `ADAdminEmail` are all
     non-empty; exits early with a targeted fix message if any are missing.
  2. **DNS resolution** -- detects whether `SMTPServer` is an IP address (skips DNS) or a
     hostname (calls `[System.Net.Dns]::GetHostEntry`); prints resolved IPs or failure details
     with likely causes on error.
  3. **TCP port connectivity** -- opens a `System.Net.Sockets.TcpClient` connection with a
     5-second timeout; distinguishes a timeout from an active refusal and lists firewall,
     wrong-port, and server-offline as likely causes.
  4. **SMTP send test** -- drives `Net.Mail.SmtpClient` directly (rather than calling
     `Send-Email`) so exceptions propagate to a catch block that distinguishes
     `SmtpException` (auth/relay failure with `StatusCode`), `AuthenticationException`
     (TLS handshake failure), `SocketException` (network drop after TCP success), and a
     general catch-all. On success, confirms the message was sent and asks the admin to
     verify delivery. The test email body includes the hostname, timestamp, and all SMTP
     settings used, giving the admin a confirmation receipt for the exact configuration.
  Prints a `[PASS]` / `[FAIL]` banner at each stage and a final summary. On any failure,
  directs the admin to the Settings Wizard in the same submenu.

**Why:** Alerting is a critical component of AD-PowerAdmin's security monitoring. When email
  delivery fails silently (e.g., after a network change or settings file edit), there is no
  built-in tool to distinguish a misconfigured setting from a firewall block from an SMTP
  authentication failure. This function gives administrators a single command that walks
  through every layer of the delivery path and surfaces exactly where the problem is.

---

### AD-PowerAdmin.ps1 -- Unattended Log Silence and Error Suppression

**Fixed:**
- `Initialize-Debug` -- The function used a `try/catch` around `Get-Transcript | Out-Null` to
  detect whether a transcript was already running. In PowerShell 5.1, `Get-Transcript` returns
  `$null` silently when no transcript is active -- it does NOT throw. The try block always
  succeeded, `$TranscriptRunning` was always `$true`, and the `if (!$TranscriptRunning)` guard
  never allowed `Start-Transcript` to execute. The debug log was therefore never created when
  the script ran under PS 5.1 (including the default Windows Task Scheduler environment).
  Replaced the pattern with: default `$false`, try calling `Get-Transcript -ErrorAction Stop`
  inside a try/catch, and use `IsNullOrWhiteSpace` on the result. The outer catch handles
  `CommandNotFoundException` on Server 2016 RTM builds (PS 5.1.14393) where `Get-Transcript`
  does not exist; the inner null-safe check handles builds where it exists but returns `$null`
  when no transcript is active.
- `Start-Automation` -- The `Invoke-Expression` call that dispatches the unattended job command
  used `-ErrorAction:SilentlyContinue`, which silenced all errors thrown by the called function.
  Any runtime error inside the job (e.g., inside `Start-HoneypotMonitor`) was swallowed before
  it could be written to the transcript, making failures completely invisible in the log.
  Removed the `-ErrorAction:SilentlyContinue` flag so errors propagate normally and are captured
  by the active transcript.
- `Start-Automation` -- Windows Task Scheduler passes PowerShell `-File` script arguments as
  raw Windows command-line tokens. Single quotes are NOT stripped by Windows argument parsing
  (only double quotes are removed). A task configured with `-JobName 'HoneypotHourlyMonitor'`
  delivered the literal string `'HoneypotHourlyMonitor'` (with quote characters) to `$JobName`.
  The hashtable key is `HoneypotHourlyMonitor` without quotes, so the `$_.JobName -eq $JobName`
  comparison always failed and no job ever ran. Added `$JobName = $JobName.Trim("'").Trim('"')`
  immediately after the null-check to strip any surrounding quote characters before matching.

**Why:** The scheduled-task path (unattended mode, PS 5.1) produced no output in either
  `AD-PowerAdmin_Unattended.log` or `AD-PowerAdmin_Debug.log` even with both `$global:Debug`
  and `$global:UnattendedLog` set to `$true`, and no job function was being executed at all.
  The three fixes together restore both log output and correct job dispatch for unattended
  runs under Windows Task Scheduler on Server 2016.

---

### Modules/AD-PowerAdmin_Utils.psm1 + AD-PowerAdmin_AuditPolicy.psm1 -- Promote Generic Helpers to Utils (v1.2 / v1.9)

**Added to Utils (v1.2):**
- `Get-SystemRole` -- Returns `'DomainController'`, `'MemberServer'`, or `'Workstation'` by querying
  `Win32_OperatingSystem.ProductType` via CIM. Promoted from `Get-ADPSystemRole` in the AuditPolicy
  module, which was private and unavailable to other modules. Any module that needs role-aware behavior
  (baseline selection, DC-only checks, etc.) can now call this shared function.
- `Write-WrappedText` -- Writes a labeled, word-wrapped text block to the console. First line is
  `Indent + Label + text`; continuation lines are indented to align under the label. Promoted from
  `Write-ADPWrappedText` in the AuditPolicy module. Complements the existing `Get-WordWrap` utility
  (which returns wrapped strings without writing to the console). Any module with a help page or
  formatted diagnostic output can now use this without reimplementing the alignment logic.

**Removed from AuditPolicy (v1.9):**
- `Get-ADPSystemRole` -- Private function removed; replaced by `Get-SystemRole` from Utils. All call
  sites in `Start-ADPAuditPolicyCheck` and `Export-ADPAuditPolicyReport` updated.
- `Write-ADPWrappedText` -- Private function removed; replaced by `Write-WrappedText` from Utils. All
  call sites in `Show-ADPAuditFindings` and `Show-ADPAuditPolicyHelp` updated.

**Why:** Both functions contained no audit-policy-specific logic and were candidates for reuse by any
  current or future module. Moving them to Utils removes the module-scoped prefix, makes them available
  framework-wide, and eliminates the need for other modules to reimplement the same WMI call or the
  same label-alignment formatting pattern.

---

### Modules/AD-PowerAdmin_Utils.psm1 -- Send-Email Clean Failure on Missing Configuration

**Fixed:**
- `Send-Email` -- Required parameters (`ToEmail`, `FromEmail`, `Subject`, `Body`) were declared
  `Mandatory=$true`. When a caller passed an empty string (e.g., `$global:ADAdminEmail` not yet
  configured), PowerShell threw an unhandled `ParameterBindingValidationException` before the
  function body could run, producing a raw engine error with no actionable message. Changed all
  parameters to `Mandatory=$false` and added explicit `[string]::IsNullOrWhiteSpace` checks at
  the top of the function body for all four required fields. Each check emits a clear red message
  naming the missing setting and the settings file where it must be configured, then returns.
- `Send-Email` -- Fixed a duplicate `Position=3` attribute on both `$CcEmail` and `$Subject`,
  which causes undefined positional parameter binding behavior in PowerShell. Assigned unique
  sequential positions (3 through 10) to all parameters.
- `Send-Email` -- The `$SmtpServer` and `$SmtpPort` resolution blocks used `$SmtpX -ne ''`
  comparisons, which do not handle `$null`. Replaced all empty-string comparisons throughout
  the parameter resolution logic with `[string]::IsNullOrWhiteSpace()` for consistency and
  correctness. Also fixed a case inconsistency where the SmtpServer block checked
  `$global:SmtpServer` (lowercase 's') but read `$global:SMTPServer` (uppercase).
- `Send-Email` -- Credential resolution used two independent `if` blocks, meaning global
  credentials always overrode explicit parameters. Replaced with `if/elseif` so explicit
  parameters take precedence over global settings, matching the precedence order used for
  SmtpServer and SmtpPort.

**Why:** Any caller passing an unconfigured global variable as `ToEmail` or `FromEmail`
  triggered a raw PowerShell engine error instead of a recoverable diagnostic. The fix ensures
  `Send-Email` always fails gracefully with a message that points to the correct remediation.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- Audit Policy Check False Negative

**Fixed:**
- `Test-HoneypotAuditPolicy` -- The function used `auditpol.exe /get /subcategory:GUID /r`
  and parsed the CSV output by filtering out any line starting with "Machine" and then
  splitting on commas to extract field index 4 (Inclusion Setting). On the target Windows
  version this parsing fails silently for all four subcategories: the `Where-Object` filter
  returns nothing (likely due to a format or blank-line difference in the `/r` output),
  so `[0]` yields `$null`, the split produces a 1-element array, the `Count -ge 5` guard
  fails, and every subcategory reports "Unknown" -- triggering a false WARN even when
  auditing is fully enabled (confirmed by the monitor finding real events immediately after).
  Replaced with plain-text `auditpol /get /subcategory:GUID` (no `/r`) and direct
  pattern-matching against the four known setting strings: "No Auditing", "Success and
  Failure", "Success", "Failure". "Success and Failure" is tested first to avoid a
  substring false-match against the single-word checks.

**Why:** Administrators were seeing audit policy warnings on a correctly configured DC,
  causing unnecessary confusion before every test run. The /r CSV parsing is fragile across
  Windows versions; the plain-text pattern match is format-independent.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- Detection Test and Event Search Bug Fixes

**Fixed:**
- `Get-HoneypotEventsBatch` -- Complete rewrite of the event query mechanism. The original
  implementation used `Get-WinEvent -FilterXPath` with a manually-constructed UTC timestamp
  string (`yyyy-MM-ddTHH:mm:ss.000Z`). The Windows Event Log RPC service evaluates this
  XPath on the remote DC; on some Windows Server versions, the TimeCreated XPath predicate
  silently returns zero results over RPC even when matching events are present. The query has
  been replaced with `Get-WinEvent -FilterHashtable` using `StartTime`/`EndTime` datetime
  objects directly, which lets PowerShell handle UTC conversion internally via the structured
  query XML path rather than raw XPath string evaluation. This resolves the silent zero-result
  failure for 4771 and other Kerberos events confirmed present in the Security log.
- `Get-HoneypotEventsBatch` -- The `IsLocal` detection compared `$ComputerName` against
  `$env:COMPUTERNAME` with an exact string match. `Get-ADDomainController` returns FQDNs
  (e.g. `FL-222.tdcme.loc`) while `$env:COMPUTERNAME` is the NetBIOS short name (`FL-222`).
  The comparison always failed when the script ran on the DC itself, causing every query to
  take the remote RPC path (querying the local machine over the network) instead of the direct
  local log access path. Fixed by splitting both names on `.` and comparing only the NetBIOS
  portion before checking equality.
- `Invoke-HoneypotTestServiceTicket` -- The function called `klist.exe get SPN` without first
  confirming the SPN was registered as `servicePrincipalName` on the honeytoken AD account. If
  the SPN existed in `$global:HoneypotSPN` but was absent from the account in AD, the KDC
  returned `KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN` and no 4769 event was logged; the klist exit code
  was reported only as a vague warning. Added a pre-flight `Get-ADUser -Properties
  servicePrincipalName` check before calling klist. If the SPN is missing, the function shows
  the SPNs currently on the account and the exact `Set-ADUser` remediation command.

- `Invoke-HoneypotTestAuthAttempt` -- The function used `AuthType::Negotiate` for the LDAP bind.
  Negotiate selects Kerberos when the DC advertises GSSAPI support (which all DCs do), generating
  Event 4771 (Kerberos pre-auth failure) but never 4625 (failed logon), because 4625 is produced
  only by NTLM authentication failures. Added a second LDAP bind using `AuthType::Ntlm` after the
  existing Kerberos bind. Both binds use the same randomly generated wrong password. The NTLM bind
  generates Event 4625 on the DC, completing coverage of both authentication protocol detection
  paths. The two binds are shown separately in output ([1/2] Kerberos, [2/2] NTLM) so the admin
  can confirm each is rejected as expected.
- `Start-HoneypotMonitor` -- The `Send-Email` call had no guard against empty `$global:ADAdminEmail`
  or `$global:SMTPServer`. When either is unconfigured, `Send-Email` threw an unhandled
  `ParameterBindingValidationException` that printed a raw PowerShell error before continuing. Added
  a pre-flight check: if either setting is empty, a clear `[SKIP]` message is printed and
  `Send-Email` is not called. The success message now says "Alert sent to <address>" only when the
  email was actually sent, and includes the recipient address for confirmation.

**Why:** Two compounding bugs prevented the event search from finding 4771 events that were
  confirmed present in the Security log: the XPath time filter failed silently over RPC on this
  Windows version, and the IsLocal check misidentified the DC as a remote machine, routing all
  queries through the failing RPC path. Switching to -FilterHashtable removes both failure modes.
  The klist pre-flight surfaces the most common cause of missing 4769 events before klist runs.
  The NTLM bind addition and email guard complete the test pipeline so all detection paths can
  be exercised end to end.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- Diagnostic and Help Alignment for Dual-CSE Requirement (v1.8)

**Fixed:**
- `Test-ADPAuditPolicyGpoDiagnostic` Check 6 -- Event filter previously matched only Security
  CSE events (`827D319E` / "Security" keyword). Because Advanced Audit Policy GPOs require two
  separate CSEs -- the Security Settings CSE (`{827D319E-...}`) and the Audit Policy Configuration
  CSE (`{F3CCC681-...}`) -- a deployment where only the Audit Policy CSE was missing would show
  zero events in Check 6, making it appear as though GP had not run at all rather than pointing to
  the missing CSE registration. The filter now also matches `F3CCC681` and the "Audit Policy" string
  so any CSE event relevant to audit policy processing is captured. Labels updated from "Security CSE
  events" to "audit policy CSE events" throughout.
- `Test-ADPAuditPolicyGpoDiagnostic` Resolution Guide step 1 -- Previously read "Security CSE GUID
  missing from AD object" and named only `{827D319E-...}`. Updated to name both required GUIDs
  (`{827D319E-...}` Security and `{F3CCC681-...}` Audit Policy) and describe the fix for each.
- `Test-ADPAuditPolicyGpoDiagnostic` `.DESCRIPTION` -- Check 6 description updated to mention both
  Security CSE and Audit Policy CSE event filtering.

**Added:**
- `Show-ADPAuditPolicyHelp` GPO Deployment section -- Added explanatory paragraph documenting the
  three CSE blocks registered in `gPCMachineExtensionNames` by each deployment (Registry CSE for
  log sizes and NTLM registry settings, Security Settings CSE for `GptTmpl.inf`, Audit Policy
  Configuration CSE for `audit.csv`). Without all three, the GP client silently skips the
  corresponding file on every refresh. Directs administrators to `Test-ADPAuditPolicyGpoDiagnostic`
  if settings appear not to be applying.

**Why:** The Check 6 event filter was written before the Audit Policy CSE (`{F3CCC681-...}`) was
  identified as a required second CSE for Advanced Audit Policy GPOs. After that root cause was
  found and the deployer was fixed, the diagnostic and help page still described only the Security
  CSE, leaving a gap between what the tool deployed and what it explained.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- Summary Count Display and Directory Service Log GPO (v1.7)

**Fixed:**
- `Show-ADPAuditFindings` -- Summary line displayed a blank value instead of the integer count
  when exactly one finding of a given severity existed. Root cause: `Where-Object` in PS5.1
  returns a scalar `PSCustomObject` (not an array) when exactly one item passes the filter.
  Calling `.Count` on a `PSCustomObject` in PS5.1 returns `$null` rather than 1, because scalar
  member synthesis in PS5.1 synthesizes `.Count = 1` only for simple value types, not for
  `PSCustomObject`. `$null` interpolates as an empty string in the format string, producing
  `" High"` instead of `"1 High"`. Fixed by wrapping all four severity `Where-Object` calls
  in `@()` to force array context before calling `.Count`, which returns the correct integer
  regardless of whether 0, 1, or many items match.
- `New-ADPAuditPolicyGpo` -- Directory Service log size policy was writing to the ADMX-backed
  registry path (`HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Directory Service\MaxSize`)
  which the Windows Event Log service does not process for application-registered logs. The
  Event Log service honors the ADMX path only for logs covered by the built-in `EventLog.admx`
  template (Security, System, Application). The Directory Service log reads its maximum size
  exclusively from the legacy registry key `HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\
  Directory Service\MaxSize`, where the value is in bytes (not KB). Fixed by removing Directory
  Service from the `$LogAdmxNames` ADMX table and adding a dedicated DC-baseline block (step 4b)
  that writes the preferred size in bytes to the correct SYSTEM path as a non-ADMX Extra Registry
  Setting. Re-deploying the DC baseline GPO and running `gpupdate /force` will now update the
  actual log maximum size.

**Why:** The v1.6 fix (adding Directory Service to `$LogAdmxNames`) wrote to the correct GPO
  object but the wrong registry key. After `gpupdate /force`, the ADMX key in SOFTWARE\Policies
  was set but the Event Log service never read it, leaving the actual log at 1 MB.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- Directory Service Log Size Missing from DC Baseline GPO (v1.6)

**Fixed:**
- `New-ADPAuditPolicyGpo` -- The `Directory Service` Windows Event Log was omitted from the
  `$LogAdmxNames` dictionary that controls which event logs have their maximum size written to
  the GPO's Registry.pol. The DomainController baseline (`$script:AuditBaselines.DomainController
  .EventLogs`) already defines `'Directory Service'` with a 256 MB compliance minimum and a 1 GB
  preferred size, and `Compare-ADPAuditPolicyBaseline` correctly flags the log as `[HIGH]` when
  under-sized -- but because the deployer skipped the log, re-deploying the baseline GPO never
  actually applied the fix. The `$LogAdmxNames` table now includes `'Directory Service' = 'Directory
  Service'`, causing the deployer to write
  `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Directory Service\MaxSize` to Registry.pol.

**Why it was fixed:** The compliance checker (45-check DC audit) correctly identified the
  Directory Service log at 1 MB as a `[HIGH]` finding, but the fix path (redeploy the DC baseline
  GPO) silently had no effect because the deployer never included that log. Symptom was the check
  remaining non-compliant after every GPO redeployment.

**Impact:** Re-deploying the DC baseline GPO (`Deploy DC Baseline GPO`) will now write the
  `Directory Service` log size policy. After `gpupdate /force`, the log maximum size will be set
  to 1024 MB (1 GB preferred), which satisfies the >= 256 MB compliance minimum.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 / AD-PowerAdmin_GPOMgr.psd1 / AD-PowerAdmin_AuditPolicy.psm1 -- Missing Audit Policy CSE in gPCMachineExtensionNames

**Fixed:**
- `Set-ADPAGPOAdvancedAuditPolicy` and `New-ADPAuditPolicyGpo` -- The Audit Policy Configuration CSE GUID `{F3CCC681-B74C-4060-9F26-CD84525DCA2A}` paired with tool GUID `{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}` was missing from `gPCMachineExtensionNames` on every GPO created by this module. Advanced Audit Policy (audit.csv) is processed by a dedicated CSE that is separate from the Security Settings CSE (`{827D319E-...}`). Without `{F3CCC681-...}` in `gPCMachineExtensionNames`: (1) the GPMC Settings display omits the Advanced Audit Policy section entirely, and (2) the Group Policy client never invokes the Audit Policy CSE so audit.csv settings are never applied to target computers regardless of how many times gpupdate runs.
- `Update-GptIniVersion` -- Added an `ExtraCseBlocks [string[]]` parameter so callers can register additional CSE blocks alongside the Security CSE. `Set-ADPAGPOAdvancedAuditPolicy` now passes `$AuditPolicyCse` when it calls `Update-GptIniVersion`, ensuring the Audit Policy CSE is registered immediately when audit.csv is written. Also refactored the AD object update to use the proper merge-and-sort pattern (parse existing blocks, add missing ones, sort alphabetically) rather than simple string concatenation, matching the format GPMC produces.

**Why:** Root cause identified by ldapsearch comparison of the AD object attributes on two GPOs: a PS-only GPO and a GPO that had been opened and saved once in the GPMC editor. The PS-only GPO had `gPCMachineExtensionNames` with two blocks (Registry CSE + Security CSE). The GPMC-saved GPO had three blocks, the third being `[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]`. This confirmed that GPMC registers the Audit Policy CSE when it saves a GPO containing Advanced Audit Policy settings, and that our code was not doing so.

**Impact:** GPOMgr version bumped from 1.9 to 2.0. AuditPolicy version bumped from 1.4 to 1.5. Previously deployed GPOs created by `New-ADPAuditPolicyGpo` have never applied their Advanced Audit Policy settings because the Audit Policy CSE was not registered. Re-run "Deploy DC Baseline GPO" or "Deploy Standard Computer Baseline GPO" (idempotent) then run `gpupdate /force` on target systems. Verify with `auditpol /get /category:*` that subcategory settings now match the baseline.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 / AD-PowerAdmin_AuditPolicy.psd1 -- GPMC Settings Display Missing Audit Policy

**Fixed:**
- `New-ADPAuditPolicyGpo` -- Step 5b (re-registration of Security CSE in gPCMachineExtensionNames after Set-GPRegistryValue overwrote it) used `Get-ADObject -Filter "Name -eq '$GpoGuidStr' ..."` which can silently return `$null` when the filter doesn't match or when there is a transient search issue. When `$null` was returned the `if ($GpoAdObj2)` guard skipped the entire update with no warning, leaving `gPCMachineExtensionNames` set to only the Registry CSE block written by `Set-GPRegistryValue`. GPMC reads `gPCMachineExtensionNames` from the AD object to determine which sections to render in the Settings display; without the Security CSE GUID `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`, the entire Security Settings section (including Advanced Audit Policy) is omitted from the report, even though audit.csv exists and is correct in SYSVOL. The GPO Editor bypasses this check and reads SYSVOL directly, which is why audit settings appeared correctly in the editor but not in the Settings display. Opening the editor and saving caused GPMC to register the Security CSE GUID in the AD object, after which the Settings display worked. The fix replaces the Filter-based lookup with a DN-based lookup (`Get-ADObject -Identity "CN={GUID},CN=Policies,CN=System,$DomainDN"`) which throws an exception if the object does not exist rather than returning null silently. The fix also explicitly adds both the Security CSE block and the Registry CSE block when building the final value, rather than only patching in the Security CSE, ensuring both the Registry Policy Processing CSE (`{35378EAC-...}`) and Security Settings CSE (`{827D319E-...}`) are always present. Added diagnostic output showing the before and after values of `gPCMachineExtensionNames` so operators can confirm the update on each deployment.

**Why:** Root cause identified by direct SYSVOL comparison between a PS-only GPO and a GPO that had been edited once in the GPMC editor. All SYSVOL files (audit.csv, GptTmpl.inf, Registry.pol, gpt.ini) were identical in content; the only functional difference was that GPMC's editor registered the Security CSE in the AD object when it saved. The prior Filter-based Get-ADObject lookup was the silent failure point.

**Impact:** AuditPolicy module version bumped from 1.3 to 1.4. Previously deployed GPOs created by `New-ADPAuditPolicyGpo` will not have shown audit policy settings in the GPMC Settings display. Re-run "Deploy DC Baseline GPO" (which is idempotent) to update the AD object's `gPCMachineExtensionNames` attribute on existing GPOs. After re-deployment run `gpupdate /force` on target systems.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 / AD-PowerAdmin_GPOMgr.psd1 -- audit.csv Encoding, INI Format, and gpt.ini Attribute Fixes

**Fixed:**
- `Set-ADPAGPOAdvancedAuditPolicy` -- audit.csv was written as UTF-16 LE with BOM (`ff fe` prefix). Direct hex comparison against a GPMC-generated audit.csv confirmed the correct encoding is UTF-8 without BOM. The Windows Security Configuration Engine skips audit.csv when a BOM is present because the file format is plain CSV and the BOM is not part of the column header. Changed `[System.Text.Encoding]::Unicode` to `[System.Text.UTF8Encoding]::new($false)` in the `StreamWriter` constructor.
- `ConvertTo-IniLines` -- Was writing `Key = Value` with spaces around the `=` delimiter. Windows INI files (gpt.ini and GptTmpl.inf) use `Key=Value` without spaces. This mismatch caused the `Version` field in regenerated gpt.ini files to be written with a space, which the Group Policy client could not parse. Fixed to use `"$Key=$($Sections[$Section][$Key])"`.
- `Update-GptIniVersion` -- Was writing a `gPCMachineExtensionNames` line into the gpt.ini file. The natural Windows gpt.ini contains only `[General]`, `Version=N`, and `displayName=New Group Policy Object`; it never contains `gPCMachineExtensionNames`. That attribute belongs exclusively in the GPO AD object (`groupPolicyContainer`), which is where the GP client reads it. The fix removes any `gPCMachineExtensionNames` key from the parsed INI sections before writing back to disk, and ensures the new-file creation path also writes only the three correct lines.

**Why:** Root cause confirmed by mounting the domain SYSVOL and hexdumping both a GPMC-generated GPO and the script-generated GPO side-by-side. The natural audit.csv had no BOM (`4d 61 63 68 69 6e 65`); the script-generated file had `ff fe` BOM followed by UTF-16 wide characters. After correcting the column layout (v1.8) the SCE could read the file structure but the BOM still blocked processing.

**Impact:** GPOMgr version bumped from 1.8 to 1.9. Re-run "Deploy DC Baseline GPO" or "Deploy Standard Computer Baseline GPO" to redeploy; the operation is idempotent. After redeployment, run `gpupdate /force` on target systems. The Advanced Audit Policy subcategory settings should now appear in GPMC and be applied by the Security Configuration Engine.

---

### AD-PowerAdmin.ps1 -- Credits Screen

**Added:**
- `Show-Credits` -- Displays a formatted attribution screen listing every third-party tool, module, and code extract that AD-PowerAdmin depends on or embeds. Each entry includes the tool name, author, a brief description of its role in the framework, and the project URL. Credits listed: DSInternals (Michal Grafnetter), Have I Been Pwned Pwned Passwords API (Troy Hunt), Weak Passwords List (weakpasswords.net), Calendar GUI Widget (PowerShell Gallery v1.0.0), and PoShEvents (Jason Walker, PowerShell Gallery v0.2.1).
- `c` shortcut in `Enter-MainMenu` -- Typing `c` at the interactive menu prompt invokes `Show-Credits`. The option is visible in the menu footer alongside `h. Help`, `q. Quit`, and `qq. Quit Application`.

**Why:** AD-PowerAdmin embeds or directly depends on several third-party works. Providing in-tool attribution acknowledges these contributions and gives administrators a single place to identify external dependencies and their upstream sources.

**Impact:** No change to AD functionality or security posture. The menu footer gains one new visible option. All existing shortcuts are unaffected.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 / AD-PowerAdmin_GPOMgr.psd1 -- audit.csv Column Layout, Encoding, and GUID Format Corrected

**Fixed:**
- `Set-ADPAGPOAdvancedAuditPolicy` -- Four corrections confirmed by comparing against a GPMC-generated audit.csv from a manually configured GPO:
  1. **Encoding**: Changed from UTF-8 without BOM to `[System.IO.StreamWriter]` with `[System.Text.Encoding]::Unicode` (UTF-16 LE with BOM). The SCE and GPMC require this encoding; UTF-8 caused both to silently skip the file.
  2. **Column layout**: The Windows format puts the text label ("No Auditing", "Success", "Failure", "Success and Failure") in the Inclusion Setting column and the corresponding integer (0-3) in the Setting Value column. Our code had this backwards -- integer in Inclusion Setting, empty in Setting Value. The GPMC snapin calls `Convert.ToUInt32()` on Setting Value; an empty value throws a `FormatException` that crashes the Advanced Audit Policy snapin with "A severe error occurred... Input string was not in a correct format."
  3. **Subcategory name**: Windows format prepends "Audit " to every subcategory display name (e.g. "Audit Credential Validation", "Audit Audit Policy Change"). Updated to match.
  4. **GUID case**: Windows format uses lowercase GUIDs. Merge table keys also normalized to lowercase to prevent duplicate entries on idempotent re-deployment.
- `Get-ADPAGPOAdvancedAuditPolicy` -- Updated to derive the integer inclusion value from the Setting Value column (new format) with fallback to Inclusion Setting text or integer (backward-compatible with pre-fix deployments).

**Why:** Root cause identified by directly inspecting the SYSVOL audit.csv from a GPO that was manually configured through the GPMC UI and comparing field by field against what our code was generating. The column layout was inverted and the subcategory naming and GUID casing did not match the format the snapin expects.

**Impact:** GPOMgr version bumped from 1.7 to 1.8. Re-run "Deploy DC Baseline GPO" or "Deploy Standard Computer Baseline GPO", then `gpupdate /force` on target systems. GPMC should now open the Advanced Audit Policy section without errors and display all configured subcategories.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- audit.csv Write Verification

**Added:**
- `New-ADPAuditPolicyGpo` -- After `Set-ADPAGPOAdvancedAuditPolicy` writes audit.csv, immediately calls `Get-ADPAGPOAdvancedAuditPolicy` to read the file back from SYSVOL. Reports the confirmed row count if it matches the expected entry count, or a `[WARN]` with the actual vs expected count if there is a mismatch. This makes SYSVOL write failures immediately visible during deployment rather than requiring manual SYSVOL inspection.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- Security CSE Overwritten by Registry Writes

**Fixed:**
- `New-ADPAuditPolicyGpo` -- After writing Advanced Audit Policy subcategory settings (`audit.csv`) and security options (`GptTmpl.inf`) via `Set-ADPAGPOAdvancedAuditPolicy` and `Set-ADPAGPOSecuritySetting`, the function then called `Set-ADPAGPORegistrySetting` (which uses `Set-GPRegistryValue`) to write event log size settings and NTLM audit registry values. The native `Set-GPRegistryValue` GP API rewrites the GPO AD object's `gPCMachineExtensionNames` attribute to register the Registry CSE, overwriting the Security Settings CSE GUID (`{827D319E-6EAC-11D2-A4EA-00C04F79F83A}`) that the earlier `Update-GptIniVersion` calls had registered. With the Security CSE GUID absent from `gPCMachineExtensionNames`, the Group Policy client skips `audit.csv` and `GptTmpl.inf` entirely on every refresh -- audit subcategory settings never apply, and GPMC does not display the Security Settings section. The fix adds a confirmation block (step 5b) between the NTLM settings write and the GPO link that reads `gPCMachineExtensionNames` from the GPO AD object, and if the Security CSE GUID is missing, parses the existing blocks, appends the Security CSE block, sorts alphabetically, and writes the merged value back via `Set-ADObject`.

**Why:** Observed after deploying the DC Audit Policy baseline GPO: GPMC showed only event log size settings (Administrative Templates), with no Advanced Audit Policy or Security Settings sections. The root cause was confirmed by reading `gPCMachineExtensionNames` on the GPO AD object directly -- it contained only the Registry CSE GUID, not the Security CSE GUID.

**Impact:** Any previously deployed GPO created by `New-ADPAuditPolicyGpo` will not have applied its audit subcategory settings. Re-run "Deploy DC Baseline GPO" or "Deploy Standard Computer Baseline GPO" to re-deploy; the operation is idempotent and will update the AD object on the existing GPO. After re-deployment, run `gpupdate /force` on target systems.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 / AD-PowerAdmin_AuditPolicy.psd1 -- GPO Diagnostic Function

**Added:**
- `Test-ADPAuditPolicyGpoDiagnostic` -- Interactive six-check diagnostic for identifying why a deployed audit policy GPO is not producing the expected effective policy on a domain controller or member system. Checks performed in order: (1) GPO existence via Get-GPO; (2) Security Settings CSE GUID registration in the GPO AD object's gPCMachineExtensionNames attribute -- the most common cause of settings not applying; (3) GPO link state for all linked locations via Get-GPOReport; (4) SYSVOL content verification -- audit.csv row count, GptTmpl.inf presence and SCENoApplyLegacyAuditPolicy inclusion, and gpt.ini version vs AD object versionNumber consistency; (5) effective audit policy on the target system via auditpol.exe with baseline comparison showing exactly which subcategories are still wrong and what they are set to; (6) Group Policy Operational event log on the target system for the last 24 hours, identifying GP refresh events and Security CSE success/warning/failure events. Ends with a numbered resolution guide ranked by likelihood of root cause. Registered as a submenu item in AuditPolicyMenu.

**Why:** After deploying the audit policy GPO and running gpupdate /force, the compliance check continued to report the same Critical and High findings. The root cause was the missing Security CSE GUID in the GPO AD object (addressed in a prior fix), but operators needed a systematic tool to diagnose this and similar issues independently without requiring manual inspection of SYSVOL, Active Directory, or event logs.

**Impact:** AuditPolicy module version bumped from 1.2 to 1.3. The diagnostic is accessible from the Audit Policy Management submenu as a fifth option.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 -- GPO AD Object Not Updated After Security Settings Write

**Fixed:**
- `Update-GptIniVersion` -- Previously updated only the `gpt.ini` file on SYSVOL. The Group Policy client reads `gPCMachineExtensionNames` from the **GPO AD object** (not from `gpt.ini`) to determine which Client-Side Extensions (CSEs) to invoke. Because the Security Settings CSE GUID `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` was never written to the AD object's `gPCMachineExtensionNames` attribute, Windows silently skipped the Security CSE on every `gpupdate`. As a result, neither `GptTmpl.inf` (which sets `SCENoApplyLegacyAuditPolicy` and other security options) nor `audit.csv` (which sets Advanced Audit Policy subcategory settings) was ever processed by target computers, regardless of how many times Group Policy was refreshed. The fix extends `Update-GptIniVersion` to also call `Set-ADObject` on the GPO container object in Active Directory, updating both `gPCMachineExtensionNames` (to register the Security CSE) and `versionNumber` (to match the version in `gpt.ini`). Event log size settings were unaffected because those use `Set-GPRegistryValue`, which updates the AD object automatically.

**Why:** Discovered after a deployed GPO produced no change in `auditpol.exe` output even after `gpupdate /force`. Root cause: the Windows GP engine reads the CSE list from the AD object at policy application time, and our SYSVOL-only write left that attribute empty.

**Impact:** GPOMgr version bumped from 1.5 to 1.6. Any GPOs previously deployed by `New-ADPAuditPolicyGpo` or other modules using `Set-ADPAGPOSecuritySetting` or `Set-ADPAGPOAdvancedAuditPolicy` were not applying their security settings. Re-run the relevant deploy action to update the AD object on each affected GPO; the operation is idempotent and will not duplicate settings.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- SCENoApplyLegacyAuditPolicy Check Always Read Local Registry

**Fixed:**
- `Compare-ADPAuditPolicyBaseline` -- The `SCENoApplyLegacyAuditPolicy` registry check always read from the local machine's registry regardless of the `$ComputerName` parameter. When targeting a remote domain controller, `auditpol.exe` data came from the DC via `Invoke-Command` but the override key check ran against the local host, producing a false positive (or false negative) for every remote audit. The fix adds a `$IsLocal` check identical to the one used by `Get-ADPEventLogStorageStatus`; when `$ComputerName` is not the local machine, the registry read runs via `Invoke-Command` on the target system.

**Why:** The flaw caused the compliance report to show `SCENoApplyLegacyAuditPolicy` as non-compliant on a remote DC even after the GPO had correctly applied the setting on that DC, giving misleading Critical findings.

**Impact:** AuditPolicy module version bumped from 1.1 to 1.2. Remote compliance checks now correctly reflect the target system's override key state.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 -- Baseline Updates from Arctic Wolf Gap Analysis

**Changed:**
- `$script:AuditPolicyTemplates` (StandardComputer and DomainController) -- Updated both baselines following a gap analysis against Arctic Wolf's recommended GPO Advanced Audit Policy settings. Specific changes:
  - **DPAPI Activity** added to both baselines at Success. Captures access to DPAPI-protected secrets (browser credential stores, certificate private keys) used by credential theft tools.
  - **Network Policy Server** added to both baselines at Success+Failure. Captures VPN, wireless 802.1x, and RADIUS authentication events (6272-6280); relevant in any domain with NPS-based access control.
  - **Authorization Policy Change** upgraded from Success to Success+Failure in both baselines. The failure side captures attempts to remove user rights assignments, which succeeds silently without this setting.
  - **Security System Extension** upgraded from Success to Success+Failure in both baselines. The failure side captures blocked attempts to register unauthorized authentication packages or notification DLLs.
- `$script:AuditSubcategoryGuids` -- Added `'Network Policy Server'` GUID `{0CCE9243-69AE-11D9-BED3-505054503030}`.
- `$script:SubcategoryDescriptions` -- Added description for `'Network Policy Server'` for display in compliance findings.

**Not added (deliberately excluded):**
- Process Termination -- high volume, low investigative value for most environments; excluded from baseline.
- Token Right Adjusted -- niche subcategory suited for targeted investigation rather than a domain-wide baseline.
- Detailed File Share -- high volume per-file SMB access; better applied as a targeted policy on file servers rather than domain-wide.

**Why:** Arctic Wolf's sensor deployment guide identifies these subcategories as necessary for their AD sensor to function correctly. Cross-referencing against our existing baseline revealed four gaps where our coverage was either absent or less strict than the recommended setting.

**Impact:** Existing GPOs deployed before this change will not automatically update. Re-run "Deploy DC Baseline GPO" and "Deploy Standard Computer Baseline GPO" to push the updated settings; both operations are idempotent and will update existing GPOs without creating duplicates.

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 / AD-PowerAdmin_AuditPolicy.psd1 -- Help Page and GPO Enforcement

**Added:**
- `Show-ADPAuditPolicyHelp` -- Interactive help page accessible by pressing H in the Audit Policy Management submenu. Displays a purpose overview, a color-coded side-by-side subcategory comparison table (Standard Computer vs Domain Controller), event log size targets by role, and descriptions of the DC-only additional checks (SACL auditing and NTLM audit settings). Color coding distinguishes subcategories that are the same in both baselines (white), where DC requires more than Standard (cyan), and DC-only subcategories not required on standard computers (yellow).
- `Format-ADPAuditSettingLabel` -- Private helper. Converts an audit inclusion key (SuccessAndFailure, Success, Failure) to a compact display string for use in the help table.

**Changed:**
- `Initialize-Module` -- Added `HelpCommand = "Show-ADPAuditPolicyHelp"` to the AuditPolicyMenu submenu definition so pressing H in the submenu displays the help page.
- `New-ADPAuditPolicyGpo` -- Both GPO link calls now pass `-Enforced 'Yes'` to `Add-ADPAGPOLink`. The DC baseline GPO linked to the Domain Controllers OU and the Standard Computer GPO linked to the selected OU are both created as Enforced links, preventing lower-priority policies from overriding the audit policy baseline.

**Why:** Administrators needed a reference page explaining the tool's purpose and the specific differences between the two baselines without having to consult external documentation. Enforced links are required because audit policy GPOs must not be blocked by block-inheritance settings or overridden by lower-priority GPOs on the domain controllers OU; non-enforced links risk silent policy bypass.

**Impact:** Module version bumped from 1.0 to 1.1. The H key is now active in the submenu. GPO links created by future deployments will be Enforced; existing links from prior deployments can be updated by re-running the deploy action (the link call is idempotent and will set Enforced on the existing link).

---

### Modules/AD-PowerAdmin_AuditPolicy.psm1 / AD-PowerAdmin_AuditPolicy.psd1 -- New Module

**Added:**
- `Initialize-Module` -- Registers the "Audit Policy Management" main-menu entry and "AuditPolicyMenu" submenu with four actions: compliance check, Deploy DC Baseline GPO, Deploy Standard Computer Baseline GPO, and Export Report. Conditionally registers the daily unattended job when `$global:AuditPolicyDailyCheck` is `$true`.
- `Start-ADPAuditPolicyCheck` -- Orchestrates the full audit workflow. Detects local system role (Domain Controller, Member Server, Workstation), selects the appropriate baseline, collects effective audit policy and event log data, compares against the baseline, and prints color-coded findings. Domain controller runs also include SACL and NTLM audit checks. Optionally audits a second remote system for comparison via Invoke-Command. Supports `-Unattended` to suppress prompts and write findings to Reports/.
- `Get-ADPAuditPolicyStatus` -- Collects effective audit policy via `auditpol.exe /get /category:* /r` from local or remote systems. Returns parsed CSV objects for use by Compare-ADPAuditPolicyBaseline.
- `Get-ADPEventLogStorageStatus` -- Collects event log size, enabled state, retention mode, and record count from local or remote systems. Checks both the live log configuration and the ADMX GPO policy registry path.
- `Compare-ADPAuditPolicyBaseline` -- Compares auditpol and event log data against the Standard Computer or Domain Controller baseline. Returns structured finding objects with severity (Critical, High, Medium, Informational, Compliant) for every subcategory, event log, and the subcategory override registry key.
- `New-ADPAuditPolicyGpo` -- Creates and configures a baseline GPO. Writes Advanced Audit Policy subcategory settings to audit.csv via GPOMgr, sets the subcategory override security option, configures event log sizes via ADMX registry keys, and writes NTLM audit settings for the DC baseline. The DC GPO links automatically to the Domain Controllers OU; the Standard Computer GPO prompts for interactive OU selection.
- `Export-ADPAuditPolicyReport` -- Runs the compliance check without interactive prompts and exports all findings to a timestamped CSV in the Reports directory.
- `Test-ADPDirectoryServiceSacl` -- Domain-controller-only check. Validates that SACL audit rules are configured on the domain root and configuration partition objects. A missing SACL means Directory Service Access and Directory Service Changes audit subcategories generate no events regardless of policy settings.
- `Test-ADPNtlmAuditSettings` -- Domain-controller-only check. Reads and validates three NTLM audit registry values (RestrictSendingNTLMTraffic, AuditNTLMInDomain, InboundNTLMTraffic) against recommended settings for outbound, inbound, and domain NTLM authentication visibility.

**Why:** The Honeypot module revealed that audit policy was not enabled on the domain, silencing all security event subcategories the honeytoken depends on. A systematic module is needed to detect these gaps, report them with severity context, and deploy remediation via GPO.

**Impact:** Adds "Audit Policy Management" to the main menu with four interactive actions and one optional daily unattended job. No breaking changes to existing modules.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 / AD-PowerAdmin_GPOMgr.psd1 -- Advanced Audit Policy Support

**Added:**
- `Set-ADPAGPOAdvancedAuditPolicy` -- Writes Advanced Audit Policy subcategory settings to the `audit.csv` file in a GPO's SYSVOL path (`Machine\Microsoft\Windows NT\Audit\audit.csv`). Merges with any existing entries, writes UTF-8 without BOM, and increments the GPO machine version via `Update-GptIniVersion`. Required for deploying subcategory-level audit policy via GPO, which cannot be done through GptTmpl.inf.
- `Get-ADPAGPOAdvancedAuditPolicy` -- Reads and parses the `audit.csv` from a named GPO. Returns a collection of subcategory settings with integer inclusion values and text descriptions. Returns an empty collection if no audit.csv exists.

**Why:** The existing GPOMgr infrastructure covers GptTmpl.inf (account policy, security options, legacy audit) but not Advanced Audit Policy subcategory settings, which are stored in a separate `audit.csv` file. The AuditPolicy module requires this primitive to deploy subcategory-level baselines via GPO.

**Impact:** GPOMgr version bumped from 1.4 to 1.5. Both functions are added to `FunctionsToExport`. No changes to existing GPOMgr functions.

---

### AD-PowerAdmin_settings.ps1 -- Audit Policy Daily Check Flag

**Added:**
- `$global:AuditPolicyDailyCheck` -- Boolean flag (default `$false`). When set to `$true`, the AuditPolicy module registers its compliance check as a daily unattended job. Set to `$false` by default so the daily check is opt-in.

**Why:** Consistent with the pattern used by other daily-optional features (SmbAdminShareAudit, ExchangeADSecurityAudit, SysvolGppCpasswordAudit). Operators who want nightly audit policy monitoring enable it explicitly.

**Impact:** No functional change when left at the default `$false`.

---

### AD-PowerAdmin.ps1 / AD-PowerAdmin_settings.ps1 -- Dedicated Unattended Task Log

**Added:**
- `Initialize-UnattendedLog` in `AD-PowerAdmin.ps1` -- Starts a dedicated PowerShell
  transcript (`Reports\AD-PowerAdmin_Unattended.log`) at the beginning of every unattended
  run, independent of `$global:Debug`. Calls `Stop-AllTranscripts` first to handle the PS5
  single-transcript limitation before starting the new transcript in append mode.
- `$global:UnattendedLog` in `AD-PowerAdmin_settings.ps1` -- Boolean flag (default `$true`)
  that controls whether the dedicated unattended log is written. Set to `$false` to revert
  to debug-transcript-only behavior.

**Changed:**
- `Initialize-UnattendedLog` -- Made idempotent. Now checks which transcript is currently
  active via `Get-Transcript` before acting: does nothing if the unattended log is already
  running, stops only a different transcript (e.g., the debug log) quietly via
  `Stop-AllTranscripts | Out-Null`, then starts the unattended log. This prevents the
  PS5 pipeline-buffering artifact that caused a "Transcript stopped, output file is
  AD-PowerAdmin_Debug.log" line to appear as the first line of every unattended log session,
  and eliminates the two-session-per-run behavior (start marker in session 1, end marker
  in session 2, job output lost between them).
- `Start-Automation` -- Now calls `Initialize-UnattendedLog` at the start and at both exit
  paths (Daily and named-job) to ensure the log is active even when a module function starts
  and stops its own transcript mid-run. Run boundary markers
  (`=== Unattended Run Start/End ===`) are now written unconditionally instead of only when
  `$global:Debug` is true. `Stop-AllTranscripts | Out-Null` is called at the end of each
  run to close the log cleanly and suppress the console "Transcript stopped" message.

**Why:** Unattended scheduled jobs ran silently when `$global:Debug = $false`. Errors, output,
  and diagnostic information were lost with no audit trail. The dedicated log ensures every
  scheduled run is captured for post-incident analysis and routine review.

**Impact:** `Reports\AD-PowerAdmin_Unattended.log` is created on first unattended run and
  appended on all subsequent runs. The file is already covered by the `Reports` gitignore
  exclusion. No changes to scheduled task configuration are required.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 / AD-PowerAdmin_settings.ps1 -- Arctic Wolf Deception Enhancements

**Added:**
- `$global:HoneypotSPN` in `AD-PowerAdmin_settings.ps1` -- Stores the Kerberoasting bait SPN set
  on the honeytoken account during provisioning. Used by `Get-HoneypotEventsBatch` to enable
  Event 4769 monitoring and by `Test-HoneytokenUserSafety` to distinguish intentional from
  unexpected SPNs.
- `$SPN` parameter to `Set-HoneypotSettings` -- Persists the bait SPN to the settings file and
  syncs `$global:HoneypotSPN` into the running session when a value is provided.
- Second XPath query in `Get-HoneypotEventsBatch` for Event 4769 (Kerberos service ticket
  request) when `$global:HoneypotSPN` is non-empty. Event 4769 stores the target account in
  `ServiceName` (not `TargetUserName`), requiring a separate query. Events from both queries
  are merged and enriched uniformly. Severity for 4769 is HIGH.
- `SpnService` field on all seven honeytoken profiles -- Provides a context-appropriate service
  class (e.g., `MSExchangeMBx`, `HTTP`, `MSSQLSvc`) used to auto-generate the suggested SPN
  during installation.
- Kerberoasting bait SPN prompt in `Install-HoneypotAccount` -- Displays a suggested SPN based
  on the chosen profile's service class and domain FQDN. Admin can accept the suggestion, type
  a custom SPN, or enter N to skip. Includes SPN uniqueness conflict check before assignment.
- Reversible password encryption prompt in `Install-HoneypotAccount` -- Optional; marks the
  account as a DCSync high-value target without real credential risk (password is a random
  32-char string).
- `lastLogonTimestamp` population in `New-HoneytokenUser` -- Set to a random value 5-21 days
  prior to provisioning so the account appears actively used to any attacker enumerating AD
  objects. Uses `Set-ADUser -Replace @{ lastLogonTimestamp = $FileTimeValue }` (100ns intervals
  since 1601-01-01 UTC); replicates domain-wide unlike `lastLogon`.
- Kerberoasting indicator line in `Start-HoneypotMonitor` alert body -- Appended when
  `$global:HoneypotSPN` is set: "Kerberoasting attack (Event 4769: service ticket requested
  for bait SPN ...)."
- Per-event `ServiceName` and `TicketOptions` fields in `Start-HoneypotMonitor` alert body --
  Included for Event 4769 events only, giving the responder the full service ticket context.
- `$global:HoneypotSPN` in `New-HoneypotLiteSettingsContent` -- Propagated to the lite
  `AD-PowerAdmin_settings.ps1` generated for decentralized DC deployments so each DC's local
  monitor can run the 4769 query when a bait SPN is configured.

**Changed:**
- Honeytoken profile descriptions -- All seven profiles now carry an enticing fake-credential
  hint in the `Description` field (e.g., "Backup sync svc acct - temp pw: Backup@2024"). These
  descriptions are visible to any user with read access to the AD object and are designed to
  attract an attacker who has enumerated the account and is looking for clues to its password.
- `New-HoneytokenUser` -- Extended with `$SpnValue` and `$EnableReversibleEncryption` parameters.
  Sets `AllowReversiblePasswordEncryption` on the new account, populates `lastLogonTimestamp`,
  and assigns the bait SPN (with conflict check) when provided. SPN assignment failures are
  non-fatal warnings.
- `Install-HoneypotAccount` -- Now calls `Set-HoneypotSettings -SPN $SpnValue` to persist the
  configured SPN alongside the existing account settings.
- `Test-HoneytokenUserSafety` SPN check -- Now context-aware. When `$global:HoneypotSPN` is
  set: reports `[OK]` if the configured SPN is present, `[WARN]` if it is missing, and `[FAIL]`
  only for unexpected additional SPNs. When no SPN is configured: original behavior (any SPN
  is a `[FAIL]`).

**Why it was changed:** Informed by a review of the Arctic Wolf Active Directory decoy account
methodology. A honeytoken account that looks identical to a freshly created test account is less
likely to be targeted by skilled attackers who may recognize the pattern. Realistic attributes --
a recent `lastLogonTimestamp`, an enticing description, and a Kerberoastable SPN -- make the
account indistinguishable from a real, carelessly administered service account. The Kerberoasting
SPN also adds a second, independent detection vector (Event 4769 on any Kerberoast tooling
attempt) that fires even if the attacker never attempts to authenticate.

**Impact:** Any new honeytoken deployment gains three additional deception layers and a second
detection event channel. Existing deployments are unaffected until re-provisioned; the
`Test-HoneytokenUserSafety` SPN check remains a safe `[OK]` for accounts without any SPN and
is no longer a false `[FAIL]` for accounts with the intentional bait SPN.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- Honeytoken Detection Test: Credential Bypass Fix and Audit Policy Check

**Fixed:**
- `Invoke-HoneypotTestAuthAttempt` -- Replaced `System.DirectoryServices.DirectoryEntry` with
  `System.DirectoryServices.Protocols.LdapConnection.Bind(NetworkCredential)`. `DirectoryEntry`
  with `AuthenticationTypes.Secure` on a domain-joined machine uses Windows SSPI Negotiate, which
  can transparently fall back to the current session's Kerberos TGT instead of the provided
  credentials. The result was that the admin's session authenticated successfully (reported as
  `[CRITICAL]`), and no events for the honeytoken account were generated. `LdapConnection.Bind`
  with an explicit `NetworkCredential` object creates a new SSPI context forced to use only the
  provided credentials, preventing any session-credential fallback. Also changed `AutoBind = $false`
  to prevent any implicit bind before the explicit credential bind.

**Added:**
- `Test-HoneypotAuditPolicy` (private) -- Checks the four Security audit subcategories required
  for honeytoken event detection by querying `auditpol.exe` in CSV mode (`/r`) with subcategory
  GUIDs (language-independent). Reports `[OK]` or `[WARN]` with a remediation command for each:
  Logon (4624/4625), Account Lockout (4740), Kerberos Authentication Service (4768/4771), and
  Kerberos Service Ticket Operations (4769). Returns `$false` if any subcategory is "No Auditing".
- Audit policy prerequisite check in `Invoke-HoneypotDetectionTest` -- `Test-HoneypotAuditPolicy`
  is called once on menu entry. If any subcategory is disabled, a warning is shown before the test
  menu so the admin knows events may not be generated even if the tests run correctly.

**Why it was fixed:** The original `DirectoryEntry` implementation produced a false `[CRITICAL]`
  on every run (current session credentials used), zero honeytoken events in the Security log, and
  no useful diagnostic information about why the monitor found nothing. The audit policy check
  addresses the second common failure mode: even with correct credential handling, event logging
  requires the appropriate subcategories to be enabled on the DC. On default Windows Server
  installations, "Kerberos Service Ticket Operations" (required for Event 4769) is not enabled.

**Impact:** The auth test now generates real Events 4625/4768/4771 for the honeytoken account.
  The audit policy check makes the prerequisite for event logging explicit before any test runs,
  turning a silent "0 events found" into an actionable "enable this subcategory" diagnosis.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- Honeytoken End-to-End Detection Test

**Added:**
- `Invoke-HoneypotDetectionTest` (public) -- Interactive menu that triggers controlled
  authentication events against the honeytoken account so administrators can verify that Security
  Event Log detection and email alerting are functioning correctly after deployment. Displays
  current account, SPN, and monitor configuration at the top of the menu. Options: [1] trigger
  a deliberate failed authentication attempt, [2] request a Kerberos service ticket against the
  bait SPN, [3] do both in sequence, [4] run the honeytoken monitor immediately, [Q] return to
  the submenu. After triggering test events, prompts the admin to run the monitor with a 3-second
  wait for events to reach the Security log. Accessible from the Honeytoken Management submenu.
- `Invoke-HoneypotTestAuthAttempt` (private) -- Sends a deliberate failed LDAP bind as the
  honeytoken account using a randomly generated wrong password via `System.DirectoryServices
  .DirectoryEntry` with `AuthenticationTypes.Secure`. Generates Events 4625 (failed network logon),
  4768 (Kerberos TGT request), and/or 4771 (Kerberos pre-authentication failure) on the DC that
  handles the request. Reports CRITICAL if authentication unexpectedly succeeds (indicates GPO
  deny-logon restriction is not in effect).
- `Invoke-HoneypotTestServiceTicket` (private) -- Invokes `klist.exe get <SPN>` against the
  configured bait SPN to force a new TGS-REQ to the KDC, bypassing the local ticket cache.
  The KDC resolves the SPN in AD (not DNS, so the non-existent service hostname is irrelevant)
  and issues a service ticket, generating Event 4769 (Kerberos service ticket request) with
  `ServiceName` matching the honeytoken sAMAccountName. Skipped with a `[SKIP]` message when no
  bait SPN is configured (`$global:HoneypotSPN` is empty).
- `HoneypotDetectionTest` submenu item in `Initialize-Module` -- Registers the test in the
  Honeytoken Management submenu so it is accessible from the interactive menu.

**Why it was added:** After deploying a honeytoken account and monitor, there was no in-tool way
to verify that the full detection chain is working. The account may be correctly provisioned and
the scheduled task may exist, yet the monitor might fail to send alerts due to SMTP misconfiguration,
event log permission issues, or incorrect account name settings. `Invoke-HoneypotDetectionTest`
provides a one-click smoke test that generates real Security log events and immediately optionally
runs the monitor, confirming or exposing gaps in the detection pipeline.

**Impact:** Administrators can validate the honeytoken system immediately after installation without
waiting for an organic attack event. Both authentication events (4625/4768/4771) and Kerberoasting
events (4769) can be tested independently, allowing targeted diagnosis of which event type is or is
not being detected correctly.

---

### AD-PowerAdmin.ps1 / Modules/AD-PowerAdmin_Honeypot.psm1 -- Honeytoken Help Guide and OU Browser

**Added:**
- `Show-HoneypotHelp` (public) -- Displays the Honeytoken system deployment guide: an overview
  of the two-layer architecture (account + monitor), the correct installation order (account
  provisioning, GP propagation, safety verification, optional decentralized deployment), the correct
  removal order (decentralized first, then account removal), and operational notes. Accessible from
  the Honeytoken Management submenu by pressing H.
- `HelpCommand` field in the `HoneypotMenu` submenu definition -- Points `Enter-SubMenu` to
  `Show-HoneypotHelp` when the user presses H.
- `Enter-SubMenu` in `AD-PowerAdmin.ps1` -- Added optional `HelpCommand` support. When a submenu
  definition includes a `HelpCommand` key, the footer shows "h. Help / Deployment Guide" and
  pressing H invokes the command. Submenus without `HelpCommand` are unaffected. The H dispatch
  follows the same pattern as numbered item dispatch: `Invoke-Expression`, surrounded by the green
  separator lines, followed by `Pause`.

**Changed:**
- `Install-HoneypotAccount` -- Replaced the manual OU distinguished-name entry block (flat list of
  top-level OUs + freeform text input + ad-hoc validation) with a `Get-AdOuSearch` call. The admin
  now navigates the OU tree interactively level by level, drilling in by number, pressing S to select
  the current location, or Q to cancel. Cancelling returns to the submenu without provisioning.

**Why it was changed:** The manual DN entry was error-prone (typos in long DN strings) and required
the admin to know the exact path in advance. `Get-AdOuSearch` provides the same hierarchical browser
already used by the GPO deployer and settings wizard, giving a consistent experience across all
OU-selection prompts in the tool. The help guide addresses a usability gap: operators who are
unfamiliar with the two-mode architecture or the required install/removal sequence have no in-tool
reference. The H key follows the same convention as Q (special letter inputs in the submenu footer).

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 -- Registry Verification Fix (Test-ADPAGPO, Find-ADPAGPOsWithRegistrySetting)

**Fixed:**
- `Test-ADPAGPO` -- Replaced the XML-report-based registry setting check with
  `Get-GPRegistryValue`. The previous implementation used XPath `//q:RegistrySetting` to parse the
  `Get-GPOReport` XML output, which silently returns zero nodes for "Extra Registry Settings"
  (settings stored via `Set-GPRegistryValue` at paths not backed by an ADMX template, such as
  `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash`). This caused a false `[FAIL]` on every
  registry-setting verification even when the setting was correctly applied and visible in GPMC.
  `Get-GPRegistryValue` reads the GPO's registry policy data directly and correctly returns the
  value regardless of ADMX backing.
- `Find-ADPAGPOsWithRegistrySetting` (private, also known as `Search-ADPAGPOSetting`) -- Same root
  cause: replaced the XML report scanning loop (`Get-GPOReport` + XPath) with per-GPO
  `Get-GPRegistryValue` calls. The old approach never matched Extra Registry Settings, so the
  overlap/conflict check always reported no existing coverage even when a GPO already enforced the
  setting. The new approach finds both ADMX-backed and Extra Registry Settings correctly.
- `Get-GPOXmlReport` (private) -- Removed. Was only called by `Test-ADPAGPO`; both callers now
  use `Get-GPRegistryValue` instead.

**Why it was changed:** `Get-GPOReport -ReportType Xml` does not expose "Extra Registry Settings"
(non-ADMX-backed settings set via `Set-GPRegistryValue`) under the expected `RegistrySetting` XML
element in a form that the XPath query was designed to find. The symptom is a `[FAIL]` on the
post-deployment verification step even though the GPO is correctly configured, as confirmed by
GPMC showing `SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash 1` under the GPO's Computer
Configuration. `Get-GPRegistryValue` is the correct API for this use case -- it reads the Registry.pol
file directly and works for all registry-backed settings regardless of ADMX backing.

**Impact:** `Test-ADPAGPO` with `-RegistrySettings` now correctly reports `[PASS]` for Extra
Registry Settings such as the LM hash and SMB signing settings deployed by
`AD-PowerAdmin_GPOBestPracticesDeployer`. `Find-ADPAGPOsWithRegistrySetting` (the overlap checker
called before each best-practice deployment) now correctly identifies existing coverage and prevents
duplicate GPOs.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 / AD-PowerAdmin_GPOBestPracticesDeployer.psm1 -- Overlap Detection (GPOMgr v1.4)

**Added (GPOMgr):**
- `Search-ADPAGPOSecuritySetting` -- Scans all GPO security templates (GptTmpl.inf) for a
  supplied list of Section + Key pairs in a single SYSVOL pass per GPO. Returns one result
  per match with `ActualValue`, `ExpectedValue`, and `Matches` (bool) to classify exact vs
  partial overlaps. Partial matches (same setting, different value) indicate a potential
  policy conflict. Efficient for multi-setting entries such as the password policy (8 keys
  resolved in one read per GPO rather than 8 separate scans).

**Added (BestPracticesDeployer):**
- `Show-BPCoverageReport` (private) -- Formats and displays coverage results grouped by GPO
  name. Exact matches are shown in green; partial matches (conflicting values) in yellow.
  Displays a legend distinguishing the two match types. Called before the mode selection
  prompt so the administrator can see the full overlap picture before committing to deploy.

**Changed (BestPracticesDeployer):**
- Coverage check in `Invoke-GPOBestPracticeDeployment` -- Completely rewritten. Now searches
  both registry settings (via existing `Search-ADPAGPOSetting`) and security template settings
  (via new `Search-ADPAGPOSecuritySetting`). Results are collected into a unified list and
  passed to `Show-BPCoverageReport` for display. Partial matches (same setting, different
  value) are now detected and clearly flagged, allowing the administrator to identify
  conflicting policies before proceeding. If no overlaps are found, a clean confirmation
  message is shown.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 / AD-PowerAdmin_GPOBestPracticesDeployer.psm1 -- Configurable Settings and Security Template Support (GPOMgr v1.3, Deployer v1.2)

**Added (GPOMgr):**
- `Set-ADPAGPOSecuritySetting` -- Writes a key-value pair to a GPO's security template
  (GptTmpl.inf) on the domain SYSVOL. Handles directory and file creation, INF section
  management, gpt.ini version increment, and Security Configuration Engine CSE GUID
  registration. Used for account policy, lockout policy, and security option settings that
  cannot be set via `Set-GPRegistryValue`.
- `ConvertFrom-IniString` (private) -- Parses INI-format strings into an ordered hashtable
  of sections. Supports GptTmpl.inf and gpt.ini file reads.
- `ConvertTo-IniLines` (private) -- Serializes a section hashtable back to INI-format strings.
- `Update-GptIniVersion` (private) -- Increments the machine-side version counter in gpt.ini
  and registers the Security Configuration Engine CSE GUID so Windows processes the updated
  security template on the next Group Policy refresh.

**Added (BestPracticesDeployer):**
- `Resolve-ConfigurableSettings` (private) -- Iterates a settings array and, for each entry
  where `Configurable = $true`, displays the `Prompt`, shows the default `Value`, and prompts
  the administrator to accept or override. Returns a resolved copy of the array with final
  values substituted.
- `DefaultDomainPasswordPolicy` entry in `$script:GPOBestPractices` -- Configures the domain
  password and account lockout policy via eight `SecuritySettings` entries (MinimumPasswordLength,
  PasswordComplexity, PasswordHistorySize, MaximumPasswordAge, MinimumPasswordAge,
  LockoutBadCount, LockoutDuration, ResetLockoutCount). All numeric fields are configurable
  with recommended defaults pre-filled. Applies to all domain user accounts; the description
  warns that account policy is only enforced by GPOs linked to the domain root.

**Changed (BestPracticesDeployer):**
- `$script:GPOBestPractices` entry schema -- `RegistrySettings` entries now support two
  optional fields: `Configurable` [bool] and `Prompt` [string]. A new `SecuritySettings`
  array field is available on each entry for security template settings using the same
  `Section`, `Key`, `Value`, `Configurable`, `Prompt` structure.
- `Invoke-BestPracticeApplyToDDP` -- Calls `Resolve-ConfigurableSettings` before deployment.
  Handles both `RegistrySettings` (via `Invoke-ADPAGPOModification`) and `SecuritySettings`
  (via `Set-ADPAGPOSecuritySetting`). For entries with only `SecuritySettings`, calls
  `Backup-ADPAGPO` directly to satisfy the backup-before-modify contract.
- `Invoke-BestPracticeCreateNewGpo` -- Calls `Resolve-ConfigurableSettings` before GPO
  creation. Applies both `RegistrySettings` and `SecuritySettings` after creation.
- `Invoke-GPOBestPracticeDeployment` -- Display block now shows `SecuritySettings` summary
  alongside `RegistrySettings`, and marks configurable fields with `[configurable]`. Coverage
  check is guarded so it only runs when `RegistrySettings` is non-empty.

---

### Modules/AD-PowerAdmin_GPOBestPracticesDeployer.psm1 -- Require SMB Signing Best Practice

**Added:**
- `RequireSmbSigning` entry in `$script:GPOBestPractices` -- Enforces SMB packet signing for
  both client-side (outbound) and server-side (inbound) SMB communications by setting
  `RequireSecuritySignature = 1` at both the LanManWorkstation and LanManServer registry paths.
  Eliminates unsigned SMB sessions that are vulnerable to relay-style attacks and in-transit
  tampering. Applies to all domain-joined computers. Includes a compatibility note warning
  administrators to pilot before broad deployment due to potential impact on legacy NAS devices,
  older Samba servers, and unsupported SMB appliances.

**Added:**
- `AD-PowerAdmin.wiki/Vulnerabilities/SMB-Signing-Not-Required.md` -- New vulnerability dossier
  covering the SMB signing not required weakness, relay attack mechanics, both required registry
  settings (client and server), affected scope, compatibility considerations, rollout guidance,
  PowerShell detection commands, and MITRE ATT&CK T1557.001 reference.

---

### Modules/AD-PowerAdmin_GPOBestPracticesDeployer.psm1 -- AppliesTo Scope Field

**Changed:**
- `$script:GPOBestPractices` entries -- Added `AppliesTo` field (string array) to the per-entry
  schema. Specifies the account or computer scope the policy targets (e.g. `'All Computers'`,
  `'Workstations'`, `'Domain Controllers'`, `'User Accounts'`). Displayed during deployment to
  guide the administrator toward the correct OU or link target.
- `Invoke-GPOBestPracticeDeployment` -- Now displays the `AppliesTo` scope line between the
  title and the description during deployment.
- `DisableLMHash` entry -- `AppliesTo` set to `@('All Computers', 'Workstations', 'Servers',
  'Domain Controllers')`, reflecting that the `NoLMHash` setting is a Computer Configuration
  policy that should be applied to all domain-joined machines.

---

### Modules/AD-PowerAdmin_GPOBestPracticesDeployer.psm1 -- Data-Driven Architecture (v1.1)

**Changed:**
- `Initialize-Module` -- Rewritten to build the submenu dynamically from `$script:GPOBestPractices`.
  Each entry in that array becomes a numbered submenu item automatically. No code changes are
  required when adding a new setting.

**Added:**
- `$script:GPOBestPractices` (module-scope data array) -- The single location where all
  best-practice GPO settings are defined. Each entry is a hashtable with fields: `Id`, `Title`,
  `Label`, `Description` (string array), `Note`, `DefaultGpoName`, `GpoDescription`, and
  `RegistrySettings` (hashtable array). The first entry defines the Disable LM Hash Storage
  setting.
- `Invoke-GPOBestPracticeDeployment` -- Generalized public deployment function. Looks up the
  best practice by `Id`, displays the description and registry details, checks for existing GPO
  coverage across all registry settings in the definition, prompts for application mode, and
  dispatches to `Invoke-BestPracticeApplyToDDP` or `Invoke-BestPracticeCreateNewGpo`. Handles
  any entry in `$script:GPOBestPractices` without modification.
- `Invoke-BestPracticeApplyToDDP` (private) -- Applies all registry settings from any best-practice
  definition to the Default Domain Policy via `Invoke-ADPAGPOModification`.
- `Invoke-BestPracticeCreateNewGpo` (private) -- Creates a new GPO, applies all registry settings
  from any best-practice definition, navigates the OU tree via `Get-AdOuSearch`, links, and
  verifies the deployed state via `Test-ADPAGPO`.
- `Select-GPOApplicationMode` (private) -- Prompts the user to choose DDP, new GPO, or cancel.

**Removed:**
- `Set-BestPracticeDisableLMHashStorage` -- Replaced by `Invoke-GPOBestPracticeDeployment` with
  the `'DisableLMHash'` best practice ID. All functionality preserved; the LM hash setting is now
  a data entry rather than a dedicated function.
- `Get-LMHashGpoRegistrySetting` (private) -- Registry details are now stored directly in the
  `$script:GPOBestPractices` array entry.
- `Invoke-LMHashApplyToDDP` (private) -- Replaced by the generalized `Invoke-BestPracticeApplyToDDP`.
- `Invoke-LMHashCreateNewGpo` (private) -- Replaced by the generalized `Invoke-BestPracticeCreateNewGpo`.

**Why it was changed:** The original implementation hard-coded each setting as a dedicated public
function and required changes in three places (function definition, `Initialize-Module`, and
`FunctionsToExport`) to add a new best practice. The refactored design defines settings as data
entries. Adding a new setting requires only one change: appending an entry to
`$script:GPOBestPractices`. The deployment workflow, menu registration, and conflict detection
are fully reused for every entry.

**Impact:** Module version bumped to 1.1. `FunctionsToExport` updated: `Set-BestPracticeDisableLMHashStorage`
replaced by `Invoke-GPOBestPracticeDeployment`. Existing LM hash functionality is preserved; the
submenu item now calls `Invoke-GPOBestPracticeDeployment 'DisableLMHash'`.

---

### Modules/AD-PowerAdmin_GPOMgr.psm1 -- Backup/Restore and Modification Safety

**Added:**
- `Backup-ADPAGPO` -- Backs up a single named GPO to `$global:ReportsPath\GPOBackups\`. Returns a
  structured result object with the backup ID, backup path, status, and any errors.
- `Backup-AllADPAGPOs` -- Backs up every GPO in the domain to the same backup directory. Returns a
  structured result with the GPO count and status.
- `Get-ADPAGPOBackupList` -- Enumerates the backup directory, parses `bkupInfo.xml` from each
  backup subfolder, and returns a sorted list of backup objects (GPO name, timestamp, ID, path).
  Returns newest-first. Used by `Restore-ADPAGPOBackup` and by administrators auditing restore
  points.
- `Restore-ADPAGPOBackup` -- Presents an interactive numbered backup picker using `Show-Menu` and
  restores the selected backup after explicit `YES` confirmation. Accepts `-BackupId` for
  non-interactive use. Returns a structured result.
- `Invoke-ADPAGPOModification` -- Safe wrapper for modifying existing GPOs. Always calls
  `Backup-ADPAGPO` before any change. If the backup fails the function aborts immediately and
  returns a failure result -- it never silently continues after a failed backup. Other modules
  must use this function (not `Set-ADPAGPORegistrySetting` directly) when modifying an existing
  GPO.
- `Invoke-GPOMgrBackupSingleMenu` (private) -- Presents a numbered list of all domain GPOs via
  `Show-Menu` and calls `Backup-ADPAGPO` on the selection. Used by the interactive submenu.

**Changed:**
- `Initialize-Module` -- Previously empty (library-only module). Now registers the "GPO Manager"
  submenu in `$global:Menu` and `$global:SubMenus` with four interactive actions: Backup All
  GPOs, Backup a GPO, List GPO Backups, and Restore a GPO.

**Why it was changed:** The GPO Manager was a library-only module with no backup or restore
capability and no interactive menu presence. Any module modifying an existing GPO had no
framework-level safety mechanism to protect the prior state. Adding `Invoke-ADPAGPOModification`
enforces backup-before-modify as a framework contract, and the new backup/restore functions give
administrators a recovery path when a GPO change has unintended consequences.

**Impact:** Module version bumped from 1.1 to 1.2. The GPO Manager now appears in the
AD-PowerAdmin interactive menu. `Invoke-ADPAGPOModification` is the required API path for any
existing-GPO modification in the framework. Backup files are stored under
`$global:ReportsPath\GPOBackups\` and persist across sessions.

---

### Modules/AD-PowerAdmin_GPOMgr.psd1 -- Version 1.2

**Changed:**
- `ModuleVersion` bumped from `1.1` to `1.2`.
- `FunctionsToExport` updated to include the five new public functions: `Backup-ADPAGPO`,
  `Backup-AllADPAGPOs`, `Get-ADPAGPOBackupList`, `Restore-ADPAGPOBackup`,
  `Invoke-ADPAGPOModification`.
- `ReleaseNotes` updated to describe v1.2 additions.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- GPO-Based Scheduled Task Deployment

**Added:**
- `New-HoneypotDCTaskGPOContent` (private) -- Generates the GPP `ScheduledTasks.xml` string for
  the decentralized DC monitor scheduled task. Uses the `TaskV2` GPP element (Vista+), runs as
  `NT AUTHORITY\System` with S4U logon (no stored password), uses `action="R"` (Replace) for
  idempotent updates, and sets a fixed `uid` so re-running the install updates the same GPP entry
  rather than creating duplicate tasks. The `StartBoundary` of `2000-01-01T00:00:00` ensures the
  task starts immediately on the first GP apply.
- `Install-HoneypotDCTaskGPO` (private) -- Creates (or updates) the `AD-PowerAdmin_HoneypotDCMonitor`
  GPO, links it to the Domain Controllers OU via `Install-ADPAGPOBaseline`, writes the GPP
  `ScheduledTasks.xml` to SYSVOL, increments the GPT.INI computer version counter, and updates the
  GPO AD object with the GPP Scheduled Tasks extension GUIDs
  (`{AADCED64-746C-4633-A97C-D61349046527}` / `{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}`) and the new
  version number, targeting the PDC emulator to avoid replication-lag failures.

**Changed:**
- `Invoke-HoneypotDCDeploy` -- Removed `$RunAsUser`, `$RunAsPassword`, and `$AdminCred` parameters.
  Removed the `Invoke-Command` (PSRemoting) block that registered the scheduled task. The function
  is now file-deployment only (UNC directory creation, ACL hardening, file copy, settings file write).
  The scheduled task is no longer registered per-DC; it is deployed domain-wide by the GPO after all
  file copies. Immediately after creating the root deployment directory, sets a restrictive NTFS ACL
  via `System.Security.AccessControl.DirectorySecurity`: inheritance is disabled
  (`SetAccessRuleProtection($true, $false)`), inherited ACEs are discarded, and only
  `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` are granted Full Control with
  `ContainerInherit,ObjectInherit` propagation. Subdirectories and all copied files inherit this ACL
  automatically. This prevents any non-administrative account from modifying the scripts that run
  as SYSTEM, eliminating a privilege-escalation path via scheduled-task script replacement.
- `Install-HoneypotDecentralized` -- Removed the "Scheduled task identity" run-as selection block
  and the `Get-Credential` admin credentials prompt (neither are required for UNC-only file copy or
  GPO-based task deployment). Updated the deployment summary to show "via GPO" instead of
  "Scheduled task as". Added a `Install-HoneypotDCTaskGPO` call after the per-DC file copy loop;
  reports GPO creation success or failure and instructs the operator to run `gpupdate /force` for
  immediate application. Updated the docstring to remove all PSRemoting prerequisites.
- `Remove-HoneypotDecentralized` -- Removed the `Invoke-Command` (PSRemoting) block and the
  `Get-Credential` admin credentials prompt. Replaced with: (1) a prompt to remove the
  `AD-PowerAdmin_HoneypotDCMonitor` GPO via `Remove-ADPAGPO -RemoveLinks` (removes the task from
  all DCs on next GP refresh), and (2) per-DC UNC directory removal using `Remove-Item` against the
  admin share path. No PSRemoting or WinRM required for either operation.

**Why it was changed:** The original `Invoke-Command` approach required WinRM to be reachable on
each target DC. Domain controllers are frequently hardened to block inbound WinRM connections.
Group Policy Preferences scheduled task delivery uses only the standard AD/SYSVOL channels (LDAP
and SMB) already required for domain membership, eliminating the WinRM dependency entirely.

**Impact:** `Install-HoneypotDecentralized` no longer prompts for run-as account or admin
credentials. The task is always deployed as `NT AUTHORITY\System` via GPO and applies to all DCs
in the Domain Controllers OU. DCs without the files will have the task registered but it exits
immediately when the script file is not found. `gpupdate /force` applies the task without waiting
for the background GP refresh (~90 minutes).

---

### Modules/AD-PowerAdmin_Installer.psm1 -- Progress Bar Bug Fix

**Fixed:**
- `Update-ADPowerAdminModules` -- Set `$ProgressPreference = 'SilentlyContinue'` around all
  `Invoke-WebRequest` calls and restore the original value on exit. In Windows PowerShell 5.1,
  `Invoke-WebRequest` renders a download progress bar to the host buffer by default; when many
  requests are made in a loop the terminal appears frozen and requires a manual Enter press to
  continue. Suppressing the progress bar eliminates the hang.
- `Update-ADPowerAdminSettingsFile` -- Same fix applied. Progress preference is suppressed for the
  duration of the function and restored in the `finally` block.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- Decentralized Monitor Mode

**Added:**
- `$global:HoneypotMonitorMode` (settings variable) -- Controls the monitor's DC query strategy.
  `'Centralized'` (default) remotely queries all DCs over RPC. `'Decentralized'` queries only the
  local machine (`$env:COMPUTERNAME`), bypassing RPC entirely for a direct Security log read.
  The lite settings file generated by `Install-HoneypotDecentralized` sets this to
  `'Decentralized'` on each target DC.
- `New-HoneypotLiteSettingsContent` (private) -- Generates the full text of a minimal
  `AD-PowerAdmin_settings.ps1` for a decentralized DC deployment. Includes only the six Honeytoken
  variables, SMTP settings, email addresses, `ReportsPath` (set to `$DeployPath\Reports`), `Debug`,
  and `MsaAccountName`. Sets `HoneypotMonitorMode = 'Decentralized'` so the local task queries only
  the local Security log.
- `Invoke-HoneypotDCDeploy` (private) -- Copies the minimum file set to one DC via the UNC admin
  share (`\\DC\C$\...`), writes the generated lite settings file, and registers the
  `AD-PowerAdmin_HoneypotMonitor` scheduled task on the DC via `Invoke-Command` PSRemoting. Supports
  `NT AUTHORITY\SYSTEM` (no stored password) or a specified domain user as the task principal.
  Returns `$true` on full success, `$false` on any step failure. Writes `[OK]` / `[FAIL]` per step.
- `Install-HoneypotDecentralized` (public) -- Interactive wizard that deploys the decentralized
  monitor to one or more DCs. Enumerates all DCs, presents a numbered selection list, prompts for
  the deployment path (default: `C:\ADPowerAdmin-Monitor`), the scheduled task identity (SYSTEM or
  domain user), and admin credentials for PSRemoting and file copy. Displays a deployment summary
  and requires explicit confirmation before proceeding. Reports per-DC success or failure and
  reminds the operator to update `HoneypotMonitorMode` on the central server if centralized
  monitoring should be disabled. Registered in the Honeytoken Management submenu as
  "Deploy Decentralized Monitor".
- `Remove-HoneypotDecentralized` (public) -- Interactive cleanup wizard. Enumerates all DCs,
  presents a selection list, removes the `AD-PowerAdmin_HoneypotMonitor` scheduled task from each
  selected DC via PSRemoting, and optionally removes the deployment directory. Reports per-DC
  success or failure. Registered in the Honeytoken Management submenu as
  "Remove Decentralized Monitor".

**Changed:**
- `Get-HoneypotEvents` -- Replaced the hardcoded `Get-ADDomainController -Filter *` call with a
  mode branch. In Centralized mode: enumerates all domain controllers (existing behavior). In
  Decentralized mode: sets the target list to `@($env:COMPUTERNAME)` only, with a `[Decentralized]`
  label in the console output.
- `Get-HoneypotEventsBatch` -- Added local fast-path detection. When `$ComputerName` matches
  `$env:COMPUTERNAME`, `localhost`, or `127.0.0.1`, the `Get-WinEvent` call omits `-ComputerName`
  entirely, using direct local log file access instead of RPC/DCOM. The `[DC-DATA]` timing output
  now labels the query as `(local)` or `(remote)` for clarity.

**Why it was built:** The centralized monitor queries every domain controller's Security Event Log
over RPC. On resource-constrained DCs, the Windows Remote Event Log Service must scan the full
Security log before returning results, even with server-side XPath filtering. This scan can take
60-90 seconds or more per DC. The decentralized mode eliminates this overhead by running the query
locally on each DC, where the Security log is accessed as a local file with no network round-trip.
A single DC deployment takes well under one second when running locally.

**Impact:** `HoneypotMonitorMode = 'Centralized'` in settings preserves all existing behavior with
no changes to normal operation. The two new public functions appear in the Honeytoken Management
submenu. The two new private functions are not exported. No changes to any other module.

---

### Modules/AD-PowerAdmin_Installer.psm1 and AD-PowerAdmin_Installer.psd1 -- Settings Configuration Wizard

**Added:**
- `Start-SettingsWizard` -- Interactive wizard that walks an administrator through every
  configurable variable in `AD-PowerAdmin_settings.ps1`, section by section. Reads the current
  file, displays each variable's current value as the default, collects replacements via
  `Read-Host` (Enter = keep current), builds a pre-write summary, creates a `.bak` backup, and
  writes the updated file using `[System.IO.File]::WriteAllText` with UTF-8 encoding. Supports
  AD OU browsing for DN-type settings. Accessible from the AD-PowerAdmin Management submenu.
- `Read-SettingBool` (private) -- Prompts for a yes/no choice with the current `$true`/`$false`
  default shown; returns `[bool]`.
- `Read-SettingString` (private) -- Prompts for a string value with the current default shown;
  pressing Enter keeps the existing value. Enforces `MaxLength` when supplied (used to limit
  `MsaAccountName` to 14 characters).
- `Read-SettingInt` (private) -- Prompts for an integer with the current default shown; validates
  numeric input and enforces a minimum value; pressing Enter keeps the existing value.
- `Read-SettingOuPath` (private) -- Prompts for an OU DistinguishedName. Supports `?` to invoke
  the AD OU browser, validates typed DNs against Active Directory before accepting them, and
  supports `AllowEmpty` for optional OU settings.
- `Get-AdOuSearch` (private) -- Consumed from `AD-PowerAdmin_Utils`; see Utils entry below.
- `Set-SettingsFileValue` (private) -- Applies a targeted regex replacement to the settings file
  content string for a named variable. Supports six `VarType` modes: `bool`, `int`,
  `string-single`, `string-double`, `string-varref`, and `array-ou-locations`.

**Why it was built:** First-time configuration of `AD-PowerAdmin_settings.ps1` requires manually
editing a ~350-line PowerShell file. Missed or blank mandatory settings (ADAdminEmail, SMTPServer,
OU paths) cause silent failures in daily audit jobs. The wizard eliminates the manual-edit barrier,
validates OU paths against the live AD environment, and reduces the risk of misconfiguration.

**Impact:** "Configure Settings Wizard" entry added to the AD-PowerAdmin Management submenu. No
behavior changes to any existing functions. The settings file format is unchanged; the wizard is a
guided editor only.

---

### Modules/AD-PowerAdmin_Utils.psm1 -- Shared OU Browser

**Added:**
- `Get-AdOuSearch` -- Hierarchical Active Directory OU browser. Starts at the domain root and
  displays direct child OUs by short name at each level. The user can drill into a child OU by
  number, step back up one level with `U`, select the current location with `S`, or cancel with
  `Q`. Returns the DistinguishedName of the selected location, or an empty string on cancel.
  Originally introduced as a private helper in `AD-PowerAdmin_Installer`; moved to Utils so any
  module can invoke it without duplicating code.

**Impact:** Available to all modules via the shared Utils import. No behavior change to existing
callers; `Read-SettingOuPath` in the Installer module now calls the Utils copy.

---

### Modules/AD-PowerAdmin_Installer.psm1 and AD-PowerAdmin_Installer.psd1 -- Settings File Upgrade

**Added:**
- `Update-ADPowerAdminSettingsFile` -- Downloads the canonical `AD-PowerAdmin_settings.ps1` from
  the configured update channel (Release or Development), extracts all `$global:*` variable names
  from both the downloaded file and the current local file, identifies variables present in the new
  file but missing from the current one, and appends them with their default values and original
  comments. All existing configured values are preserved; only missing variables are added.
  Creates a `.bak` backup before writing. Accessible from the AD-PowerAdmin Management submenu.
- `Get-GlobalVarNames` (private) -- Accepts a settings file content string and returns a
  `HashSet[string]` of all `$global:*` variable names found. Handles both `=` and `+=` assignment
  forms via the regex `(?m)^\[(?:bool|string|int|Int|array)\]\$global:(\w+)\s*[+]?=`. The `^\[`
  anchor excludes comment lines (`# EXAMPLE: [string]$global:Foo = ...`) which start with `#`.
- `Get-SettingsMigrationContent` (private) -- Accepts the new-file lines and the set of missing
  variable names; returns a formatted migration block string ready to append to the current file.
  For each missing variable, collects the preceding comment block (stopping at a blank line or
  another typed declaration), the declaration line itself, the full array body for `@(...)` types,
  and any `+=` continuation lines (e.g., `PwAuditAlertEmailMessage`). Prefixes the block with a
  dated migration header comment.

**Why it was built:** Module updates delivered via `Update-ADPowerAdminModules` may reference new
`$global:*` settings variables that do not yet exist in an operator's current settings file. Without
migration, modules run but silently use `$null` for the missing settings, causing unpredictable
behavior. This function closes the gap by making settings file upgrades safe and explicit.

**Impact:** "Upgrade Settings File" entry added to the AD-PowerAdmin Management submenu.
`Update-ADPowerAdminSettingsFile` added to `FunctionsToExport` in `AD-PowerAdmin_Installer.psd1`.
No changes to existing functions or settings file format.

---

### Modules/AD-PowerAdmin_SmbAdminShareAudit.psm1 and AD-PowerAdmin_SmbAdminShareAudit.psd1 -- New Module

**Added:**
- `Get-ADAdminShareInventory` -- Enumerates hidden SMB admin shares (`Name -match '\$$'`) on all
  enabled AD computers via WinRM. Classifies each host as Workstation, Server, or
  DomainController using AD OperatingSystem attribute and DC enumeration. Unreachable systems are
  recorded as `UnableToQuery` without aborting the scan.
- `Test-ADAdminShareRegistryPolicy` -- Checks `AutoShareWks` and `AutoShareServer` registry
  values at `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` remotely. A
  missing value is treated as default-enabled. Severity: Medium on workstations, High on servers,
  Critical on domain controllers.
- `Test-ADSMBFirewallExposure` -- Audits inbound Allow rules for TCP ports 445/139 on all
  computers. Flags `RemoteAddress=Any` or broad subnets on workstations (High) and DC
  reachability from non-approved sources (Critical). Compares against
  `$global:ApprovedSmbAdminHosts`.
- `Get-ADLocalAdminExposure` -- Enumerates local Administrators group remotely. Flags Domain
  Users in local Admins (Critical), broad domain groups (High), service accounts (Medium), and
  unapproved domain accounts (High). Post-collects AD disabled state for flagged accounts.
- `Test-ADLAPSCoverage` -- Pure AD query (no WinRM) for `msLAPS-PasswordExpirationTime`
  (Windows LAPS) and `ms-Mcs-AdmPwdExpirationTime` (legacy LAPS). Flags missing LAPS attribute
  (High), stale expiration beyond `$global:SmbLapsExpiredDays` (Medium), and domain-wide
  coverage below 80% (Medium). Emits Critical when neither LAPS schema attribute exists in AD.
- `Search-ADAdminShareAccessEvents` -- Searches Security event logs (Event IDs 5140 and 5145)
  on all DCs and AD servers. Flags access to `ADMIN$`, `C$`, `IPC$`, or `D$` from sources not
  in `$global:ApprovedSmbAdminHosts`. Caps at 10,000 events per host.
- `Invoke-ADAdminShareExposureAudit` -- Orchestrates all six audit checks in sequence,
  aggregates findings, exports a timestamped CSV via `Export-AdPowerAdminData`, and saves a
  plain ASCII text narrative report to `$global:ReportsPath`. Available as a daily unattended job
  controlled by `$global:SmbAdminShareAudit`.
- `Invoke-ADAdminShareSafeRemediation` -- Three-stage, confirmation-gated remediation. Stage 1
  removes unapproved domain accounts from local Administrators (per-item y/N). Stage 2 restricts
  firewall `RemoteAddress` to approved sources (CONFIRM gate; skipped if
  `$global:ApprovedSmbAdminHosts` is empty). Stage 3 sets AutoShare registry values to 0 (CONFIRM
  gate with explicit warning). Each stage saves a JSON backup before applying changes. Admin shares
  are never disabled automatically.
- `Restore-ADAdminShareRemediationBackup` -- Reads a `SmbAdminShare-Backup_*.json` file,
  displays a diff of OldValue vs. NewValue per item, and restores prior firewall rules, registry
  values, and local group membership after CONFIRM input.
- `New-SmbAuditTextReport` (private) -- Builds the ASCII text narrative report consumed by
  `Invoke-ADAdminShareExposureAudit`. Groups findings by category with evidence, risk, and action
  per finding, written to a timestamped `.txt` in `$global:ReportsPath`.
- `Initialize-Module` -- Registers the "SMB Admin Share Audit" submenu (nine items), one main
  menu entry, and the `SmbAdminShareDailyAudit` unattended job (Daily flag driven by
  `$global:SmbAdminShareAudit`).

**Why it was built:** SMB administrative shares (`ADMIN$`, `C$`, `IPC$`) are a primary lateral
movement vector (ATT&CK T1021.002) once an attacker obtains valid credentials. The six risk
enablers -- no LAPS, excessive local admin rights, broad inbound SMB firewall rules, uncontrolled
AutoShare registry, domain controllers reachable over SMB, and NTLM without controls -- were not
audited by any existing AD-PowerAdmin module. This module addresses the conditions enumerated in
`Research/SMB_Windows_Admin_Shares_Abuse_Audit_Remediation_Methodology.md`.

**Impact:** "SMB Admin Share Audit" submenu added to the main menu. Channel: Alpha. Three new
settings added to `AD-PowerAdmin_settings.ps1`: `SmbAdminShareAudit` (bool, default `$false`),
`ApprovedSmbAdminHosts` (string array, default empty), `SmbLapsExpiredDays` (int, default 30).

---

### Modules/AD-PowerAdmin_PasswordsCtl -- v3.0: AS-REP Roasting Audit and Remediation

**Changed:**
- `ModuleVersion` bumped from `2.0` to `3.0`.
- `Initialize-Module` -- Added stale-entry removal for `Start-DailyAsRepRoastingAudit` in
  `$global:UnattendedJobs`, ensuring safe module reloads. Added two new items to the
  `PasswordsCtlMenu` submenu: `AS-REP Roasting Audit` and `AS-REP Roasting Remediation`.
  Registered the `Start-DailyAsRepRoastingAudit` daily unattended job.
- Module `Description` and `ReleaseNotes` updated to document the AS-REP Roasting capability.

**Added:**
- `Get-AsRepRoastableAccounts` -- Domain-wide discovery of all user accounts with
  `DoesNotRequirePreAuth` set. Each finding is cross-referenced against high-privilege group
  membership via the existing `Get-PrivilegedAccountNames` helper and assigned a risk level:
  Critical (enabled + privileged group), High (enabled + SPN or AdminCount=1), Medium
  (enabled, no special indicators), or Low (disabled). Returns a `PSCustomObject[]` with
  thirteen fields including SPN, AdminCount, PasswordLastSet, and DistinguishedName.
- `Show-AsRepRoastingFindings` -- Shared display helper that renders a colour-coded,
  risk-grouped console report. Includes a mandatory post-display warning that re-enabling
  preauthentication does not invalidate previously captured AS-REP hashes.
- `Get-AsRepRoastingAudit` -- Interactive audit function. Calls `Get-AsRepRoastableAccounts`,
  displays the risk-rated report, and calls `Export-AdPowerAdminData` to offer CSV export to
  `Reports/`.
- `Start-AsRepRoastingRemediation` -- Interactive remediation workflow. Displays the full
  audit report, requires the operator to type `YES` exactly before setting
  `DoesNotRequirePreAuth` to `$false` on all listed accounts via `Set-ADAccountControl`.
  Logs every operation (success and failure) and exports the log to `Reports/`. Does not
  auto-reset passwords because service account password resets require operator judgment;
  the function displays a mandatory action-required reminder before and after remediation.
- `Start-DailyAsRepRoastingAudit` -- Unattended daily job. Checks the domain for accounts
  with `DoesNotRequirePreAuth` set, exports a dated CSV to `Reports/`, and emails the
  administrator when any Critical or High risk accounts are found. Controlled by the
  `$global:AsRepRoastingAudit` feature flag.

**Why it changed:** AS-REP Roasting is an offline credential-theft attack against accounts
where Kerberos preauthentication is disabled. It can be executed without any initial domain
access and produces crackable hashes for targeted accounts. It is a direct sibling of the
`PASSWD_NOTREQD` misconfiguration already audited in this module.

**Impact:** `AS-REP Roasting Audit` and `AS-REP Roasting Remediation` appear under the
`Password Management` sub-menu. The daily unattended job runs when
`$global:AsRepRoastingAudit = $true`. No behavior change to any existing function.

---

### AD-PowerAdmin_settings.ps1 -- AsRepRoastingAudit Feature Flag

**Added:**
- `$global:AsRepRoastingAudit` (`bool`, default `$true`) -- Enables or disables the daily
  unattended `Start-DailyAsRepRoastingAudit` job. Set to `$false` to suppress daily
  monitoring without removing the module or hiding the interactive menu options.

---

### AD-PowerAdmin.wiki/Vulnerabilities/AS-REP-Roasting.md -- New Vulnerability Dossier

**Added:**
- Vulnerability dossier covering: what AS-REP Roasting is, how Kerberos preauthentication
  works, the full attack chain, differences from Kerberoasting, why the flag exists, account
  impact by type, Event ID 4768 monitoring guidance, change-monitoring event IDs 4738 and
  5136, and six preventive controls including gMSA migration and Fine-Grained Password
  Policies.

---

### AD-PowerAdmin.wiki/AsRepRoasting-Module.md -- New Module Documentation

**Added:**
- AD-PowerAdmin-specific implementation documentation covering: why the capability is in
  PasswordsCtl (architectural rationale as sibling to PASSWD_NOTREQD), function table, audit
  methodology and AD query used, risk rating model with rationale per level, remediation
  workflow with post-remediation manual steps, safety design rationale for not auto-resetting
  passwords, the daily job and feature flag, and exception handling guidance.

---

### Modules/AD-PowerAdmin_ExchangeAdSecurity.psd1 -- Promoted to Production

**Changed:**
- Module channel promoted from `Beta` to `Production`. The audit and remediation functions
  have been validated against a live domain and produce correct output in both Exchange and
  non-Exchange environments. All functions degrade gracefully when Exchange groups are absent.
- `ReleaseNotes` updated to document the v1.0 Production promotion milestone.

**Why it changed:** The module has been exercised in a production domain environment. All
five public functions (domain root ACE audit, group membership audit, group ACL risk audit,
full orchestrated report, and guided ACE removal) operate correctly. No functional changes
were required; this is a maturity promotion only.

**Impact:** The Exchange AD Security module is now Production-channel. The overall channel
reported by `Get-ADPAVersion` will reflect this promotion.

---

### Modules/AD-PowerAdmin_LogMgr.psd1 -- Promoted to Production

**Changed:**
- Module channel promoted from `Beta` to `Production`. All functions have been stable across interactive and scheduled use with no known issues.
- `ModuleVersion` bumped from `1.0` to `1.1` to mark the Production promotion milestone.
- `ReleaseNotes` updated to document the v1.1 Production promotion.

**Why it changed:** The Event Log Manager module has been in Beta since its initial release. The interactive functions (`Show-ADUserLockouts`, `Get-CurrentLockedoutUsers`, `Show-AdUserFailedLoginEvents`, `Get-FailedLoginEvents`) and the daily unattended job (`Start-DailyLockoutSummaryReport`) have all been exercised in production environments without reported issues. No functional changes were required; this is a maturity promotion only.

**Impact:** The Event Log Manager module is now Production-channel. The overall channel reported by `Get-ADPAVersion` will increase if this was the only non-Production module in the active load set.

---

### Modules/AD-PowerAdmin_ExchangeAdSecurity.psm1 and AD-PowerAdmin_ExchangeAdSecurity.psd1 -- New Module

**Added:**
- `Search-ExchangeDomainRootAce` -- Reads the domain root ACL and filters for ACEs where an
  Exchange security group (Exchange Windows Permissions, Exchange Trusted Subsystem,
  Organization Management, Exchange Recipient Administrators) holds WriteDACL, GenericAll,
  WriteOwner, GenericWrite, or AllExtendedRights. Each finding is tagged Critical or High.
  Supports `-ReturnAcl` for pipeline use by the orchestrator and the remediation function.
- `Search-ExchangeGroupMembership` -- Recursively enumerates membership of all Exchange
  security groups in `$global:ExchangeGroupsToAudit` and flags members whose SamAccountName
  does not match known Exchange service account patterns and whose ObjectClass is not
  `computer`. Supports `-ReturnData` for pipeline use.
- `Search-ExchangeGroupAclRisk` -- Reads the ACL on the Exchange Windows Permissions group
  object and identifies principals holding GenericAll, WriteDACL, WriteOwner, GenericWrite, or
  WriteProperty. Any such principal can add themselves or another account to the group and
  thereby gain its domain-root WriteDACL right. Supports `-ReturnAcl`.
- `Get-ExchangeAuditReport` -- Orchestrates all four checks (domain root ACE, group
  membership, group ACL risk, and DCSync correlation via `Search-DcSyncRisk -ReturnAcl`),
  computes an overall severity rating (Critical/High/Medium/Clean), exports a flat CSV via
  `Export-AdPowerAdminData`, saves a categorized explanatory text report, and sends an email
  alert when `$global:ExchangeADSecurityAudit = $true` and SMTP is configured.
- `Remove-ExchangeDangerousAce` -- Interactive guided removal of dangerous Exchange ACEs from
  the domain root. Exports a pre-change ACL backup, requires explicit `CONFIRM` input, removes
  matching ACEs via `$Acl.RemoveAccessRule()` and `Set-Acl` on the raw .NET ACL object, and
  exports a post-change verification report.
- `New-ExchangeAuditTextReport` (private) -- Builds the categorized text report consumed by
  `Get-ExchangeAuditReport`. Each finding section contains a grouped findings table, a WHAT
  THIS MEANS explanation, an attack walkthrough, numbered remediation steps, wiki anchor links,
  and a remediation validation checklist. Returns plain ASCII written to a timestamped `.txt`
  in `$global:ReportsPath`.
- `Initialize-Module` -- Registers the "Exchange AD Security" submenu (5 items), one main
  menu entry, and the `ExchangeAuditReport` unattended job (Daily flag driven by
  `$global:ExchangeADSecurityAudit`).

**Why it was built:** Exchange historically grants the Exchange Windows Permissions group
WriteDACL on the domain root, creating a well-known escalation path to DCSync that no
existing AD-PowerAdmin module detected or remediated. The vulnerability is documented in
`AD-PowerAdmin.wiki/Vulnerabilities/exchange_ad_permission_escalation.md`; this module
implements the audit procedure and guided remediation described there.

**Impact:** "Exchange AD Security" submenu added to the main menu. The module degrades
gracefully in environments without Exchange (yellow `[WARN]` per missing group, no errors).
Channel: Beta.

---

### AD-PowerAdmin_settings.ps1 -- Exchange Audit Settings

**Added:**
- `$global:ExchangeADSecurityAudit` -- Boolean (default `$false`) controlling whether the
  Exchange audit runs as a daily unattended job and triggers the email alert after each run.
- `$global:ExchangeGroupsToAudit` -- String array of Exchange security group names checked
  for dangerous domain-root ACEs and audited for membership. Default covers the four standard
  Exchange permission groups.

**Impact:** No behavior change to existing modules. Settings have no effect until the Exchange
module is loaded.

---

### Modules/AD-PowerAdmin_PasswordNotRequired.psm1 and AD-PowerAdmin_PasswordNotRequired.psd1 -- MERGED (not shipped as standalone)

**Note:** This capability was merged into `AD-PowerAdmin_PasswordsCtl` v2.0 rather than
shipping as a standalone module. See the `AD-PowerAdmin_PasswordsCtl v2.0` entry below for
the full function list, design rationale, and impact.

---

### Modules/AD-PowerAdmin_PasswordsCtl.psm1 and AD-PowerAdmin_PasswordsCtl.psd1 -- v2.0: PasswordNotRequired Merge

**Changed:**
- `ModuleVersion` bumped from `1.0` to `2.0`.
- `Initialize-Module` -- Added stale-entry removal for `PasswordNotRequiredMenu` (in both
  `$global:Menu` and `$global:SubMenus`) and `Start-DailyPasswordNotRequiredAudit` (in
  `$global:UnattendedJobs`), ensuring safe module reloads if the standalone module was
  previously loaded. Added two new items to the `PasswordsCtlMenu` submenu:
  `PasswordNotRequired Audit` and `PasswordNotRequired Remediation`. Updated the main menu
  Label to reflect the expanded scope. Registered the `Start-DailyPasswordNotRequiredAudit`
  daily unattended job.
- Module description updated to document the PasswordNotRequired audit and remediation
  capability.

**Added:**
- `Get-PasswordNotRequiredAccounts` -- Domain-wide discovery of all user and computer accounts
  with the `PasswordNotRequired` (`PASSWD_NOTREQD`) flag set. Each finding is cross-referenced
  against high-privilege group membership (Domain Admins, Enterprise Admins, Schema Admins,
  Administrators, and ten additional privileged groups) and assigned a risk level: Critical,
  High, Medium, Low, or Review. Returns a `PSCustomObject[]` with twelve fields including
  `RiskLevel` and `RecommendedAction`. Used by all other functions in this area and by
  `Test-ADSecurityBestPractices` in the Audits module.
- `Get-PasswordNotRequiredAudit` -- Interactive audit function. Calls
  `Get-PasswordNotRequiredAccounts`, displays a risk-grouped report to the console, and
  calls `Export-AdPowerAdminData` to offer CSV export to `Reports/`.
- `Show-PasswordNotRequiredFindings` -- Shared display helper used internally by
  `Get-PasswordNotRequiredAudit` and `Start-PasswordNotRequiredRemediation` to render the
  colour-coded risk-rated report without prompting for export.
- `Start-PasswordNotRequiredRemediation` -- Interactive remediation workflow. Displays the
  full audit report, then requires the operator to type `YES` exactly before clearing
  `PasswordNotRequired` from all listed user accounts. Empty input, `Y`, `y`, or any other
  string cancels with no changes made. Logs every operation (success and failure) and exports
  the log to `Reports/`. Computer accounts are listed separately with manual remediation
  guidance and are never modified automatically.
- `Start-DailyPasswordNotRequiredAudit` -- Unattended daily job. Checks the domain for
  `PasswordNotRequired` accounts, exports a dated CSV to `Reports/`, and emails the
  administrator when any Critical or High risk accounts are found. Controlled by the
  `$global:PasswordNotRequiredAudit` feature flag.
- `Get-PrivilegedAccountNames` (private, not exported) -- Builds a case-insensitive HashSet
  of all member DNs across the fourteen defined high-privilege groups. Used by
  `Get-PasswordNotRequiredAccounts` to determine `PrivilegedGroupMember` and assign
  Critical/Medium risk levels.

**Removed:**
- `Modules/AD-PowerAdmin_PasswordNotRequired.psm1` -- Standalone module file deleted; all
  five functions and menu registrations merged into `AD-PowerAdmin_PasswordsCtl`.
- `Modules/AD-PowerAdmin_PasswordNotRequired.psd1` -- Standalone manifest deleted.

**Why this changed:** The PasswordNotRequired audit and remediation capability was initially
developed as a standalone module. Because it is password security functionality -- directly
complementary to the existing KRBTGT rotation, breached password audit, and password policy
controls already in PasswordsCtl -- shipping it separately created artificial fragmentation.
The merge consolidates all password security capabilities into one module with a unified
sub-menu. The confirmation behavior was also tightened: the remediation prompt now requires
the exact string `YES` rather than defaulting to proceed on empty input, which is the
correct default for an operation that modifies account attributes domain-wide.

**Impact:** The `PasswordNotRequired Audit` and `PasswordNotRequired Remediation` items now
appear under the `Password Management` sub-menu alongside KRBTGT and password audit functions.
The daily unattended job runs alongside other daily jobs when
`$global:PasswordNotRequiredAudit = $true`. `Test-ADSecurityBestPractices` continues to call
`Get-PasswordNotRequiredAccounts` with no change required -- the function is now exported from
PasswordsCtl instead of the standalone module. No behavior change to any other module.

---

### AD-PowerAdmin_settings.ps1 -- PasswordNotRequiredAudit Feature Flag

**Added:**
- `$global:PasswordNotRequiredAudit` (`bool`, default `$true`) -- Enables or disables the
  daily unattended `Start-DailyPasswordNotRequiredAudit` job. Set to `$false` to suppress
  daily monitoring without removing the module or hiding the interactive menu options.

---

### Modules/AD-PowerAdmin_Audits.psm1 -- PasswordNotRequired Check in Security Best Practices

**Changed:**
- `Test-ADSecurityBestPractices` -- Added a new check section that calls
  `Get-PasswordNotRequiredAccounts` (with a `Get-Command` guard so the section degrades
  gracefully if the module is not installed) and reports a count summary broken down by
  Critical, High, and Other risk levels. Points operators to the dedicated sub-menu for
  full details and remediation. The check is positioned after the Machine Account Quota
  audit and before the inactive users check.

**Why it changed:** `Test-ADSecurityBestPractices` is the comprehensive domain security
sweep. `PasswordNotRequired` is a misconfiguration with Critical-severity impact on
privileged accounts and should be surfaced in the same run as DCSync risks, adminCount
anomalies, and password policy weaknesses.

**Impact:** The comprehensive security best practices report now surfaces `PasswordNotRequired`
findings inline. No existing functionality changed. The guard prevents failures in
environments that have not installed the new module.

---

### Modules/AD-PowerAdmin_GPOMgr.psd1 -- Promoted to Beta

**Changed:**
- Module channel promoted from `Alpha` to `Beta`. The GPO infrastructure layer has been exercised on production domain infrastructure through the Honeypot module integration (GPO creation, SYSVOL writing, AD object updates, link management, and removal) without known issues.
- `ReleaseNotes` in the manifest updated to document the v1.1 Beta promotion milestone.

**Why it changed:** The GPOMgr module was deployed as the runtime dependency for Honeypot GPO automation (`Install-ADPAGPOBaseline`, `Find-ADPAGPO`, `Remove-ADPAGPO`, `Test-ADPAGPO`, `Set-ADPAGPOPermission`, `Add-ADPAGPOLink`). That integration has been validated against a production domain including multi-DC replication and PDC emulator targeting. No functional changes were made; this is a maturity promotion only.

**Impact:** The GPO Manager module is now Beta-channel. The overall channel reported by `Get-ADPAVersion` will increase for installations where GPOMgr was the only non-Beta/Production module in the load set.

---

### AD-PowerAdmin.ps1 -- Unattended debug logging hardened

**Changed:**
- `Start-Automation` -- Added `Initialize-Debug` call at the top of the function body (before job dispatch), mirroring the identical guard already present in `Enter-MainMenu`. Prevents silent log gaps when a module job calls `Stop-Transcript` internally -- on return from that job, `Initialize-Debug` detects the transcript is gone and restarts it before the next job runs.
- `Start-Automation` -- Added timestamped run-boundary markers (`=== Unattended Run Start/End: <JobName> | <timestamp> ===`) written via `Write-Host` when `$global:Debug` is true. The markers are written at the start of the function and at every exit point (both the `Daily` branch and the named-job branch), ensuring the transcript captures a clear delimiter for each scheduled run.

**Why it changed:** Previously `Start-Automation` had no transcript guard. Any module job that called `Stop-Transcript` (e.g. installer functions) would silently drop all subsequent output from that unattended run. Additionally, the append-only `AD-PowerAdmin_Debug.log` file had no per-run markers, making it impossible to isolate a specific scheduled run's output when reviewing the log after multiple automated executions.

**Impact:** Unattended runs with `$global:Debug = $true` now produce complete, individually delimited output in `Reports/AD-PowerAdmin_Debug.log`. No behavior change when `$global:Debug = $false`.

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

### Modules/AD-PowerAdmin_Honeypot.psm1 -- Report Time Range Menu Expanded

**Changed:**
- `Show-HoneypotReport` -- The time range selection menu has been restructured. Options are now: (1) 15 minutes [default], (2) 1 hour, (3) 24 hours, (4) 7 days, (5) Custom date/time range, (6) Custom minutes back from now. Pressing Enter without a selection now defaults to 15 minutes rather than 24 hours. The new option 6 prompts for a plain integer (number of minutes to look back from now), which is simpler than option 5's full date/time entry and useful for targeted investigation or performance-conscious queries. Invalid input on option 6 falls back to 15 minutes. A performance warning block is now displayed before the menu, explaining that Security Event Log retrieval from remote systems is slow by nature of the Windows log transfer mechanism, that longer time ranges significantly increase retrieval time, and that shorter ranges should be preferred on large or busy domains.

**Why it changed:**
Security Event Log queries against remote domain controllers can be slow. The previous default of 24 hours retrieves a large volume of raw events per DC, making interactive report runs noticeably slow in multi-DC environments. Setting the default to 15 minutes matches the configured monitor interval and keeps interactive queries fast by default. The custom-minutes option provides a convenient middle ground between the fixed presets and full date/time entry for cases where the administrator knows how far back to look without needing to specify exact timestamps.

**Impact:**
- Pressing Enter at the time range prompt now queries the last 15 minutes instead of the last 24 hours.
- The performance warning ensures administrators understand the source of any slowness before initiating a long-range query.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- XPath Server-Side Event Filtering

**Changed:**
- `Get-HoneypotEventsBatch` -- Replaced `FilterHashtable` with a `FilterXPath` query that includes the honeytoken `TargetUserName` as a server-side filter condition. Previously, the query sent EventID and time filters to the DC but the username filter ran in PowerShell after all matching events were transferred. A busy DC could return hundreds of authentication events per 15-minute window, all of which were serialized, sent across the network, deserialized, and then discarded. With `FilterXPath`, the DC evaluates `TargetUserName` before sending any data: on a clean run (no attacker activity), zero events cross the network. The XPath uses an exact-match predicate (`Data[@Name='TargetUserName']='username'`) which is the form supported by the Windows Event Log XPath subset. String functions such as `starts-with()` are not supported inside `EventData` predicates by the Windows Event Log service and must not be used. The client-side `Split('@')[0]` check is retained as a safety net for the rare cross-realm Kerberos case where a realm suffix is appended. Timestamps are converted to UTC ISO 8601 format as required by the Windows Event Log XPath engine.
- `Get-HoneypotEventsBatch` -- The timing output now splits the `Get-WinEvent` call duration from the XML enrichment loop duration. The `[DC-DATA]` line reports how many events were returned and how long the network query took. A new `[DC-PARSE]` line (printed only when events were returned) reports XML enrichment time. This split makes it possible to distinguish network-transfer latency from local parse overhead when diagnosing slow runs.

**Why it changed:**
The Windows Event Log remote query API (`Get-WinEvent -ComputerName`) transfers events as fully serialized XML objects. With `FilterHashtable`, filtering by `TargetUserName` is not possible server-side, so every authentication event in the time window crosses the network. `FilterXPath` exposes the full XPath 1.0 query engine of the DC Event Log service, which evaluates field-level predicates including `EventData/Data[@Name]` comparisons before any data leaves the DC. For a honeytoken monitor that expects zero matches on most runs, this eliminates the dominant source of query latency.

**Impact:**
- Per-DC query time should drop from the baseline (observed 80s+ with hundreds of events transferred) to the residual connection + scan overhead for a zero-result query, typically 2-10 seconds depending on Security log size and DC load.
- XML enrichment and CSV export behavior are unchanged; the `[DC-PARSE]` line only appears when events are actually found.
- If the Security log scan overhead (not data transfer) is the remaining bottleneck, parallel DC queries via `Start-Job` are the logical next step.

---

### Modules/AD-PowerAdmin_Honeypot.psm1 -- DC Event Log Query Timing Diagnostics

**Changed:**
- `Get-HoneypotEventsBatch` -- After retrieving raw Security log events from a DC, the function now writes a `[DC-DATA]` line reporting the DC hostname and the count of raw events returned by `Get-WinEvent` before username filtering is applied. The `[WARN]` message on query failure was also promoted to `[DC-WARN]` and reformatted consistently. This raw count makes it possible to distinguish between "DC returned 0 events in the window" and "DC returned many events but none matched the honeytoken account."
- `Get-HoneypotEvents` -- Each domain controller query is now wrapped with per-DC timing output: a `Start` line (with timestamp and DC name) is written before the query and a `Finish` line (with timestamp, DC name, matching event count, and elapsed seconds) is written after. A summary line at the end reports total DC count, total elapsed time, and total matching events across all DCs. The opening line now shows the full query window (start time to end time) and the count of DCs being queried. The `$DomainControllers` array is explicitly cast to `@()` so `.Count` is reliable when only one DC exists.

**Why it changed:**
Security Event Log queries against remote domain controllers over WMI/RPC can be slow when the DC is distant, under load, or when the log is large. Before deciding whether to restrict log queries to the local DC (or a preferred DC list), the per-DC elapsed times are needed to identify where the latency is concentrated. Without timing output, a slow run produces no information about which DC is responsible for the delay or how long each query took. With this output captured by the AD-PowerAdmin transcript/debug system, a single run produces a clear breakdown of query time per DC and total throughput, sufficient to guide the next optimization step.

**Impact:**
- Every honeytoken monitor run (automated and interactive) now writes per-DC timing to the terminal, which is captured by the transcript when `$global:Debug = $true`.
- No behavioral change to event collection, filtering, alerting, or CSV export.

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

### Modules/AD-PowerAdmin_SysvolAudit.psd1 -- Promoted to Production

**Changed:**
- Module channel promoted from `Beta` to `Production`. The SYSVOL audit module has been exercised against production domain infrastructure across all six audit functions (script inventory, credential and risk pattern scan, GPP cpassword scan, permission scan, GPO delegation audit, and external script path review) with no known issues. Post-testing refinements resolved false positives in the delegation and external-path audits.

**Why it changed:** The module completed iterative testing and refinement across multiple test runs. All identified issues (email removal, GpoCustom false-positive filtering, GPO GUID/name display split, drive-map exclusion, external path traceability fields) have been resolved. The module is stable and suitable for production deployments.

**Impact:** The SYSVOL Security Audit submenu is now Production-channel. The overall channel reported by `Get-ADPAVersion` will increase if this was the only non-Production module in the load set.

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
| `Get-PasswordNotRequiredAccounts` | Complete |
| `Get-PasswordNotRequiredAudit` | Complete |
| `Show-PasswordNotRequiredFindings` | Complete |
| `Start-PasswordNotRequiredRemediation` | Complete |
| `Start-DailyPasswordNotRequiredAudit` | Complete |

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
