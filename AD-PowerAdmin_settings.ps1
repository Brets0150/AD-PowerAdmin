#Requires -RunAsAdministrator
<#
.SYNOPSIS
	Only variables and configurations for AD-PowerAdmin.

.VERSION
    1.0.4

.DESCRIPTION
    Only variables and configurations for AD-PowerAdmin.

.EXAMPLE
    Do not use this script directly. This script is called by the main script.

.LINK
	https://github.com/Brets0150/AD-PowerAdmin

.NOTES
	Author: Bret.s AKA: CyberGladius / License: MIT
#>
####################################################################################################
# Debugging
[bool]$global:Debug = $true

####################################################################################################
# Unattended Task Logging
# When $true, all output from unattended jobs is captured to a dedicated log file
# (Reports\AD-PowerAdmin_Unattended.log) regardless of the $global:Debug setting.
[bool]$global:UnattendedLog = $true

####################################################################################################
# -------------------[Mandatory]------------------- #
# Set the email address of the AD Administrator, or the a admin email distribution list.
# This is used for the email notifications.
# Example: $global:AdminEmail = "securityGourp@example.com"
# Example: $global:AdminEmail = "John.d@example.com"
[string]$global:ADAdminEmail = ""

# -------------------[Mandatory]------------------- #
# Set the default email address this scruit will send email from.
# Example: $global:FromEmail = "AdPowerAdmin@example.com"
[string]$global:FromEmail = ""

# -------------------[Mandatory]------------------- #
# Set the sMSA account name that AD-PowerAdmin will create and use.
# This name can be no longer than 14 characters!
# You do NOT need to alter the default value, nor do I recommend it.
[string]$global:MsaAccountName = "ADPowerAdmMSA"

# -------------------[Mandatory]------------------- #
# AD-PowerAdmin Install Directory.
# This is the directory where AD-PowerAdmin will be installed.
# The default is to install AD-PowerAdmin in C:\Scripts\AD-PowerAdmin.
# If you want to change the install directory, you can change the value below.
# Example: $global:InstallDirectory = "C:\Scripts\AD-PowerAdmin"
[string]$global:InstallDirectory = "C:\Scripts\AD-PowerAdmin"

####################################################################################################
# -------------------[Optional]------------------- #
# Module update channel. Controls which source is used when "Update Modules" is run from the
# AD-PowerAdmin Management menu.
#   'Release'     -- downloads the latest officially released version from GitHub Releases.
#   'Development' -- downloads the current main branch files directly from GitHub.
[string]$global:UpdateChannel = 'Release'

####################################################################################################
# Daily Task Enable / Disable
# Set each flag to $true to include that task in the scheduled daily run, $false to skip it.
# -------------------[Optional]------------------- #
[bool]$global:KerberosKRBTGTAudit           = $true   # KRBTGT password age check
[bool]$global:InactiveComputerAudit         = $true   # Stale computer accounts
[bool]$global:InactiveUserAudit             = $true   # Stale user accounts
[bool]$global:WeakPasswordAudit             = $true   # HIBP / weak-password scan
[bool]$global:LockoutDailyReport            = $true   # Account lockout summary email
[bool]$global:NTLMAuthDailyReport           = $true   # NTLMv1/v2 authentication report
[bool]$global:PasswordNotRequiredAudit      = $true   # Accounts with PASSWD_NOTREQD flag
[bool]$global:AsRepRoastingAudit            = $true   # AS-REP roastable accounts
[bool]$global:SysvolGppCpasswordAudit       = $false  # GPP cpassword scan in SYSVOL
[bool]$global:ExchangeADSecurityAudit       = $false  # Exchange AD ACL audit (Exchange envs only)
[bool]$global:SmbAdminShareAudit            = $false  # SMB administrative share audit
[bool]$global:AuditPolicyDailyCheck         = $false  # Audit policy compliance check

####################################################################################################
# -------------------[Mandatory]------------------- #
# Kerberos KRBTGT password and account settings.
# The number of days between KRBTGT password updates. Default is 90 days.
[int]$global:krbtgtPwUpdateInterval = 90

####################################################################################################
# Daily Inactive Computer clean up settings.
# -------------------[Mandatory]------------------- #
# Specify inactivity range value below in days.
[Int]$global:InactiveDays = 90

# -------------------[Mandatory]------------------- #
# Inactive computer maybe within multiple OU's. So we need build an array of OU's to search and
# clean up. The details are nested in a hashtable in the array.
# Each hashtable contains the following keys:
# 1 - SearchOUbase    = Set the basic search path in AD. You can limit the search to a specific OU.
#      Example: OU=Computers,OU=MyCompany,DC=MyDomain,DC=local
# 2 - DisabledOULocal = Set the OU path where the computer objects will be moved to after being
#      disabled.
#      Example: OU=DisabledComputers,OU=MyCompany,DC=MyDomain,DC=local

# You are able to add as many OU's as you want. Just add a new hashtable to the array. Inversly,
# you can remove second hashtable if you only want to search one OU.
[array]$global:InactiveComputersLocations = @(

    @{
        SearchOUbase    = 'OU=Desktops,DC=EXAMPLE,DC=COM'
        DisabledOULocal = 'OU=Disabled.Desktop,OU=Desktops,DC=EXAMPLE,DC=COM'
    }

    @{
        SearchOUbase    = 'OU=Servers,DC=EXAMPLE,DC=COM'
        DisabledOULocal = 'OU=Disabled.Servers,OU=Servers,DC=EXAMPLE,DC=COM'
    }

)

####################################################################################################
# Daily Inactive Users clean up settings.

# -------------------[Mandatory]------------------- #
# Inactive Users maybe within multiple OU's. So we need build an array of OU's to search and
# clean up. The details are nested in a hashtable in the array.
# Each hashtable contains the following keys:
# 1 - SearchOUbase    = Set the basic search path in AD. You can limit the search to a specific OU.
#      Example: OU=Users,OU=MyCompany,DC=MyDomain,DC=local
# 2 - DisabledOULocal = Set the OU path where the user objects will be moved to after being
#      disabled.
#      Example: OU=DisabledUsers,OU=MyCompany,DC=MyDomain,DC=local
# You are able to add as many OU's as you want. Just add a new hashtable to the array. Inversly,
# you can remove second hashtable if you only want to search one OU.
[array]$global:InactiveUsersLocations = @(

    @{
        # Set the basic search path in AD. You can limit the search to a specific OU. If you
        # want to search all user accounts in AD, leave this blank.
        # Example: 'OU=Users,DC=EXAMPLE,DC=COM'
        SearchOUbase = 'DC=EXAMPLE,DC=COM'

        # The disabled Users OU location in AD. This is where the users will be moved to.
        DisabledOULocal = 'OU=Disabled.Users,OU=Users,DC=EXAMPLE,DC=COM'
    }

)

####################################################################################################
# Password Quality Test Settings
# The password quality test checks every AD user account for breached or weak passwords using
# the Have I Been Pwned (HIBP) NTLM hash database and an optional weak-password dictionary.
#
# The HIBP hash data can be stored in one of two ways -- as a single sorted file or as a
# directory of per-range files. Choose the mode that matches how you downloaded the data:
#
# --------------------------------------------------------------------------------------------------
# OPTION A: SINGLE-FILE MODE
# --------------------------------------------------------------------------------------------------
# The downloader produces one large sorted flat file containing all NTLM hashes.
# As of 2026 this file is approximately 70 GB.
#
# Use single-file mode when:
#   - You are doing an initial setup and have not yet chosen a long-term approach.
#   - Storage is not a concern and you are comfortable re-downloading 70 GB on each update.
#
# How the audit uses it:
#   DSInternals Test-PasswordQuality reads the file directly via -WeakPasswordHashesSortedFile.
#   This is fast because the file is sorted and can be binary-searched.
#
# To use single-file mode:
#   1. Set $global:NtlmHashDataDir = ''  (leave it empty, see below)
#   2. Set $global:NtlmHashDataFile to the filename of the sorted hash file.
#   3. Run "Update HIBP Database" from the HIBP submenu to download the file.
#
# Example:
#   [string]$global:NtlmHashDataFile = 'pwned-passwords-ntlm-ordered-by-hash-v8.txt'
#   [string]$global:NtlmHashDataDir  = ''
#
# --------------------------------------------------------------------------------------------------
# OPTION B: DIRECTORY MODE  (recommended for ongoing use)
# --------------------------------------------------------------------------------------------------
# The downloader writes hashes as individual range files named by their 5-character hex
# prefix (e.g. A3B4C.txt). Each file contains SUFFIX:count lines for that prefix range.
# There are roughly 1 million range files covering all possible prefixes.
#
# On the first run all range files are downloaded (~70 GB total).
# On subsequent runs the tool compares each file's ETag with the server and downloads only
# the files that have changed -- typically a small fraction of the full dataset. This makes
# weekly updates far more efficient than replacing the entire single file.
#
# Use directory mode when:
#   - You want efficient incremental weekly updates (strongly recommended).
#   - You have already completed the first 70 GB download.
#   - You want audits to complete in seconds rather than scanning a 70 GB flat file.
#
# How the audit uses it:
#   A custom function (Test-NtlmHashesInDirectory) performs a prefix-based lookup instead
#   of scanning the full dataset. It collects all AD account NT hashes and groups them by
#   their 5-character hash prefix. It then reads only the range files whose names match
#   those prefixes -- every other file in the directory is ignored entirely.
#
#   A typical AD environment with hundreds or thousands of users has at most a few hundred
#   unique 5-character prefixes, so the audit opens only a few hundred files even though
#   the directory contains roughly one million. This is why directory-mode audits complete
#   in seconds regardless of the total database size. Fast completion is by design and does
#   not indicate partial or incomplete processing -- every AD account is evaluated against
#   its matching range file; only the irrelevant range files are skipped.
#
#   The outcome is identical to single-file mode: breached users are notified by email,
#   follow-up tasks are scheduled, and the monthly admin report reflects all findings.
#
# To use directory mode:
#   1. Set $global:NtlmHashDataDir to a folder name (relative to the script directory).
#   2. Leave $global:NtlmHashDataFile at its default value (it is not used in this mode).
#   3. Run "Update HIBP Database" from the HIBP submenu to download the range files.
#
# Example:
#   [string]$global:NtlmHashDataFile = ''
#   [string]$global:NtlmHashDataDir  = 'hibp-ntlm-hashes'
#
# --------------------------------------------------------------------------------------------------
# ACTIVE CONFIGURATION
# --------------------------------------------------------------------------------------------------
# TLDR: If there is anything configured for "$global:NtlmHashDataDir" The script will download in
#       directory mode. It will not matter what you have configured for "$global:NtlmHashDataFile",
#       if "$global:NtlmHashDataDir" is configured with any value, you are automatically forced
#       into directory mode, which I recommend you do anyways.

# $global:NtlmHashDataFile -- filename for single-file mode; used when NtlmHashDataDir is empty.
[string]$global:NtlmHashDataFile = 'pwned-passwords-ntlm-ordered-by-hash.txt'

# $global:NtlmHashDataDir -- directory name for directory mode. Set to '' for single-file mode.
[string]$global:NtlmHashDataDir = 'hibp-ntlm-hashes'

# If you want to test for weak passwords, you can add a plain text file with a list of weak
# passwords. One password per line. You will need to save it to the same directory as the
# AD-PowerAdmin.ps1 script. The Have-I-Been-Pwned module also has an automatic download of a
# well-known weak plain text passwords that rotate with the seasons and year from the site 
# weakpasswords.net.
# 
# Set the file path to the weak password list file.
[string]$global:WeakPassDictFile = 'weak-passwords.txt'

# Set the SearchOUbase to the OU path where you want to search for user accounts. If you want
# to search all user accounts in AD, leave this blank.
# Example: [string]$global:PasswordQualityTestSearchOUbase = ''
[string]$global:PasswordQualityTestSearchOUbase = ''

# Enable CC the AD Admins on the password audit alert email. When a user is found with a breached
# or weak password, the user will receive an email with the message above. The AD Admins will
# also receive a copy of the email.
# EXAMPLE: [bool]$global:PwAuditAlertEmailCCAdmins = $true
[bool]$global:PwAuditAlertEmailCCAdmins = $true

# -------------------[Mandatory]------------------- #
# The number of DAYS before the user is forced to update there password.
# EXAMPLE: [int]$global:PwAuditPwChangeGracePeriod = 3
[int]$global:PwAuditPwChangeGracePeriod = 3

# -------------------[Mandatory]------------------- #
# Message to send to the user.
# Users who are discovered with a breached or weak password will receive an email with the
# following message.
# To make the settings cleaner looking, I increment the message variable over multiple lines.
# This is not required. However, it is easier to read. You can put the message on one line if
# you want, or you can add more lines.
# The email message will automatically add "Hello <User Name>," to the beginning of the
# message. The user name will be taken from the user account in AD. So you do not need to
# add an opening greeting to the message.
[string]$global:PwAuditAlertEmailMessage  = "Your password has been identified in a breached or is weak. You have $global:PwAuditPwChangeGracePeriod days to change it."
[string]$global:PwAuditAlertEmailMessage += " If you do not change your password, your account will be forced to update your password on next login." + "`r`n"
[string]$global:PwAuditAlertEmailMessage += "Contact the IT Security department if you have any questions." + "`r`n" + "`r`n" + "Thank you,`r`n" + "Security Team"

# -------------------[Mandatory]------------------- #
# Email Alert Message Subject.
[string]$global:PwAuditAlertEmailSubject  = "ADPowerAdmin: Password Breached or Weak"
[string]$global:PwAuditAlertEmailSubject += " - ACTION REQUIRED"

####################################################################################################
# Email Settings.
# Configure the variables that are used for sending emails.
# You need to configure at a minimum the following variables to send emails. The rest are
# optional, depending on your SMTP server settings.
# 1 - $global:SMTPServer   = The SMTP server address.
# 2 - $global:FromEmail    = The email address that emails will be sent from.
# 3 - $global:ADAdminEmail = The email address that reports and alerts will be sent to.

# -------------------[Mandatory]------------------- #
# The SMTP server address.
# EXAMPLE: [string]$global:SMTPServer = 'smtp.example.com'
[string]$global:SMTPServer = ''

# ------------
# Optional variables. These variables are optional, but it really depends on your SMTP server
# settings. If you do need a Username and Password, you will need to create a new user account
# in AD and give it the permission to send emails ONLY!! You are hard coding the password in
# the script. So you will need to encrypt the password using the ConvertTo-SecureString cmdlet.
# Consider the security implications of hard coding the password in the script.

# Use SSL to connect to the SMTP server.
# EXAMPLE: [bool]$global:SmtpEnableSSL = $true
[bool]$global:SmtpEnableSSL = $true

# The SMTP server port. The default port is 587.
# EXAMPLE: [int]$global:SMTPServerPort = 587
[int]$global:SMTPPort = 25

# The SMTP server username.
# EXAMPLE: [string]$global:SMTPServerUsername = 'AdPowerAdmin'
[string]$global:SMTPUsername = ''

# The SMTP server password.
# EXAMPLE: [string]$global:SMTPServerPassword = 'P@ssw0rd'
[string]$global:SMTPPassword = ''

####################################################################################################
# Exchange AD Security Audit Settings
# -------------------[Optional]------------------- #
# Exchange security groups checked for dangerous domain-root ACEs.
# Modify only if your environment uses non-standard Exchange group names.
# Note: Enable/disable the daily Exchange audit via $global:ExchangeADSecurityAudit above.
[array]$global:ExchangeGroupsToAudit = @(
    "Exchange Windows Permissions",
    "Exchange Trusted Subsystem",
    "Organization Management",
    "Exchange Recipient Administrators"
)

####################################################################################################
# Honeytoken Account Settings
# -------------------[Optional]------------------- #
# Enable the unattended honeytoken authentication event monitor.
# Set to $true automatically when the honeypot install wizard completes.
# Set to $false to disable monitoring without removing the account.
# Note: This task runs on its own dedicated scheduled task, not the daily job.
[bool]$global:HoneypotAudit = $false

# -------------------[Optional]------------------- #
# How often (in minutes) the honeytoken monitor scheduled task runs.
# This value also controls how far back the Security log search looks:
# the lookback window is this value plus one additional minute to prevent
# timing gaps between consecutive task executions.
# Example: 15 means the task runs every 15 minutes and reviews the past 16 minutes.
# Example: 60 means the task runs every 60 minutes and reviews the past 61 minutes.
# Default is 60 minutes.
[int]$global:HoneypotMonitorIntervalMinutes = 15

# The sAMAccountName of the configured honeytoken user account.
# Set automatically by the honeypot install wizard. Do not edit manually.
[string]$global:HoneypotUsername = ''

# The name of the deny-logon security group that blocks the honeytoken account from all logon
# types. Updated by the honeypot install wizard if a custom name is chosen during provisioning.
[string]$global:HoneypotDenyGroup = 'GG_Honeytoken_DenyLogon'

# The DistinguishedName of the OU where the honeytoken user account was created.
# Set automatically by the honeypot install wizard. Do not edit manually.
[string]$global:HoneypotOU = ''

# The Service Principal Name (SPN) set on the honeytoken account as a Kerberoasting bait.
# Any Kerberos service ticket request (Event 4769) against this SPN is a high-confidence attack
# indicator. Set automatically by the install wizard. Leave empty if no SPN was configured.
[string]$global:HoneypotSPN = ''

# Monitor mode for the honeytoken scheduled task.
# 'Centralized'   - One central AD-PowerAdmin remotely queries every DC's Security log over RPC.
#                   This is the default and requires no additional deployment.
# 'Decentralized' - A lightweight AD-PowerAdmin copy runs locally on each DC and queries only
#                   the local Security log (no RPC overhead). Use when remote log queries are
#                   too slow (e.g., resource-constrained DCs). Requires
#                   Install-HoneypotDecentralized.
[string]$global:HoneypotMonitorMode = 'Centralized'

####################################################################################################
# SMB Admin Share Audit Settings -- for unreleased module still in alpha. Ignore for now.
# -------------------[Optional]------------------- #
# Note: Enable/disable the daily SMB audit via $global:SmbAdminShareAudit above.

# Host names or IP addresses approved to access SMB admin shares.
# Used by Test-ADSMBFirewallExposure and Search-ADAdminShareAccessEvents to suppress expected
# administrative traffic from management stations, backup servers, and monitoring systems.
# Example: [string[]]$global:ApprovedSmbAdminHosts = @('MGMT01', 'BACKUP-SRV', '10.0.0.5')
[string[]]$global:ApprovedSmbAdminHosts = @()

# -------------------[Optional]------------------- #
# Number of days after which a LAPS expiration timestamp is considered stale.
# Computers whose LAPS expiration is this many days in the past will be flagged Medium severity.
# Default is 30 days.
[int]$global:SmbLapsExpiredDays = 30

####################################################################################################
