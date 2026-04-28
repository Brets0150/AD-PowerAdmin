<div align="center">
    <div style="display: flex; align-items: flex-start;">
        <img align=top src="https://cybergladius.com/wp-content/uploads/2023/02/ADPowerAdmin_Logo_half.png" />
    </div>
</div>

#  AD-PowerAdmin Overview
AD-PowerAdmin is a tool to help Active Directory administrators secure and manage their AD. Automating security checks ranging from User and Computer cleanup, password audits, security misconfiguration audits, and much more. The core philosophy is to automate daily testing of AD security and email when there is an issue. This tool focuses on common weaknesses, and attack-vectors adversaries use and defends against them.

# Features
Here is a quick list of features
- Install, test, or remove AD-PowerAdmin as a Windows scheduled task with a standalone Managed Service Account (sMSA) for unattended daily execution. Includes a setup helper to install PowerShell 7 if not already present.
- Disable and decommission user accounts manually or automatically when they have not been active within a configurable number of days.
- Disable and decommission computer accounts manually or automatically when they have not been active within a configurable number of days.
- User account decommissioning workflow: strips all group memberships, rotates the password to a random value, disables the account, and moves it to a designated disabled OU.
- Audit accounts within high-privilege groups. Produces a complete view of users with, or able to escalate to, Domain Admin and other high-privilege group rights.
- Breached and weak password audit. Cross-references user password hashes against the Have I Been Pwned NTLM hash database and a configurable weak-password dictionary. Users with breached or weak passwords are automatically emailed with a grace period to change; accounts that do not comply have "User must change password at next logon" set.
- Monthly email report of breached and weak passwords. Also available on demand.
- KRBTGT password rotation: automated age-check-and-rotate or forced rotation as a defense against Golden Ticket attacks.
- Active Directory security best-practice audit: checks for common misconfigurations and weak settings across the domain.
- Active Directory ACL audit: identifies high-risk Access Control Entries and accounts configured with DCSync delegation rights.
- Active Directory object search: interactive lookup of users, computers, and other AD objects.
- Download and manage the Have I Been Pwned NTLM password hash database used for breach detection. The downloader is embedded pure PowerShell 5.1 with no external tools or runtimes required. Supports both single-file and incremental directory modes; directory mode uses ETag-based comparison to only re-download changed hash ranges, making weekly updates far more efficient than the full 70 GB dataset.
- Machine Account Quota audit: checks ms-DS-MachineAccountQuota, finds computer accounts created by non-admin users via ms-DS-CreatorSID, and flags computers with Resource-Based Constrained Delegation configured (msDS-AllowedToActOnBehalfOfOtherIdentity).
- Machine Account Quota remediation: sets ms-DS-MachineAccountQuota to 0 to eliminate the attack surface for non-admin computer account creation.
- Event log analysis: search for account lockout events (4740), view currently locked-out users with an unlock option, and search for failed logon events (4625).
- Daily account lockout summary report emailed to the administrator, covering all lockout events from the past 24 hours with a per-account breakdown and a full CSV export.
- Exchange AD permission escalation audit: detects dangerous permissions (WriteDACL, GenericAll, WriteOwner) held by Exchange security groups on the domain root, audits Exchange group membership for unexpected principals, checks who can control Exchange Windows Permissions, correlates with DCSync rights, and provides guided removal of dangerous ACEs.
- SYSVOL and NETLOGON script inventory: enumerate all scripts, logon/startup scripts, and configuration files stored in the domain's SYSVOL and NETLOGON shares.
- SYSVOL credential and secret scanning: scan SYSVOL and NETLOGON scripts for embedded credentials, plaintext passwords, API tokens, and dangerous execution patterns such as ExecutionPolicy Bypass, encoded commands, and unauthenticated downloads.
- GPP cpassword detection: identify legacy Group Policy Preferences XML files in SYSVOL containing cpassword values whose AES-256 encryption key was publicly disclosed (MS14-025).
- SYSVOL permission auditing: audit SYSVOL file and folder ACLs for write or modify rights granted to broad or non-administrative principals such as Everyone, Domain Users, or Authenticated Users.
- GPO delegation risk assessment: identify Group Policy Objects with edit rights assigned to non-Tier-0 identities, stale accounts, or broad security groups.
- GPO external script path analysis: identify GPO script references pointing to UNC paths outside SYSVOL and NETLOGON that may reside on servers with weaker access controls.
- Honeytoken account deployment and monitoring: provision a hardened, realistic-looking Active Directory account that should never authenticate; any authentication attempt generates a high-confidence alert for password spray, brute-force, credential stuffing, or attacker reconnaissance activity. Automatically creates and configures the deny-logon Group Policy Object linked to the domain root, eliminating manual GPO setup. Includes hourly automated log monitoring across all domain controllers, structured email alerts with recommended response actions, interactive log review, safety validation, and a fully automated reversible removal workflow.
- Group Policy Object management: shared GPO infrastructure used by other AD-PowerAdmin modules to create, configure, link, audit, and remove Group Policy Objects programmatically. Includes a configuration-level search that identifies which existing GPOs already enforce a given registry setting, preventing duplicate or conflicting policies across the domain.

[See the wiki for more details of each feature](https://github.com/Brets0150/AD-PowerAdmin/wiki)

# Installation
[See the Wiki for installation instructions.](https://github.com/Brets0150/AD-PowerAdmin/wiki/Install)
#
