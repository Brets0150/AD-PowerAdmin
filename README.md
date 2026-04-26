<div align="center">
    <div style="display: flex; align-items: flex-start;">
        <img align=top src="https://cybergladius.com/wp-content/uploads/2023/02/ADPowerAdmin_Logo_half.png" />
    </div>
</div>

#  AD-PowerAdmin Overview
AD-PowerAdmin is a tool to help Active Directory administrators secure and manage their AD. Automating security checks ranging from User and Computer cleanup, password audits, security misconfiguration audits, and much more. The core philosophy is to automate daily testing of AD security and email when there is an issue. This tool focuses on common weaknesses, and attack-vectors adversaries use and defends against them.

# Features
Here is a quick list of features
- A module PowerShell framework so you can add your own custom functions to AD-PowerAdmin!
- AD-PowerAdmin Management sub-menu: install, test, or remove AD-PowerAdmin (scheduled task and sMSA account) and install PowerShell 7, all grouped under a single main menu entry.
- AD Audits sub-menu: AD admin and user reports, inactive computer and user searches (report-only or disable), AD object search, and AD security best-practice checks, all grouped under a single main menu entry.
- AD Access Rights Audits sub-menu: high risk AD ACE audit and DCSync delegation risk audit, grouped under a single main menu entry.
- Password Management sub-menu: KRBTGT password rotation (age-checked or forced), breached/weak password audit report, and email report, grouped under a single main menu entry.
- Event Log Manager sub-menu: account lockout search, currently locked-out user lookup with unlock option, and failed logon event search, grouped under a single main menu entry.
- Disable and decommission User accounts manually, or automatically, that have not been used within X days.
-   Disable and decommission Computer accounts manually, or automatically, that have not been used within X days.
-   Audit Accounts within a high-privilege group. A complete view of users with or the ability to escalate to Domain Admin group rights.
-   Breached or weak User password audit. Users with breached or weak passwords will automatically be emailed telling them to update their password within a grace period. Users who do not update their password then have the attribute "User must change password at next logon" set.
- Monthly email report of weak passwords and settings. The report can be run on-demand as well.
- Rotate the Kerberos KRBTGT Active Directory user password automatically. Golden Ticket attack defense.
- Audit Active Directory security settings. This includes checking for weak settings and misconfigurations.
- AD Searching tools.
- Download and manage the Have I Been Pwned NTLM password hash database used for breach detection, with automated install of the required .NET SDK and downloader tool. Supports both single-file and incremental directory modes; directory mode only re-downloads changed hash ranges, making weekly updates far more efficient than the full 70 GB dataset.
- Decommission AD user accounts on demand: strips all group memberships (preserving a record of former groups in the account description), rotates the password, disables the account, and moves it to the disabled OU.
- Machine Account Quota audit: checks ms-DS-MachineAccountQuota, finds computer accounts created by non-admin users via ms-DS-CreatorSID, and flags computers with Resource-Based Constrained Delegation configured (msDS-AllowedToActOnBehalfOfOtherIdentity).

[See the wiki for more details of each feature](https://github.com/Brets0150/AD-PowerAdmin/wiki)

# Installation
[See the Wiki for installation instructions.](https://github.com/Brets0150/AD-PowerAdmin/wiki/Install)
#
