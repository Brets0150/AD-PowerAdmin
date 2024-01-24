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
- Disable and decommission User accounts manually, or automatically, that have not been used within X days.
-   Disable and decommission Computer accounts manually, or automatically, that have not been used within X days.
-   Audit Accounts within a high-privilege group. A complete view of users with or the ability to escalate to Domain Admin group rights.
-   Breached or weak User password audit. Users with breached or weak passwords will automatically be emailed telling them to update their password within a grace period. Users who do not update their password then have the attribute "User must change password at next logon" set.
- Monthly email report of weak passwords and settings. The report can be run on-demand as well.
- Rotate the Kerberos KRBTGT Active Directory user password automatically. Golden Ticket attack defense.
- Audit Active Directory security settings. This includes checking for weak settings and misconfigurations.
- AD Searching tools.

[See the wiki for more details of each feature](https://github.com/Brets0150/AD-PowerAdmin/wiki)

# Installation
[See the Wiki for installation instructions.](https://github.com/Brets0150/AD-PowerAdmin/wiki/Install)
#
