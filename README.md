
<div align="center">
    <div style="display: flex; align-items: flex-start;">
        <img align=top src="https://cybergladius.com/wp-content/uploads/2023/02/ADPowerAdmin_Logo_half.png" />
    </div>
</div>

#  AD-PowerAdmin Overview
AD-PowerAdmin is a tool to help Active Directory administrators secure and manage their AD. Automating security checks ranging from User and Computer cleanup, password audits, security misconfiguration audits, and much more. The core philosophy is to automate daily testing of AD security and email when there is an issue. This tool focuses on common weaknesses, and attack-vectors adversaries use and defends against them.

# Features
Here is a quick list of features
-   Disable and decommission User accounts that have not been used within X days.
-   Disable and decommission Computer accounts that have not been used within X days.
-   Audit Accounts within a high-privilege group. A complete view of users with or the ability to escalate to Domain Admin group rights.
-   Breached or weak User password checks. Users with breached or weak passwords will automatically be emailed telling them to update their password within a grace period. Users who do not update their password then have the attribute "User must change password at next logon" set.
- Monthly email report of weak passwords and settings. The report can be run on-demand as well.
- Rotate the Kerberos KRBTGT Active Directory user password. Golden Ticket attack defense.

## Installing AD-PowerAdmin
### Requirements
 - PowerShell v5 or higher.
 - Domain Admin rights.
 - Install the script on a Domain Controller.
### Optional
 - Download the breached password list from Have-I-Been-Pwned "https://haveibeenpwned.com/Passwords"
 - Build a list of weak passwords.

### Installing
To get started download the latest release ZIP file or clone this repositories.

    PS C:\Scripts> git clone https://github.com/Brets0150/AD-PowerAdmin.git
    PS C:\Scripts> cd AD-PowerAdmin

You need to edit the settings file, "AD-PowerAdmin_settings.ps1", that resides within the "AD-PowerAdmin" folder. The settings that you need to change are indicated with a "`[Mandatory]`" flag.

After updating the AD-PowerAdmin file you can then run the AD-PowerAdmin scripts.

    PS C:\Scripts> ./AD-PowerAdmin.ps1

AD-PowerAdmin can be run manually, on-demand, or installed for full automation. To install the fully automated version, manually run the script, and in the main menu, enter "i" and enter to start the installer process.
 The install process does a few things that are required to manage Windows Scheduled Tasks automatically. To manage schedule tasks, the following configurations are made to Active Directory.

 - A standalone Managed Service(sMSA) account named "ADPowerAdmMSA" is created. The sMSA account, "ADPowerAdmMSA", user account is restricted to the one computer it is installed on.
 - The sMSA account, "ADPowerAdmMSA", is given Domain Admins rights. Its is required, and no, there is not a more limited permissions set to preformed the tasks needed.
 - A new Group Policy is created named "AD-PowerAdminGPO". This GPO gives the "ADPowerAdmMSA" user account the "Log on as a service" permissions.
 - A Scheduled Task is created with the sMSA account, "ADPowerAdmMSA", that will launch the AD-PowerAdmin script daily at 9AM.

#
# Features In-Depth
## Audit for AD Security Best Practices
This audit will look for many small security and best practices recommendations. Most of the tests are simple but could leave an AD server open to attack. Test performed include the following.

 - Unprivileged accounts with "adminCount=1" attribute set. [REF-LINK](https://cybergladius.social/@CyberGladius/109649278142902592)
 - Users and computers with non-default Primary Group IDs.
 - Disabled accounts with Group Membership other than 'Domain Users' group.

## Audit AD Admin Account Report
This admin audit report will generate a list of all user accounts within the domain that have group membership in highly privileged groups. These groups should be used as little as possible, and membership should only be given if required by a job role. Here is a list of the groups audited.

 - Domain Admins
 - Enterprise Admins
 - Administrators
 - Schema Admins
 - Backup Operators
 - Account Operators
 - Server Operators
 - Domain Controllers
 - Print Operators
 - Replicator
 - Enterprise Key Admins
 - Key Admins

The audit includes Domain Controllers, and Managed Service Accounts. Any account that have group membership that could be used to escalate to Domain Admins will be listed in the report. This is a good way to find rogue domain controllers, and managed service accounts that have been compromised.

## Force KRBTGT password Update
This option will update the KRBTGT password for all domain controllers.
During normal operation, the KRBTGT password needs to be updated every 90 days, twice.
Every 90 days, update the KRBTGT password, wait 10 hours, then update it again.
Alternatively, use this scripts '-Daily' option to automate this process.

See my blog post for more details: https://cybergladius.com/ad-hardening-against-kerberos-golden-ticket-attack/

## Search for inactive computers
Search for computers that have been inactive for more than X days; default is 90 days. This will disable the computer,
strip all group membership, and move it to the Disabled.Desktop OU. This can be run manually or automated
via the 'Daily' option.

See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

!!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

## Search for inactive Users
Search for User that have been inactive for more than X days; default is 90 days. This will disable the user,
strip all group membership, and move it to the Disabled.Users OU. This can be run manually or automated
via the 'Daily' option.

See my blog post for more details: https://cybergladius.com/ad-hardening-inactive-computer-objects/

!!NOTE!!: You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.

## Password Audit for User
The Password Audit checks for the following.
- Weak or breached passwords.
- Groups of User accounts that all have the same password.
- User accounts will never expire.
- Administrative accounts are allowed to be delegated to a service account.

If you want to test for known breached passwords, you will need to download the breached password list
from https://haveibeenpwned.com/Passwords. The file is a 7z compressed file. You will need to extract
the file and save it to the same directory as the AD-PowerAdmin.ps1 script. The file name should be
'pwned-passwords-ntlm-ordered-by-hash-v8.txt' and the file size should be 28.5GB uncompressed. The file is updated
every 12 months. You will need to download the new file and replace the old file when it is updated.

If you want to test for weak passwords, you will need to download or build a list of weak passwords.
The file should be a text file with one password per line. Consider all the bad passwords you have seen in
the past within your company and add them to the list. This will help prevent users from using these very
bad passwords. Every company is guilty of using bad passwords with the company name in it, or the name of
the CEO, or the name of the company mascot, etc.
Example: `'<CompanyName>2022!', '<CompanyInitials>2022!', '<CompanyHqCityName>@<YearEstablished>'`, etc.
The file name should be 'weak-passwords.txt' and reside in the same directory as the AD-PowerAdmin.ps1 script.

Users will be notified via email if their password is weak or breached. User accounts with a weak or breached
password will have X days to change their password, default is 3 days. If the user does not change their
password within X days, the user account will have the 'User must change password at next logon' option enabled.

On the first day of the month, the script will send an email to the admin account with a report of all the audit results.
### Process Flow
<div align="center">
    <div style="display: flex; align-items: flex-start;">
        <img align=top src="https://cybergladius.com/wp-content/uploads/2023/02/ADPowerAdmin_WeakPWTest.png" />
    </div>
</div>

### !!!   NOTES   !!!
- You must update the settings in 'AD-PowerAdmin_settings.ps1' to matches your AD setup.
- The follow up process to ensure users change their password is done via a scheduled task.
- The process by which the password data is pulled is done via a DCSync. This can trigger an alert in your SIEM.
    A DCSync, is not an attack, it is a normal process, but attackers are known to use DCSync to get password hashes.
- If non-user accounts have the warning 'These administrative accounts are allowed to be delegated to a service' then it
    may be a false positive. See my post here for more details: https://cybergladius.social/@CyberGladius/109649278142902592

#


