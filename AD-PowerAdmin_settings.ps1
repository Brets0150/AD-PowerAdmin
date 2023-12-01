#Requires -RunAsAdministrator
<#
.SYNOPSIS
	Only variables and configurations for AD-PowerAdmin.

.VERSION
    1.0.2 Alpha

.DESCRIPTION
    Only variables and configurations for AD-PowerAdmin.

.EXAMPLE
    Do not use this script directly. This script is called by the main script.

.LINK
	https://github.com/Brets0150/AD-PowerAdmin

.NOTES
	Author: Bret.s AKA: CyberGladius / License: MIT
#>
##############################################################################################
# Debugging
[bool]$global:Debug = $true

##############################################################################################
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

##############################################################################################
# -------------------[Optional]------------------- #
# Enable or disable the Daily tasks that will be run.
[bool]$global:KerberosKRBTGTAudit      = $true
[bool]$global:InactiveComputerAudit    = $true
[bool]$global:InactiveUserAudit        = $true
[bool]$global:WeakPasswordAudit        = $true

##############################################################################################
# -------------------[Mandatory]------------------- #
# Kerberos KRBTGT password and account settings.
# The number of days between KRBTGT password updates. Default is 90 days.
[int]$global:krbtgtPwUpdateInterval = 90

##############################################################################################
# Daily Inactive Computer clean up settings.
# -------------------[Mandatory]------------------- #
# Specify inactivity range value below in days.
[Int]$global:InactiveDays = 90

# -------------------[Mandatory]------------------- #
# Inactive computer maybe within multiple OU's. So we need build an array of OU's to search and clean up. The details are nested in a hashtable in the array.
# Each hashtable contains the following keys:
# 1 - SearchOUbase = Set the basic search path in AD. You can limit the search to a specific OU.
#      Example: OU=Computers,OU=MyCompany,DC=MyDomain,DC=local
# 2 - DisabledOULocal = Set the OU path where the computer objects will be moved to after being disabled.
#      Example: OU=DisabledComputers,OU=MyCompany,DC=MyDomain,DC=local

# You are able to add as many OU's as you want. Just add a new hashtable to the array. Inversly, you can remove second hashtable if you only want to search one OU.
[array]$global:InactiveComputersLocations = @(
    @{
        # Set the basic search path in AD. You can limit the search to a specific OU.
        SearchOUbase = 'OU=Desktops,DC=EXAMPLE,DC=COM'

        # The disabled Computers OU location in AD. This is where the computers will be moved to.
        DisabledOULocal = 'OU=Disabled.Desktop,OU=Desktops,DC=EXAMPLE,DC=COM'
    }

    @{
        # Set the basic search path in AD. You can limit the search to a specific OU.
        SearchOUbase = 'OU=Servers,DC=EXAMPLE,DC=COM'

        # The disabled Computers OU location in AD. This is where the computers will be moved to.
        DisabledOULocal = 'OU=Disabled.Servers,OU=Servers,DC=EXAMPLE,DC=COM'
    }

)

##############################################################################################
# Daily Inactive Users clean up settings.

# -------------------[Mandatory]------------------- #
# Inactive Users maybe within multiple OU's. So we need build an array of OU's to search and clean up. The details are nested in a hashtable in the array.
# Each hashtable contains the following keys:
# 1 - SearchOUbase = Set the basic search path in AD. You can limit the search to a specific OU.
#      Example: OU=Users,OU=MyCompany,DC=MyDomain,DC=local
# 2 - DisabledOULocal = Set the OU path where the user objects will be moved to after being disabled.
#      Example: OU=DisabledUsers,OU=MyCompany,DC=MyDomain,DC=local
# You are able to add as many OU's as you want. Just add a new hashtable to the array. Inversly, you can remove second hashtable if you only want to search one OU.
[array]$global:InactiveUsersLocations = @(

    @{
        # Set the basic search path in AD. You can limit the search to a specific OU. If you want to search all user accounts in AD, leave this blank.
        # Example: 'OU=Users,DC=EXAMPLE,DC=COM'
        SearchOUbase = 'DC=EXAMPLE,DC=COM'

        # The disabled Computers OU location in AD. This is where the computers will be moved to.
        DisabledOULocal = 'OU=Disabled.Users,OU=Users,DC=EXAMPLE,DC=COM'
    }

)

##############################################################################################
# Password Quality Test Settings
# The password quality test is used to check the password quality of all user accounts in AD.

# If you want to test for known breached passwords, you will need to download the breached password list from https://haveibeenpwned.com/Passwords.
# The file is a 7z compressed file. You will need to extract the file and save it to the same directory as the AD-PowerAdmin.ps1 script.
# The file name should be "pwned-passwords-ntlm-ordered-by-hash-v8.txt" and the file size should be 28.5GB.
# The file is updated every 12 months. You will need to download the new file and replace the old file when it is updated.

# Set the file path to the breached password list file.
[string]$global:NtlmHashDataFile = 'pwned-passwords-ntlm-ordered-by-hash-v8.txt'

# If you want to test for weak passwords, you can add a plain text file with a list of weak passwords. One password per line.
# The file is a plain text file. You will need to save it to the same directory as the AD-PowerAdmin.ps1 script.
# The file name should be "weak-passwords.txt".
# The file is updated every 12 months. You will need to download the new file and replace the old file when it is updated.

# Set the file path to the weak password list file.
[string]$global:WeakPassDictFile = 'weak-passwords.txt'

# Set the SearchOUbase to the OU path where you want to search for user accounts. If you want to search all user accounts in AD, leave this blank.
# Example: [string]$global:PasswordQualityTestSearchOUbase = 'OU=Users,DC=EXAMPLE,DC=COM'
[string]$global:PasswordQualityTestSearchOUbase = ''

# The email address that the email will be sent to.
# The default is to is to use the main admin email address at the top of the script, but if you want to send the reports to a different email address, you can set it here.
# EXAMPLE: [string]$global:ReportAdminEmailTo = 'Joe.doe@example.com'
# EXAMPLE: [string]$global:ReportAdminEmailTo = 'SecurityTeamDistroGroup@example.com
[string]$global:ReportAdminEmailTo = $global:ADAdminEmail

# Enable CC the AD Admins on the password audit alert email. When a user is found with a breached or weak password, the user will receive an email with the message above. The AD Admins will also receive a copy of the email.
# EXAMPLE: [bool]$global:PwAuditAlertEmailCCAdmins = $true
[bool]$global:PwAuditAlertEmailCCAdmins = $false

# -------------------[Mandatory]------------------- #
# The number of DAYS before the user is forced to update there password.
# EXAMPLE: [int]$global:PwAuditPwChangeGracePeriod = 3
[int]$global:PwAuditPwChangeGracePeriod = 3

# -------------------[Mandatory]------------------- #
# Message to send to the user.
# Users who are discovered with a breached or weak password will receive an email with the following message.
# To make the settings cleaner looking, I increment the message variable over multiple lines. This is not required. However, it is easier to read. You can put the message on one line if you want, or you can add more lines.
# The email message will automattically add "Hello <User Name>," to the beginning of the message. The user name will be taken from the user account in AD. So you do not need to add an opening greeting to the message.
[string]$global:PwAuditAlertEmailMessage  = "Your password has been identified in a breached or is weak. You have $global:PwAuditPwChangeGracePeriod days to change it."
[string]$global:PwAuditAlertEmailMessage += " If you do not change your password, your account will be forced to update your password on next login." + "`r`n"
[string]$global:PwAuditAlertEmailMessage += "Contact the IT Security department if you have any questions." + "`r`n" + "`r`n" + "Thank you," + "`r`n" + "Security Team"

# -------------------[Mandatory]------------------- #
# Email Allert Message Subject.
[string]$global:PwAuditAlertEmailSubject   = "ADPowerAdmin: Password Breached or Weak - ACTION REQUIRED"

##############################################################################################
# Email Settings.
# Configure the variable that are used for sending emails.
# You need to configure at a minimum the following variables to send emails. The rest of the variables are optional, but it really depends on your SMTP server settings.
# 1 - $global:SMTPServer = The SMTP server address.
# 2 - $global:ReportEmailFrom = The email address that the email will be sent from.
# 3 - $global:ReportAdminEmailTo = The email address that the email will be sent to.

# -------------------[Mandatory]------------------- #
# The SMTP server address.
# EXAMPLE: [string]$global:SMTPServer = 'smtp.example.com'
# EXAMPLE: [string]$global:SMTPServer = '10.110.15.35'
[string]$global:SMTPServer = ''

# ------------
# Optional variables. These variables are optional, but it really depends on your SMTP server settings.
# If you do need a Username and Password, you will need to create a new user account in AD and give it the permission to send emails ONLY!!
# You are hard coding the password in the script. So you will need to encrypt the password using the ConvertTo-SecureString cmdlet.
# Consider the security implications of hard coding the password in the script.
# NOTE: SSL always enabled. It is hardcode in the script.

# The email address that the email will be sent from.
# EXAMPLE: [string]$global:ReportEmailFrom = 'AdPowerAdmin@example.com'
[string]$global:ReportsEmailFrom = $global:FromEmail

# Use SSL to connect to the SMTP server.
# EXAMPLE: [bool]$global:SmtpEnableSSL = $true
[bool]$global:SmtpEnableSSL = $true

# The SMTP server port. The default port is 587.
# EXAMPLE: [int]$global:SMTPServerPort = 587
[string]$global:SMTPPort = ''

# The SMTP server username.
# EXAMPLE: [string]$global:SMTPServerUsername = 'AdPowerAdmin'
[string]$global:SMTPUsername = ''

# The SMTP server password.
# EXAMPLE: [string]$global:SMTPServerPassword = 'P@ssw0rd'
[string]$global:SMTPPassword = ''

##############################################################################################