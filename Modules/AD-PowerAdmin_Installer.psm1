Function Initialize-Module {
        <#
    .SYNOPSIS
    Initialize-Module

    .DESCRIPTION
    Initialize-Module

    .EXAMPLE
    Initialize-Module

    .NOTES
    Initialize-Module is called by AD-PowerAdmin_Main.ps1 to initialize the module.

    #>
    # Remove stale entries if module is reloaded.
    $global:Menu.Remove('InstallerMenu')
    $global:SubMenus.Remove('InstallerMenu')

    # Register the sub-menu items.
    $global:SubMenus += @{
        'InstallerMenu' = @{
            Title       = "AD-PowerAdmin Management"
            HelpCommand = "Show-InstallHelp"
            Items = @{
                'InstallADPowerAdmin' = @{
                    Title   = "Install AD-PowerAdmin"
                    Label   = "Install AD-PowerAdmin to run daily tasks as a scheduled task using a managed service account."
                    Command = "Install-ADPowerAdmin"
                }
                'TestADPowerAdminInstall' = @{
                    Title   = "Test Installation"
                    Label   = "Test if the AD-PowerAdmin script is installed correctly and all components are functioning."
                    Command = "Test-ADPowerAdminInstall"
                }
                'RemoveADPowerAdmin' = @{
                    Title   = "Remove AD-PowerAdmin"
                    Label   = "Remove the AD-PowerAdmin script and all related objects, including the scheduled task and sMSA account."
                    Command = "Remove-ADPowerAdmin"
                }
                'InstallPowerShell7' = @{
                    Title   = "Install PowerShell 7"
                    Label   = "Install PowerShell 7 on the system using WinGet."
                    Command = "Install-PowerShell7"
                }
                'UpdateModules' = @{
                    Title   = "Update Modules"
                    Label   = "Download and apply the latest module files from GitHub. Channel (Release or Development) is set by UpdateChannel in settings."
                    Command = "Update-ADPowerAdminModules"
                }
                'UpdateMainScript' = @{
                    Title   = "Update Main Script"
                    Label   = "Download and apply the latest AD-PowerAdmin.ps1 from GitHub. Displays current vs. available version, prompts for confirmation, and creates a read-only backup before replacing the file. Channel (Release or Development) is set by UpdateChannel in settings."
                    Command = "Update-ADPowerAdminMainScript"
                }
                'SettingsWizard' = @{
                    Title   = "Configure Settings Wizard"
                    Label   = "Interactive wizard to configure all AD-PowerAdmin settings in AD-PowerAdmin_settings.ps1, section by section. Prompts for each value with the current default shown, supports AD OU search, and creates a read-only backup before writing."
                    Command = "Start-SettingsWizard"
                }
                'UpdateSettings' = @{
                    Title   = "Migrate Settings File"
                    Label   = "Download the latest settings file from GitHub and transplant all user-configured values into the new structure. Adopts the new file layout and variable ordering while preserving every setting you have configured."
                    Command = "Update-ADPowerAdminSettingsFile"
                }
                'TestEmailConfig' = @{
                    Title   = "Test Email Configuration"
                    Label   = "Run a multi-stage diagnostic to verify SMTP settings: validates configuration values, tests DNS resolution of the SMTP server, tests TCP port connectivity, and attempts to send a test email to ADAdminEmail. Detailed pass/fail output at each stage aids troubleshooting."
                    Command = "Test-EmailConfiguration"
                }
            }
        }
    }

    # Register a single main menu entry that opens the sub-menu.
    $global:Menu += @{
        'InstallerMenu' = @{
            Title    = "AD-PowerAdmin Management"
            Label    = "Install, test, or remove AD-PowerAdmin and its dependencies."
            Module   = "AD-PowerAdmin_Installer"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'InstallerMenu'"
        }
    }
}

Initialize-Module

function Show-InstallHelp {
    <#
    .SYNOPSIS
    Displays a detailed guide covering installation, updates, and settings management.

    .DESCRIPTION
    Prints a section-by-section guide covering every system change made during installation,
    every action performed by the three update functions, and the update channel system.
    Accessible from the AD-PowerAdmin Management submenu by pressing h.

    .EXAMPLE
    Show-InstallHelp

    .NOTES
    Menu path: AD-PowerAdmin Management -> h (Help / Deployment Guide)
    #>

    [string]$Bar  = '=' * $global:OptionsMaxTextLength
    [string]$Bar2 = '-' * $global:OptionsMaxTextLength

    function Write-HelpHeader([string]$Title) {
        Write-Host ""
        Write-Host $Bar  -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host $Bar  -ForegroundColor Cyan
    }

    function Write-HelpStep([string]$StepNum, [string]$Title) {
        Write-Host ""
        Write-Host "  Step $StepNum -- $Title" -ForegroundColor Yellow
        Write-Host $Bar2 -ForegroundColor DarkGray
    }

    function Write-HelpSection([string]$Title) {
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Yellow
        Write-Host $Bar2 -ForegroundColor DarkGray
    }

    function Write-HelpLine([string]$Text) {
        Write-Host "  $Text" -ForegroundColor White
    }

    function Write-HelpDetail([string]$Text) {
        Write-Host "      $Text" -ForegroundColor Gray
    }

    function Write-HelpNote([string]$Text) {
        Write-Host "  NOTE: $Text" -ForegroundColor DarkYellow
    }

    function Write-HelpCreate([string]$Text) {
        Write-Host "  [CREATES]  $Text" -ForegroundColor Green
    }

    function Write-HelpModify([string]$Text) {
        Write-Host "  [MODIFIES] $Text" -ForegroundColor Magenta
    }

    function Write-HelpRead([string]$Text) {
        Write-Host "  [READS]    $Text" -ForegroundColor Cyan
    }

    # =========================================================================
    Write-HelpHeader "AD-PowerAdmin Management -- Help / Deployment Guide"
    Write-Host ""
    Write-HelpLine "This guide covers three topics:"
    Write-HelpLine "  Part 1 -- Installation  (what Install AD-PowerAdmin does)"
    Write-HelpLine "  Part 2 -- Updates       (Update Modules, Update Main Script)"
    Write-HelpLine "  Part 3 -- Settings      (Migrate Settings File)"

    # #########################################################################
    Write-HelpHeader "Part 1: Installation"
    Write-Host ""
    Write-HelpLine "The installer is IDEMPOTENT -- it checks each component before acting."
    Write-HelpLine "It is safe to run multiple times. Steps already complete are skipped"
    Write-HelpLine "or confirmed rather than duplicated."
    Write-Host ""
    Write-HelpLine "Seven steps are performed in this order:"

    # =========================================================================
    Write-HelpStep "1" "Confirm Installation Directory"
    Write-HelpLine "Before making any system change, the installer shows the current value"
    Write-HelpLine "of InstallDirectory from settings and asks you to confirm or change it."
    Write-Host ""
    Write-HelpRead   "AD-PowerAdmin_settings.ps1  (`$global:InstallDirectory)"
    Write-HelpModify "AD-PowerAdmin_settings.ps1  (only if you enter a new path)"
    Write-HelpModify "`$global:InstallDirectory    (updated in memory for this session)"
    Write-Host ""
    Write-HelpNote "A changed path is written back to the settings file immediately so it"
    Write-HelpNote "persists after a restart."

    # =========================================================================
    Write-HelpStep "2" "Create and Harden the Install Directory"
    Write-HelpLine "Creates the install directory if it does not already exist, then locks"
    Write-HelpLine "it down and enables auditing so all access is recorded."
    Write-Host ""
    Write-HelpCreate "Install directory folder  (path from `$global:InstallDirectory)"
    Write-Host ""
    Write-HelpLine "ACL hardening applied to the directory:"
    Write-HelpDetail "Owner         : Domain Admins group"
    Write-HelpDetail "Inheritance   : All inherited permissions are removed"
    Write-HelpDetail "Access        : Only Domain Admins receive FullControl"
    Write-Host ""
    Write-HelpLine "Audit policy changes:"
    Write-HelpDetail "System-level File System auditing is enabled via auditpol.exe:"
    Write-HelpDetail "  auditpol /set /subcategory:""File System"" /success:enable /failure:enable"
    Write-HelpDetail "A SACL is written to the folder for the principal 'Everyone':"
    Write-HelpDetail "  Audited rights : ExecuteFile, DeleteSubdirectoriesAndFiles, Write,"
    Write-HelpDetail "                   Delete, ChangePermissions, TakeOwnership"
    Write-HelpDetail "  Inheritance    : ContainerInherit + ObjectInherit (all children)"
    Write-HelpDetail "  Audit flags    : Success and Failure"
    Write-HelpDetail "Every interaction with the directory generates a Security event log entry."
    Write-Host ""
    Write-HelpModify "System audit policy  (File System subcategory -- Success + Failure)"
    Write-HelpModify "Install directory ACL  (owner, DACL, and SACL)"

    # =========================================================================
    Write-HelpStep "3" "Deploy Production Files"
    Write-HelpLine "Copies only the required files from the current running location to the"
    Write-HelpLine "install directory. Development files are never copied."
    Write-Host ""
    Write-HelpLine "What is copied:"
    Write-HelpDetail "AD-PowerAdmin.ps1           -- main script"
    Write-HelpDetail "AD-PowerAdmin_settings.ps1  -- all configuration variables"
    Write-HelpDetail "Modules\                    -- all module files (recursive)"
    Write-HelpDetail "README.md                   -- project documentation"
    Write-Host ""
    Write-HelpLine "What is NOT copied:"
    Write-HelpDetail ".git\, temp\, Reports\, password lists, test scripts, and everything"
    Write-HelpDetail "else not in the four items above."
    Write-Host ""
    Write-HelpLine "After copying, the installer verifies these three critical items exist"
    Write-HelpLine "in the install directory: AD-PowerAdmin.ps1, AD-PowerAdmin_settings.ps1,"
    Write-HelpLine "and Modules\"
    Write-Host ""
    Write-HelpCreate "AD-PowerAdmin.ps1, AD-PowerAdmin_settings.ps1, Modules\, README.md"
    Write-HelpNote "If you are already running from the install directory this step is skipped."

    # =========================================================================
    Write-HelpStep "4" "Create the Standalone Managed Service Account (sMSA)"
    Write-HelpLine "Creates a Standalone Managed Service Account in Active Directory. The"
    Write-HelpLine "scheduled task runs under this account, which holds Domain Admin rights"
    Write-HelpLine "so AD-PowerAdmin can perform all required AD operations unattended."
    Write-Host ""
    Write-HelpLine "Account details:"
    Write-HelpDetail "Name        : `$global:MsaAccountName (default: ADPowerAdmMSA)"
    Write-HelpDetail "Type        : Standalone MSA (-RestrictToSingleComputer)"
    Write-HelpDetail "Password    : Auto-generated by AD; rotates every 30 days automatically"
    Write-HelpDetail "              Only this one computer can ever read the password from AD"
    Write-HelpDetail "Location    : domain.com/Managed Service Accounts container"
    Write-HelpDetail "Membership  : Domain Admins"
    Write-Host ""
    Write-HelpLine "Local installation performed after AD account creation:"
    Write-HelpDetail "Add-ADComputerServiceAccount  -- tells AD this computer uses the sMSA"
    Write-HelpDetail "Install-ADServiceAccount      -- installs the sMSA credential locally"
    Write-HelpDetail "Test-ADServiceAccount         -- confirms local install succeeded"
    Write-Host ""
    Write-HelpLine "Re-install behavior (account already exists in AD):"
    Write-HelpDetail "Test-ADServiceAccount runs to check if the sMSA is installed on this"
    Write-HelpDetail "computer. If it is not (new server, or previous partial install), the"
    Write-HelpDetail "local installation steps above are run again before continuing."
    Write-Host ""
    Write-HelpCreate "AD Service Account object    in Active Directory"
    Write-HelpModify "Domain Admins group          (sMSA added as a member)"
    Write-HelpModify "Local computer               (sMSA credential installed locally)"

    # =========================================================================
    Write-HelpStep "5" "Modify the Default Domain Controllers Policy GPO"
    Write-HelpLine "Grants the sMSA the 'Log on as a service' right on the domain controller."
    Write-HelpLine "Windows requires this right before a service account can be assigned to"
    Write-HelpLine "a scheduled task running on a DC."
    Write-Host ""
    Write-HelpLine "Why the Default Domain Controllers Policy is modified directly:"
    Write-HelpDetail "PowerShell has no cmdlet that writes the SeServiceLogonRight privilege"
    Write-HelpDetail "to a GPO. The only way to do it is to directly edit the security template"
    Write-HelpDetail "file (GptTmpl.inf) on SYSVOL. The existing DC policy is used because it"
    Write-HelpDetail "is always present and already linked to the Domain Controllers OU, so no"
    Write-HelpDetail "new GPO needs to be created or linked."
    Write-Host ""
    Write-HelpLine "GPO targeted:"
    Write-HelpDetail "Name : Default Domain Controllers Policy"
    Write-HelpDetail "GUID : {6AC1786C-016F-11D2-945F-00C04fB984F9}"
    Write-Host ""
    Write-HelpLine "File edited on SYSVOL:"
    Write-HelpDetail "\\domain.fqdn\SYSVOL\domain.fqdn\Policies\"
    Write-HelpDetail "  {6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\"
    Write-HelpDetail "  Windows NT\SecEdit\GptTmpl.inf"
    Write-Host ""
    Write-HelpLine "What changes inside GptTmpl.inf:"
    Write-HelpDetail "The sMSA's SID is appended to the SeServiceLogonRight line. The SID is"
    Write-HelpDetail "used instead of the account name so the entry survives account renames."
    Write-HelpDetail "If SeServiceLogonRight does not exist yet, it is added after the"
    Write-HelpDetail "SeBatchLogonRight line."
    Write-Host ""
    Write-HelpLine "A forced GPO refresh is triggered after the file is written:"
    Write-HelpDetail "Invoke-GPUpdate -Force"
    Write-Host ""
    Write-HelpModify "GptTmpl.inf on SYSVOL  (SeServiceLogonRight, sMSA SID appended)"
    Write-HelpModify "Group Policy           (Invoke-GPUpdate -Force on this DC)"
    Write-Host ""
    Write-HelpNote "Security note: the sMSA password is random, AD-managed, and readable only"
    Write-HelpNote "by this DC. Any attacker who could abuse SeServiceLogonRight on the DC"
    Write-HelpNote "would already have full control of the domain."

    # =========================================================================
    Write-HelpStep "6" "Register the AD-PowerAdmin_Daily Scheduled Task"
    Write-HelpLine "Creates a Windows Scheduled Task that runs AD-PowerAdmin daily in"
    Write-HelpLine "unattended mode, executing all audit jobs flagged Daily = true."
    Write-Host ""
    Write-HelpLine "Task configuration:"
    Write-HelpDetail "Name              : AD-PowerAdmin_Daily"
    Write-HelpDetail "Run as            : `$global:MsaAccountName (sMSA)"
    Write-HelpDetail "Privilege level   : Highest (runs elevated)"
    Write-HelpDetail "Schedule          : Daily, first run tomorrow at 09:00 AM"
    Write-HelpDetail "Network required  : Yes (task waits for network availability)"
    Write-HelpDetail "Wake to run       : Yes"
    Write-HelpDetail "Working directory : install directory"
    Write-Host ""
    Write-HelpLine "Command the task executes:"
    Write-HelpDetail "PowerShell.exe -File ""<InstallDir>\AD-PowerAdmin.ps1"""
    Write-HelpDetail "               -Unattended -JobName 'Daily'"
    Write-Host ""
    Write-HelpLine "If the task already exists the installer prompts before replacing it."
    Write-Host ""
    Write-HelpCreate "Scheduled task  'AD-PowerAdmin_Daily'  in Windows Task Scheduler"

    # =========================================================================
    Write-HelpStep "7" "Install the DSInternals PowerShell Module"
    Write-HelpLine "Checks whether DSInternals is installed and installs it from PSGallery"
    Write-HelpLine "if it is not already present."
    Write-Host ""
    Write-HelpLine "Why DSInternals is needed:"
    Write-HelpDetail "The password audit module uses DSInternals to read AD password hashes"
    Write-HelpDetail "and compare them against the HaveIBeenPwned breach database and a local"
    Write-HelpDetail "weak-password dictionary. Password auditing will not work without it."
    Write-Host ""
    Write-HelpDetail "Install command: Install-Module -Name DSInternals -Scope AllUsers -Force"
    Write-HelpDetail "Requires outbound access to PowerShell Gallery (www.powershellgallery.com)."
    Write-Host ""
    Write-HelpCreate "DSInternals module  in the system-wide PowerShell module path"

    # =========================================================================
    Write-HelpHeader "Post-Installation Checks"
    Write-HelpLine "After all steps complete, Test-ADPowerAdminInstall runs automatically"
    Write-HelpLine "and verifies the following:"
    Write-Host ""
    Write-HelpDetail "[CHECK]  sMSA account exists in AD"
    Write-HelpDetail "[CHECK]  sMSA is a member of Domain Admins"
    Write-HelpDetail "[CHECK]  Default Domain Controllers Policy contains sMSA SeServiceLogonRight"
    Write-HelpDetail "[CHECK]  Scheduled task 'AD-PowerAdmin_Daily' exists and is enabled"
    Write-HelpDetail "[CHECK]  System File System audit policy is enabled (Success + Failure)"
    Write-HelpDetail "[CHECK]  Install directory has the correct SACL audit entries"
    Write-Host ""
    Write-HelpLine "If the test passes the script exits. Relaunch from the install directory:"
    Write-HelpDetail "powershell.exe -File ""`$global:InstallDirectory\AD-PowerAdmin.ps1"""
    Write-Host ""
    Write-HelpNote "GPO changes take effect on the next refresh cycle. Invoke-GPUpdate -Force"
    Write-HelpNote "is run on this DC but other DCs need one replication + refresh cycle."
    Write-HelpNote "The scheduled task will not run on the day of installation (first run"
    Write-HelpNote "is tomorrow at 09:00 AM)."

    # #########################################################################
    Write-HelpHeader "Part 2: Updates"
    Write-Host ""
    Write-HelpLine "AD-PowerAdmin has two separate update functions covering different parts"
    Write-HelpLine "of the codebase. Both respect the update channel setting."

    # =========================================================================
    Write-HelpSection "Update Channel"
    Write-HelpLine "Both update functions check `$global:UpdateChannel before downloading."
    Write-HelpLine "The channel is set in AD-PowerAdmin_settings.ps1 and can be changed"
    Write-HelpLine "via the Configure Settings Wizard."
    Write-Host ""
    Write-HelpDetail "Release (default)"
    Write-HelpDetail "  Queries the GitHub API to find the latest published release tag."
    Write-HelpDetail "  Downloads files from that specific tagged commit."
    Write-HelpDetail "  Example URL pattern:"
    Write-HelpDetail "    https://raw.githubusercontent.com/Brets0150/AD-PowerAdmin/"
    Write-HelpDetail "    v1.2.0/AD-PowerAdmin.ps1"
    Write-HelpDetail "  Use this for production. You get tested, versioned code."
    Write-Host ""
    Write-HelpDetail "Development"
    Write-HelpDetail "  Downloads files directly from the 'main' branch on GitHub."
    Write-HelpDetail "  You get whatever is currently committed to main -- including"
    Write-HelpDetail "  work-in-progress changes that have not been tested or released."
    Write-HelpDetail "  Example URL pattern:"
    Write-HelpDetail "    https://raw.githubusercontent.com/Brets0150/AD-PowerAdmin/"
    Write-HelpDetail "    main/AD-PowerAdmin.ps1"
    Write-HelpDetail "  Use this only if you are testing pre-release features and understand"
    Write-HelpDetail "  that the code may be incomplete or broken."
    Write-Host ""
    Write-HelpNote "The update functions do NOT use zip archives or cloning. They fetch"
    Write-HelpNote "raw file content directly over HTTPS from raw.githubusercontent.com"
    Write-HelpNote "one file at a time using Invoke-WebRequest."

    # =========================================================================
    Write-HelpSection "Update Modules"
    Write-HelpLine "Downloads each .psm1 and .psd1 file in the Modules\ directory from"
    Write-HelpLine "GitHub and replaces the local copy if the content differs."
    Write-Host ""
    Write-HelpLine "What it does, in order:"
    Write-HelpDetail "1. Determines the download ref (release tag or 'main') from the channel."
    Write-HelpDetail "2. Scans the local Modules\ folder for every .psm1 and .psd1 file."
    Write-HelpDetail "3. For each file, fetches the raw content from GitHub."
    Write-HelpDetail "4. Compares the remote content to the local file (CRLF-normalized)."
    Write-HelpDetail "5. If the files differ:"
    Write-HelpDetail "   a. Creates a timestamped backup directory:"
    Write-HelpDetail "      Reports\ModuleBackups\yyyyMMdd_HHmmss\"
    Write-HelpDetail "   b. Copies the current local file to the backup as <filename>.txt"
    Write-HelpDetail "      The .txt extension prevents PowerShell from executing the backup."
    Write-HelpDetail "      The backup file is marked read-only."
    Write-HelpDetail "   c. Overwrites the local file with the downloaded content."
    Write-HelpDetail "6. Reports [UP TO DATE], [UPDATED], or [FAILED] per file."
    Write-Host ""
    Write-HelpLine "What it does NOT do:"
    Write-HelpDetail "It does not add new module files that do not already exist locally."
    Write-HelpDetail "It does not delete modules you have removed from GitHub."
    Write-HelpDetail "It does not restart AD-PowerAdmin (you must do that manually)."
    Write-Host ""
    Write-HelpModify "Local .psm1 and .psd1 files in Modules\"
    Write-HelpCreate "Backup copies under Reports\ModuleBackups\  (.txt, read-only)"
    Write-HelpNote "Restart AD-PowerAdmin after updating modules for changes to take effect."

    # =========================================================================
    Write-HelpSection "Update Main Script"
    Write-HelpLine "Downloads the latest AD-PowerAdmin.ps1 from GitHub and replaces the"
    Write-HelpLine "local copy if the content has changed."
    Write-Host ""
    Write-HelpLine "What it does, in order:"
    Write-HelpDetail "1. Determines the download ref (release tag or 'main') from the channel."
    Write-HelpDetail "2. Fetches the raw AD-PowerAdmin.ps1 content from GitHub."
    Write-HelpDetail "3. Compares the remote content to the running script (CRLF-normalized)."
    Write-HelpDetail "4. If the files are identical, reports [UP TO DATE] and stops."
    Write-HelpDetail "5. If they differ:"
    Write-HelpDetail "   a. Extracts the version number from the remote file."
    Write-HelpDetail "   b. Shows: current version  -->  available version."
    Write-HelpDetail "   c. Prompts: 'Apply update? (y/N)'"
    Write-HelpDetail "   d. If confirmed:"
    Write-HelpDetail "      - Creates a timestamped backup directory:"
    Write-HelpDetail "        Reports\MainScriptBackups\yyyyMMdd_HHmmss\"
    Write-HelpDetail "      - Copies the current script to the backup as AD-PowerAdmin.ps1.txt"
    Write-HelpDetail "        The .txt extension prevents execution; the file is read-only."
    Write-HelpDetail "      - Writes the downloaded content to the running script path."
    Write-HelpDetail "      - Reports [UPDATED] and reminds you to restart."
    Write-Host ""
    Write-HelpLine "Why it is safe to overwrite the running script:"
    Write-HelpDetail "PowerShell reads the entire script into memory before executing it."
    Write-HelpDetail "Overwriting the file on disk does not affect the current session."
    Write-HelpDetail "The new version takes effect the next time you launch AD-PowerAdmin."
    Write-Host ""
    Write-HelpModify "AD-PowerAdmin.ps1  (replaced with downloaded content)"
    Write-HelpCreate "Backup copy under Reports\MainScriptBackups\  (.txt, read-only)"
    Write-HelpNote "Restart AD-PowerAdmin after updating the main script."

    # #########################################################################
    Write-HelpHeader "Part 3: Settings"

    # =========================================================================
    Write-HelpSection "Migrate Settings File"
    Write-HelpLine "Downloads the latest AD-PowerAdmin_settings.ps1 from GitHub, extracts"
    Write-HelpLine "all of your configured values from the current file, and transplants"
    Write-HelpLine "them into the new file's structure. The result is the new file layout"
    Write-HelpLine "with your settings preserved."
    Write-Host ""
    Write-HelpLine "What it does, in order:"
    Write-HelpDetail "1. Downloads the new settings file from GitHub (respects update channel)."
    Write-HelpDetail "2. Reads every typed `$global:* variable from your current settings file."
    Write-HelpDetail "3. Identifies which of your variables also exist in the new file."
    Write-HelpDetail "4. Shows a migration plan:"
    Write-HelpDetail "   - Variables to migrate  (your values will be carried over)"
    Write-HelpDetail "   - New variables          (new defaults from the downloaded file)"
    Write-HelpDetail "   - Removed variables      (dropped -- they no longer exist)"
    Write-HelpDetail "5. Prompts for confirmation before making any change."
    Write-HelpDetail "6. Creates a read-only backup: AD-PowerAdmin_settings.ps1.txt"
    Write-HelpDetail "7. Applies each of your values to the new file using targeted regex"
    Write-HelpDetail "   replacements, then writes the merged result to disk."
    Write-Host ""
    Write-HelpLine "What is preserved:"
    Write-HelpDetail "Every setting you have configured that still exists in the new version."
    Write-Host ""
    Write-HelpLine "What is NOT preserved:"
    Write-HelpDetail "Variables removed from the new version are dropped."
    Write-HelpDetail "Variables where your value is a computed reference (e.g. a value that"
    Write-HelpDetail "references another variable) are skipped -- the new file's formula is"
    Write-HelpDetail "kept so the reference chain stays intact."
    Write-Host ""
    Write-HelpModify "AD-PowerAdmin_settings.ps1  (replaced with merged content)"
    Write-HelpCreate "Backup copy: AD-PowerAdmin_settings.ps1.txt  (read-only)"
    Write-HelpNote "Restart AD-PowerAdmin after migration for the new settings to load."
    Write-HelpNote "Run Configure Settings Wizard after migration to review and fill in"
    Write-HelpNote "any new variables that arrived with their default values."

    Write-Host ""
    Write-Host $Bar -ForegroundColor Cyan
    Write-Host ""
# End of the Show-InstallHelp function.
}

function Install-ADPowerAdmin {
    <#
    .SYNOPSIS
    A function to install the AD-PowerAdmin script to run daily as a scheduled task.

    .DESCRIPTION
    Install the AD-PowerAdmin script to run daily tasks as a scheduled task.

    Note: The function that make up the install process check if there objectives are already completed before
        they try to complete them. For example, the function to create the AD-PowerAdmin home directory
        will check if the home directory already exists before it tries to create it.
        This allows the install script to be run multiple times without causing any issues.

    The install will:
    - Confirm the installation directory. Displays the current InstallDirectory setting and
        asks the administrator to confirm or change it before any changes are made. If the path
        is changed, the new value is written back to AD-PowerAdmin_settings.ps1 immediately.

    - Create the AD-PowerAdmin home directory as defined in the AD-PowerAdmin_settings.ps1 file.
        Set the owner of the AD-PowerAdmin home directory to the Domain Administrators group
        and remove all other permissions. Set the system audit policy and the AD-PowerAdmin
        home directory audit policy to "Everyone" for "Success" and "Failure". These audit
        settings means that any interaction with the AD-PowerAdmin home directory will be
        logged in the security event log.

    - Copy the production files to the install directory (defined in AD-PowerAdmin_settings.ps1)
        if AD-PowerAdmin is not already running from that directory. Only the required
        production items are copied: AD-PowerAdmin.ps1, AD-PowerAdmin_settings.ps1,
        Modules\, and README.md. Development-related content is intentionally excluded
        to keep the installation directory clean and scoped to what the scheduled task needs.

    - Install the DSInternals PowerShell module.

    - Create the AD-PowerAdmin sMSA account; needed for the unattended Scheduled Task.
        Create a new standalone Managed Service Account (sMSA) for the AD-PowerAdmin schedule task.
        The sMSA account will be the name defined in the AD-PowerAdmin_settings.ps1($global:MsaAccountName) file.
        The sMSA account will be created in the "domain.com/Managed Service Accounts" container,
            and will be a member of the "Domain Admins" group.
        The sMSA will be created with a random password and change ever 30-days.

    - Modify the existing "Domian Controllers Policy" GPO to give the sMSA account the "Log on as a service" right.
        I know this sounds odd. Read the comments in the Set-ADPowerAdminGPO function for more information.

    - Create a AD-PowerAdmin Schduled daily task.
        The task will be named "AD-PowerAdmin_Daily".
        The task will run the AD-PowerAdmin script daily at 9:00 AM.
        The task will run the AD-PowerAdmin script with the "-Unattended" and "-JobName 'Daily'" parameters.

    .EXAMPLE
    Install-ADPowerAdmin

    .NOTES

    #>

    # Confirm the installation directory before making any changes.
    if (-not (Confirm-InstallDirectory)) { return }

    # Determine whether a file copy is needed. If the confirmed install directory is the
    # same as the directory the script is currently running from, the files are already in
    # place and no copy should be attempted.
    [string]$NormInstallDir = [System.IO.Path]::GetFullPath($global:InstallDirectory).TrimEnd('\')
    [string]$NormScriptDir  = [System.IO.Path]::GetFullPath($global:ThisScriptDir).TrimEnd('\')
    [bool]$CopyRequired = ($NormInstallDir -ne $NormScriptDir)
    if (-not $CopyRequired) {
        Write-Host "Install directory matches the current running directory. File copy will be skipped." -ForegroundColor Cyan
    }

    # Create the home directory and copy files only when the install directory differs from
    # the current running directory. If they match the directory and files are already in place.
    if ($CopyRequired) {
        Write-Host ""
        Write-Host "  [Step 1/5] Creating install directory and setting permissions..." -ForegroundColor Cyan
        New-ADPowerAdminHomeFolder

        Write-Host ""
        Write-Host "  [Step 2/5] Copying production files to install directory..." -ForegroundColor Cyan
        Copy-AdPowerAdmin
    } else {
        Write-Host ""
        Write-Host "  [Step 1/5] Create install directory   -- SKIPPED (already running from install directory)" -ForegroundColor DarkGray
        Write-Host "  [Step 2/5] Copy production files      -- SKIPPED (already running from install directory)" -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  [Step 3/5] Creating sMSA service account..." -ForegroundColor Cyan
    # Create a ADPowerAdmMSA account with domain admin rights.
    New-ADPowerAdminSmsaAccount

    Write-Host ""
    Write-Host "  [Step 4/5] Configuring GPO (Log on as a service right for sMSA)..." -ForegroundColor Cyan
    # Create a new GPO to give the sMSA account the "Log on as a service" right.
    Set-ADPowerAdminGPO -Install

    Write-Host ""
    Write-Host "  [Step 5/5] Creating scheduled task..." -ForegroundColor Cyan
    # Create a new scheduled task to run the AD-PowerAdmin script daily.
    New-ADPowerAdminScheduledTask -ScriptFullPathForScheduleTask "$global:InstallDirectory\$global:ThisScriptsName"

    Write-Host ""
    Write-Host "  [Post-install] Installing DSInternals module..." -ForegroundColor Cyan
    # Install the DSInternals PowerShell module.
    Install-DSInternals

    # Test the AD-PowerAdmin install.
    Write-Host ""
    Write-Host "  [Post-install] Validating installation..." -ForegroundColor Cyan
    Write-host "  ----------------------------------------" -ForegroundColor White
    if (Test-ADPowerAdminInstall) {
        Write-Host "  Installation validated successfully." -ForegroundColor Green
        Write-Host "  Exiting -- relaunch AD-PowerAdmin from the install directory to continue." -ForegroundColor Green
        exit 0
    } else {
        Write-Host "  Installation validation FAILED. Review the output above for errors." -ForegroundColor Red
    }
# End of the Install-ADPowerAdmin function.
}

Function Install-DSInternals {
    <#
    .SYNOPSIS
    Function to check if the DSInternals PowerShell module is installed. If not, then install it, if the install fails, error and exit the script.

    .DESCRIPTION
    Function to check if the DSInternals PowerShell module is installed. If not, then install it, if the install fails, error and exit the script.
    DSInternals is used to audit users passwords and other security attributes.
    The module is well-vetted by Microsoft and is safe to use.
    PowerShell Gallery: https://www.powershellgallery.com/packages/DSInternals/4.7
    GitHub: https://github.com/MichaelGrafnetter/DSInternals

    .EXAMPLE
    Install-DSInternals

    .NOTES

    #>

    # Check if the DSInternals PowerShell module is installed. If not, then install it.
    if ( $null -eq (Get-Module -ListAvailable -Name DSInternals) ) {
        # Install the DSInternals PowerShell module.
        Install-Module -Name DSInternals -Force -ErrorAction SilentlyContinue
    }
    # Checkc if the DSInternals PowerShell module is installed. Try again to install it.
    if ( $null -eq (Get-Module -ListAvailable -Name DSInternals) ) {
        Write-Host "Warning: The DSInternals PowerShell module failed to install. Trying another method...." -ForegroundColor Yellow
        # TLS 1.2 must be enabled on older versions of Windows.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        # Download the NuGet package manager binary.
        Install-PackageProvider -Name NuGet -Force
        # Register the PowerShell Gallery as package repository if it is missing for any reason.
        if($null -eq (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) { Register-PSRepository -Default }
        # Download the DSInternals PowerShell module.
        Install-Module -Name DSInternals -Force
    }

    # confrim that the DSInternals PowerShell module is installed. If not, then output an error and exit the script.
    if ( $null -eq (Get-Module -ListAvailable -Name DSInternals) ) {
        Write-Host "Error: The DSInternals PowerShell module is not installed. Please install it and try again." -ForegroundColor Red
        Exit 1
    }

    # Try to import the DSInternals PowerShell module. If the import fails, then output an error and exit the script.
    try {
        Import-Module -Name DSInternals -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Error: The DSInternals PowerShell module failed to import." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }

# End of Install-DSInternals function
}

Function Install-PowerShell7 {
    <#
    .SYNOPSIS
    A function to install PowerShell 7.

    .DESCRIPTION
    This function will install PowerShell Version 7 system wide.
    It will download the PowerShell 7 installer script from Microsoft and run it.

    .EXAMPLE
    Install-PowerShell7

    .NOTES
    #>
    # Check if PowerShell 7 is already installed.
    if ( $null -eq (Get-Command pwsh -ErrorAction SilentlyContinue) ) {
        Write-Host "PowerShell 7 is not installed. Installing now..." -ForegroundColor Yellow
    } else {
        Write-Host "PowerShell 7 is already installed." -ForegroundColor Green
        return
    }

    # Confirm the WinGet installation
    if ( $null -eq (Get-Command winget -ErrorAction SilentlyContinue) ) {
        Write-Host "WinGet is not installed. Please install WinGet and try again." -ForegroundColor Red
        Exit 1
    }

    # Download the PowerShell 7 latest version for Windows using winget.
    winget.exe install --id Microsoft.PowerShell --source winget

    # Check if PowerShell 7 is installed.
    Test-PowerShell7-Installed
}

function New-ADPowerAdminSmsaAccount {
    <#
    .SYNOPSIS
    function to create a AD-PowerAdmin sMSA account.

    .DESCRIPTION
    Create the AD-PowerAdmin sMSA account; needed for the unattended Scheduled Task.
        Create a new standalone Managed Service Account (sMSA) for the AD-PowerAdmin schedule task.
        The sMSA account will be the name defined in the AD-PowerAdmin_settings.ps1($global:MsaAccountName) file.
        The sMSA account will be created in the "domain.com/Managed Service Accounts" container,
            and will be a member of the "Domain Admins" group.
        The sMSA will be created with a random password and change ever 30-days.

    .EXAMPLE
    New-ADPowerAdminSmsaAccount

    .NOTES

    #>

    [string]$MsaAccountDescription = "AD-PowerAdmin sMSA Account"
    # Check if the AD-PowerAdmin_MSA account already exists.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'"
    # Check if the "$global:MsaAccountName" sMSA account already exists. If it does not exist, then create the sMSA account.
    if ($null -eq $MsaIdentity) {

        # Check if the defined sMSA account name "$global:MsaAccountName" is longer than 14 characters.
        if ($global:MsaAccountName.Length -gt 14) {
            Write-Host "Error: The sMSA account name '$global:MsaAccountName' is longer than 14 characters." -ForegroundColor Red
            Write-Host "Error: The sMSA account name must be 14 characters or less." -ForegroundColor Red
            return
        }

        # Try to run the New-ADServiceAccount command. If the command fails, then display an error and exit the function.
        try {
            New-ADServiceAccount -SamAccountName "$global:MsaAccountName" -Name "$global:MsaAccountName" -Description "$MsaAccountDescription" -RestrictToSingleComputer -Enabled $true
        } catch {
            Write-Host "Error: The AD-PowerAdmin sMSA account was not created." -ForegroundColor Red
            Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
            return
        }
        $AdServerIdentity = Get-ADComputer -identity "$env:COMPUTERNAME"
        $MsaIdentity      = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -Properties * -ErrorAction SilentlyContinue
        Add-ADComputerServiceAccount -Identity $AdServerIdentity -ServiceAccount $MsaIdentity.sAMAccountName
        Install-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
        # Test that the sMSA account was created and this compluter is a member of the sMSA group.
        if ($null -eq $MsaIdentity) {
            Write-Host "Error: The AD-PowerAdmin sMSA account was not created." -ForegroundColor Red
            return
        }
        # Test that the sMSA account was created and this compluter is a member of the sMSA group.
        $TestAdServiceAccount = Test-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
        if (-Not $TestAdServiceAccount) {
            Write-Host "Error: The AD-PowerAdmin sMSA group was not created." -ForegroundColor Red
            return
        }
        # Add the sMSA account to the "Domain Admins" group.
        Add-ADGroupMember -Identity "Domain Admins" -Members $MsaIdentity.SamAccountName
    } else {
        Write-Host "The sMSA account '$global:MsaAccountName' already exists." -ForegroundColor Yellow
        # The account exists in AD but may not be installed on this computer (re-install or
        # new server). Task Scheduler requires a locally installed sMSA to register a task.
        [bool]$IsInstalledLocally = $false
        try {
            $IsInstalledLocally = Test-ADServiceAccount -Identity $global:MsaAccountName -ErrorAction Stop
        } catch {
            $IsInstalledLocally = $false
        }

        if (-not $IsInstalledLocally) {
            Write-Host "The sMSA account is not installed on this computer. Installing..." -ForegroundColor Yellow
            $MsaIdentity      = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -Properties * -ErrorAction SilentlyContinue
            $AdServerIdentity = Get-ADComputer -Identity "$env:COMPUTERNAME"
            try {
                Add-ADComputerServiceAccount -Identity $AdServerIdentity -ServiceAccount $MsaIdentity.sAMAccountName -ErrorAction Stop
            } catch {
                # May already be assigned to this computer in AD; proceed to Install.
            }
            Install-ADServiceAccount -Identity $MsaIdentity.sAMAccountName
            [bool]$VerifyInstall = Test-ADServiceAccount -Identity $global:MsaAccountName
            if ($VerifyInstall) {
                Write-Host "The sMSA account is now installed on this computer." -ForegroundColor Green
            } else {
                Write-Host "Error: Could not install the sMSA account on this computer." -ForegroundColor Red
                Write-Host "       Scheduled task creation will likely fail." -ForegroundColor Red
            }
        } else {
            Write-Host "The sMSA account is already installed on this computer." -ForegroundColor Green
        }
    }
# End of the New-ADPowerAdminSmsaAccount function.
}

function New-ADPowerAdminScheduledTask {
    <#
    .SYNOPSIS
    function to create a AD-PowerAdmin Schduled daily task.

    .DESCRIPTION
    function to create a AD-PowerAdmin Schduled daily task.
    The task will be named "AD-PowerAdmin_Daily".
    The task will run the AD-PowerAdmin script daily at 9:00 AM.
    The task will run the AD-PowerAdmin script with the "-Unattended" and "-JobName 'Daily'" parameters.

    .EXAMPLE
    New-ADPowerAdminScheduledTask

    .NOTES

    #>

    param (
        [Parameter(Mandatory=$false, Position=1)]
        [string]$ScriptFullPathForScheduleTask = "$global:InstallDirectory\\$global:ThisScript"
    )

    # ---------- Create the AD-PowerAdmin schedule task ----------
    [string]$TaskName = "AD-PowerAdmin_Daily"
    # Set ScheduleRunTime to be tomorrow at 9:00 AM.
    [datetime]$ScheduleRunTime = (Get-Date).AddDays(1).Date + "09:00:00"
    [string]$TaskDiscription = "AD-PowerAdmin Daily Tasks"
    [string]$ThisScriptsFullName = "$ScriptFullPathForScheduleTask"
    # Check if the AD-PowerAdmin_Daily schedule task already exists.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin schedule task already exists, then ask the user if they want to overwrite the existing schedule task.
        Write-Host "The AD-PowerAdmin schedule task already exists." -ForegroundColor Yellow
        $OverwriteScheduleTask = Read-Host "Do you want to overwrite the existing schedule task? (Default Y: Y/n)"
        # If the user does not want to overwrite the existing schedule task, then exit the function.
        if ($OverwriteScheduleTask -eq 'N' -or $OverwriteScheduleTask -eq 'n') {
            Write-Host "The AD-PowerAdmin schedule task was not overwritten." -ForegroundColor Yellow
            return
        }
        # If the user wants to overwrite the existing schedule task, then delete the existing schedule task.
        Write-Host "Deleting the existing AD-PowerAdmin schedule task." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
    }
    # Try to set up a new schedule task to run the AD-PowerAdmin script daily.
    try {
        # Create a new schedule task to run the AD-PowerAdmin script daily.
        AD-PowerAdmin_Utils\New-ScheduledTask -ActionString 'PowerShell.exe' -ActionArguments "$ThisScriptsFullName -Unattended -JobName 'Daily'" -ScheduleRunTime $ScheduleRunTime -Recurring "Daliy" -TaskName $TaskName -TaskDiscription $TaskDiscription
    } catch {
        Write-Host "Error: The AD-PowerAdmin schedule task failed to be created." -ForegroundColor Red
        Write-Host "       $($_.Exception.Message)" -ForegroundColor Red
        return
    }
# End of the New-ADPowerAdminScheduledTask function.
}

function New-ADPowerAdminHomeFolder {
    <#
    .SYNOPSIS
    A function to set up the AD-PowerAdmin script home directory.

    .DESCRIPTION
    - Create the AD-PowerAdmin home directory.
    - The home directory will be named "AD-PowerAdmin".
    - The home directory will be created in the "C:\Scripts" directory.
    - Set the owner of the AD-PowerAdmin home directory to the Domain Administrators group.
    - Set the system audit policy and the AD-PowerAdmin home directory to audit policy to "Everyone" for "Success" and "Failure".

    .EXAMPLE
    Install-ADPowerAdmin

    .NOTES

    #>

    # Check if the AD-PowerAdmin home directory exists at C:\Scripts\AD-PowerAdmin, if not then create it and all parent directories.
    if (-Not (Test-Path -Path "$global:InstallDirectory")) {
        New-Item -Path "$global:InstallDirectory" -ItemType Directory -Force | Out-Null
    }

    # Set the owner of the AD-PowerAdmin home directory to the Domain Admins group and apply
    # explicit ACEs with full inheritance so the same permissions apply to every file and
    # subdirectory created inside the install directory.
    $InstallDirACL     = Get-Acl -Path "$global:InstallDirectory"
    $DomainAdminsGroup = New-Object System.Security.Principal.NTAccount("Domain Admins")
    $LocalAdminsGroup  = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
    $SystemAccount     = New-Object System.Security.Principal.NTAccount("NT AUTHORITY", "SYSTEM")
    # ContainerInherit propagates to child directories; ObjectInherit propagates to child files.
    # Without these flags the ACE would apply only to the directory container itself and files
    # copied into the directory would receive no inherited rights, causing Access Denied for
    # any admin who did not personally run the original Copy-Item.
    $InheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropFlags    = [System.Security.AccessControl.PropagationFlags]::None
    $InstallDirACL.SetOwner($DomainAdminsGroup)
    $InstallDirACL.SetAccessRuleProtection($true, $false)
    $InstallDirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $DomainAdminsGroup, "FullControl", $InheritFlags, $PropFlags, "Allow")))
    $InstallDirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $LocalAdminsGroup,  "FullControl", $InheritFlags, $PropFlags, "Allow")))
    $InstallDirACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $SystemAccount,     "FullControl", $InheritFlags, $PropFlags, "Allow")))
    Set-Acl -Path "$global:InstallDirectory" -AclObject $InstallDirACL

    # # Enable folder-level auditing
    Enable-AuditLogging -FolderPath "$global:InstallDirectory" -Principal "Everyone" -AuditSuccess $true -AuditFailure $true -Policy "File System" -AuditFlags "Success,Failure"
# End of the Install-ADPowerAdminHomeFolder function.
}

function Enable-AuditLogging {
    <#
    .SYNOPSIS
    A function to enable audit logging on a folder.

    .DESCRIPTION
    Enable audit logging on the system usign the "auditpol" cmdlet. Then enable audit logging on the given folder.

    .EXAMPLE
    Enable-AuditLogging -FolderPath "C:\Scripts\AD-PowerAdmin" -AuditSuccess $true -AuditFailure $true -Policy "File System" -AuditFlags "Success,Failure"

    .NOTES

    #>

    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$FolderPath,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Principal = "Everyone",
        [bool]$AuditSuccess = $true,
        [Parameter(Mandatory=$false, Position=3)]
        [bool]$AuditFailure = $true,
        [Parameter(Mandatory=$true, Position=4)]
        [string]$Policy,
        [Parameter(Mandatory=$false, Position=5)]
        [string]$AuditFlags = "Success,Failure"
    )

    # Enable the audit policy for the given folder.
    [string]$AuditFlagsSuccess = "disable"
    [string]$AuditFlagsFailure = "disable"

    if ($AuditSuccess) {
        $AuditFlagsSuccess = "enable"
    }

    if ($AuditFailure) {
        $AuditFlagsFailure = "enable"
    }

    # File system auditing needs to be enabled before we can set the audit policy on objects)files and folders).
    # The cmdlet "auditpol" requires admin rights to run.
    # The cmdlet command being run by PowerShell is "auditpol /set /subcategory:"File System" /success:enable /failure:enable"
    Start-Process -FilePath auditpol -ArgumentList "/set /subcategory:`"$Policy`" /success:$AuditFlagsSuccess /failure:$AuditFlagsFailure" -Verb RunAs -Wait

    # Enable folder-level auditing on the given folder.

    # Get the current audit settings for the folder.
    $FolderACL = Get-Acl -Path $FolderPath

    # Create an array of audit rules to apply to the folder.
    $AuditSettings = @{
        # FileSystemRights = "CreateFiles", "Delete", "WriteData"
        FileSystemRights = "ExecuteFile", "DeleteSubdirectoriesAndFiles", "Write", "Delete", "ChangePermissions", "TakeOwnership"
    }

    # For each audit rule, create a new audit rule object and add it to the folder's ACL.
    foreach ($FileSystemRight in $AuditSettings["FileSystemRights"]) {
        $AuditRule = New-Object System.Security.AccessControl.FileSystemAuditRule($Principal, $FileSystemRight, "ContainerInherit,ObjectInherit", "None", "$AuditFlags")
        $FolderACL.AddAuditRule($AuditRule)
    }

    # Try to apply the audit settings and ACL rules to the folder.
    try {
        Set-Acl -Path $FolderPath -AclObject $FolderACL
    } catch {
        Write-Host "Error: The audit settings failed to be applied to the folder '$FolderPath'." -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        break
    }
# End of the Enable-AuditLogging function.
}

function Confirm-InstallDirectory {
    <#
    .SYNOPSIS
    Prompts the administrator to confirm or change the install directory before installation begins.

    .DESCRIPTION
    Displays the current InstallDirectory value from AD-PowerAdmin_settings.ps1 and asks
    whether to proceed with it or enter a new path. If a new path is entered it is written
    back to the settings file and $global:InstallDirectory is updated in memory so the rest
    of the install sequence uses the new value.

    Returns $true if a directory was confirmed. Returns $false if the user aborted.

    .NOTES
    Called by Install-ADPowerAdmin. Not exported.
    #>

    Write-Host ""
    Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
    Write-Host "  Installation Directory Confirmation" -ForegroundColor Cyan
    Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Current install directory (from AD-PowerAdmin_settings.ps1):" -ForegroundColor White
    Write-Host "    $global:InstallDirectory" -ForegroundColor Yellow
    Write-Host ""

    [string]$Change = Read-Host "  Is this the correct install directory? (Y/n)"
    if ($Change -eq 'n' -or $Change -eq 'N') {
        # User wants to change the directory.
        [string]$NewPath = ''
        while ($true) {
            $NewPath = (Read-Host "  Enter new install directory (absolute path)").Trim()
            if ([string]::IsNullOrEmpty($NewPath)) {
                Write-Host "  Path cannot be empty. Press Ctrl+C to cancel the install." -ForegroundColor Yellow
                continue
            }
            if (-not [System.IO.Path]::IsPathRooted($NewPath)) {
                Write-Host "  '$NewPath' is not an absolute path. Enter a full path (e.g. C:\Scripts\AD-PowerAdmin)." -ForegroundColor Yellow
                continue
            }
            break
        }

        [string]$ConfirmNew = Read-Host "  Use '$NewPath' as the install directory? (y/N)"
        if ($ConfirmNew -ne 'y' -and $ConfirmNew -ne 'Y') {
            Write-Host "  Install cancelled." -ForegroundColor Gray
            return $false
        }

        # Persist the change to the settings file so it survives a restart.
        [string]$SettingsFile = Join-Path $global:ThisScriptDir 'AD-PowerAdmin_settings.ps1'
        if (Test-Path $SettingsFile) {
            try {
                [string]$Content = Get-Content $SettingsFile -Raw
                [string]$Updated = Set-SettingsFileValue -Content $Content -VarName 'InstallDirectory' -NewValue $NewPath -VarType 'string-double'
                Write-FileUtf8Crlf -Path $SettingsFile -Content $Updated
                Write-Host "  Settings file updated." -ForegroundColor Green
            } catch {
                Write-Host "  WARNING: Could not write new path to settings file: $_" -ForegroundColor Yellow
                Write-Host "  The install will proceed with the new path for this session only." -ForegroundColor Yellow
            }
        }

        $global:InstallDirectory = $NewPath
        Write-Host "  Install directory set to: $global:InstallDirectory" -ForegroundColor Green
    } else {
        Write-Host "  Proceeding with install directory: $global:InstallDirectory" -ForegroundColor Green
    }

    Write-Host ""
    return $true
# End of the Confirm-InstallDirectory function.
}

function Copy-AdPowerAdmin {
    <#
    .SYNOPSIS
    Copies the production AD-PowerAdmin files to the install directory.

    .DESCRIPTION
    Copies only the required production files from the current running directory to the
    configured install directory ($global:InstallDirectory):
      - AD-PowerAdmin.ps1     (main script)
      - AD-PowerAdmin_settings.ps1
      - Modules\              (recursive)
      - README.md

    Development-related content in the source location (.git, Reports, temp, test scripts,
    password lists, etc.) is intentionally excluded. This keeps the install directory clean
    and scoped to what the scheduled task actually needs to run.

    If the script is already running from the install directory, no action is taken.

    .EXAMPLE
    Copy-AdPowerAdmin

    .NOTES
    Called by Install-ADPowerAdmin. Not exported.
    #>

    if ($global:InstallDirectory -eq $global:ThisScriptDir) {
        Write-Host "AD-PowerAdmin is already running from the install directory. No files to copy." -ForegroundColor Green
        return
    }

    Write-Host "Copying production files to: $global:InstallDirectory" -ForegroundColor Yellow
    Write-Host ""

    # The four items that make up a production installation.
    [array]$ProductionItems = @(
        @{ Name = $global:ThisScriptsName;      IsDirectory = $false },
        @{ Name = 'AD-PowerAdmin_settings.ps1'; IsDirectory = $false },
        @{ Name = 'Modules';                    IsDirectory = $true  },
        @{ Name = 'README.md';                  IsDirectory = $false }
    )

    [bool]$CopyOk = $true

    foreach ($Item in $ProductionItems) {
        [string]$SourcePath = Join-Path $global:ThisScriptDir $Item.Name

        if (-not (Test-Path $SourcePath)) {
            Write-Host "  [SKIP]  $($Item.Name)  (not found in source directory)" -ForegroundColor Yellow
            continue
        }

        try {
            if ($Item.IsDirectory) {
                Copy-Item -Path $SourcePath -Destination $global:InstallDirectory -Recurse -Force -ErrorAction Stop
            } else {
                Copy-Item -Path $SourcePath -Destination $global:InstallDirectory -Force -ErrorAction Stop
            }
            Write-Host "  [OK]    $($Item.Name)" -ForegroundColor Green
        } catch {
            Write-Host "  [FAIL]  $($Item.Name) -- $_" -ForegroundColor Red
            $CopyOk = $false
        }
    }

    Write-Host ""

    # Verify the critical items are present in the install directory.
    [array]$CriticalItems = @($global:ThisScriptsName, 'AD-PowerAdmin_settings.ps1', 'Modules')
    [bool]$VerifyOk = $true
    foreach ($Name in $CriticalItems) {
        if (-not (Test-Path (Join-Path $global:InstallDirectory $Name))) {
            Write-Host "  [MISSING]  $Name not found in install directory after copy." -ForegroundColor Red
            $VerifyOk = $false
        }
    }

    if ($CopyOk -and $VerifyOk) {
        Write-Host "Production files copied successfully to the install directory." -ForegroundColor Green
    } else {
        Write-Host "One or more files were not copied. Check the errors above before proceeding." -ForegroundColor Red
    }
# End of the Copy-AdPowerAdmin function.
}

Function Set-ADPowerAdminGPO {
    <#
    .SYNOPSIS
    A Function that will update the "Default Domain Controllers Policy" GPO to give the AD-PowerAdmin sMSA account the "Log on as a service" right.

    .DESCRIPTION
    - A-PowerAdmin requires the "Log on as a service" right to run rights for the AD-PowerAdmin sMSA account. Without this right, the AD-PowerAdmin script will not run because Windows is dumb.
        If you want more information on this issue, please see the following links: https://cybergladius.com/secure-windows-scheduled-tasks-with-managed-service-accounts/

        To complicate the issue, the "Log on as a service" GPO setting cannot be applied via PowerShell. This makes it impossible for me to create a new GPO with the "Log on as a service" right.
        So, the workaround I came up with is to edit the "Default Domain Controllers Policy" GPO to add the "Log on as a service" right to the AD-PowerAdmin sMSA account.
        Now, you may be asking, "isn't editing the "Log on as a service" setting a security issue?" Yes, but not really. Since we use an sMSA account, the password is random and changes every 30 days.
        In addition, only this domain controller can read the password for the sMSA account. So, if an attacker could read the AD-PowerAdmin sMSA account password, they would have already compromised the domain controller.
        So it's a moot point.

        - Open the "Default Domain Controllers Policy" GPO.
        - Check if the GPO contains the "Log on as a service" right configured for the AD-PowerAdmin sMSA account.
        - if the GPO does not contain the "Log on as a service" right configured for the AD-PowerAdmin sMSA account, then add it.
        - Force the server is update its GPO settings.

    .EXAMPLE
    Set-ADPowerAdminGPO -Install
    Set-ADPowerAdminGPO -Uninstall
    Set-ADPowerAdminGPO -Test

    .NOTES
    The GPO will be created with a random password and change ever 30-days.

    #>

    param (
        [Parameter(Mandatory=$false, Position=1)]
        [switch]$Install,
        [Parameter(Mandatory=$false, Position=2)]
        [switch]$Uninstall,
        [Parameter(Mandatory=$false, Position=3)]
        [switch]$Test
    )

    # Check if the Install, Uninstall, or Test switch is set. If more than one switch is set, then display an error and exit the function.
    if (($Install -and $Uninstall) -or ($Install -and $Test) -or ($Uninstall -and $Test)) {
        Write-Host "Error: Only one of the following switches can be set: -Install, -Uninstall, or -Test." -ForegroundColor Red
        return
    }

    # Check if the Install, Uninstall, or Test switch is set. If none of the switches are set, then display an error and exit the function.
    if (-Not ($Install -or $Uninstall -or $Test)) {
        Write-Host "Error: One of the following switches must be set: -Install, -Uninstall, or -Test." -ForegroundColor Red
        return
    }

    try {
        # Get domain controller to run all commands against
        [object]$DomainContollerServer = Get-ADDomainController
        # Get the Active Directory root DNS domain name.
        [object]$DnsRootDomainName = Get-ADDomain -Identity $DomainContollerServer.Domain | Select-Object -Property DNSRoot
        # \\localhost\SYSVOL\domain.loc\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
        [string]$GpoCfgFile = "\\$($DnsRootDomainName.DNSRoot)\SYSVOL\$($DnsRootDomainName.DNSRoot)\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
        # Get content of the $GpoCfgFile. Maintain the line breaks.
        [string]$GpoCfgFileContent = Get-Content -Path $GpoCfgFile -Raw
        $SID = Get-ADServiceAccount -Identity "$global:MsaAccountName`$" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue
    }
    catch {
        # If the above throws an error, then the AD-PowerAdmin sMSA account does not exist.
        return $false
    }


    #Check it $GpoCfgFile exists.
    if (-Not (Test-Path -Path "$GpoCfgFile")) {
        Write-Host "Error: The GPO configuration file '$GpoCfgFile' does not exist." -ForegroundColor Red
        break
    }

    # If Install or Uninstall switch is set, then check if the $GpoCfgFileContent contains the "SeServiceLogonRight" line.
    if ($Install -or $Uninstall) {
        # Check if the $GpoCfgFileContent contains the "SeServiceLogonRight" line.
        if ($GpoCfgFileContent -notmatch "SeServiceLogonRight") {
            Write-Host "Warrning: The GPO configuration file '$GpoCfgFile' does not contain the 'SeServiceLogonRight' line." -ForegroundColor Yellow
        }
        # Check if the $SID is null.
        if ($null -eq $SID) {
            Write-Host "Error: The SID for the sMSA account '$global:MsaAccountName' was not found." -ForegroundColor Red
            break
        }
    }

    # If the Install switch is set, then add the $global:MsaAccountName to the "SeServiceLogonRight" line.
    if ($Install) {

        # Check if the $GpoCfgFileContent contains $global:MsaAccountName or $SID.Value is already in the "SeServiceLogonRight" line.
        if (($GpoCfgFileContent -match "$global:MsaAccountName") -or ($GpoCfgFileContent -match "$($SID.Value)")) {
            Write-Host "The GPO configuration file '$GpoCfgFile' already contains the '$global:MsaAccountName' or '$($SID.Value)' line." -ForegroundColor Yellow
            return
        }

        # For each line of a file, check if the line contains the "SeServiceLogonRight" line.
        # If the line contains the "SeServiceLogonRight" line, then add the $global:MsaAccountName to the line.
        # If the line does not contain the "SeServiceLogonRight" line, then add the line to the $GpoCfgFileContentNew variable.
        [string]$GpoCfgFileContentNew = ""
        foreach ($Line in $GpoCfgFileContent.Split("`n")) {
            if ($Line -match "SeServiceLogonRight") {
                # Track if the SeServiceLogonRight line is found.
                [bool]$SeServiceLogonRightLineFound = $true
                # Remove the line break from the end of the line.
                $Line = $Line.TrimEnd()
                $Line = $Line + ",*$($SID.Value)"
            }
            $GpoCfgFileContentNew = $GpoCfgFileContentNew + $Line + "`n"
        }
        # Check if the SeServiceLogonRight line was found. If it was not found then add a new line containing'SeServiceLogonRight = "*$($SID.Value)"' agfter the line that starts with 'SeBatchLogonRight'.
        if (-Not $SeServiceLogonRightLineFound) {
            [string]$GpoCfgFileContentNew = ""
            foreach ($Line in $GpoCfgFileContent.Split("`n")) {
                if ($Line -match "SeBatchLogonRight") {
                    $Line = $Line + "`n" + "SeServiceLogonRight = *$($SID.Value)"
                }
                $GpoCfgFileContentNew = $GpoCfgFileContentNew + $Line + "`n"
            }
        }
    }

    # If the Uninstall switch is set, then remove the $global:MsaAccountName from the "SeServiceLogonRight" line.
    if ($Uninstall) {
        # For each line of a file, check if the line contains the "SeServiceLogonRight" line.
        # If the line contains the "SeServiceLogonRight" line, then remove the $global:MsaAccountName from the line but keeping everything else intact.
        # If the line does not contain the "SeServiceLogonRight" line, then add the line to the $GpoCfgFileContentNew variable.
        [string]$GpoCfgFileContentNew = ""
        foreach ($Line in $GpoCfgFileContent.Split("`n")) {
            if ($Line -match "SeServiceLogonRight") {
                # Remove the line break from the end of the line.
                $Line = $Line.TrimEnd()
                $Line = $Line -replace ",\*$($SID.Value)", ""
                $Line = $Line -replace ",$global:MsaAccountName", ""
            }
            $GpoCfgFileContentNew = $GpoCfgFileContentNew + $Line + "`n"
        }
        Write-host "The '$global:MsaAccountName' account has been removed from the  GPO configuration file." -ForegroundColor Yellow
    }

    # If the Test switch is set, then remove the $global:MsaAccountName from the "SeServiceLogonRight" line.
    if ($Test) {
        # Get the "SeServiceLogonRight" line from the $GpoCfgFileContent, and test that line contains the $global:MsaAccountName or $SID.Value.
        [string]$SeServiceLogonRightLine = $GpoCfgFileContent | Select-String -Pattern "SeServiceLogonRight"
        if (($SeServiceLogonRightLine -match "$global:MsaAccountName") -or ($SeServiceLogonRightLine -match "$($SID.Value)")) {
            return $true
        }
        return $false
    }

    # If Install or Uninstall switch is set, then write the $GpoCfgFileContentNew to the $GpoCfgFile.
    if ($Install -or $Uninstall) {
        # Write-Output $GpoCfgFile
        $GpoCfgFileContentNew | Out-File "$GpoCfgFile" -Encoding unicode -Force -NoNewline
        # Confirm that the $GpoCfgFile matches the $GpoCfgFileContentNew.
        [string]$GpoCfgFileContentNewTest = Get-Content -Path $GpoCfgFile -Raw
        if ($GpoCfgFileContentNewTest -ne $GpoCfgFileContentNew) {
            Write-Host '----------------------------------------' -ForegroundColor Yellow
            $GpoCfgFileContentNew
            Write-Host '----------------------------------------' -ForegroundColor Yellow
            $GpoCfgFileContentNewTest
            Write-Host '----------------------------------------' -ForegroundColor Yellow
            Write-Host "Error: The GPO configuration file '$GpoCfgFile' was not updated." -ForegroundColor Red
            Exit 1
        }
        # Create a object variable that contains the "Default Domain Controllers Policy" GPO.
        [object]$DefaultDomainControllersPolicy = Get-GPO -Guid '6AC1786C-016F-11D2-945F-00C04fB984F9'
        #Force AD to process new GPO
        $DefaultDomainControllersPolicy | Set-GPRegistryValue -Key HKLM\SOFTWARE -ValueName "Default" -Value "" -Type String -Server $DomainContollerServer | Out-Null
        $DefaultDomainControllersPolicy | Remove-GPRegistryValue -Key HKLM\SOFTWARE -ValueName "Default" -Server $DomainContollerServer | Out-Null
        Invoke-GPUpdate -Force
    }
# End of the New-ADPowerAdminGPO function.
}

function Test-PowerShell7-Installed {
    <#
    .SYNOPSIS
    A function to test if PowerShell 7 is installed.

    .DESCRIPTION
    Test if PowerShell 7 is installed.

    .EXAMPLE
    Test-PowerShell7-Installed

    .NOTES

    #>
    if ( $null -eq (Get-Command pwsh -ErrorAction SilentlyContinue) ) {
        Write-Host "Error: PowerShell 7 is not installed." -ForegroundColor Red
        return $false
    }
    Write-Host "PowerShell 7 is installed." -ForegroundColor Green
    return $true
}

function Test-ADPowerAdminInstall {
    <#
    .SYNOPSIS
    A function to test if the AD-PowerAdmin script is installed.

    .DESCRIPTION
    Test if the AD-PowerAdmin script is installed.

    .EXAMPLE
    Test-ADPowerAdminInstall

    .NOTES

    #>

    [bool]$TestAdPowerAdminInstallGood = $true
    # Check is the $global:MsaAccountName sMSA account exists.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'"

    # Check if the "$global:MsaAccountName" sMSA account already exists. If it does not exist, then create the sMSA account.
    if ($null -eq $MsaIdentity) {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' does not exist." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' exists." -ForegroundColor Green
    }

    # Check if the $global:MsaAccountName sMSA account is a member of the "Domain Admins" group.
    $MsaIdentity = Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -Properties * -ErrorAction SilentlyContinue
    if ($null -eq $MsaIdentity) {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' is not a member of the 'Domain Admins' group." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin sMSA account '$global:MsaAccountName' is a member of the 'Domain Admins' group." -ForegroundColor Green
    }

    # Check if the AD-PowerAdmin GPO settings are correct.
    if (Set-ADPowerAdminGPO -Test) {
        Write-Host "The AD-PowerAdmin_GPO GPO exists." -ForegroundColor Green
    } else {
        Write-Host "The AD-PowerAdmin_GPO GPO does not exist." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    }

    # Check if the AD-PowerAdmin_Daily schedule task exists.
    $TaskIdentity = Get-ScheduledTask -TaskName "AD-PowerAdmin_Daily" -ErrorAction SilentlyContinue
    if ($null -eq $TaskIdentity) {
        Write-Host "The AD-PowerAdmin_Daily schedule task does not exist." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin_Daily schedule task exists." -ForegroundColor Green
    }

    # Check if the AD-PowerAdmin_Daily schedule task is enabled.
    $TaskIdentity = Get-ScheduledTask -TaskName "AD-PowerAdmin_Daily" -ErrorAction SilentlyContinue
    if ($null -eq $TaskIdentity) {
        Write-Host "The AD-PowerAdmin_Daily schedule task is not enabled." -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The AD-PowerAdmin_Daily schedule task is enabled." -ForegroundColor Green
    }

    # Check if the Audit Policy is set correctly.
    if (-Not (Test-SystemAuditPolicy -Policy "File System" -AuditSuccess $true -AuditFailure $true)) {
        Write-Host "The system Audit Policy is set incorrectly" -ForegroundColor Red
        Write-Host "The Audit Policy maybe getting reset by a GPO?" -ForegroundColor Yellow
        $TestAdPowerAdminInstallGood = $false
    } else {
        Write-Host "The system Audit Policy is set correctly" -ForegroundColor Green
    }

    # Check if the Install folder ACL are set correctly.
    if ((Test-FolderAuditPolicy -FolderPath "$global:InstallDirectory" -Principal "Everyone" -AuditFlags "Success,Failure")) {
        Write-Host "The Install folder Audit Policies are set correctly" -ForegroundColor Green
    } else {
        Write-Host "The Install folder Audit Policies are incorrect" -ForegroundColor Red
        $TestAdPowerAdminInstallGood = $false
    }

    return $TestAdPowerAdminInstallGood
# End of the Test-ADPowerAdminInstall function.
}

function Test-SystemAuditPolicy {
    <#
    .SYNOPSIS
    A function to test if the audit policy is set correctly.

    .DESCRIPTION
    Test if the system audit policy is set correctly based on given parameters. Return true or false.

    .EXAMPLE
    Test-SystemAuditPolicy -Policy "File System" -AuditSuccess $true -AuditFailure $true

    .NOTES

    #>

    param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Policy,
        [Parameter(Mandatory=$false, Position=2)]
        [bool]$AuditSuccess = $true,
        [Parameter(Mandatory=$false, Position=3)]
        [bool]$AuditFailure = $true

    )

    # Set the default output to $false.
    $AuditPoliciesCorrect = $false

    # Check the $AuditFlags parameter for Success and/or Failure. If the AuditFlag contains Success then set the Success flag to "enable". If the AuditFlag contains Failure then set the Failure flag to "enable".
    if ($AuditSuccess -and $AuditFailure){
        $AuditPolicyCorrectOutput = "Success and Failure"
    }

    if ($AuditSuccess -and $AuditFailure -eq $false) {
        $AuditPolicyCorrectOutput = "Success"
    }

    if ($AuditFailure -and $AuditSuccess -eq $false) {
        $AuditPolicyCorrectOutput = "Failure"
    }

    # Get all audit policies
    $AllAuditPolicies = (auditpol.exe /get /category:* /r | ConvertFrom-Csv)

    # If $SinglePolicyToCheck is not set, then error and exit the function.
    if ('' -eq $Policy) {
        Write-Host "Error: The Policy parameter is not set." -ForegroundColor Red
        return
    }

    # Filter the audit policies to only the policy that we want to check.
    $AllAuditPolicies = $AllAuditPolicies | Where-Object { $_.Subcategory -eq $Policy }

    # String compare the audit policy to the expected output.
    [string]$AuditSetting = $AllAuditPolicies.{Inclusion Setting}
    if ($AuditSetting -eq $AuditPolicyCorrectOutput) {
        $AuditPoliciesCorrect = $true
    }

    # Return the audit policy results.
    $AuditPoliciesCorrect
# End of the Test-AuditSettings function.
}

function Test-FolderAuditPolicy {
    <#
    .SYNOPSIS
    A function to test if the audit policy is set correctly on a folder.

    .DESCRIPTION
    Test if the audit policy is set correctly on a folder based on given parameters. Return true or false.

    .EXAMPLE
    Test-FolderAuditPolicy -FolderPath "C:\Scripts\AD-PowerAdmin" -Principal "Everyone" -AuditFlags "Success,Failure"

    .NOTES

    #>

    param (
        [Parameter(Mandatory=$true, Position=1)]
        [string]$FolderPath,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$Principal = "Everyone",
        [Parameter(Mandatory=$false, Position=3)]
        [string]$auditFlags = "Success,Failure"
    )
    # Set default output to $false.
    $AuditPoliciesCorrect = $false

    # Check if the folder path is provided
    if (-not $FolderPath) {
        Write-Host "Please provide a folder path."
        return
    }

    # Check if the folder exists
    if (-not (Test-Path -Path $FolderPath -PathType Container)) {
        Write-Host "The specified folder does not exist." -ForegroundColor Red
        return
    }

    try {
        # Get the current audit settings for the folder
        $CurrentAuditSettings = (Get-Acl -Path "$FolderPath" -Audit).GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        # Define the expected audit settings
        $ExpectedAuditSettings = @{
            FileSystemRights = "ExecuteFile, DeleteSubdirectoriesAndFiles, Write, Delete, ChangePermissions, TakeOwnership"
        }

        # Check if the expected audit settings match the current audit settings.
        if ($CurrentAuditSettings.FileSystemRights -eq $ExpectedAuditSettings.FileSystemRights) {
            $AuditPoliciesCorrect = $true
        }
    } catch {
        Write-Host "Error: $_"
    }
    $AuditPoliciesCorrect
# End of the Test-FolderAuditPolicy function.
}

function Remove-AdPowerAdmin {
    <#
    .SYNOPSIS
    A function to remove the AD-PowerAdmin script.

    .DESCRIPTION
    This function does a partial uninstall of the AD-PowerAdmin script.
    - Remove the AD-PowerAdmin schedule task.
    - Remove the sMSA account.
    - Remove the sMSA account from the "login as a service" setting in the "Default Domain Controllers Policy" GPO.
    - Remove the AD-PowerAdmin home directory.
    !NOTE!: YES, this will delete the AD-PowerAdmin script and all of its files! But you will be asked to confirm this action.

    What is not removed:
    - The system audit policy is not changed.
    - DSInternals is not removed.

    .EXAMPLE
    Remove-AdPowerAdmin

    .NOTES

    #>

    # ---------- Remove the AD-PowerAdmin schedule task ----------
    [string]$TaskName = "AD-PowerAdmin_Daily"
    # Check if the AD-PowerAdmin_Daily schedule task exists.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin schedule task exists, then delete the existing schedule task.
        Write-Host "Deleting the existing AD-PowerAdmin schedule task." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName "$TaskName" -Confirm:$false
    }

    # ---------- Remove the AD-PowerAdmin_GPO GPO ----------
    Set-ADPowerAdminGPO -Uninstall

    # ---------- Remove the AD-PowerAdmin sMSA account ----------
    # Check if the AD-PowerAdmin_MSA account exists.
    if (Get-ADServiceAccount -Filter "Name -eq '$global:MsaAccountName'" -ErrorAction SilentlyContinue) {
        # If the AD-PowerAdmin_MSA account exists, then delete the existing sMSA account.
        Write-Host "Deleting the existing AD-PowerAdmin_MSA account." -ForegroundColor Yellow
        Remove-ADServiceAccount -Identity "$global:MsaAccountName" -Confirm:$false
    }

    # Ask the user if they want to delete the AD-PowerAdmin home directory.
    $DeleteHomeDirectory = Read-Host "Do you want to delete the AD-PowerAdmin home directory? (Y/N)"
    # If the user does not want to delete the AD-PowerAdmin home directory, then exit the function.
    if ($DeleteHomeDirectory -eq 'Y' -or $DeleteHomeDirectory -eq 'y') {
        # Check if the AD-PowerAdmin home directory exists at C:\Scripts\AD-PowerAdmin, if it exists then delete it.
        if (Test-Path -Path "$global:InstallDirectory") {
            Write-Host "Deleting the existing AD-PowerAdmin home directory." -ForegroundColor Yellow
            Remove-Item -Path "$global:InstallDirectory" -Recurse -Force
        }
    }
# End of the Remove-AdPowerAdmin function.
}

function Get-ADPowerAdminLatestReleaseTag {
    <#
    .SYNOPSIS
    Queries the GitHub Releases API and returns the latest release tag string.

    .DESCRIPTION
    Calls https://api.github.com/repos/Brets0150/AD-PowerAdmin/releases/latest and
    returns the tag_name field (e.g. 'v0.6.2'). Returns $null on failure.

    .NOTES
    Private helper for Update-ADPowerAdminModules. Not exported.
    #>
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        $ApiUrl  = 'https://api.github.com/repos/Brets0150/AD-PowerAdmin/releases/latest'
        $Release = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing -ErrorAction Stop
        return $Release.tag_name
    } catch {
        Write-Host "ERROR: Failed to query GitHub Releases API. $_" -ForegroundColor Red
        return $null
    }
# End of the Get-ADPowerAdminLatestReleaseTag function.
}

function Get-ADPowerAdminRemoteModuleList {
    <#
    .SYNOPSIS
    Queries the GitHub Contents API and returns the list of .psm1/.psd1 file names
    in the remote Modules directory for the given Git ref.

    .DESCRIPTION
    Calls https://api.github.com/repos/Brets0150/AD-PowerAdmin/contents/Modules?ref=<GitRef>
    and returns an array of file name strings where the entry type is 'file' and the
    extension is .psm1 or .psd1. Returns $null on failure so the caller can fall back
    gracefully to local-only update behavior.

    .PARAMETER GitRef
    The Git ref to query: a release tag (e.g. 'v0.6.2') or branch name (e.g. 'main').

    .NOTES
    Private helper for Update-ADPowerAdminModules. Not exported.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$GitRef
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [string]$ApiUrl = "https://api.github.com/repos/Brets0150/AD-PowerAdmin/contents/Modules?ref=$GitRef"
    try {
        $Entries = Invoke-RestMethod -Uri $ApiUrl -UseBasicParsing -ErrorAction Stop
        [array]$FileNames = $Entries |
            Where-Object { $_.type -eq 'file' -and ($_.name -like '*.psm1' -or $_.name -like '*.psd1') } |
            Select-Object -ExpandProperty name
        return $FileNames
    } catch {
        Write-Host "WARNING: Could not query GitHub Contents API for remote module list. New-module detection unavailable. $_" -ForegroundColor Yellow
        return $null
    }
# End of the Get-ADPowerAdminRemoteModuleList function.
}

function Set-BackupFileProtection {
    <#
    .SYNOPSIS
    Marks a backup file read-only.

    .DESCRIPTION
    Applies the IsReadOnly attribute to the file at the given path. Called after every
    backup write to prevent accidental modification or re-execution of an archived file.
    The primary execution guard is the .txt extension applied at path construction time;
    this adds a second layer.

    .PARAMETER Path
    Full path to the backup file.

    .NOTES
    Private helper. Not exported.
    #>
    param([string]$Path)
    try {
        Set-ItemProperty -Path $Path -Name IsReadOnly -Value $true -ErrorAction Stop
    } catch {
        Write-Host "WARNING: Could not set read-only on backup '$Path': $_" -ForegroundColor Yellow
    }
# End of the Set-BackupFileProtection function.
}

function Write-FileUtf8Crlf {
    <#
    .SYNOPSIS
    Writes a string to a file as UTF-8 (no BOM) with Windows CRLF line endings.

    .DESCRIPTION
    Clears the read-only attribute on the target file if set, normalizes all line
    endings to CRLF, then writes the content as UTF-8 without BOM.  Use this
    instead of [System.IO.File]::WriteAllText() for every settings/script write
    so that files open correctly in Windows Notepad and are not blocked by the
    read-only attribute that Set-BackupFileProtection applies to backup copies.

    .PARAMETER Path
    Full path to the file to write.

    .PARAMETER Content
    The string content to write.

    .NOTES
    Private helper. Not exported.
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Content
    )
    try {
        if ((Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue).IsReadOnly) {
            Set-ItemProperty -LiteralPath $Path -Name IsReadOnly -Value $false -ErrorAction Stop
        }
    } catch { }
    [string]$CrlfContent = $Content -replace '\r?\n', "`r`n"
    [System.IO.File]::WriteAllText($Path, $CrlfContent, [System.Text.Encoding]::UTF8)
# End of the Write-FileUtf8Crlf function.
}

function Update-ADPowerAdminModules {
    <#
    .SYNOPSIS
    Downloads the latest module files from GitHub and applies them locally.

    .DESCRIPTION
    Fetches every .psm1 and .psd1 file found in the local Modules directory from
    the GitHub repository, and also downloads any new modules present on GitHub
    that do not yet exist locally. The source is determined by $global:UpdateChannel:
      'Development' -- pulls from the main branch (latest uncommitted work).
      'Release'     -- pulls from the most recent GitHub Release tag (default).

    Files that differ from the remote copy are backed up to a timestamped folder
    under $global:ReportsPath\ModuleBackups\ before being overwritten. Files that
    match the remote copy are left untouched. Files with no remote counterpart
    (local-only modules) are skipped with a warning. New modules present only on
    GitHub are downloaded directly to the Modules directory without a backup.

    A restart of PowerShell is required after updating or adding modules for the
    new module code to take effect in the current session.

    .EXAMPLE
    Update-ADPowerAdminModules

    .NOTES
    Requires internet access to raw.githubusercontent.com and api.github.com.
    If the GitHub Contents API is unavailable, new-module detection is skipped and
    existing modules are still checked for updates.
    #>

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Suppress Invoke-WebRequest's download progress bar. In PS5.1 the progress
    # bar writes to the host buffer and makes the terminal appear frozen until
    # Enter is pressed. Restore the original preference when the function exits.
    [string]$OriginalProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    # Determine the Git ref to pull from.
    [string]$Channel = if ($global:UpdateChannel) { $global:UpdateChannel } else { 'Release' }

    if ($Channel -eq 'Development') {
        [string]$GitRef = 'main'
        Write-Host "Update channel: Development (main branch)" -ForegroundColor Cyan
    } else {
        Write-Host "Update channel: Release -- querying GitHub for latest release tag..." -ForegroundColor Cyan
        [string]$GitRef = Get-ADPowerAdminLatestReleaseTag
        if (-not $GitRef) {
            Write-Host "ERROR: Could not determine the latest release tag. Aborting update." -ForegroundColor Red
            return
        }
        Write-Host "Latest release tag: $GitRef" -ForegroundColor Cyan
    }

    [string]$BaseUrl = "https://raw.githubusercontent.com/Brets0150/AD-PowerAdmin/$GitRef/Modules/"

    # Query GitHub Contents API for the full remote module list.
    # If unavailable, $RemoteFileNames is $null and new-module detection is skipped.
    $RemoteFileNames = Get-ADPowerAdminRemoteModuleList -GitRef $GitRef

    # Collect local module files (.psm1 and .psd1).
    [array]$LocalFiles = Get-ChildItem -Path $global:ModulesPath -Filter '*.ps?1' -File |
        Where-Object { $_.Extension -in '.psm1', '.psd1' }

    if ($LocalFiles.Count -eq 0) {
        Write-Host "No module files found in $global:ModulesPath. Nothing to update." -ForegroundColor Yellow
        return
    }

    # Create a timestamped backup directory.
    [string]$Timestamp  = (Get-Date -Format 'yyyyMMdd_HHmmss')
    [string]$BackupRoot = Join-Path $global:ReportsPath 'ModuleBackups'
    [string]$BackupDir  = Join-Path $BackupRoot $Timestamp
    [bool]$BackupCreated = $false

    # Tracking counters.
    [System.Collections.Generic.List[string]]$Updated    = [System.Collections.Generic.List[string]]::new()
    [System.Collections.Generic.List[string]]$Current    = [System.Collections.Generic.List[string]]::new()
    [System.Collections.Generic.List[string]]$Skipped    = [System.Collections.Generic.List[string]]::new()
    [System.Collections.Generic.List[string]]$NewModules = [System.Collections.Generic.List[string]]::new()

    Write-Host ""
    Write-Host "Checking $($LocalFiles.Count) local module file(s) against $GitRef ..." -ForegroundColor Cyan
    Write-Host ""

    foreach ($LocalFile in $LocalFiles) {
        [string]$FileName  = $LocalFile.Name
        [string]$RemoteUrl = "$BaseUrl$FileName"
        [string]$TempFile  = Join-Path $env:TEMP "$FileName.update"

        try {
            # Download the remote file to a temp location.
            Invoke-WebRequest -Uri $RemoteUrl -OutFile $TempFile -UseBasicParsing -ErrorAction Stop

            # Compare remote content to local content (line-joined to normalise EOL).
            [string]$RemoteContent = (Get-Content -Path $TempFile -Raw) -replace "`r`n", "`n"
            [string]$LocalContent  = (Get-Content -Path $LocalFile.FullName -Raw) -replace "`r`n", "`n"

            if ($RemoteContent -eq $LocalContent) {
                Write-Host "  [UP TO DATE]  $FileName" -ForegroundColor Green
                $Current.Add($FileName)
            } else {
                # Create backup directory on first use.
                if (-not $BackupCreated) {
                    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
                    $BackupCreated = $true
                }
                # Back up the existing local file. Append .txt so the archived copy cannot
                # be imported or executed; mark it read-only as a second layer of protection.
                [string]$BackupFilePath = Join-Path $BackupDir "$FileName.txt"
                Copy-Item -Path $LocalFile.FullName -Destination $BackupFilePath -Force
                Set-BackupFileProtection -Path $BackupFilePath
                # Overwrite local file with downloaded content.
                Copy-Item -Path $TempFile -Destination $LocalFile.FullName -Force
                Write-Host "  [UPDATED]     $FileName" -ForegroundColor Yellow
                $Updated.Add($FileName)
            }
        } catch {
            # A 404 means this file has no remote counterpart (local-only module).
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
                Write-Host "  [SKIPPED]     $FileName  (not found on remote -- local-only module)" -ForegroundColor Gray
            } else {
                Write-Host "  [ERROR]       $FileName  -- $_" -ForegroundColor Red
            }
            $Skipped.Add($FileName)
        } finally {
            if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
        }
    }

    # Detect and download modules present on GitHub but not yet installed locally.
    if ($null -ne $RemoteFileNames) {
        [string[]]$LocalFileNames  = $LocalFiles | Select-Object -ExpandProperty Name
        [array]$NewRemoteFiles     = $RemoteFileNames | Where-Object { $_ -notin $LocalFileNames }

        if ($NewRemoteFiles.Count -gt 0) {
            Write-Host ""
            Write-Host "Downloading $($NewRemoteFiles.Count) new module file(s) not present locally ..." -ForegroundColor Cyan
            Write-Host ""

            foreach ($NewFileName in $NewRemoteFiles) {
                [string]$RemoteUrl = "$BaseUrl$NewFileName"
                [string]$LocalDest = Join-Path $global:ModulesPath $NewFileName
                [string]$TempFile  = Join-Path $env:TEMP "$NewFileName.update"

                try {
                    Invoke-WebRequest -Uri $RemoteUrl -OutFile $TempFile -UseBasicParsing -ErrorAction Stop
                    Copy-Item -Path $TempFile -Destination $LocalDest -Force
                    Write-Host "  [NEW]         $NewFileName" -ForegroundColor Green
                    $NewModules.Add($NewFileName)
                } catch {
                    Write-Host "  [ERROR]       $NewFileName  -- $_" -ForegroundColor Red
                    $Skipped.Add($NewFileName)
                } finally {
                    if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
                }
            }
        }
    }

    # Summary report.
    Write-Host ""
    Write-Host "--- Update Summary ---" -ForegroundColor Cyan
    Write-Host "  Updated   : $($Updated.Count)"    -ForegroundColor Yellow
    Write-Host "  Up to date: $($Current.Count)"    -ForegroundColor Green
    Write-Host "  New       : $($NewModules.Count)" -ForegroundColor Green
    Write-Host "  Skipped   : $($Skipped.Count)"    -ForegroundColor Gray
    if ($BackupCreated) {
        Write-Host "  Backups saved to: $BackupDir" -ForegroundColor Cyan
    }
    if ($null -eq $RemoteFileNames) {
        Write-Host ""
        Write-Host "NOTE: New-module detection was skipped (GitHub Contents API unavailable)." -ForegroundColor Yellow
    }

    if ($Updated.Count -gt 0 -or $NewModules.Count -gt 0) {
        Write-Host ""
        Write-Host "NOTE: Restart PowerShell for updated modules to take effect in this session." -ForegroundColor Yellow
    }

    $ProgressPreference = $OriginalProgressPreference
# End of the Update-ADPowerAdminModules function.
}

function Update-ADPowerAdminMainScript {
    <#
    .SYNOPSIS
    Downloads the latest AD-PowerAdmin.ps1 from GitHub and applies it locally.

    .DESCRIPTION
    Fetches AD-PowerAdmin.ps1 from the GitHub repository. The source is determined by
    $global:UpdateChannel:
      'Development' -- pulls from the main branch (latest uncommitted work).
      'Release'     -- pulls from the most recent GitHub Release tag (default).

    If the remote file differs from the local copy, the current version is backed up to a
    timestamped folder under $global:ReportsPath\MainScriptBackups\ (as AD-PowerAdmin.ps1.txt,
    read-only) before the local file is replaced.

    The running session is not affected; restart AD-PowerAdmin to use the updated script.

    .EXAMPLE
    Update-ADPowerAdminMainScript

    .NOTES
    Requires internet access to raw.githubusercontent.com and, for the Release channel,
    to api.github.com.
    #>

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    [string]$OriginalProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    # Determine the Git ref to pull from.
    [string]$Channel = if ($global:UpdateChannel) { $global:UpdateChannel } else { 'Release' }

    if ($Channel -eq 'Development') {
        [string]$GitRef = 'main'
        Write-Host "Update channel: Development (main branch)" -ForegroundColor Cyan
    } else {
        Write-Host "Update channel: Release -- querying GitHub for latest release tag..." -ForegroundColor Cyan
        [string]$GitRef = Get-ADPowerAdminLatestReleaseTag
        if (-not $GitRef) {
            Write-Host "ERROR: Could not determine the latest release tag. Aborting update." -ForegroundColor Red
            $ProgressPreference = $OriginalProgressPreference
            return
        }
        Write-Host "Latest release tag: $GitRef" -ForegroundColor Cyan
    }

    [string]$RemoteUrl = "https://raw.githubusercontent.com/Brets0150/AD-PowerAdmin/$GitRef/AD-PowerAdmin.ps1"
    [string]$LocalPath = $global:ThisScript
    [string]$TempFile  = Join-Path $env:TEMP 'AD-PowerAdmin.ps1.update'

    Write-Host ""
    Write-Host "Checking AD-PowerAdmin.ps1 against $GitRef ..." -ForegroundColor Cyan

    try {
        # Download the remote file to a temp location.
        Invoke-WebRequest -Uri $RemoteUrl -OutFile $TempFile -UseBasicParsing -ErrorAction Stop

        # Normalise EOL for comparison.
        [string]$RemoteContent = (Get-Content -Path $TempFile -Raw) -replace "`r`n", "`n"
        [string]$LocalContent  = (Get-Content -Path $LocalPath -Raw) -replace "`r`n", "`n"

        if ($RemoteContent -eq $LocalContent) {
            Write-Host ""
            Write-Host "  [UP TO DATE]  AD-PowerAdmin.ps1" -ForegroundColor Green
            Write-Host ""
            Write-Host "The main script is already up to date." -ForegroundColor Green
            return
        }

        # Extract version strings for display.
        [string]$RemoteVersion = 'unknown'
        if ($RemoteContent -match '\[System\.Version\]\$global:Version\s*=\s*"([\d.]+)"') {
            $RemoteVersion = $Matches[1]
        }
        [string]$LocalVersion = $global:Version.ToString()

        Write-Host ""
        Write-Host "  An update is available:" -ForegroundColor Yellow
        Write-Host "    Current version  : $LocalVersion" -ForegroundColor White
        Write-Host "    Available version: $RemoteVersion" -ForegroundColor Cyan
        Write-Host ""

        # Confirm before applying.
        [string]$Confirm = Read-Host "Apply update? (y/N)"
        if ($Confirm -notmatch '^[Yy]') {
            Write-Host "Update cancelled." -ForegroundColor Gray
            return
        }

        # Create a timestamped backup directory.
        [string]$Timestamp  = (Get-Date -Format 'yyyyMMdd_HHmmss')
        [string]$BackupRoot = Join-Path $global:ReportsPath 'MainScriptBackups'
        [string]$BackupDir  = Join-Path $BackupRoot $Timestamp
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

        # Back up the current file. Append .txt so the archived copy cannot be executed;
        # mark it read-only as a second layer of protection.
        [string]$BackupFile = Join-Path $BackupDir 'AD-PowerAdmin.ps1.txt'
        Copy-Item -Path $LocalPath -Destination $BackupFile -Force -ErrorAction Stop
        Set-BackupFileProtection -Path $BackupFile
        Write-Host "  Backup saved to: $BackupFile" -ForegroundColor Cyan

        # Write the updated content. Normalize to CRLF for Windows Notepad compatibility.
        Write-FileUtf8Crlf -Path $LocalPath -Content $RemoteContent

        Write-Host ""
        Write-Host "  [UPDATED]  AD-PowerAdmin.ps1  ($LocalVersion --> $RemoteVersion)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "NOTE: Restart AD-PowerAdmin for the updated script to take effect." -ForegroundColor Yellow

    } catch {
        Write-Host ""
        Write-Host "ERROR: Update failed -- $_" -ForegroundColor Red
    } finally {
        if (Test-Path $TempFile) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
        $ProgressPreference = $OriginalProgressPreference
    }
# End of the Update-ADPowerAdminMainScript function.
}

##############################################################################################
# Settings File Upgrade -- private helpers and public entry point.
##############################################################################################

function Get-GlobalVarNames {
    <#
    .SYNOPSIS
    Extract every $global:* variable name declared in a settings file content string.

    .DESCRIPTION
    Applies a regex anchored to line start so inline comment examples are not matched.
    Handles both = and += assignment forms so multi-line += chains count as one variable.
    Returns a case-insensitive HashSet of bare variable names (without '$global:').

    .PARAMETER Content
    The full raw text of a settings file.
    #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param(
        [Parameter(Mandatory=$true)][string]$Content
    )

    $Names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Matches = [regex]::Matches($Content, '(?m)^\[(?:bool|string|int|Int|array)\]\$global:(\w+)\s*[+]?=')
    foreach ($M in $Matches) {
        $null = $Names.Add($M.Groups[1].Value)
    }
    return $Names
}

function Get-SettingsFileValues {
    <#
    .SYNOPSIS
    Extracts all typed $global:* variable values from a settings file content string.

    .DESCRIPTION
    Scans the content line by line. For each initial typed declaration (not a += continuation),
    extracts the variable name, current value, and the VarType understood by Set-SettingsFileValue.
    Multi-line array declarations are collected in full. Variables whose right-hand side is a bare
    $global: reference are silently skipped -- their formula should come from the new file.

    Returns a List of PSCustomObjects with properties: Name, Value, VarType.

    .PARAMETER Content
    Full raw text of the settings file.

    .NOTES
    Private helper for Update-ADPowerAdminSettingsFile. Not exported.
    #>
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param(
        [Parameter(Mandatory=$true)][string]$Content
    )

    $Result = [System.Collections.Generic.List[PSCustomObject]]::new()
    [string[]]$Lines = @($Content -split '\r?\n')
    [int]$i = 0

    while ($i -lt $Lines.Count) {
        [string]$Line = $Lines[$i]

        # Match initial typed declarations only (not += continuation lines).
        $TypeMatch = [regex]::Match($Line, '^\[(bool|string|int|Int|array)\]\$global:(\w+)\s*=')
        if (-not $TypeMatch.Success) {
            $i++
            continue
        }

        [string]$TypeStr = $TypeMatch.Groups[1].Value
        [string]$VarName = $TypeMatch.Groups[2].Value

        if ($TypeStr -eq 'bool') {
            $ValMatch = [regex]::Match($Line, '\$global:' + $VarName + '\s*=\s*\$(true|false)')
            if ($ValMatch.Success) {
                $Result.Add([PSCustomObject]@{
                    Name    = $VarName
                    Value   = $ValMatch.Groups[1].Value   # "true" or "false" (no leading $)
                    VarType = 'bool'
                })
            }

        } elseif ($TypeStr -match '^[Ii]nt$') {
            $ValMatch = [regex]::Match($Line, '\$global:' + $VarName + '\s*=\s*(\d+)')
            if ($ValMatch.Success) {
                $Result.Add([PSCustomObject]@{
                    Name    = $VarName
                    Value   = $ValMatch.Groups[1].Value
                    VarType = 'int'
                })
            }

        } elseif ($TypeStr -eq 'array') {
            # Collect the inner body between @( and the closing ) on its own line.
            $InnerLines = [System.Collections.Generic.List[string]]::new()
            $j = $i + 1
            while ($j -lt $Lines.Count) {
                if ($Lines[$j] -match '^\s*\)\s*$') { break }
                $InnerLines.Add($Lines[$j])
                $j++
            }
            $i = $j   # advance past closing ) so the final $i++ moves beyond it
            $Result.Add([PSCustomObject]@{
                Name    = $VarName
                Value   = ($InnerLines -join "`n")
                VarType = 'array-ou-locations'
            })

        } elseif ($TypeStr -eq 'string') {
            # Try single-quoted literal.
            $ValMatch = [regex]::Match($Line, '^\[string\]\$global:' + $VarName + "\s*=\s*'([^']*)'")
            if ($ValMatch.Success) {
                $Result.Add([PSCustomObject]@{
                    Name    = $VarName
                    Value   = $ValMatch.Groups[1].Value
                    VarType = 'string-single'
                })
            } else {
                # Try double-quoted literal.
                $ValMatch = [regex]::Match($Line, '^\[string\]\$global:' + $VarName + '\s*=\s*"([^"]*)"')
                if ($ValMatch.Success) {
                    $Result.Add([PSCustomObject]@{
                        Name    = $VarName
                        Value   = $ValMatch.Groups[1].Value
                        VarType = 'string-double'
                    })
                }
                # Bare $global: references are intentionally skipped -- the new file's
                # formula for those variables is preserved as-is.
            }
        }

        $i++
    }

    return $Result
# End of the Get-SettingsFileValues function.
}

function Update-ADPowerAdminSettingsFile {
    <#
    .SYNOPSIS
    Migrates the current settings file to the latest version structure from GitHub.

    .DESCRIPTION
    Downloads the latest AD-PowerAdmin_settings.ps1 from GitHub, then reads every typed
    $global:* value from the current local file and applies those values to the new file.
    The result adopts the new file's structure, layout, and variable ordering while
    preserving all user-configured settings.

    Variables present in the old file but absent from the new version are dropped.
    Variables new in the downloaded version that were not in the old file keep their
    new-file default values.

    A read-only backup (.txt) of the current file is created before any write occurs.

    .EXAMPLE
    Update-ADPowerAdminSettingsFile

    .NOTES
    Menu path: AD-PowerAdmin Management -> Upgrade Settings File
    Requires internet access to raw.githubusercontent.com.
    #>

    [string]$SettingsFile = Join-Path $global:ThisScriptDir 'AD-PowerAdmin_settings.ps1'
    if (-not (Test-Path $SettingsFile)) {
        Write-Host "ERROR: Settings file not found at: $SettingsFile" -ForegroundColor Red
        return
    }

    [string]$Channel  = if ($global:UpdateChannel) { $global:UpdateChannel } else { 'Release' }
    [string]$GitRef   = ''
    [string]$TempFile = Join-Path $env:TEMP 'AD-PowerAdmin_settings.ps1.update'

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [string]$OriginalProgressPreference = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        if ($Channel -eq 'Development') {
            $GitRef = 'main'
            Write-Host "Update channel: Development (main branch)" -ForegroundColor Cyan
        } else {
            Write-Host "Update channel: Release -- querying GitHub for latest tag..." -ForegroundColor Cyan
            $GitRef = Get-ADPowerAdminLatestReleaseTag
            if (-not $GitRef) {
                Write-Host "ERROR: Could not determine the latest release tag. Aborting." -ForegroundColor Red
                return
            }
            Write-Host "Latest release tag: $GitRef" -ForegroundColor Cyan
        }

        [string]$Url = "https://raw.githubusercontent.com/Brets0150/AD-PowerAdmin/$GitRef/AD-PowerAdmin_settings.ps1"
        Write-Host "Downloading new settings file from $GitRef ..." -ForegroundColor Cyan

        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -OutFile $TempFile -ErrorAction Stop
        } catch {
            Write-Host "ERROR: Failed to download settings file: $_" -ForegroundColor Red
            return
        }

        [string]$OldContent = Get-Content $SettingsFile -Raw
        [string]$NewContent = Get-Content $TempFile -Raw

        # Extract every configured value from the current file; get variable names from the new file.
        $OldValues   = Get-SettingsFileValues -Content $OldContent
        $NewVarNames = Get-GlobalVarNames -Content $NewContent

        # Build a lookup set of old variable names.
        $OldNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($Entry in $OldValues) { $null = $OldNames.Add($Entry.Name) }

        # Partition: what migrates vs. what is new (keeps defaults) vs. what is removed.
        $ToMigrate       = [System.Collections.Generic.List[PSCustomObject]]::new()
        [int]$RemovedCnt = 0
        foreach ($Entry in $OldValues) {
            if ($NewVarNames.Contains($Entry.Name)) { $ToMigrate.Add($Entry) }
            else { $RemovedCnt++ }
        }
        [int]$NewDefaultCnt = @($NewVarNames | Where-Object { -not $OldNames.Contains($_) }).Count

        # Display migration plan.
        Write-Host ""
        Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
        Write-Host "  Settings migration plan: $GitRef" -ForegroundColor Cyan
        Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Configured values to migrate : $($ToMigrate.Count)  (your settings preserved)" -ForegroundColor White
        Write-Host "  New variables (keep defaults): $NewDefaultCnt  (added in this version)" -ForegroundColor White
        Write-Host "  Removed variables (dropped)  : $RemovedCnt  (no longer in new version)" -ForegroundColor White
        Write-Host ""
        Write-Host "  The current file will be replaced by the new version's structure." -ForegroundColor DarkGray
        Write-Host "  All user-configured values will be transplanted into the new layout." -ForegroundColor DarkGray
        Write-Host ""

        [string]$Confirm = Read-Host "Apply migration? (y/N)"
        if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
            Write-Host "Migration cancelled. No files modified." -ForegroundColor Gray
            return
        }

        # Back up the current settings file. Append .txt so the archived copy cannot be
        # executed; mark it read-only as a second layer of protection.
        [string]$BackupPath = $SettingsFile + '.txt'
        try {
            Copy-Item -Path $SettingsFile -Destination $BackupPath -Force -ErrorAction Stop
            Set-BackupFileProtection -Path $BackupPath
        } catch {
            Write-Host "WARNING: Could not create backup at '$BackupPath': $_" -ForegroundColor Red
            [string]$ContinueAnyway = Read-Host "Continue without backup? (y/N)"
            if ($ContinueAnyway -ne 'y' -and $ContinueAnyway -ne 'Y') {
                Write-Host "Aborted. No files modified." -ForegroundColor Gray
                return
            }
            $BackupPath = ''
        }

        # Start from the new file as the base and transplant each configured old value.
        [string]$MergedContent = $NewContent
        [int]$AppliedCnt  = 0
        [int]$SkippedCnt  = 0
        foreach ($Entry in $ToMigrate) {
            [string]$Before = $MergedContent
            $MergedContent  = Set-SettingsFileValue -Content $MergedContent `
                                  -VarName $Entry.Name -NewValue $Entry.Value -VarType $Entry.VarType
            if ($MergedContent -ne $Before) { $AppliedCnt++ } else { $SkippedCnt++ }
        }

        Write-FileUtf8Crlf -Path $SettingsFile -Content $MergedContent

        Write-Host ""
        Write-Host "Migration complete." -ForegroundColor Green
        Write-Host "  Transplanted: $AppliedCnt variable(s)" -ForegroundColor Green
        if ($SkippedCnt -gt 0) {
            Write-Host "  Unchanged   : $SkippedCnt variable(s) (value matched new default or pattern unmatched)" -ForegroundColor DarkGray
        }
        if ($BackupPath) {
            Write-Host "  Backup      : $BackupPath" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "NOTE: Restart AD-PowerAdmin for changes to take effect." -ForegroundColor Yellow
        Write-Host "      Run the Settings Wizard to review and configure any new variables." -ForegroundColor Yellow

    } finally {
        if ($TempFile -and (Test-Path $TempFile)) { Remove-Item $TempFile -Force -ErrorAction SilentlyContinue }
        $ProgressPreference = $OriginalProgressPreference
    }
# End of the Update-ADPowerAdminSettingsFile function.
}

##############################################################################################
# Settings Configuration Wizard -- private helpers and public entry point.
# NOTE: These functions write directly to AD-PowerAdmin_settings.ps1. They are the deliberate
# exception to the module read-only convention for $global:* settings.
##############################################################################################

function Read-SettingBool {
    <#
    .SYNOPSIS
    Prompt for a yes/no setting value with the current default displayed.

    .DESCRIPTION
    Displays the current bool value and prompts the user to change it. Pressing Enter
    keeps the current default. Returns [bool].

    .PARAMETER Prompt
    The prompt label shown to the user.

    .PARAMETER Default
    The current value to use if the user presses Enter.
    #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][bool]$Default
    )

    if ($Default) {
        $HintText = "(Y/n)"
        $DefaultLabel = "True"
    } else {
        $HintText = "(y/N)"
        $DefaultLabel = "False"
    }

    Write-Host "  Current value: $DefaultLabel" -ForegroundColor Gray

    while ($true) {
        [string]$UserInput = Read-Host "  $Prompt $HintText"
        if ([string]::IsNullOrEmpty($UserInput)) {
            return $Default
        }
        if ($UserInput -eq 'y' -or $UserInput -eq 'Y') { return $true }
        if ($UserInput -eq 'n' -or $UserInput -eq 'N') { return $false }
        Write-Host "  Please enter 'y' or 'n'." -ForegroundColor Yellow
    }
}

function Read-SettingString {
    <#
    .SYNOPSIS
    Prompt for a string setting value with the current default displayed.

    .DESCRIPTION
    Displays the current value and prompts the user. Pressing Enter keeps the current
    default. Enforces MaxLength when supplied (loops until within bounds). Returns [string].

    .PARAMETER Prompt
    The prompt label shown to the user.

    .PARAMETER Default
    The current value to use if the user presses Enter.

    .PARAMETER MaxLength
    When greater than 0, rejects input that exceeds this character count.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$false)][AllowEmptyString()][string]$Default = '',
        [Parameter(Mandatory=$false)][int]$MaxLength = 0
    )

    if ([string]::IsNullOrEmpty($Default)) {
        Write-Host "  Current value: (empty)" -ForegroundColor Gray
    } else {
        Write-Host "  Current value: $Default" -ForegroundColor Gray
    }

    while ($true) {
        [string]$UserInput = Read-Host "  $Prompt (Enter = keep current)"
        if ([string]::IsNullOrEmpty($UserInput)) {
            return $Default
        }
        if ($MaxLength -gt 0 -and $UserInput.Length -gt $MaxLength) {
            Write-Host "  Value must be $MaxLength characters or fewer (entered: $($UserInput.Length))." -ForegroundColor Yellow
            continue
        }
        return $UserInput
    }
}

function Read-SettingInt {
    <#
    .SYNOPSIS
    Prompt for an integer setting value with the current default displayed.

    .DESCRIPTION
    Displays the current integer value and prompts the user. Pressing Enter keeps the
    current default. Validates that input is numeric and meets MinValue. Returns [int].

    .PARAMETER Prompt
    The prompt label shown to the user.

    .PARAMETER Default
    The current value to use if the user presses Enter.

    .PARAMETER MinValue
    Minimum accepted integer value (default 1).
    #>
    [OutputType([int])]
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][int]$Default,
        [Parameter(Mandatory=$false)][int]$MinValue = 1
    )

    Write-Host "  Current value: $Default" -ForegroundColor Gray

    while ($true) {
        [string]$UserInput = Read-Host "  $Prompt (Enter = keep current)"
        if ([string]::IsNullOrEmpty($UserInput)) {
            return $Default
        }
        [int]$Parsed = 0
        if (-not [Int32]::TryParse($UserInput, [ref]$Parsed)) {
            Write-Host "  Please enter a whole number." -ForegroundColor Yellow
            continue
        }
        if ($Parsed -lt $MinValue) {
            Write-Host "  Value must be $MinValue or greater." -ForegroundColor Yellow
            continue
        }
        return $Parsed
    }
}

function Read-SettingOuPath {
    <#
    .SYNOPSIS
    Prompt for an OU DistinguishedName with optional AD browser and live validation.

    .DESCRIPTION
    Displays the current value and prompts the user. The user can press Enter to keep
    the current value, type '?' to browse AD OUs interactively, or type a DN directly.
    Direct input is validated against AD; invalid DNs trigger a warning and a confirm
    prompt before being accepted. Returns [string].

    .PARAMETER Prompt
    The prompt label shown to the user.

    .PARAMETER Default
    The current value to use if the user presses Enter.

    .PARAMETER AllowEmpty
    When $true, pressing Enter with no current value returns an empty string.
    When $false (default), an empty value is not accepted.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$false)][AllowEmptyString()][string]$Default = '',
        [Parameter(Mandatory=$false)][bool]$AllowEmpty = $false
    )

    if ([string]::IsNullOrEmpty($Default)) {
        Write-Host "  Current value: (empty)" -ForegroundColor Gray
    } else {
        Write-Host "  Current value: $Default" -ForegroundColor Gray
    }
    Write-Host "  Tip: Press ENTER to keep current, type '?' to browse AD OUs, or enter a DN directly." -ForegroundColor DarkGray

    while ($true) {
        [string]$UserInput = Read-Host "  $Prompt"

        if ([string]::IsNullOrEmpty($UserInput)) {
            if ($AllowEmpty -or -not [string]::IsNullOrEmpty($Default)) {
                return $Default
            }
            Write-Host "  A value is required. Type '?' to browse AD OUs." -ForegroundColor Yellow
            continue
        }

        if ($UserInput -eq '?') {
            [string]$Selected = Get-AdOuSearch
            if (-not [string]::IsNullOrEmpty($Selected)) {
                return $Selected
            }
            Write-Host "  No OU selected. Try again or type a DN directly." -ForegroundColor Yellow
            continue
        }

        # Validate the typed DN against AD
        try {
            $null = Get-ADOrganizationalUnit -Identity $UserInput -ErrorAction Stop
            return $UserInput
        } catch {
            Write-Host "  WARNING: '$UserInput' was not found as an OU in Active Directory." -ForegroundColor Yellow
            [string]$UseAnyway = Read-Host "  Use this value anyway? (y/N)"
            if ($UseAnyway -eq 'y' -or $UseAnyway -eq 'Y') {
                return $UserInput
            }
        }
    }
}

function Edit-OuLocationList {
    <#
    .SYNOPSIS
    Interactive manager for an array of SearchOUbase/DisabledOULocal location pairs.

    .DESCRIPTION
    Displays the current entries in a numbered list and offers Add, Remove, Clear all, and Done
    options in a loop. Returns the modified List[hashtable] when changes are made, or $null when
    the user exits without changes.

    .PARAMETER ObjectType
    Human-readable noun used in prompts (e.g. 'computer' or 'user').

    .PARAMETER CurrentEntries
    The current array of hashtables, each with SearchOUbase and DisabledOULocal keys.

    .PARAMETER AllowEmptySearch
    When $true, SearchOUbase may be left blank (meaning search the entire domain).
    #>
    param(
        [Parameter(Mandatory=$true)][string]$ObjectType,
        [Parameter(Mandatory=$true)][object[]]$CurrentEntries,
        [Parameter(Mandatory=$true)][bool]$AllowEmptySearch
    )

    $WorkingList = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($Entry in $CurrentEntries) {
        $WorkingList.Add(@{ SearchOUbase = $Entry.SearchOUbase; DisabledOULocal = $Entry.DisabledOULocal })
    }
    [bool]$Modified = $false

    while ($true) {
        Write-Host ""
        if ($WorkingList.Count -eq 0) {
            Write-Host "  (no entries configured)" -ForegroundColor Yellow
        } else {
            for ($i = 0; $i -lt $WorkingList.Count; $i++) {
                Write-Host ("  {0,2}. Search : {1}" -f ($i + 1), $WorkingList[$i].SearchOUbase) -ForegroundColor Gray
                Write-Host ("      Disable: {0}" -f $WorkingList[$i].DisabledOULocal) -ForegroundColor Gray
                Write-Host ""
            }
        }
        Write-Host "  Options: A=Add  R=Remove  C=Clear all  D=Done" -ForegroundColor Cyan

        [string]$Choice = Read-Host "  Select option"

        switch ($Choice.ToUpper()) {
            'A' {
                Write-Host ""
                Write-Host "  -- New Entry --" -ForegroundColor Cyan
                if ($AllowEmptySearch) {
                    [string]$SearchOU = Read-SettingOuPath -Prompt "SearchOUbase (blank = search all ${ObjectType}s)" -Default '' -AllowEmpty $true
                } else {
                    [string]$SearchOU = Read-SettingOuPath -Prompt "SearchOUbase (OU to search for inactive ${ObjectType}s)" -Default '' -AllowEmpty $false
                }
                [string]$DisabledOU = Read-SettingOuPath -Prompt "DisabledOULocal (OU to move disabled ${ObjectType}s to)" -Default '' -AllowEmpty $false
                $WorkingList.Add(@{ SearchOUbase = $SearchOU; DisabledOULocal = $DisabledOU })
                $Modified = $true
                Write-Host "  Entry added." -ForegroundColor Green
            }
            'R' {
                if ($WorkingList.Count -eq 0) {
                    Write-Host "  No entries to remove." -ForegroundColor Yellow
                    break
                }
                Write-Host ""
                Write-Host "  Select entry to remove:" -ForegroundColor Cyan
                for ($i = 0; $i -lt $WorkingList.Count; $i++) {
                    Write-Host ("  {0,2}. Search : {1}" -f ($i + 1), $WorkingList[$i].SearchOUbase)
                    Write-Host ("      Disable: {0}" -f $WorkingList[$i].DisabledOULocal)
                    Write-Host ""
                }
                while ($true) {
                    [string]$RemoveRaw = Read-Host "  Enter number to remove (or 'q' to cancel)"
                    if ($RemoveRaw -eq 'q' -or $RemoveRaw -eq 'Q') { break }
                    [int]$RemoveIdx = 0
                    if ([Int32]::TryParse($RemoveRaw, [ref]$RemoveIdx) -and $RemoveIdx -ge 1 -and $RemoveIdx -le $WorkingList.Count) {
                        $WorkingList.RemoveAt($RemoveIdx - 1)
                        $Modified = $true
                        Write-Host ("  Entry {0} removed." -f $RemoveIdx) -ForegroundColor Green
                        break
                    }
                    Write-Host ("  Invalid selection. Enter 1-{0} or 'q'." -f $WorkingList.Count) -ForegroundColor Yellow
                }
            }
            'C' {
                if ($WorkingList.Count -eq 0) {
                    Write-Host "  No entries to clear." -ForegroundColor Yellow
                    break
                }
                [string]$ConfirmClear = Read-Host ("  Clear all {0} entr{1}? (y/N)" -f $WorkingList.Count, $(if ($WorkingList.Count -eq 1) { 'y' } else { 'ies' }))
                if ($ConfirmClear -eq 'y' -or $ConfirmClear -eq 'Y') {
                    $WorkingList.Clear()
                    $Modified = $true
                    Write-Host "  All entries cleared." -ForegroundColor Green
                }
            }
            'D' {
                if ($Modified) { return ,$WorkingList }
                return $null
            }
            default {
                Write-Host "  Invalid option. Enter A, R, C, or D." -ForegroundColor Yellow
            }
        }
    }
}

function Start-SettingsWizard {
    <#
    .SYNOPSIS
    Interactive wizard that guides an administrator through configuring AD-PowerAdmin_settings.ps1.

    .DESCRIPTION
    Reads the current settings file, prompts for each configurable variable section by section
    (displaying the current value as the default), then writes the updated file after confirmation.
    A read-only backup (.txt) is created before any write occurs.

    NOTE: This function writes directly to AD-PowerAdmin_settings.ps1. It is the deliberate
    exception to the module read-only convention for $global:* settings.

    .EXAMPLE
    Start-SettingsWizard

    .NOTES
    Menu path: AD-PowerAdmin Management -> Configure Settings Wizard
    #>

    [string]$SettingsFile = Join-Path $global:ThisScriptDir 'AD-PowerAdmin_settings.ps1'
    if (-not (Test-Path $SettingsFile)) {
        Write-Host "ERROR: Settings file not found at: $SettingsFile" -ForegroundColor Red
        return
    }

    [string]$Content = Get-Content $SettingsFile -Raw
    $Changes = [ordered]@{}

    function Show-SectionHeader([string]$Title) {
        Write-Host ""
        Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
        Write-Host ""
    }

    Write-Host ""
    Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
    Write-Host "  AD-PowerAdmin Settings Configuration Wizard" -ForegroundColor Cyan
    Write-Host "  Press ENTER at any prompt to keep the current value." -ForegroundColor Cyan
    Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan

    ##############################################################################################
    Show-SectionHeader "Debugging"
    Write-Host "  Controls whether a transcript debug log is written to the Reports folder." -ForegroundColor DarkGray
    Write-Host "  Recommended: False for production use." -ForegroundColor DarkGray
    [bool]$NewDebug = Read-SettingBool -Prompt "Enable debug logging" -Default $global:Debug
    $Changes['Debug'] = @{ Value = $NewDebug.ToString().ToLower(); VarType = 'bool' }

    ##############################################################################################
    Show-SectionHeader "Mandatory Configuration"

    Write-Host "  ADAdminEmail: The AD administrator or security team email address." -ForegroundColor DarkGray
    Write-Host "  Used as the default recipient for all audit reports and alerts." -ForegroundColor DarkGray
    [string]$NewAdminEmail = Read-SettingString -Prompt "AD Admin Email address" -Default $global:ADAdminEmail
    $Changes['ADAdminEmail'] = @{ Value = $NewAdminEmail; VarType = 'string-double' }

    Write-Host ""
    Write-Host "  FromEmail: The address AD-PowerAdmin sends email from." -ForegroundColor DarkGray
    Write-Host "  This account must be permitted to relay through your SMTP server." -ForegroundColor DarkGray
    [string]$NewFromEmail = Read-SettingString -Prompt "From Email address" -Default $global:FromEmail
    $Changes['FromEmail'] = @{ Value = $NewFromEmail; VarType = 'string-double' }

    Write-Host ""
    Write-Host "  MsaAccountName: The standalone Managed Service Account name for the scheduled task." -ForegroundColor DarkGray
    Write-Host "  Maximum 14 characters. The default is recommended; only change if required." -ForegroundColor DarkGray
    [string]$NewMsaName = Read-SettingString -Prompt "sMSA Account Name (max 14 chars)" -Default $global:MsaAccountName -MaxLength 14
    $Changes['MsaAccountName'] = @{ Value = $NewMsaName; VarType = 'string-double' }

    Write-Host ""
    Write-Host "  InstallDirectory: Where AD-PowerAdmin files are copied when installed as a service." -ForegroundColor DarkGray
    [string]$NewInstallDir = Read-SettingString -Prompt "Install Directory" -Default $global:InstallDirectory
    $Changes['InstallDirectory'] = @{ Value = $NewInstallDir; VarType = 'string-double' }

    ##############################################################################################
    Show-SectionHeader "Optional Module Settings"

    Write-Host "  UpdateChannel: Controls which source is used when 'Update Modules' is run." -ForegroundColor DarkGray
    Write-Host "  'Release' = latest official GitHub release. 'Development' = main branch." -ForegroundColor DarkGray
    [string]$NewChannel = ''
    while ($true) {
        $NewChannel = Read-SettingString -Prompt "Update channel (Release/Development)" -Default $global:UpdateChannel
        if ($NewChannel -eq 'Release' -or $NewChannel -eq 'Development') { break }
        Write-Host "  Value must be 'Release' or 'Development'." -ForegroundColor Yellow
    }
    $Changes['UpdateChannel'] = @{ Value = $NewChannel; VarType = 'string-single' }

    ##############################################################################################
    Show-SectionHeader "Optional Daily Tasks"
    Write-Host "  Enable or disable each automated daily audit. All default to enabled." -ForegroundColor DarkGray
    Write-Host ""

    [bool]$NewKRBTGT = Read-SettingBool -Prompt "Enable daily Kerberos KRBTGT age check" -Default $global:KerberosKRBTGTAudit
    $Changes['KerberosKRBTGTAudit'] = @{ Value = $NewKRBTGT.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    [bool]$NewInactComp = Read-SettingBool -Prompt "Enable daily inactive computer audit" -Default $global:InactiveComputerAudit
    $Changes['InactiveComputerAudit'] = @{ Value = $NewInactComp.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    [bool]$NewInactUser = Read-SettingBool -Prompt "Enable daily inactive user audit" -Default $global:InactiveUserAudit
    $Changes['InactiveUserAudit'] = @{ Value = $NewInactUser.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    [bool]$NewWeakPw = Read-SettingBool -Prompt "Enable daily weak/breached password audit" -Default $global:WeakPasswordAudit
    $Changes['WeakPasswordAudit'] = @{ Value = $NewWeakPw.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    [bool]$NewLockout = Read-SettingBool -Prompt "Enable daily account lockout report" -Default $global:LockoutDailyReport
    $Changes['LockoutDailyReport'] = @{ Value = $NewLockout.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    [bool]$NewPwNotReq = Read-SettingBool -Prompt "Enable daily password-not-required audit" -Default $global:PasswordNotRequiredAudit
    $Changes['PasswordNotRequiredAudit'] = @{ Value = $NewPwNotReq.ToString().ToLower(); VarType = 'bool' }

    ##############################################################################################
    Show-SectionHeader "Kerberos KRBTGT Settings"
    Write-Host "  Number of days between automatic KRBTGT password rotations." -ForegroundColor DarkGray
    Write-Host "  Microsoft recommends rotating every 90-180 days. Default is 90." -ForegroundColor DarkGray
    [int]$NewKrbtgtInterval = Read-SettingInt -Prompt "KRBTGT password rotation interval (days)" -Default $global:krbtgtPwUpdateInterval
    $Changes['krbtgtPwUpdateInterval'] = @{ Value = $NewKrbtgtInterval.ToString(); VarType = 'int' }

    ##############################################################################################
    Show-SectionHeader "Inactive Computer Cleanup"
    Write-Host "  InactiveDays: Computers with no logon activity beyond this threshold are disabled." -ForegroundColor DarkGray
    [int]$NewInactiveDays = Read-SettingInt -Prompt "Inactivity threshold (days)" -Default $global:InactiveDays
    $Changes['InactiveDays'] = @{ Value = $NewInactiveDays.ToString(); VarType = 'int' }

    Write-Host ""
    Write-Host "  InactiveComputersLocations: OU pairs that define where to search for inactive" -ForegroundColor DarkGray
    Write-Host "  computers and where to move them after disabling." -ForegroundColor DarkGray

    $CompResult = Edit-OuLocationList -ObjectType 'computer' -CurrentEntries $global:InactiveComputersLocations -AllowEmptySearch $false
    if ($null -ne $CompResult) {
        $CompBlocks = [System.Collections.Generic.List[string]]::new()
        foreach ($Entry in $CompResult) {
            $CompBlocks.Add("    @{`n        SearchOUbase    = '$($Entry.SearchOUbase)'`n        DisabledOULocal = '$($Entry.DisabledOULocal)'`n    }")
        }
        $Changes['InactiveComputersLocations'] = @{ Value = ($CompBlocks -join "`n`n"); VarType = 'array-ou-locations' }
    }

    ##############################################################################################
    Show-SectionHeader "Inactive Users Cleanup"
    Write-Host "  InactiveUsersLocations: OU pairs that define where to search for inactive" -ForegroundColor DarkGray
    Write-Host "  users and where to move them after disabling." -ForegroundColor DarkGray

    $UserResult = Edit-OuLocationList -ObjectType 'user' -CurrentEntries $global:InactiveUsersLocations -AllowEmptySearch $true
    if ($null -ne $UserResult) {
        $UserBlocks = [System.Collections.Generic.List[string]]::new()
        foreach ($Entry in $UserResult) {
            $UserBlocks.Add("    @{`n        SearchOUbase    = '$($Entry.SearchOUbase)'`n        DisabledOULocal = '$($Entry.DisabledOULocal)'`n    }")
        }
        $Changes['InactiveUsersLocations'] = @{ Value = ($UserBlocks -join "`n`n"); VarType = 'array-ou-locations' }
    }

    ##############################################################################################
    Show-SectionHeader "Password Quality Test Settings"

    Write-Host "  HIBP hash data can be stored as a single sorted file or as a directory of range files." -ForegroundColor DarkGray
    Write-Host "  Directory mode is recommended: it enables fast incremental weekly updates (~70 GB initial" -ForegroundColor DarkGray
    Write-Host "  download; only changed range files downloaded on subsequent runs)." -ForegroundColor DarkGray
    Write-Host "  Single-file mode downloads the entire ~70 GB file on every update." -ForegroundColor DarkGray
    Write-Host "  To use single-file mode: set NtlmHashDataDir to empty. To use directory mode: set it." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  NtlmHashDataFile: filename for single-file mode (always present even in directory mode)." -ForegroundColor DarkGray
    [string]$NewNtlmFile = Read-SettingString -Prompt "HIBP single-file name" -Default $global:NtlmHashDataFile
    $Changes['NtlmHashDataFile'] = @{ Value = $NewNtlmFile; VarType = 'string-single' }

    Write-Host ""
    Write-Host "  NtlmHashDataDir: directory name for directory mode. Leave empty to use single-file mode." -ForegroundColor DarkGray
    [string]$NewNtlmDir = Read-SettingString -Prompt "HIBP directory name (empty = single-file mode)" -Default $global:NtlmHashDataDir
    $Changes['NtlmHashDataDir'] = @{ Value = $NewNtlmDir; VarType = 'string-single' }

    Write-Host ""
    Write-Host "  WeakPassDictFile: plain-text file of known weak passwords, one per line." -ForegroundColor DarkGray
    [string]$NewWeakDict = Read-SettingString -Prompt "Weak password dictionary filename" -Default $global:WeakPassDictFile
    $Changes['WeakPassDictFile'] = @{ Value = $NewWeakDict; VarType = 'string-single' }

    Write-Host ""
    Write-Host "  PasswordQualityTestSearchOUbase: OU to limit the password audit to." -ForegroundColor DarkGray
    Write-Host "  Leave empty to audit all user accounts in AD." -ForegroundColor DarkGray
    [string]$NewPwOU = Read-SettingOuPath -Prompt "Password audit OU (empty = all users)" -Default $global:PasswordQualityTestSearchOUbase -AllowEmpty $true
    $Changes['PasswordQualityTestSearchOUbase'] = @{ Value = $NewPwOU; VarType = 'string-single' }

    Write-Host ""
    Write-Host "  PwAuditAlertEmailCCAdmins: when enabled, the admin also receives a copy of every" -ForegroundColor DarkGray
    Write-Host "  breach alert sent to end users." -ForegroundColor DarkGray
    [bool]$NewCcAdmins = Read-SettingBool -Prompt "CC admins on user breach alert emails" -Default $global:PwAuditAlertEmailCCAdmins
    $Changes['PwAuditAlertEmailCCAdmins'] = @{ Value = $NewCcAdmins.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    Write-Host "  PwAuditPwChangeGracePeriod: days a user has to change a breached/weak password" -ForegroundColor DarkGray
    Write-Host "  before the account is force-expired at next login." -ForegroundColor DarkGray
    [int]$NewGrace = Read-SettingInt -Prompt "Password change grace period (days)" -Default $global:PwAuditPwChangeGracePeriod
    $Changes['PwAuditPwChangeGracePeriod'] = @{ Value = $NewGrace.ToString(); VarType = 'int' }

    Write-Host ""
    Write-Host "  PwAuditAlertEmailSubject: subject line for breach alert emails sent to users." -ForegroundColor DarkGray
    [string]$NewAlertSubject = Read-SettingString -Prompt "Alert email subject" -Default $global:PwAuditAlertEmailSubject
    $Changes['PwAuditAlertEmailSubject'] = @{ Value = $NewAlertSubject; VarType = 'string-double' }

    Write-Host ""
    Write-Host "  NOTE: PwAuditAlertEmailMessage spans multiple concatenated lines with variable" -ForegroundColor Yellow
    Write-Host "        interpolation. Edit this value manually in AD-PowerAdmin_settings.ps1." -ForegroundColor Yellow
    Write-Host "        Skipping automated configuration of this variable." -ForegroundColor Yellow

    ##############################################################################################
    Show-SectionHeader "Email / SMTP Settings"

    Write-Host "  SMTPServer: hostname or IP address of your SMTP relay." -ForegroundColor DarkGray
    [string]$NewSMTP = Read-SettingString -Prompt "SMTP Server" -Default $global:SMTPServer
    $Changes['SMTPServer'] = @{ Value = $NewSMTP; VarType = 'string-single' }

    Write-Host ""
    Write-Host "  SmtpEnableSSL: whether to require SSL/TLS when connecting to the SMTP server." -ForegroundColor DarkGray
    [bool]$NewSSL = Read-SettingBool -Prompt "Enable SMTP SSL/TLS" -Default $global:SmtpEnableSSL
    $Changes['SmtpEnableSSL'] = @{ Value = $NewSSL.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    Write-Host "  SMTPPort: SMTP server port. Typical values: 587 (STARTTLS), 465 (SSL), 25 (plain)." -ForegroundColor DarkGray
    [int]$NewSMTPPort = Read-SettingInt -Prompt "SMTP Port" -Default $global:SMTPPort
    $Changes['SMTPPort'] = @{ Value = $NewSMTPPort.ToString(); VarType = 'int' }

    Write-Host ""
    Write-Host "  SMTPUsername: SMTP authentication username (leave empty if your relay does not require auth)." -ForegroundColor DarkGray
    [string]$NewSMTPUser = Read-SettingString -Prompt "SMTP Username" -Default $global:SMTPUsername
    $Changes['SMTPUsername'] = @{ Value = $NewSMTPUser; VarType = 'string-single' }

    Write-Host ""
    Write-Host "  SMTPPassword: SMTP authentication password stored in plaintext." -ForegroundColor DarkGray
    Write-Host "  WARNING: Restrict access to AD-PowerAdmin_settings.ps1 to Domain Admins only." -ForegroundColor Yellow
    Write-Host "  Press ENTER to keep the current value without displaying it." -ForegroundColor DarkGray
    [string]$NewSMTPPass = Read-Host "  SMTP Password (Enter = keep current)"
    if (-not [string]::IsNullOrEmpty($NewSMTPPass)) {
        $Changes['SMTPPassword'] = @{ Value = $NewSMTPPass; VarType = 'string-single' }
    }

    ##############################################################################################
    Show-SectionHeader "SYSVOL Security Audit"
    Write-Host "  When enabled, AD-PowerAdmin scans SYSVOL Group Policy Preference XML files daily" -ForegroundColor DarkGray
    Write-Host "  for cpassword values and emails the administrator immediately if any are found." -ForegroundColor DarkGray
    [bool]$NewSysvol = Read-SettingBool -Prompt "Enable daily GPP cpassword scan" -Default $global:SysvolGppCpasswordAudit
    $Changes['SysvolGppCpasswordAudit'] = @{ Value = $NewSysvol.ToString().ToLower(); VarType = 'bool' }

    ##############################################################################################
    Show-SectionHeader "Exchange AD Security Audit"
    Write-Host "  Enable only in environments where Exchange is installed. This audit checks" -ForegroundColor DarkGray
    Write-Host "  Exchange security group ACEs for dangerous domain-root permissions." -ForegroundColor DarkGray
    Write-Host "  ExchangeGroupsToAudit is pre-configured and not modified by this wizard." -ForegroundColor DarkGray
    [bool]$NewExchange = Read-SettingBool -Prompt "Enable daily Exchange AD security audit" -Default $global:ExchangeADSecurityAudit
    $Changes['ExchangeADSecurityAudit'] = @{ Value = $NewExchange.ToString().ToLower(); VarType = 'bool' }

    ##############################################################################################
    Show-SectionHeader "Honeytoken Account Settings"
    Write-Host "  HoneypotAudit: enables the honeytoken authentication event monitor." -ForegroundColor DarkGray
    Write-Host "  Set to True automatically when the Honeypot install wizard completes." -ForegroundColor DarkGray
    [bool]$NewHoneypot = Read-SettingBool -Prompt "Enable honeytoken authentication monitor" -Default $global:HoneypotAudit
    $Changes['HoneypotAudit'] = @{ Value = $NewHoneypot.ToString().ToLower(); VarType = 'bool' }

    Write-Host ""
    Write-Host "  HoneypotMonitorIntervalMinutes: how often the monitor scheduled task runs." -ForegroundColor DarkGray
    Write-Host "  Also controls the Security log lookback window (interval + 1 minute)." -ForegroundColor DarkGray
    [int]$NewHoneypotInterval = Read-SettingInt -Prompt "Honeytoken monitor interval (minutes)" -Default $global:HoneypotMonitorIntervalMinutes
    $Changes['HoneypotMonitorIntervalMinutes'] = @{ Value = $NewHoneypotInterval.ToString(); VarType = 'int' }

    Write-Host ""
    Write-Host "  NOTE: HoneypotUsername, HoneypotDenyGroup, and HoneypotOU are managed" -ForegroundColor Yellow
    Write-Host "        automatically by the Honeypot install wizard. Do not edit them here." -ForegroundColor Yellow

    ##############################################################################################
    # Summary and confirmation
    ##############################################################################################
    Write-Host ""
    Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan
    Write-Host "  Summary of Changes" -ForegroundColor Cyan
    Write-Host ('=' * $global:OptionsMaxTextLength) -ForegroundColor Cyan

    if ($Changes.Count -eq 0) {
        Write-Host "  No settings were changed." -ForegroundColor Gray
        Write-Host ""
        return
    }

    Write-Host ""
    foreach ($Key in $Changes.Keys) {
        $Val = $Changes[$Key].Value
        if ($Changes[$Key].VarType -eq 'array-ou-locations') {
            Write-Host ("  {0,-40} = [updated OU location entries]" -f $Key) -ForegroundColor White
        } elseif ($Key -eq 'SMTPPassword') {
            Write-Host ("  {0,-40} = [updated - not displayed]" -f $Key) -ForegroundColor White
        } else {
            Write-Host ("  {0,-40} = {1}" -f $Key, $Val) -ForegroundColor White
        }
    }
    Write-Host ""

    [string]$Confirm = ''
    while ($Confirm -ne 'y' -and $Confirm -ne 'Y' -and $Confirm -ne 'n' -and $Confirm -ne 'N') {
        $Confirm = Read-Host "Write these changes to AD-PowerAdmin_settings.ps1? (y/n)"
        if ($Confirm -ne 'y' -and $Confirm -ne 'Y' -and $Confirm -ne 'n' -and $Confirm -ne 'N') {
            Write-Host "  Please enter 'y' or 'n'." -ForegroundColor Yellow
        }
    }
    if ($Confirm -eq 'n' -or $Confirm -eq 'N') {
        Write-Host "Changes discarded. No files modified." -ForegroundColor Gray
        return
    }

    # Back up the settings file before writing. Append .txt so the archived copy cannot
    # be executed; mark it read-only as a second layer of protection.
    [string]$BackupPath = $SettingsFile + '.txt'
    try {
        Copy-Item -Path $SettingsFile -Destination $BackupPath -Force -ErrorAction Stop
        Set-BackupFileProtection -Path $BackupPath
    } catch {
        Write-Host "WARNING: Could not create backup at '$BackupPath': $_" -ForegroundColor Red
        [string]$ContinueAnyway = Read-Host "Continue without backup? (y/N)"
        if ($ContinueAnyway -ne 'y' -and $ContinueAnyway -ne 'Y') {
            Write-Host "Aborted. No files modified." -ForegroundColor Gray
            return
        }
    }

    # Apply all replacements to the content string.
    foreach ($Key in $Changes.Keys) {
        $Content = Set-SettingsFileValue -Content $Content -VarName $Key -NewValue $Changes[$Key].Value -VarType $Changes[$Key].VarType
    }

    # Write the updated content back to the settings file. Normalize to CRLF for Windows
    # Notepad compatibility and clear read-only if set.
    try {
        Write-FileUtf8Crlf -Path $SettingsFile -Content $Content
    } catch {
        Write-Host ""
        Write-Host "ERROR: Could not write settings file -- $_" -ForegroundColor Red
        Write-Host "       Check that the file is not locked and you have write access." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "Settings written to: $SettingsFile" -ForegroundColor Green
    if (Test-Path $BackupPath) {
        Write-Host "Backup saved to   : $BackupPath" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "NOTE: Restart AD-PowerAdmin for the new settings to take effect." -ForegroundColor Yellow
    Write-Host ""
}

Function Test-EmailConfiguration {
    <#
    .SYNOPSIS
        Send a test email and run multi-stage SMTP diagnostics.

    .DESCRIPTION
        Performs four sequential diagnostic stages using the email settings from
        AD-PowerAdmin_settings.ps1:
          Stage 1 - Validates that required settings are present.
          Stage 2 - Tests DNS resolution of the SMTP server hostname.
          Stage 3 - Tests TCP connectivity to the SMTP server on the configured port.
          Stage 4 - Attempts to send a test email and captures any SMTP-level errors.
        Each stage prints [PASS], [FAIL], or [INFO] with contextual troubleshooting
        guidance to help isolate whether a failure is a config, DNS, network, or
        SMTP authentication problem.

    .EXAMPLE
        Test-EmailConfiguration
    #>

    Write-Host ""
    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host "  Email Configuration Diagnostic" -ForegroundColor Cyan
    Write-Host "==================================================================================" -ForegroundColor Cyan
    Write-Host ""

    # --- Display current settings ---
    Write-Host "  Current Email Settings:" -ForegroundColor Yellow
    Write-Host ("    SMTP Server   : " + $(if ([string]::IsNullOrWhiteSpace($global:SMTPServer))  { "(not set)" } else { $global:SMTPServer }))
    Write-Host ("    SMTP Port     : " + $(if ([string]::IsNullOrWhiteSpace($global:SMTPPort))    { "(not set - will default to 587)" } else { $global:SMTPPort }))
    Write-Host ("    SSL Enabled   : " + $global:SmtpEnableSSL)
    Write-Host ("    SMTP Username : " + $(if ([string]::IsNullOrWhiteSpace($global:SMTPUsername)) { "(not set)" } else { $global:SMTPUsername }))
    Write-Host ("    SMTP Password : " + $(if ([string]::IsNullOrWhiteSpace($global:SMTPPassword)) { "(not set)" } else { "(configured)" }))
    Write-Host ("    From Address  : " + $(if ([string]::IsNullOrWhiteSpace($global:FromEmail))   { "(not set)" } else { $global:FromEmail }))
    Write-Host ("    To Address    : " + $(if ([string]::IsNullOrWhiteSpace($global:ADAdminEmail)) { "(not set)" } else { $global:ADAdminEmail }))
    Write-Host ""

    [bool]$AllPassed = $true

    # -------------------------------------------------------------------------
    # Stage 1: Settings Validation
    # -------------------------------------------------------------------------
    Write-Host "  --- Stage 1: Settings Validation ---" -ForegroundColor Yellow
    [bool]$SettingsOk = $true

    if ([string]::IsNullOrWhiteSpace($global:SMTPServer)) {
        Write-Host "  [FAIL] SMTPServer is not configured." -ForegroundColor Red
        Write-Host "         Set SMTPServer in AD-PowerAdmin_settings.ps1." -ForegroundColor Yellow
        $SettingsOk = $false
        $AllPassed  = $false
    }
    if ([string]::IsNullOrWhiteSpace($global:FromEmail)) {
        Write-Host "  [FAIL] FromEmail is not configured." -ForegroundColor Red
        Write-Host "         Set FromEmail in AD-PowerAdmin_settings.ps1." -ForegroundColor Yellow
        $SettingsOk = $false
        $AllPassed  = $false
    }
    if ([string]::IsNullOrWhiteSpace($global:ADAdminEmail)) {
        Write-Host "  [FAIL] ADAdminEmail is not configured." -ForegroundColor Red
        Write-Host "         Set ADAdminEmail in AD-PowerAdmin_settings.ps1." -ForegroundColor Yellow
        $SettingsOk = $false
        $AllPassed  = $false
    }

    if (-not $SettingsOk) {
        Write-Host ""
        Write-Host "  Cannot continue diagnostics -- fix the missing settings above, then re-run." -ForegroundColor Red
        Write-Host "  Use 'Configure Settings Wizard' from this menu to update the settings file." -ForegroundColor Yellow
        Write-Host ""
        return
    }
    Write-Host "  [PASS] All required settings are present." -ForegroundColor Green
    Write-Host ""

    # Resolve effective port (default 587).
    [int]$EffectivePort = 587
    if (-not [string]::IsNullOrWhiteSpace($global:SMTPPort)) {
        [int]$EffectivePort = [int]$global:SMTPPort
    }

    # -------------------------------------------------------------------------
    # Stage 2: DNS Resolution
    # -------------------------------------------------------------------------
    Write-Host "  --- Stage 2: DNS Resolution ---" -ForegroundColor Yellow

    [System.Net.IPAddress]$ParsedIp = $null
    if ([System.Net.IPAddress]::TryParse($global:SMTPServer, [ref]$ParsedIp)) {
        Write-Host "  [INFO] SMTP server is configured as an IP address: $global:SMTPServer" -ForegroundColor Cyan
        Write-Host "  [INFO] DNS resolution skipped (direct IP, no hostname to resolve)." -ForegroundColor Cyan
    } else {
        Write-Host "  Resolving hostname: $global:SMTPServer" -ForegroundColor White
        try {
            [System.Net.IPHostEntry]$HostEntry = [System.Net.Dns]::GetHostEntry($global:SMTPServer)
            if ($HostEntry.AddressList.Count -gt 0) {
                [string]$PrimaryIp = $HostEntry.AddressList[0].ToString()
                Write-Host "  [PASS] Resolved '$($global:SMTPServer)' -> $PrimaryIp" -ForegroundColor Green
                if ($HostEntry.AddressList.Count -gt 1) {
                    [string]$ExtraIps = ($HostEntry.AddressList[1..($HostEntry.AddressList.Count - 1)] | ForEach-Object { $_.ToString() }) -join ", "
                    Write-Host "  [INFO] Additional addresses: $ExtraIps" -ForegroundColor Cyan
                }
            } else {
                Write-Host "  [FAIL] DNS resolved '$($global:SMTPServer)' but returned no IP addresses." -ForegroundColor Red
                $AllPassed = $false
            }
        } catch {
            Write-Host "  [FAIL] DNS resolution failed for '$($global:SMTPServer)'." -ForegroundColor Red
            Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "         Possible causes:" -ForegroundColor Yellow
            Write-Host "           - Hostname is misspelled in settings." -ForegroundColor Yellow
            Write-Host "           - The DNS server used by this machine cannot reach the SMTP host." -ForegroundColor Yellow
            Write-Host "           - The hostname does not exist in DNS." -ForegroundColor Yellow
            $AllPassed = $false
        }
    }
    Write-Host ""

    # -------------------------------------------------------------------------
    # Stage 3: TCP Port Connectivity
    # -------------------------------------------------------------------------
    Write-Host "  --- Stage 3: TCP Port Connectivity (port $EffectivePort) ---" -ForegroundColor Yellow
    Write-Host "  Connecting to $($global:SMTPServer):$EffectivePort ..." -ForegroundColor White

    try {
        $TcpClient    = New-Object System.Net.Sockets.TcpClient
        $ConnectAsync = $TcpClient.BeginConnect($global:SMTPServer, $EffectivePort, $null, $null)
        [bool]$Connected = $ConnectAsync.AsyncWaitHandle.WaitOne(5000, $false)

        if ($Connected -and $TcpClient.Connected) {
            Write-Host "  [PASS] TCP connection to $($global:SMTPServer):$EffectivePort succeeded." -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] TCP connection to $($global:SMTPServer):$EffectivePort timed out (5 s)." -ForegroundColor Red
            Write-Host "         Possible causes:" -ForegroundColor Yellow
            Write-Host "           - A firewall is blocking port $EffectivePort between this host and the SMTP server." -ForegroundColor Yellow
            Write-Host "           - The SMTP server is not listening on port $EffectivePort." -ForegroundColor Yellow
            Write-Host "           - The SMTP server is offline or unreachable." -ForegroundColor Yellow
            Write-Host "           - SMTPPort in settings is incorrect (currently: $EffectivePort)." -ForegroundColor Yellow
            $AllPassed = $false
        }
        try { $TcpClient.Close() } catch {}
    } catch {
        Write-Host "  [FAIL] TCP connection to $($global:SMTPServer):$EffectivePort failed." -ForegroundColor Red
        Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         Possible causes:" -ForegroundColor Yellow
        Write-Host "           - A firewall or routing issue is preventing the connection." -ForegroundColor Yellow
        Write-Host "           - The SMTP server actively refused the connection (wrong port)." -ForegroundColor Yellow
        Write-Host "           - DNS resolved to an address that is not routable from this host." -ForegroundColor Yellow
        $AllPassed = $false
    }
    Write-Host ""

    # -------------------------------------------------------------------------
    # Stage 4: SMTP Send Test
    # -------------------------------------------------------------------------
    Write-Host "  --- Stage 4: SMTP Send Test ---" -ForegroundColor Yellow
    Write-Host "  Sending test email to $($global:ADAdminEmail) ..." -ForegroundColor White

    [string]$Hostname  = $env:COMPUTERNAME
    [string]$Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    [string]$TestSubject = "ADPowerAdmin: Email Configuration Test"
    [string]$TestBody = @"
This is an automated email configuration test sent by AD-PowerAdmin.

If you received this email, your SMTP configuration is working correctly.

Test details:
  Sent from  : $Hostname
  Timestamp  : $Timestamp
  SMTP Server: $($global:SMTPServer)
  SMTP Port  : $EffectivePort
  SSL Enabled: $($global:SmtpEnableSSL)
  From       : $($global:FromEmail)
  To         : $($global:ADAdminEmail)
"@

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $TestMessage        = New-Object Net.Mail.MailMessage
    $TestMessage.From   = $global:FromEmail
    $TestMessage.To.Add($global:ADAdminEmail)
    $TestMessage.Subject = $TestSubject
    $TestMessage.Body    = $TestBody

    $TestSmtp           = New-Object Net.Mail.SmtpClient($global:SMTPServer, $EffectivePort)
    $TestSmtp.EnableSSL = [bool]$global:SmtpEnableSSL

    if ((-not [string]::IsNullOrWhiteSpace($global:SMTPUsername)) -and (-not [string]::IsNullOrWhiteSpace($global:SMTPPassword))) {
        $TestSmtp.Credentials = New-Object System.Net.NetworkCredential($global:SMTPUsername, $global:SMTPPassword)
    }

    try {
        $TestSmtp.Send($TestMessage)
        Write-Host "  [PASS] Test email sent successfully." -ForegroundColor Green
        Write-Host "  [INFO] Please verify the message arrived at: $($global:ADAdminEmail)" -ForegroundColor Cyan
        Write-Host "  [INFO] Check spam/junk folders if it does not appear in the inbox." -ForegroundColor Cyan
    } catch [System.Net.Mail.SmtpException] {
        [string]$SmtpCode = $_.Exception.StatusCode
        Write-Host "  [FAIL] SMTP protocol error (status: $SmtpCode)." -ForegroundColor Red
        Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         Possible causes:" -ForegroundColor Yellow
        switch ($SmtpCode) {
            "MustIssueStartTlsFirst" {
                Write-Host "           - Server requires STARTTLS. Set SmtpEnableSSL = true in settings." -ForegroundColor Yellow
            }
            "ClientNotPermitted" {
                Write-Host "           - Server rejected the connection. Check IP allowlists on the SMTP relay." -ForegroundColor Yellow
            }
            "MailboxUnavailable" {
                Write-Host "           - The From address was rejected. Verify FromEmail in settings." -ForegroundColor Yellow
            }
            "InsufficientStorage" {
                Write-Host "           - Server-side storage or quota issue. Contact your mail admin." -ForegroundColor Yellow
            }
            default {
                Write-Host "           - Authentication failure: verify SMTPUsername and SMTPPassword." -ForegroundColor Yellow
                Write-Host "           - Relay denied: this host may not be permitted to relay through the SMTP server." -ForegroundColor Yellow
                Write-Host "           - The From address may not be permitted by the SMTP server policy." -ForegroundColor Yellow
            }
        }
        $AllPassed = $false
    } catch [System.Security.Authentication.AuthenticationException] {
        Write-Host "  [FAIL] TLS/SSL handshake failed." -ForegroundColor Red
        Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         Possible causes:" -ForegroundColor Yellow
        Write-Host "           - SmtpEnableSSL is set to true but the server does not support SSL on port $EffectivePort." -ForegroundColor Yellow
        Write-Host "           - SmtpEnableSSL is set to false but the server requires SSL/TLS." -ForegroundColor Yellow
        Write-Host "           - The server's TLS certificate is untrusted or expired." -ForegroundColor Yellow
        Write-Host "           - Try toggling SmtpEnableSSL and/or switching ports (25, 465, 587)." -ForegroundColor Yellow
        $AllPassed = $false
    } catch [System.Net.Sockets.SocketException] {
        Write-Host "  [FAIL] Network error during SMTP send (socket error $($_.Exception.SocketErrorCode))." -ForegroundColor Red
        Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         The TCP test passed but the connection dropped during the SMTP handshake." -ForegroundColor Yellow
        Write-Host "         The server may have closed the connection due to a policy or load issue." -ForegroundColor Yellow
        $AllPassed = $false
    } catch {
        Write-Host "  [FAIL] Unexpected error while sending test email." -ForegroundColor Red
        Write-Host "         Error: $($_.Exception.Message)" -ForegroundColor Red
        $AllPassed = $false
    } finally {
        try { $TestMessage.Dispose() } catch {}
        try { $TestSmtp.Dispose()    } catch {}
    }
    Write-Host ""

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    Write-Host "  --- Diagnostic Summary ---" -ForegroundColor Yellow
    if ($AllPassed) {
        Write-Host "  [PASS] All stages passed. Email configuration appears correct." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] One or more stages failed. Review the details above." -ForegroundColor Red
        Write-Host "         Use 'Configure Settings Wizard' from this menu to update settings." -ForegroundColor Yellow
    }
    Write-Host ""
}