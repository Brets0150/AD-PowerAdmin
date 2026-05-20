<div align="center">
    <div style="display: flex; align-items: flex-start;">
        <img align=top src="https://cybergladius.com/wp-content/uploads/2023/02/ADPowerAdmin_Logo_half.png" />
    </div>
</div>

## AD-PowerAdmin Overview
AD-PowerAdmin is a tool to help Active Directory administrators secure and manage their AD environment. It automates daily security checks -- user and computer lifecycle management, password auditing, misconfiguration detection, and more -- and emails alerts when issues are found. The core philosophy is to encode best practices directly into scripts so that security checks run consistently, every time, without manual intervention. This tool focuses on the common weaknesses and attack vectors adversaries exploit and defends against them.

---

## Mission

I built AD-PowerAdmin from a simple premise: an Active Directory environment should be hardened against the attack techniques that are actually being used, not the ones on a theoretical checklist.

This project began as a personal toolset -- a collection of PowerShell scripts I wrote to automate security enforcement within my own production AD environment. As my understanding of AD attack techniques deepened through hands-on penetration testing, those scripts grew into a framework. Nearly every feature in AD-PowerAdmin traces directly to a technique I encountered during a penetration test. The pattern repeated consistently: learn the technique, understand it well enough to execute it, then build a defensive procedure and automate it so that the same technique could not succeed in my monitored environment. The script became the policy.

This project also predates the era of AI-assisted development. For years -- long before it was possible to simply prompt an AI and vibe code your way through a scripting challenge -- I struggled and fretted over getting this framework right. The correct way to structure PowerShell modules, build consistent function patterns, enforce a methodology, and design procedural workflows that would hold up as the project grew were not problems I could hand off. I had to work through them. By the time AI entered the picture, that foundation was already in place. The methodology was defined, the conventions were established, and the architecture had been tested against real operational demands. When AI was brought in to help extend the project, it had something meaningful to read, understand, and follow -- a coherent framework with years of deliberate decisions behind it, rather than a blank slate. That context matters. AI-assisted development built on top of a well-reasoned, hard-won foundation produces meaningfully better results than AI generating a project from scratch, because the difficult architectural decisions were already made by someone who had to live with the consequences.

This project is not a theoretical hardening guide translated into code. It is a record of real attack methods turned into real defenses, built because my job required that the defenses actually work.

**Password security** was among my earliest and most urgent priorities. Weak and breached passwords remain one of the most actively exploited weaknesses in Active Directory, particularly in environments where multi-factor authentication cannot be enforced across every access method -- legacy protocols, service accounts, and on-premises integrations frequently fall outside MFA coverage. As someone deeply invested in the password cracking community, I had direct experience with how quickly exposed credentials are identified and weaponized after a breach. The Have I Been Pwned integration and DSInternals-based hash auditing exist to give administrators the same visibility into password exposure that attackers already have -- and to automate enforcement before that exposure becomes an incident.

**Auditability and accountability** are equally central to the project. Running a security check once is not enough. AD-PowerAdmin is designed so that audits execute on a schedule, produce structured reports, and maintain a clear record of what was checked, when, and what was found. That record serves both operational and compliance purposes -- it is the evidence you can produce when asked to demonstrate that your environment is being actively monitored and maintained.

This project is for administrators who are not content to assume their environment is secure. It is for those who want to know.

---

## Installation
[See the Wiki for installation instructions.](https://github.com/Brets0150/AD-PowerAdmin/wiki/Install)

---

## Signature Features

> ### Breached and Weak Password Auditing
>
> Cross-references every domain account's NTLM password hash against the Have I Been Pwned breach database and a configurable weak-password dictionary. Users with compromised or weak passwords receive an automated email with a grace period to remediate; accounts that do not comply within the grace period have "User must change password at next logon" enforced automatically. The HIBP database manager is a pure-PowerShell 5.1 downloader with no external runtime dependencies. It supports both full and incremental ETag-based updates so the 70 GB hash dataset can be kept current without re-downloading unchanged ranges.
>
> [Full documentation](https://github.com/Brets0150/AD-PowerAdmin/wiki/AD-UserPasswordAudit)

> ### Honeytoken Decoy Account
>
> Provisions a hardened, realistic-looking Active Directory account that should never authenticate under any legitimate circumstances. Any authentication attempt against it -- whether from a password spray, credential stuffing attack, brute force, or attacker reconnaissance -- triggers a high-confidence intrusion alert with a structured email and recommended response actions. Supports centralized monitoring (one installation queries all domain controllers remotely) and decentralized monitoring (a lightweight copy deployed on each DC queries only its local Security log). GPO-based deny-logon enforcement is created and linked to the domain root automatically -- no manual Group Policy configuration required.
>
> [Full documentation](https://github.com/Brets0150/AD-PowerAdmin/wiki/Honeytoken-Module)

> ### Active Directory ACL Auditing
>
> Audits Active Directory Access Control Lists to identify high-risk Access Control Entries and accounts configured with DCSync delegation rights. Includes a dedicated Exchange AD permission escalation audit that detects dangerous permissions (WriteDACL, GenericAll, WriteOwner) held by Exchange security groups on the domain root, audits Exchange group membership for unexpected principals, correlates findings with DCSync rights, and provides guided interactive removal of dangerous ACEs.
>
> [Full documentation](https://github.com/Brets0150/AD-PowerAdmin/wiki/AD-AccessControlRights)

---

## Features

### Password and Credential Security
Rotates the KRBTGT account password on a configurable schedule as a defense against Golden Ticket attacks, with age checking and forced-rotation options. Generates on-demand and monthly email reports of breached and weak password findings across the domain. The HIBP hash database downloader keeps the local breach dataset up to date using incremental range comparisons, making recurring updates efficient regardless of dataset size.

### Security Auditing
Detects accounts configured with Kerberos preauthentication disabled (AS-REP Roasting), assigns risk severity based on account privilege and state, and enables interactive remediation with daily automated alerting. Identifies accounts with the PasswordNotRequired flag set and flags Machine Account Quota misconfigurations, non-admin computer account creation, and Resource-Based Constrained Delegation exposure. Evaluates domain-wide Active Directory security settings against known best practices and reports misconfigurations. Compares effective audit policy settings on domain controllers and member computers against hardened baselines, reports gaps by severity, flags undersized event logs and missing SACL or NTLM audit settings, and identifies competing Group Policy Objects that may be overriding audit policy enforcement settings.

### Group Policy Management
Creates, backs up, restores, links, and removes Group Policy Objects to support policy-driven security enforcement across the domain. Includes conflict detection to identify existing GPO coverage before deploying new settings and a backup-before-modify safety contract for any change to an existing GPO. Applies recommended Group Policy security baselines including LAN Manager hash storage elimination, SMB signing enforcement, domain password and account lockout policy, NTLM audit enabling on domain controllers, and consolidated NTLM protocol restriction policies. Identifies GPOs with edit rights assigned to non-Tier-0 identities or broad security groups, flags GPO script references pointing to UNC paths outside SYSVOL, and deploys GPOs enforcing recommended audit policy subcategory settings and event log sizing.

### SYSVOL and Infrastructure Security
Inventories all scripts, logon and startup scripts, and configuration files stored in the domain's SYSVOL and NETLOGON shares. Scans those files for embedded credentials, plaintext passwords, API tokens, ExecutionPolicy Bypass patterns, encoded commands, and unauthenticated download calls. Detects legacy Group Policy Preferences XML files containing cpassword values (MS14-025). Audits SYSVOL file and folder ACLs for write or modify rights granted to broad or non-administrative principals. Audits hidden administrative shares (ADMIN$, C$, IPC$) on all domain computers, checks SMB firewall exposure, reviews Windows LAPS coverage, inspects local Administrator group membership for excessive domain principals, and provides confirmation-gated remediation with full rollback capability.

### Account Lifecycle Management
Detects user and computer accounts that have not been active within a configurable number of days and disables or decommissions them manually or automatically. The decommissioning workflow strips all group memberships, rotates the password to a random value, disables the account, and moves it to a designated OU -- in the same order, with the same checks, every time. Audits membership of high-privilege groups including Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, and others, producing a complete view of accounts with or capable of escalating to domain-level rights. Provides interactive Active Directory object search for users, computers, and other AD objects. Assigns a cryptographically random 64-character password to any AD user account -- including disabled accounts -- to lock distribution-list mailboxes, legacy service accounts, and other user objects that must have a password set but are never used for interactive login.

### Event Log Analysis and Monitoring
Searches domain controller Security event logs for account lockout events (4740) and failed logon events (4625), with filtering by account and time range, and displays currently locked-out users with an in-tool unlock option. Emails the administrator a daily lockout summary covering all lockout events from the past 24 hours with a per-account breakdown and a full CSV export. Queries the NTLM Operational log across all domain controllers to identify which systems, users, and service accounts are still authenticating over NTLMv1 or NTLMv2, with grouped summary output and CSV export for remediation planning. A daily NTLM authentication summary report provides continuous visibility as legacy NTLM dependencies are phased out.

### Installation and Configuration
Installs, tests, and removes AD-PowerAdmin as a Windows scheduled task running under a standalone Managed Service Account (sMSA) for unattended daily execution. Includes a helper to install PowerShell 7 if not already present. An interactive settings configuration wizard guides administrators through every configurable variable section by section, with Active Directory OU search, live DN validation, and automatic settings backup before any change is written.

[Full feature documentation in the wiki](https://github.com/Brets0150/AD-PowerAdmin/wiki)
