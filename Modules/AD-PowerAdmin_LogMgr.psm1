#Requires -RunAsAdministrator
#Requires -Version 5

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
    # Append $global:Menu with the menu items to be displayed.
    $global:Menu += @{
        'Show-ADUserLockouts' = @{
            Title    = "Search Account Lockouts"
            Label    = "Search Event Log for Account Lockouts"
            Module   = "AD-PowerAdmin_LogMgr"
            Function = "Show-ADUserLockouts"
            Command  = "Show-ADUserLockouts"
        }
        'Get-CurrentLockedoutUsers' = @{
            Title    = "Get Current Lockedout Users"
            Label    = "Search Active Directory for currently locked out users and select an account to unlock."
            Module   = "AD-PowerAdmin_LogMgr"
            Function = "Get-CurrentLockedoutUsers"
            Command  = "Get-CurrentLockedoutUsers"
        }
        'Show-AdUserFailedLoginEvents' = @{
            Title    = "Search Account Failed Logons"
            Label    = "Search a specific computer, Domain Controller, or the localhost for failed logon events(ID: 4625)."
            Module   = "AD-PowerAdmin_LogMgr"
            Function = "Show-AdUserFailedLoginEvents"
            Command  = "Show-AdUserFailedLoginEvents"
        }
    }
}

Initialize-Module

Function Get-ADUserLockouts {
    <#
    .SYNOPSIS
        Get-ADUserLockouts

    .DESCRIPTION
        Function to search Event logs on a Domain Controller or the localhost for account lockouts events.
        This function will return an array of hash tables with the lockout events data.

    .EXAMPLE
        Example: $Lockouts = Get-ADUserLockouts

    .INPUTS
        Get-ADUserLockouts does not take pipeline input.

    .OUTPUTS
        Output a PSCustomObject with all the lockout events records for the requested time frame.

    .NOTES

    #>
    [CmdletBinding()]
    param ([Parameter(Mandatory=$false,Position=1)][switch]$ShowOutput)

    [PSCustomObject]$LockoutEvents = @()

    # Get the computer name to search for lockout events.
    $ComputerName = Get-ComputerForLogSearch

    $LockoutEvents = Search-WindowsEventLogs -LogName 'Security' -ID 4740 -ComputerName ($ComputerName)

    # Check if $LockoutEvents is null. If it is, return null.
    if (-not $LockoutEvents){
        # Tell the user that no lockout events were found.
        Write-Host "No lockout events found on $ComputerName." -ForegroundColor Yellow
        return $null
    }
    # If the SHowOutput switch is provided, output the lockout events to the console.
    if ($ShowOutput){
        $LockoutEvents | Format-Table -Property TargetUsername,SubjectDomainName,TimeCreated,TargetDomainName,MachineName -AutoSize
    }
    return $LockoutEvents
# End of the Search-EventLogForAccountLockouts function.
}

Function Get-LogonTypeDiscription {
    <#
    .SYNOPSIS
        Get-LogonTypeDiscription
    .DESCRIPTION
        Get-LogonTypeDiscription is a function that outputs the logon type descriptions to the console.
    .EXAMPLE
        Get-LogonTypeDiscription
    .NOTES
    #>
    $Message  = '------------------------------------------------------------------------------------------------------------------------------' + "`n"
    $Message += '------------------------------------------------------------Logon-Types-------------------------------------------------------' + "`n"
    $Message += 'ID#--Name----------------------Discription------------------------------------------------------------------------------------' + "`n"
    $Message += '2   Interactive         - A user logged on to this computer.' + "`n"
    $Message += '3   Network             - A user or computer logged on to this computer from the network.' + "`n"
    $Message += '4   Batch               - Batch logon type is used by batch servers, where processes may be executing on behalf of a user without' + "`n"
    $Message += '                          their direct intervention.' + "`n"
    $Message += '5   Service             - A service was started by the Service Control Manager.' + "`n"
    $Message += '7   Unlock              - This workstation was unlocked.' + "`n"
    $Message += '8   NetworkCleartext    - A user logged on to this computer from the network. The users password was passed to the authentication' + "`n"
    $Message += '                          package in its unhashed form. The built-in authentication packages all hash credentials before sending' + "`n"
    $Message += '                          them across the network. The credentials do not traverse the network in plaintext (also called cleartext).' + "`n"
    $Message += '9   NewCredentials     -  A caller cloned its current token and specified new credentials for outbound connections. The new logon' + "`n"
    $Message += '                          session has the same local identity, but uses different credentials for other network connections.' + "`n"
    $Message += '10  RemoteInteractive  -  A user logged on to this computer remotely using Terminal Services or Remote Desktop.' + "`n"
    $Message += '11  CachedInteractive  -  A user logged on to this computer with network credentials that were stored locally on the computer.' + "`n"
    $Message += '                          The domain controller was not contacted to verify the credentials.' + "`n"
    $Message += '-------------------------------------------------------------------------------------------------------------------------------' + "`n"
    Write-Host $Message -ForegroundColor White
}

Function Get-LockOutEventExplaination {
    <#
    .SYNOPSIS
        Get-LockOutEventExplaination

    .DESCRIPTION
        Get-LockOutEventExplaination is a function that outputs the lockout event explaination to the console.

    .EXAMPLE
        Get-LockOutEventExplaination

    .NOTES
    #>
    $Message  = '------------------------------------------------------------------------------------------------------------------------------' + "`n"
    $Message += '------------------------------------------------------------Lockout-Events----------------------------------------------------' + "`n"
    $Message += 'ID#--Name----------------------Discription------------------------------------------------------------------------------------' + "`n"
    $Message += '4740  Account Lockout      - A user account was locked out.' + "`n"
    $Message += '4771  Kerberos pre-auth    - A Kerberos authentication ticket (TGT) was requested.' + "`n"
    $Message += '4776  Account Unlocked     - The domain controller attempted to validate the credentials for an account.' + "`n"
    $Message += '-------------------------------------------------------------------------------------------------------------------------------' + "`n"
    $Message += '                                     +------------------------------+'
    $Message += '                                     |   Lockout Event ID: 4740     |'
    $Message += '                                     |------------------------------|'
    $Message += '                                     | A user account was locked out|'
    $Message += '                                     |                              |'
    $Message += '                                     | Subject:                     |'
    $Message += '                                     |   Security ID: SYSTEM        |'
    $Message += '                                     |   Account Name: AdServer01$  |'
    $Message += '                                     |   Account Domain: ACME       |'
    $Message += '                                     |   Logon ID: 0x3e7            |'
    $Message += '                                     |                              |'
    $Message += '                                     | Account That Was Locked Out: |'
    $Message += '                                     |   Security ID: ACME\bret     |'
    $Message += '                                     |   Account Name: bret         |'
    $Message += '                                     |                              |'
    $Message += '                                     | Additional Information:      |'
    $Message += '                                     |   Caller Computer Name: PC01 |'
    $Message += '                                     +------------------------------+'
    $Message += '                                                     ^'
    $Message += '                                                     |'
    $Message += '                                                     |'
    $Message += '                                             +---------------+'
    $Message += '+-----------------------+                    |               |'
    $Message += '| Name: PC01            |                    |               |'
    $Message += '| Role: Calling Computer|                    |               |'
    $Message += '| Logged: Nothing       |                    |               |'
    $Message += '+-----------------------+                    |               |'
    $Message += '             |                                \             /'
    $Message += '             |                                 \           /'
    $Message += '             |                                  \         /'
    $Message += '         RDP | Connection                        \       /'
    $Message += '             |                                    \     /'
    $Message += '             |                                     \   /'
    $Message += '             |                                      \ /'
    $Message += '             v                                       v'
    $Message += '+-------------------------+              Authentication Request        +------------------------+'
    $Message += '| Name: Server01         | ------------------------------------------> | Name: AdServer01       |'
    $Message += '| Role: Logon Target     |                                             | Role: Active Directory |'
    $Message += '| Logged: Failed Logon   |                                             | Logged: Lockout Event  |'
    $Message += '| EventID: 4725          |                                             |         ID: 4740       |'
    $Message += '+------------------------+                                             +------------------------+'
    $Message += '-------------------------------------------------------------------------------------------------------------------------------' + "`n"
    Write-Host $Message -ForegroundColor White
}
Function Get-CurrentLockedoutUsers {
    <#
    .SYNOPSIS
        Get-CurrentLockedoutUsers

    .DESCRIPTION
        Get-CurrentLockedoutUsers is a function that searches for CURRENTLY(at time of running) locked out user accounts in Active Directory and asks if the user wants to unlock an account.
        This function has no input or output. It will output the locked out accounts to the console and ask the user to select an account to unlock.

    .EXAMPLE
        Get-CurrentLockedoutUsers

    .NOTES
    #>

    #Try catch block to catch any errors that may occur.
    try {
        # Get the currently locked out users accounts.
        $CurrentlyLockedAdAccount = Search-ADAccount -LockedOut
        # Check if $CurrentlyLockedAdAccount is null. If it is, return null.
        if (-not $CurrentlyLockedAdAccount){
            # Tell the user that no lockout events were found.
            Write-Host "No accounts are currently locked out." -ForegroundColor Yellow
            return $null
        }

        # Build a case select menu for the user to select an account to unlock.
        $Menu = @{}
        $i = 1
        $CurrentlyLockedAdAccount | ForEach-Object {
            $Menu.Add($i, $_.DistinguishedName)
            $i++
        }

        # Build a selection menu for the user to select an account to unlock.
        $Selection = Show-Menu -MenuName "Select an account you want to unlock" -MenuItems $Menu
        Write-Host "Unlocking account: $($Selection)" -ForegroundColor Green

        # Unlock the selected account.
        Unlock-ADAccount -Identity $($Selection)
        return
    }
    catch {
        Write-Host "Failed to load the Active Directory module." -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        return
    }
}

Function Get-ComputerForLogSearch {
    # Ask the user in a "do" loop if they want to search for locakout events in the localhost or the primary domain controller.
    do{
        $Prompt = "Do you want to search for failed log event on, a (R)emote system, on (L)ocalhost, or the primary (D)omain controller? (r/l/D)"
        $Confirm = $null
        $Confirm = Read-Host -Prompt $Prompt
        if ($Confirm -eq "L" -or $Confirm -eq "l"){
            $ComputerName = $env:COMPUTERNAME
        }
        if ($Confirm -eq "D" -or $Confirm -eq "d" -or $null -eq $Confirm -or $Confirm -eq ''){
            $ComputerName = (Get-ADDomain).PDCEmulator
            $Confirm = "D"
        }
        # If the user enters the 'r' or 'R' then prompt the user for the remote system name and search for that system name in Active Directory.
        if ($Confirm -eq "R" -or $Confirm -eq "r"){
            $ComputerName = (Search-SingleAdObject -Computer).Name
            # If the $AdComputer is null, then the computer name was not found in Active Directory and return to the top of the loop.
            if (-not $ComputerName){
                Write-Host "The computer name was not found in Active Directory, please try again." -ForegroundColor Red
                $ComputerName = $null
                $Confirm = $null
                continue
            }
        }
    } until ($Confirm -eq "L" -or $Confirm -eq "l" -or $Confirm -eq "D" -or $Confirm -eq "d" -or $Confirm -eq "R" -or $Confirm -eq "r")
    return $ComputerName
}

function Add-LogonFailureReason {
    <#
    .SYNOPSIS
        Add-LogonFailureReason

    .DESCRIPTION
        Add-LogonFailureReason takes in a Failed login event hashtable and then adds the FailureReasonText to the hashtable.

    .EXAMPLE
        Add-LogonFailureReason  -EventRecord $EventRecord
        $EventRecord | Add-LogonFailureReason

    .NOTES
        Add-LogonFailureReason is copied from https://www.powershellgallery.com/packages/PoShEvents/0.2.1/Content/Private%5CGet-LogonFailureReason.ps1
        With some modifications to work with the AD-PowerAdmin module.
    #>

    param(
    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][PSCustomObject]$EventRecord
    )
    $Reason = $null
    switch ($EventRecord.FailureReason) {
        "%%2305" { $Reason = 'The specified user account has expired.' }
        "%%2309" { $Reason = "The specified account's password has expired." }
        "%%2310" { $Reason = 'Account currently disabled.' }
        "%%2311" { $Reason = 'Account logon time restriction violation.' }
        "%%2312" { $Reason = 'User not allowed to logon at this computer.' }
        "%%2313" { $Reason = 'Unknown user name or bad password.' }
        "%%2304" { $Reason = 'An Error occurred during Logon.' }
    }
    if ($EventRecord.Id -eq 4625) {
        switch ($EventRecord.Status) {
            "0xC0000234" { $Reason += " Account locked out" }
            "0xC0000193" { $Reason += " Account expired" }
            "0xC0000133" { $Reason += " Clocks out of sync" }
            "0xC0000224" { $Reason += " Password change required" }
            "0xc000015b" { $Reason += " User does not have logon right" }
            "0xc000006d" { $Reason += " Logon failure." }
            "0xc000006e" { $Reason += " Account restriction" }
            "0xc00002ee" { $Reason += " An error occurred during logon" }
            "0xC0000071" { $Reason += " Password expired" }
            "0xC0000072" { $Reason += " Account disabled" }
            "0xC0000413" { $Reason += " Authentication firewall prohibits logon" }
            default { $Reason + $Event.Status }
        }
        if ($EventRecord.Status -ne $EventRecord.SubStatus) {
            switch ($EventRecord.SubStatus) {
                "0xC0000234" { $Reason += " : Account locked out" }
                "0xC0000193" { $Reason += " : Account expired" }
                "0xC0000133" { $Reason += " : Clocks out of sync" }
                "0xC0000224" { $Reason += " : Password change required" }
                "0xc000015b" { $Reason += " : User does not have logon right" }
                "0xc000006d" { $Reason += " : Logon failure" }
                "0xc000006e" { $Reason += " : Account restriction" }
                "0xc00002ee" { $Reason += " : An error occurred during logon" }
                "0xC0000071" { $Reason += " : Password expired" }
                "0xC0000072" { $Reason += " : Account disabled" }
                "0xc000006a" { $Reason += " : Incorrect password" }
                "0xc0000064" { $Reason += " : Account does not exist" }
                "0xC0000413" { $Reason += " : Authentication firewall prohibits logon" }
                default { $Reason += " : " + $EventRecord.SubStatus }
            }
        }
    } elseif ($EventRecord.Id -eq 4771)  {
        switch ($EventRecord.Status) {
            "0x1" { $Reason = "Client's entry in database has expired" }
            "0x2" { $Reason = "Server's entry in database has expired" }
            "0x3" { $Reason = "Requested protocol version # not supported" }
            "0x4" { $Reason = "Client's key encrypted in old master key" }
            "0x5" { $Reason = "Server's key encrypted in old master key" }
            "0x6" { $Reason = "Client not found in Kerberos database" }    #Bad user name, or new computer/user account has not replicated to DC yet
            "0x7" { $Reason = "Server not found in Kerberos database" } # New computer account has not replicated yet or computer is pre-w2k
            "0x8" { $Reason = "Multiple principal entries in database" }
            "0x9" { $Reason = "The client or server has a null key" } # administrator should reset the password on the account
            "0xA" { $Reason = "Ticket not eligible for postdating" }
            "0xB" { $Reason = "Requested start time is later than end time" }
            "0xC" { $Reason = "KDC policy rejects request" } # Workstation restriction
            "0xD" { $Reason = "KDC cannot accommodate requested option" }
            "0xE" { $Reason = "KDC has no support for encryption type" }
            "0xF" { $Reason = "KDC has no support for checksum type" }
            "0x10" { $Reason = "KDC has no support for padata type" }
            "0x11" { $Reason = "KDC has no support for transited type" }
            "0x12" { $Reason = "Clients credentials have been revoked" } # Account disabled, expired, locked out, logon hours.
            "0x13" { $Reason = "Credentials for server have been revoked" }
            "0x14" { $Reason = "TGT has been revoked" }
            "0x15" { $Reason = "Client not yet valid - try again later" }
            "0x16" { $Reason = "Server not yet valid - try again later" }
            "0x17" { $Reason = "Password has expired" } # The user’s password has expired.
            "0x18" { $Reason = "Pre-authentication information was invalid" } # Usually means bad password
            "0x19" { $Reason = "Additional pre-authentication required*" }
            "0x1F" { $Reason = "Integrity check on decrypted field failed" }
            "0x20" { $Reason = "Ticket expired" } #Frequently logged by computer accounts
            "0x21" { $Reason = "Ticket not yet valid" }
            "0x21" { $Reason = "Ticket not yet valid" }
            "0x22" { $Reason = "Request is a replay" }
            "0x23" { $Reason = "The ticket isn't for us" }
            "0x24" { $Reason = "Ticket and authenticator don't match" }
            "0x25" { $Reason = "Clock skew too great" } # Workstation’s clock too far out of sync with the DC’s
            "0x26" { $Reason = "Incorrect net address" } # IP address change?
            "0x27" { $Reason = "Protocol version mismatch" }
            "0x28" { $Reason = "Invalid msg type" }
            "0x29" { $Reason = "Message stream modified" }
            "0x2A" { $Reason = "Message out of order" }
            "0x2C" { $Reason = "Specified version of key is not available" }
            "0x2D" { $Reason = "Service key not available" }
            "0x2E" { $Reason = "Mutual authentication failed" } # may be a memory allocation failure
            "0x2F" { $Reason = "Incorrect message direction" }
            "0x30" { $Reason = "Alternative authentication method required*" }
            "0x31" { $Reason = "Incorrect sequence number in message" }
            "0x32" { $Reason = "Inappropriate type of checksum in message" }
            "0x3C" { $Reason = "Generic error (description in e-text)" }
            "0x3D" { $Reason = "Field is too long for this implementation" }
            default { $Reason = $EventRecord.Status }
        }
    }
    Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'FailureReasonText' -Value $Reason -Force
}

Function Add-LogonTypeDescription {
    <#
    .SYNOPSIS
        Add-LogonTypeDescription

    .DESCRIPTION
        Add-LogonTypeDescription is a function takes in a Failed login event hashtable adn then adds the LogonTypeName and LogonTypeDescription to the hashtable.
        The passed hashtable is returned with the LogonTypeName and LogonTypeDescription added to it.

        Foreach $FailedLoginEventsFiltered record, look up the LogonType and convert it to a text version.
            2 	Interactive 	A user logged on to this computer.
            3 	Network 	A user or computer logged on to this computer from the network.
            4 	Batch 	Batch logon type is used by batch servers, where processes may be executing on behalf of a user without their direct intervention.
            5 	Service 	A service was started by the Service Control Manager.
            7 	Unlock 	This workstation was unlocked.
            8 	NetworkCleartext 	A user logged on to this computer from the network. The user's password was passed to the authentication package in its unhashed form. The built-in authentication packages all hash credentials before sending them across the network. The credentials do not traverse the network in plaintext (also called cleartext).
            9 	NewCredentials 	A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections.
            10 	RemoteInteractive 	A user logged on to this computer remotely using Terminal Services or Remote Desktop.
            11 	CachedInteractive 	A user logged on to this computer with network credentials that were stored locally on the computer. The domain controller was not contacted to verify the credentials.

    .EXAMPLE
        Add-LogonTypeDescription -EventRecord $EventRecord
        $EventRecord | Add-LogonTypeDescription

    .NOTES

    #>

    param(
    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][PSCustomObject]$EventRecord
    )
    switch ($EventRecord.LogonType) {
        2 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'Interactive' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A user logged on to this computer.' -Force
        }
        3 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'Network' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A user or computer logged on to this computer from the network.' -Force
        }
        4 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'Batch' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'Batch logon type is used by batch servers, where processes may be executing on behalf of a user without their direct intervention.' -Force
        }
        5 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'Service' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A service was started by the Service Control Manager.' -Force
        }
        7 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'Unlock' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'This workstation was unlocked.' -Force
        }
        8 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'NetworkCleartext' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A user logged on to this computer from the network. The user''s password was passed to the authentication package in its unhashed form. The built-in authentication packages all hash credentials before sending them across the network. The credentials do not traverse the network in plaintext (also called cleartext).' -Force
        }
        9 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'NewCredentials' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A caller cloned its current token and specified new credentials for outbound connections. The new logon session has the same local identity, but uses different credentials for other network connections.' -Force
        }
        10 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'RemoteInteractive' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A user logged on to this computer remotely using Terminal Services or Remote Desktop.' -Force
        }
        11 {
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeName' -Value 'CachedInteractive' -Force
            Add-Member -InputObject $EventRecord -MemberType NoteProperty -Name 'LogonTypeDescription' -Value 'A user logged on to this computer with network credentials that were stored locally on the computer. The domain controller was not contacted to verify the credentials.' -Force
        }
    }
}

Function Search-WindowsEventLogs {
    <#
    .SYNOPSIS
        Search-WindowsEventLogs

    .DESCRIPTION
        Search-WindowsEventLogs is a function that searches the local or remote Windows Event Logs for a specific Event ID.
        1- Ask the user if they want to search for a specific date range, or the last 24 hours.
        2 - Ask the user if they want to search for a specific END date range, or the current date and time.
        3 - Search the Windows Event Logs for the Event ID and log file during the specified date range.
        4 - If no events are found, return the oldest event in the log and the log size.
            When no events are found, the function will return $null.
            No events being found means the log file is not large to hold the event far enough back in time to our search date.
            This is why I check the max log size so you can reevaluate your logging configuration.
        5 - If events are found, we enrich the hahstable with the event properties.
            The Get-WinEvent cmdlet returns a "Message" and a "Properties" valuse in its hashtable, but both are not easy to work with.
            So we can convert the event to XML format, then convert the XML to a hashtable.
            This allows us to add the values of "Properties" to the event hashtable , making it easier to work with the event details.
        6 - Return an Array of HashTables event details.

    .EXAMPLE
        $Events = Search-WindowsEventLogs -LogName 'Security' -ID 4740 -StartTime (Get-Date).AddDays(-7)

    .NOTES

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True,Position=1)][string]$LogName,
        [Parameter(Mandatory=$True,Position=2)][int]$ID,
        [Parameter(Mandatory=$false,Position=3)][datetime]$StartTime,
        [Parameter(Mandatory=$false,Position=4)][datetime]$EndTime,
        # [Parameter(Mandatory=$false,Position=5)][string]$ComputerName = $env:COMPUTERNAME
        [Parameter(Mandatory=$true,Position=5)][string]$ComputerName
    )


    # Default number of days to search for events. I am using 24-hours as the default because searching for more then 24-hours can take a long time.
    #     However, I put this option here for you to change if you want.
    [int]$DefaultDays = 1

    $LogFilter = @{
        'LogName' = $LogName
        'ID' = $ID
    }

    # Check if $StartTime is provided. If not, ask the user if they want to search for a specific date, or just the last 24 hours.
    if (-not $PSBoundParameters.ContainsKey('StartTime')){
        $Prompt = "Do you want to search a specific START date range? Default is past 24-hours. (y/N)"
        $Confirm = Read-Host -Prompt $Prompt
        if ($Confirm -eq "Y" -or $Confirm -eq "y"){
            Write-Host "Select the search start date in the GUI." -ForegroundColor White
            $LogFilter['StartTime'] = Get-DatePickerGui
        }
        # If the user doesn't want to search for a specific date range, search the last 24 hours.
        if ($Confirm -ne "Y" -or $Confirm -ne "y"){
            $LogFilter['StartTime'] = (Get-Date).AddDays(-$DefaultDays)
        }
    }

    # Check if $EndTime is provided. If not, ask the user if they want to search for a specific date, or just the current date and time.
    if ( -not $PSBoundParameters.ContainsKey('EndTime')){
        $Prompt = "Do you want to search a specific END date range? Default is `"now`". (y/N)"
        $Confirm = Read-Host -Prompt $Prompt
        if ($Confirm -eq "Y" -or $Confirm -eq "y"){
            Write-Host "Select the search end date in the GUI." -ForegroundColor White
            $LogFilter['EndTime'] = Get-DatePickerGui
        }
        # If the user doesn't want to search END date, then set the END date to the current date and time.
        if ($Confirm -ne "Y" -or $Confirm -ne "y"){
            $LogFilter['EndTime'] = (Get-Date)
        }
    }
    if ($PSBoundParameters.ContainsKey('StartTime')){
        $LogFilter['StartTime'] = $StartTime
    }
    if ($PSBoundParameters.ContainsKey('EndTime')){
        $LogFilter['EndTime'] = $EndTime
    }
    Write-Host "Searching for EventID $ID, in the $LogName log, from Start Time: $($LogFilter['StartTime']) to End Time: $($LogFilter['EndTime'])" -ForegroundColor White

    # Try to search the Windows Event Logs.
    try {
        $SearchResults = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $LogFilter -ErrorAction SilentlyContinue

        # Count number of records found, if 0, then get the oldest record in the log and gets timestamp.
        if ($SearchResults.Count -eq 0){
            $OldestRecord = Get-WinEvent -ComputerName $ComputerName -LogName $LogFilter['LogName'] -MaxEvents 1 -Oldest
            # Get the log size from the server.
            $LogDetails = Get-WinEvent -ListLog $LogName -ComputerName $ComputerName
            Write-Host "No Event ID $ID found in the $LogName log between $($LogFilter['StartTime']) and $($LogFilter['EndTime']) on $ComputerName." -ForegroundColor Red
            Write-Host "Oldest Record On System: $($OldestRecord.TimeCreated)" -ForegroundColor Red
            Write-Host "Max Log Size: $($($LogDetails.MaximumSizeInBytes) /1mb)MB" -ForegroundColor Red
            return $null
        }
    }
    catch {
        Write-Host "Failed to search the $LogName log on $ComputerName for Event ID $ID." -ForegroundColor Red
        Write-Host "Error: $_" -ForegroundColor Red
        # Ask the user if they want to try the search again until they enter 'Y' or 'n'.
        do{
            $Confirm = $null
            $Prompt = "Do you want to try the search again? (Y/n)"
            $Confirm = Read-Host -Prompt $Prompt
            if ($Confirm -eq "Y" -or $Confirm -eq "y"){
                Search-WindowsEventLogs -LogName $LogName -ID $ID -StartTime $LogFilter['StartTime'] -EndTime $LogFilter['EndTime'] -ComputerName $ComputerName
            }
            if ($Confirm -eq "N" -or $Confirm -eq "n"){
                return $null
            }
        } until ($Confirm -eq "Y" -or $Confirm -eq "y" -or $Confirm -eq "N" -or $Confirm -eq "n")
    }

    # Check if the number of results is greater than 0.
    if ($SearchResults.Count -eq 0){
        Write-Host "No Event ID $ID found in the $LogName log between $($LogFilter['StartTime']) and $($LogFilter['EndTime']) on $ComputerName." -ForegroundColor Yellow
        return $null
    }

    # We want to add all the properties of the event to the hashtable so we can easily call details of the event later.
    $EnrichedEventsList = @()
    # For each event found, convert the Event Properties Details to XML format, then convert the XML to a hashtable. Add that hashtable to the original event, then add the whole event to the $EnrichedEventsList array.
    $SearchResults | ForEach-Object {
        $SingleEvent = $_
        # Convert the event to XML format. This will allow us to easily convert the event to a hashtable.
        [xml]$SingleEventXml = $SingleEvent.ToXml()
        $SingleEventXml.Event.EventData.Data | ForEach-Object {
            # Add the hashtable to the EnrichedEventsList array.
            Add-Member -InputObject $SingleEvent -MemberType NoteProperty -Name $_.Name -Value $_.'#text' -Force
        }
        $EnrichedEventsList += $SingleEvent
    }
    return $EnrichedEventsList
}

Function Show-AdUserLockouts {
    <#
    .SYNOPSIS
        The Show-AdUserLockouts function pull the Get-ADUserLockouts and Trace-AdUserLockout functions together to search the Event Logs for locked out user accounts.

    .DESCRIPTION
        Search the primary AD server of the localhost for locked out user account history.
            1. Search for the logout events in the Event Logs.
            2. Display the lockout events to the user.
            3. Prompt the user to select a lockout event to view the details.
            4. Trace the lockout event to the source of the failed login attempts that caused the lockout.
                (Remotely pulls logs from the source system)
            5. Display the failed login attempts to the user.

    .EXAMPLE
        Show-AdUserLockouts

    .Output
        This function outputs to the console lockout events and failed login attempts. It does not return any objects.

    .NOTES

    #>
    [CmdletBinding()]
    param (
        # Pipe in the lockout event.
        [Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$true)][PSCustomObject]$LockoutReports
    )
    # Check if $LockoutReports is null. If it is, run the Get-ADUserLockouts function.
    if (-not $LockoutReports){
        $LockoutReports = Get-ADUserLockouts
    }
    # Output to console the number of lockout events found.
    Write-Host "Number of lockout events found: $($LockoutReports.Count)" -ForegroundColor White

    # Check if $LockoutReports is null. If it is, return null.
    if (-not $LockoutReports){
        return $null
    }

    # Output a message to the user explaining the AuthRequestingSystem and AuthServer.
    Write-Host "AuthRequestingSystem is the system that requested the authentication." -ForegroundColor Green
    Write-Host "AuthServer is the system that authenticated the user; Active Directory Server, or localhost" -ForegroundColor Green

    # Output the list of lockout events to the use in a table format and give each and index number.
    #   Then prompt the user to select a lockout event to view the details.
    $i = 0 # Set the index number to 0.
    $LockoutReports | ForEach-Object {
        $i++
        [PSCustomObject]@{
            Index = $i
            TimeCreated = $_.TimeCreated
            TargetUsername = $_.TargetUsername
            SubjectDomainName = $_.SubjectDomainName
            AuthRequestingSystem = $_.TargetDomainName
            AuthServer = $_.MachineName
        }
    } | Format-Table -AutoSize

    # I know this loop iis a fucking mess, but for some unknow reason the efficient version will not work consistantly. So, whatever, fuck you, it works.
    [int]$TotalLockoutEventCount = $LockoutReports.Count
    # A While loop that propmts the user to select a lockout event index number to view the details, Confirm the user input is a number within the range of the lockout events, or Q to quit.
    do {
        $SelectedLockoutEventIndex = $null
        $Prompt = "Enter the index number of the lockout event you want to investigate, or Q to quit"
        $SelectedLockoutEventIndex = Read-Host -Prompt $Prompt
        if ($SelectedLockoutEventIndex -eq "Q" -or $SelectedLockoutEventIndex -eq "q"){
            return
        }
        # If $SelectedLockoutEventIndex is a number convert it to an integer.
        if ($SelectedLockoutEventIndex -match '^\d+$'){
            $SelectedLockoutEventIndex = [int]$SelectedLockoutEventIndex
        }
        if ($SelectedLockoutEventIndex -lt 1 -or $SelectedLockoutEventIndex -gt $TotalLockoutEventCount){
            Write-Host "Invalid selection, please try again." -ForegroundColor Red
        }
        if ($SelectedLockoutEventIndex -ge 1 -and $SelectedLockoutEventIndex -le $TotalLockoutEventCount){
            break
        }
    } until ($SelectedLockoutEventIndex -ge 1 -and $SelectedLockoutEventIndex -le $TotalLockoutEventCount)

    # Trace the lockout event to the source of the lockout.
    $FailedLoginEvents = $LockoutReports[$SelectedLockoutEventIndex - 1] | Trace-AdUserLockout

    # Check if $FailedLoginEvents is null. If it is, return null.
    if (-not $FailedLoginEvents){
        Write-Host "No failed login attempts search came back empty. The system with the logs may not be reachable." -ForegroundColor Yellow
        return
    }

    # Output the failed login attempts to the user.
    $FailedLoginEvents | Format-List -Property TargetUsername,TargetDomainName,MachineName,TimeCreated,RequestingServerDNS,LogonTypeName,IpAddress,IpPort,ProcessName,FailureReasonText

    # In a until loop, ask the user if they want to view another lockout event, confirm the user input is 'y' or 'n', if 'y' then sent the $LockoutReports back to the top of the loop.
    do {
        $Prompt = "Do you want to view another lockout event, (E)xport this report to a CSV, or the LogonType (D)escription? (e/d/y/n)"
        $Confirm = Read-Host -Prompt $Prompt
        if ($Confirm -eq "Y" -or $Confirm -eq "y"){
            Show-AdUserLockouts -LockoutReports $LockoutReports
        }
        if ($Confirm -eq "N" -or $Confirm -eq "N"){
            return
        }
        if ($Confirm -eq "D" -or $Confirm -eq "d"){
            Get-LogonTypeDiscription
        }
        if ($Confirm -eq "E" -or $Confirm -eq "e"){
            $UserName = $FailedLoginEvents[0].TargetUsername
            Export-AdPowerAdminData -Data $FailedLoginEvents -ReportName "FailedLogonAttempts_$($UserName)" -Force
            Write-Host "Report exported to `"$($global:ReportsPath)`" directory." -ForegroundColor Green
        }
    } until ($Confirm -eq "Y" -or $Confirm -eq "y")
    # End of the Show-AdUserLockout function.
}

Function Get-FailedLoginEvents {
    <#
    .SYNOPSIS
        Get-AdUserFailedLoginEvents

    .DESCRIPTION
        Get-AdUserFailedLoginEvents is a function that searches the Windows Event Logs for failed login attempts.
        The function will search the Security Event Log for Event ID 4625, which is the failed login attempt event.
        The function will return an array of hash tables of the failed login attempts.

    .EXAMPLE
        $FailedLoginEvents = Get-AdUserFailedLoginEvents

    .NOTES

    #>

    $ComputerName = Get-ComputerForLogSearch
    # Search the Windows Event Logs for the failed login attempts.
    $FailedLoginEvents = Search-WindowsEventLogs -LogName 'Security' -ID 4625 -ComputerName $ComputerName

    # Check if $FailedLoginEvents is null. If it is, return null.
    if (-not $FailedLoginEvents){
        Write-Host "No failed login attempts(ID: 4625) found in the $ComputerName Security log." -ForegroundColor Yellow
        return $null
    }
    return $FailedLoginEvents
    # End of the Get-AdUserFailedLoginEvents function.
}

Function Show-AdUserFailedLoginEvents {
    <#
    .SYNOPSIS
        Show-FailedLoginEvents

    .DESCRIPTION
        Show-FailedLoginEvents is a function that takes in a list of failed login events and displays them to the user.
        The function will display the failed login events in a table format to the user.

    .EXAMPLE
        $FailedLoginEvents | Show-FailedLoginEvents

    .NOTES

    #>
    # Search the Windows Event Logs for the failed login attempts.
    $FailedLoginEvents = Get-FailedLoginEvents

    # Check if $FailedLoginEvents is null. If it is, return null.
    if (-not $FailedLoginEvents){
        return $null
    }

    # Output the failed login attempts to the user.
    $FailedLoginEvents | Format-List -Property TargetUsername,TargetDomainName,MachineName,TimeCreated,RequestingServerDNS,LogonTypeName,IpAddress,IpPort,ProcessName,FailureReasonText

    # In a until loop, ask the user if they want, export the log, to view another lockout event, confirm the user input is 'y' or 'n', if 'y' then sent the $LockoutReports back to the top of the loop.
    do {
        $Prompt = "Do you want to view another lockout event, (E)xport this report to a CSV, or the LogonType (D)escription? (e/d/y/n)"
        $Confirm = Read-Host -Prompt $Prompt
        if ($Confirm -eq "Y" -or $Confirm -eq "y"){
            Show-AdUserLockouts -LockoutReports $LockoutReports
        }
        if ($Confirm -eq "N" -or $Confirm -eq "N"){
            return
        }
        if ($Confirm -eq "D" -or $Confirm -eq "d"){
            Get-LogonTypeDiscription
        }
        if ($Confirm -eq "E" -or $Confirm -eq "e"){
            $UserName = $FailedLoginEvents[0].TargetUsername
            Export-AdPowerAdminData -Data $FailedLoginEvents -ReportName "FailedLogonAttempts_$($UserName)" -Force
            Write-Host "Report exported to `"$($global:ReportsPath)`" directory." -ForegroundColor Green
        }
    } until ($Confirm -eq "Y" -or $Confirm -eq "y")
    # End of the Show-AdUserFailedLoginEvents function.
}

Function Trace-AdUserLockout {
    <#
    .SYNOPSIS
        Trace-AdUserLockout

    .DESCRIPTION
        This function can take in multiple lockout events genorated by the Get-ADUserLockouts function.
        The function will search the Security Event Log for the failed login attempts for the user account "lockoutObservationWindow" minutes before the lockout event occured.

            1 - Get the current password locakout policy. We need the lockoutObservationWindow, lockoutThreshold. If there is inconsistency in the AD GPO password policy, then incorrect results may be returned.
                Ensure your passsword policy is consistent across all systems.
            2 - The Lockout event passed in include "TargetDomainName" value. This is the system someone/thing was trying to login to.
                We will then search this system for the failed login attempts events, ID 4625, for the user account that was locked out.
            3 - Each failed login attempt will have the IP address of the system that was trying to login.
                We will then perform a nslookup on the IP address to get the DNSHostName of the system.
                We will then add the DNSHostName to the hashtable.
            4 - We will then update the failed login attempt record with the failed login attempt reason.
                Each failed attempt has a code reason, we will convert that code to a text reason.
            5 - We will then update the failed login attempt record with the logon type description.
                Each failed attempt has a logon type code, we will convert that code to a text description.
            6 - Finally, we will output a hashtable of the failed login attempts.

            All Data we added to the hashtable is added as a NoteProperty. To make it easier to call the data later.

    .EXAMPLE
        $LockOuts = Get-ADUserLockouts
        $FaileLogins = $LockOuts[0] | Trace-AdUserLockout

    .NOTES
        This function is called by the Show-AdUserLockouts function.
    #>

    [CmdletBinding()]
    param (
        # Pipe in the lockout event.
        [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][PSCustomObject]$LockoutReports
    )
    Begin {
        # Get current lockout policy
        $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy
        # Take the $PasswordPolicy.lockoutObservationWindow and convert it to minutes.
        [int]$LockoutObservationWindow = ($PasswordPolicy.lockoutObservationWindow).TotalMinutes
        # Get a list of all Server Names in AD and their DNSHostName and put them into a hashtable.
        # We will need to look up the AuthServer in the AD to get the full dns name. So we will make one call now for all the servers to avoid multiple calls later, and slowing down the script.
        $ServersInAd = @{}
        Get-ADComputer -Filter * -Properties DNSHostName | Foreach-Object {$ServersInAd.Add( $_.Name, $_.DNSHostName)}

        Write-Host "Lockout Observation Window: $LockoutObservationWindow minutes" -ForegroundColor White
        Write-Host "Starting log search on remote system, this may take a few minutes." -ForegroundColor White
    }
    Process{
        foreach ($LockoutEvent in $LockoutReports){
            # Check if the LockoutEvent is null. If it is, return null.
            if (-not $LockoutEvent){
                continue
            }
            # Confirm the event in $LockoutEvent is a 4740 event.
            if ($LockoutEvent.Id -ne 4740){
                Write-Host "The event in the pipeline is not a lockout event." -ForegroundColor Red
                continue
            }

            # Check is $LockoutEvent.TargetDomainName is null. If it is, then set the $LockoutEvent.TargetDomainName to the localhost.
            if (-not $LockoutEvent.TargetDomainName){
                $LockoutEvent.TargetDomainName = $env:COMPUTERNAME
                Write-Host "The TargetDomainName(Authentication Requesting system) is null, setting it to the localhost." -ForegroundColor Yellow
            }
            # Get the $CallingComputer DNSHostName
            $CallingComputer = $ServersInAd[($LockoutEvent.TargetDomainName).Split('$')[0]]
            # Set the start time to the lockoutObservationWindow minutes before the lockout event occured and Round down to the nearest minute.
            $StartTime = $LockoutEvent.TimeCreated.AddMinutes(-$LockoutObservationWindow).AddSeconds(-($LockoutEvent.TimeCreated.Second))
            # Set the end time to the $LockoutEvent.TimeCreated lockout event and Round up to the nearest minute.
            $EndTime = $LockoutEvent.TimeCreated.AddSeconds(-($LockoutEvent.TimeCreated.Second)).AddMinutes(1)

            # Check if $CallingComputer is null. If it is, return null.
            if (-not $CallingComputer){
                Write-Host "The Computer that initiated the lockout event is not in the AD." -ForegroundColor Red
                Write-Host "Calling Computer: $($LockoutEvent.TargetDomainName)" -ForegroundColor Red
                # Ask the user if they want to try and search the PDCEmulator for the failed login attempts, in a do loop until the user enters 'Y' or 'n'.
                do {
                    $Prompt = "Do you want to try and search the PDCEmulator for the failed login attempts? (Y/n)"
                    $Confirm = Read-Host -Prompt $Prompt
                    if ($Confirm -eq "Y" -or $Confirm -eq "y"){
                        $CallingComputer = (Get-ADDomain).PDCEmulator
                        break
                    }
                    if ($Confirm -eq "N" -or $Confirm -eq "n"){
                        continue
                    }
                } until ($Confirm -eq "Y" -or $Confirm -eq "y" -or $Confirm -eq "N" -or $Confirm -eq "n")
            }

            # Get the failed login attempts for the user account "lockoutObservationWindow" minutes before the lockout event occured.
            $FailedLoginEvents = Search-WindowsEventLogs -LogName 'Security' -ID 4625 -StartTime $StartTime -EndTime $EndTime -ComputerName $CallingComputer

            # Check if $FailedLoginEventsRaw is null. If it is, return null.
            if (-not $FailedLoginEvents){
                continue
            }
            # Since the Search-WindowsEventLogs function returns all failed login attempts, we need to filter the results to only the user account that was locked out.
            $FailedLoginEventsFiltered = $FailedLoginEvents | Where-Object { $_.TargetUserName.Split('@')[0] -eq $LockoutEvent.TargetUserName }

            # Foreach $FailedLoginEvents, perform a nslookup on the IpAdress to get the DNSHostName, then add the DNSHostName to the hashtable.
            try {
                $FailedLoginEventsFiltered | ForEach-Object {
                    # Get the DNSHostName of the IP Address.
                    $DnsHostName = [System.Net.Dns]::GetHostEntry($_.IpAddress).HostName
                    # Add the DNSHostName to the hashtable.
                    Add-Member -InputObject $_ -MemberType NoteProperty -Name 'RequestingServerDNS' -Value $DnsHostName -Force
                }
            }
            catch {
                # If there is an error, then add "NotFound" to the hashtable.
                Add-Member -InputObject $_ -MemberType NoteProperty -Name 'RequestingServerDNS' -Value "NotFound" -Force
            }

            # Foreach $FailedLoginEvents record, update the single record with the failed login attempt reason.
            $FailedLoginEventsFiltered | ForEach-Object { $_ | Add-LogonFailureReason }

            # Foreach $FailedLoginEvents record, update the single record with the logon type description.
            $FailedLoginEventsFiltered | ForEach-Object { $_ | Add-LogonTypeDescription }
        }
    }
    End{
        # Output the failed login attempts Array of HashTables.
        return $FailedLoginEventsFiltered
    }
}
