Function Get-DownloadFile {

    <#
    .SYNOPSIS
    Function take a link and download the file to the current directory.

    .DESCRIPTION
    Function take a link and download the file to the current directory.

    .EXAMPLE
    Get-DownloadFile -URL "https://download.sysinternals.com/files/PSTools.zip"

    .INPUTS
    Get-DownloadFile does not take pipeline input, but requires the following parameters: URL

    .OUTPUTS
    Get-DownloadFile will output the following: None

    .NOTES
    This function is used by AD-PowerAdmin_Main.ps1 to download the Sysinternals tools.

    #>

    Param(
        [Parameter(Mandatory=$True,Position=1)][string]$URL,
        [Parameter(Mandatory=$False,Position=2)][string]$OutFileName
    )

    # Enable Tls12
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # If $OutFileName not given, Get the file name from the link
    if ($OutFileName -eq $null) {
        $OutFileName = $env:temp+'\'+$URL.Split('/').Last()
    }

    # Download the file
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $URL -OutFile $OutFileName

        # Confrim the file was downloaded.
        if (Test-Path -Path $OutFileName) {
            Write-Host "File downloaded successfully." -ForegroundColor Green
        }
        else {
            Write-Host "File download failed." -ForegroundColor Red
            exit 1
        }
    }
    catch {
        Write-Host "Error: Could not download the file." -ForegroundColor Red
        exit 1
    }

    # Return the file name
    return $OutFileName

    # End of Get-DownloadFile function
}

Function New-ADPAScheduledTask {
    <#
    .SYNOPSIS
    Function that will create a scheduled task that runs a command at a specified time.

    .DESCRIPTION
    Create a scheduled task that runs a command at a specified time.

    .EXAMPLE
    New-ADPAScheduledTask -ActionString "Taskmgr.exe" -ActionArguments "/q" -ScheduleRunTime "09:00" -Recurring Once -TaskName "Test" -TaskDiscription "Just a Test"

    .INPUTS
    New-ADPAScheduledTask does not take pipeline input, but requires the following parameters: ActionString, ActionArguments, ScheduleRunTime, Recurring, TaskName, TaskDiscription

    .OUTPUTS
    New-ADPAScheduledTask will output the following: None

    .NOTES
    This function is used by AD-PowerAdmin modules to create scheduled tasks.

    #>
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$ActionString,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$ActionArguments,
        [Parameter(Mandatory=$True,Position=3)]
        [string]$ScheduleRunTime,
        [Parameter(Mandatory=$True,Position=4)][ValidateSet("Daliy","Weekly","Monthly","Once","Interval")]
        [string]$Recurring,
        [Parameter(Mandatory=$True,Position=5)]
        [string]$TaskName,
        [Parameter(Mandatory=$True,Position=6)]
        [string]$TaskDiscription,
        [Parameter(Mandatory=$False,Position=7)]
        [int]$RepeatIntervalMinutes = 0
    )

    # Create $trigger based on $Recurring
    if ($Recurring -eq "Daliy") {
        $Trigger = New-ScheduledTaskTrigger -Daily -DaysInterval 1 -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Weekly") {
        $Trigger = New-ScheduledTaskTrigger -WeeksInterval 1 -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Monthly") {
        $Trigger = New-ScheduledTaskTrigger -MonthsInterval 1 -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Once") {
        $Trigger = New-ScheduledTaskTrigger -Once -At $ScheduleRunTime
    }
    elseif ($Recurring -eq "Interval") {
        $Trigger = New-ScheduledTaskTrigger -Once -At $ScheduleRunTime -RepetitionInterval (New-TimeSpan -Minutes $RepeatIntervalMinutes)
    }

    try {
        $Action          = New-ScheduledTaskAction -Execute $ActionString -Argument $ActionArguments -WorkingDirectory "$global:ThisScriptDir"
        $Settings        = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
        $DomainNameShort = (Get-ADDomain -ErrorAction Stop).NetBIOSName
        $UserId          = "$DomainNameShort\$($global:MsaAccountName)`$"
        $MsaAccount      = Get-ADServiceAccount -Filter "Name -eq '$($global:MsaAccountName)'" -ErrorAction SilentlyContinue
        if ($MsaAccount) {
            $Principal = New-ScheduledTaskPrincipal -UserID $UserId -LogonType Password -RunLevel Highest
        } else {
            Write-Host "  [WARN] sMSA account '$($global:MsaAccountName)' not found. Task will run as current user." -ForegroundColor Yellow
            $Principal = New-ScheduledTaskPrincipal -UserId "$env:UserDomain\$env:UserName" -LogonType Interactive -RunLevel Highest
        }

        Register-ScheduledTask -TaskName "$TaskName" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "$TaskDiscription" -ErrorAction Stop | Out-Null

        # Confirm the task was created
        if (Get-ScheduledTask -TaskName "$TaskName" -ErrorAction SilentlyContinue) {
            Write-Host "Task created successfully." -ForegroundColor Green
        }
        else {
            throw "Task was not found after registration."
        }
    }
    catch {
        Write-Host "Unable to create schedule task: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }

    #End of New-ADPAScheduledTask function
}

Function Send-Email {
    <#
    .SYNOPSIS
        Function to send an email.

    .DESCRIPTION
        # A Function that takes in "TO" and "FROM" email addresses and a subject line and sends an email with the contents of the $ReportData variable.

    #>
    # Parameters for this function.
    # All parameters are Mandatory=$false so that missing or empty values produce a clean
    # diagnostic message rather than an unhandled ParameterBindingValidationException.
    Param(
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ToEmail,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$FromEmail,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$CcEmail,
        [Parameter(Mandatory=$false,Position=4)]
        [string]$Subject,
        [Parameter(Mandatory=$false,Position=5)]
        [string]$Body,
        [Parameter(Mandatory=$false,Position=6)]
        [string]$SmtpServer,
        [Parameter(Mandatory=$false,Position=7)]
        [string]$SmtpPort,
        [Parameter(Mandatory=$false,Position=8)]
        [string]$SmtpUser,
        [Parameter(Mandatory=$false,Position=9)]
        [string]$SmtpPass,
        [Parameter(Mandatory=$false,Position=10)]
        [bool]$DebugEmail
    )

    # Validate required fields before attempting anything. Callers may pass empty strings
    # when global settings are unconfigured; a clean message is better than a binding error.
    if ([string]::IsNullOrWhiteSpace($ToEmail)) {
        Write-Host "Send-Email: ToEmail is not set. Configure ADAdminEmail in AD-PowerAdmin_settings.ps1." -ForegroundColor Red
        return
    }
    if ([string]::IsNullOrWhiteSpace($FromEmail)) {
        Write-Host "Send-Email: FromEmail is not set. Configure the from-address setting in AD-PowerAdmin_settings.ps1." -ForegroundColor Red
        return
    }
    if ([string]::IsNullOrWhiteSpace($Subject)) {
        Write-Host "Send-Email: Subject is not set." -ForegroundColor Red
        return
    }
    if ([string]::IsNullOrWhiteSpace($Body)) {
        Write-Host "Send-Email: Body is not set." -ForegroundColor Red
        return
    }

    # Set the email Security Protocol to TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Build the email sending variables.
    $EmailServerParam = @{}

    # Resolve SMTP server: parameter takes precedence over global setting.
    if (-not [string]::IsNullOrWhiteSpace($SmtpServer)) {
        $EmailServerParam.SmtpServer = $SmtpServer
    } elseif (-not [string]::IsNullOrWhiteSpace($global:SMTPServer)) {
        $EmailServerParam.SmtpServer = $global:SMTPServer
    } else {
        Write-Host "Send-Email: SMTPServer is not set. Configure SMTPServer in AD-PowerAdmin_settings.ps1." -ForegroundColor Red
        return
    }

    # Resolve SMTP port: parameter takes precedence over global setting; default to 587.
    if (-not [string]::IsNullOrWhiteSpace($SmtpPort)) {
        $EmailServerParam.Port = $SmtpPort
    } elseif (-not [string]::IsNullOrWhiteSpace($global:SMTPPort)) {
        $EmailServerParam.Port = $global:SMTPPort
    } else {
        $EmailServerParam.Port = "587"
    }
    # Build the email sending variables.
    $Message = New-Object Net.Mail.MailMessage;
    $Message.From = $FromEmail;
    $Message.To.Add($ToEmail);
    $Message.Subject = "$Subject";
    $Message.Body = "$Body";

    if (-not [string]::IsNullOrWhiteSpace($CcEmail)) {
        $Message.CC.Add($CcEmail);
    }

    $Smtp = New-Object Net.Mail.SmtpClient($EmailServerParam.SmtpServer, $EmailServerParam.Port);
    $Smtp.EnableSSL = [bool]$global:SmtpEnableSSL;

    # Resolve credentials: explicit parameters take precedence over global settings.
    if ((-not [string]::IsNullOrWhiteSpace($SmtpUser)) -and (-not [string]::IsNullOrWhiteSpace($SmtpPass))) {
        $Smtp.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPass);
    } elseif ((-not [string]::IsNullOrWhiteSpace($global:SMTPUsername)) -and (-not [string]::IsNullOrWhiteSpace($global:SMTPPassword))) {
        $Smtp.Credentials = New-Object System.Net.NetworkCredential($global:SMTPUsername, $global:SMTPPassword);
    }

    # Try to send the email.
    try {
        $Smtp.send($Message);
    } catch {
        # If the email fails, then output an error and exit the function.
        Write-Host "Error: The email failed to send to $ToEmail " -ForegroundColor Red
        Write-Host "    Please check the 'AD-PowerAdmin_settings.ps1' file and make sure the email settings are correct." -ForegroundColor Red
        # If $global:Debug is true, then output the full error message.
        if (($global:Debug) -or ($DebugEmail)) {
            Write-Host $_.Exception -ForegroundColor Red
        }
        return
    }
    # Close the SMTP connection.
    $Message.Dispose();
    $Smtp.Dispose();
    # Start a sleep timer for 1 second.
    Start-Sleep -Seconds 1
# End of the Send-Email function.
}

function Get-DateFromCalendar {
    <#
    .SYNOPSIS
        Function to get a date from a calendar GUI.

    .DESCRIPTION
        # The GUI calander date select function. This code was taken from the following website: https://www.powershellgallery.com/packages/Calendar/1.0.0
        # The code was modified to work with the AD-PowerAdmin script.
    #>

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object Windows.Forms.Form -Property @{
        StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
        Size          = New-Object Drawing.Size 243, 230
        Text          = 'Select a Date'
        Topmost       = $true
    }

    $calendar = New-Object Windows.Forms.MonthCalendar -Property @{
        ShowTodayCircle   = $false
        MaxSelectionCount = 1
    }
    $form.Controls.Add($calendar)

    $okButton = New-Object Windows.Forms.Button -Property @{
        Location     = New-Object Drawing.Point 38, 165
        Size         = New-Object Drawing.Size 75, 23
        Text         = 'OK'
        DialogResult = [Windows.Forms.DialogResult]::OK
    }
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object Windows.Forms.Button -Property @{
        Location     = New-Object Drawing.Point 113, 165
        Size         = New-Object Drawing.Size 75, 23
        Text         = 'Cancel'
        DialogResult = [Windows.Forms.DialogResult]::Cancel
    }
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $result = $form.ShowDialog()

    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        $date = $calendar.SelectionStart
        return $date
    }
    # End of the Get-DateFromCalendar function.
}

Function Export-AdPowerAdminData {
    <#
    .SYNOPSIS
        Function that will export data to a CSV file.

    .DESCRIPTION
        Export data to a CSV file.

    .EXAMPLE
        Export-AdPowerAdminData -Data $ReportData -ReportName "ADPowerAdmin"

    .PARAMETER Data
        The data to be exported to a file. This is a required parameter.
        You can use the pipeline to send data to this function, or you can use the -Data parameter.

    .PARAMETER ReportName
        The name of the report will be part of the filename that is created with the exported data. This is a required parameter.
        Example: "ADPowerAdmin"
        Result: "ADPowerAdmin_2020-01-01_00-00-00.csv"

    .PARAMETER Force
        If the $Force switch is used, then the function will not ask the user if they want to export the results to a CSV file, it will just export the results to a CSV file.

    .NOTES
        This function is used by AD-PowerAdmin_Main.ps1 to export data to a CSV file.

    #>
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,Position=1)]
        [object]$Data,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$ReportName,
        [Parameter(Mandatory=$False,Position=3)]
        [switch]$Force
    )

    # Get the current datetime and put it in a variable.
    [string]$CurrentDateTime = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")

    # Making this a variable now, so if I want to expand this funtion in the future, I can add more file types.
    $FileExtension = "CSV"
    # Set the file name.
    $FileName = "$($global:ReportsPath)\\$($ReportName)_$($CurrentDateTime).$FileExtension"

    # Check if the reports directory exists. If it does not exist, then create the directory.
    if (-not (Test-Path -Path $global:ReportsPath)) {
        New-Item -ItemType Directory -Path $global:ReportsPath
    }

    # Export the data to a CSV file.
    try {
        # Confirm the $Data variable is not empty.
        if ($null -eq $Data) {
            Write-Host "Error: Data sent for export is empty." -ForegroundColor Red
            return
        }
        # If the $Force switch is not used, then export the data to a CSV file.
        if (-not $Force) {
            # Ask the user if they want to export the results to a CSV file.
            $ExportQuestion = Read-Host "Would you like to export the results to a $FileExtension file? (Default:N, y/N)"
        }
        # If the user enters "Y" or "y", then export the results to a CSV file.
        if ($ExportQuestion -eq "Y" -or $ExportQuestion -eq "y" -or $Force) {
            # Export the results to a CSV file.
            $Data | Export-Csv -Path "$FileName" -NoTypeInformation -Force
        }
        # If anything else is entered, then do not export the results to a CSV file.
        else {
            return
        }
    }
    catch {
        Write-Host "Error: Unable to export data to `"$FileName`"." -ForegroundColor Red
        Write-Host "       Please check the file path and try again." -ForegroundColor Red
        return
    }

    # Confirm the file was created.
    if (Test-Path -Path $FileName) {
        # Display a message to the user that the results were exported to a CSV file.
        Write-Host "The results were exported to a CSV file located in the same directory as this script." -ForegroundColor Green
    }
    else {
        Write-Host "Error: Unable to export data to `"$FileName`"." -ForegroundColor Red
        Write-Host "    Please check the file path and try again." -ForegroundColor Red
        return
    }
# End of Export-Data function
}

Function Convert-TimeDurationString {
    <#
    .SYNOPSIS
    Function that will convert a time string("01:10:00") to minutes.

    #>
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$TimeString
    )

    # Split the time string into hours, minutes, and seconds
    $Parts = $TimeString -split ":"
    # Extract hours, minutes, and seconds from the parts
    $Hours   = [int]$Parts[0]
    $Minutes = [int]$Parts[1]
    $Seconds = [int]$Parts[2]
    # Calculate the total minutes
    [int]$TotalMinutes = ($Hours * 60) + $Minutes + [math]::Floor($Seconds / 60)

    # Return the time duration in a human readable format.
    return $TotalMinutes
}

function Search-SingleAdObject {
    <#
    .SYNOPSIS
        Function to search for an AD Object and return a single result object. Used to provide other function a search method to find a single object.

    .DESCRIPTION
        Function to search for an AD Object and return a single result object. Used to provide other function a search method to find a single object.

    .PARAMETER AllObjects
        If the $AllObjects switch is used, then search for all objects types.

    .PARAMETER Computer
        If the $Computer switch is used, then search for a computer object.

    .PARAMETER User
        If the $User switch is used, then search for a user object.

    .EXAMPLE
        Unregister-AdUser -AdUserToDisable $(Search-SingleAdObject)
        $AdUser = Search-SingleAdObject -User
        $AdComputer = Search-SingleAdObject -Computer
        $AdObject = Search-SingleAdObject -AllObjects

    #>
    Param(
        [Parameter(Mandatory=$False,Position=1)][switch]$AllObjects,
        [Parameter(Mandatory=$False,Position=2)][switch]$Computer,
        [Parameter(Mandatory=$False,Position=3)][switch]$User
    )

    # Case 1: If the $AllObjects switch is used, then search for all objects. Case 2: If the $Computer switch is used, then search for a computer. Case 3: If the $User switch is used, then search for a user.
    switch ($true) {
        { $AllObjects } { $SearchType = 'A' }
        { $Computer } { $SearchType = 'C' }
        { $User } { $SearchType = 'U' }
        Default { $SearchType = '' }
    }

    # Check if the $SearchType is not equal to 'C', 'U', or 'A', or is empty. The check should not be case insensitive.
    if ($SearchType -ne 'C' -and $SearchType -ne 'c' -and $SearchType -ne 'U' -and $SearchType -ne 'u' -and $SearchType -ne 'A' -and $SearchType -ne 'a' -or $SearchType -eq '') {
        # Ask the user if they want to search for a computer, user or all objects.
        [string]$SearchType = Read-Host "Do you want to search for a Computer, User or All objects? (Default:A, c/u/A)"
        # Check if the $SearchType is not equal to 'C', 'U', or 'A', or is empty. The check should be case insensitive.
        if ($SearchType -ne 'C' -and $SearchType -ne 'U' -and $SearchType -ne 'A' -and $SearchType -ne 'c' -and $SearchType -ne 'u' -and $SearchType -ne 'a' -or $SearchType -eq '') {
            Write-Host "Warrning: The SearchType given was empty. Defaulting to all Objects" -ForegroundColor Yellow
            $SearchType = 'A'
        }
    }

    # While $AdObject is empty, ask the user for the object name to search for.
    while ($null -eq $AdObject) {
        # Ask the user for the obect name to search for.
        [string]$AdObject = Read-Host "Enter the name of the User/Computer/Object to search for"
    }

    # If the user wants to search for a computer, then search for the computer.
    if ($SearchType -eq 'C' -or $SearchType -eq 'c') {
        # Search for the given Computer in Active Directory.
        [Object]$SearchResults = Get-AdComputer -Filter "(Name -like '*$AdObject*') -and (Enabled -eq 'True')" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName,samAccountName
    }

    # If the user wants to search for a user, then search for the user.
    if ($SearchType -eq 'U' -or $SearchType -eq 'u') {
        # Search for the given User in Active Directory.
        [Object]$SearchResults = Get-AdUser -Filter "(Name -like '*$AdObject*') -and (Enabled -eq 'True')" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName,samAccountName
    }

    # If the user wants to search for all objects, then search for the object.
    if ($SearchType -eq 'A' -or $SearchType -eq 'a') {
        # Search for the given Object in Active Directory.
        [Object]$SearchResults = Get-AdObject -Filter "(Name -like '*$AdObject*')" -Properties * | Select-Object Name,Enabled,UserPrincipalName,DistinguishedName,samAccountName
    }

    # Check if the $SearchResults variable is empty.
    if ($null -eq $SearchResults) {
        Write-Host "Error: No AD Object with a name like '$AdObject' was found in Active Directory." -ForegroundColor Red
        return
    }

    # If more that one object in $SearchResults was found, list out each with a select number and ask the user to pick one.
    if ($SearchResults.Count -gt 1) {
        $SearchResults | ForEach-Object -Begin { $i = 1 } -Process {
            Write-Host "$i. $($_.Name -f 20) $( " -- samAccountName: $($_.samAccountName)" -f 40) $("DistinguishedName: $($_.DistinguishedName)" -f 40)"
            Write-Host "------------------------------------------------------------"
            $i++
        }
        $Selection = 0
        # If the user selects a number that is not in the list or a non-numeric value, prompt the user to select a valid number.
        while ($Selection -lt 1 -or $Selection -gt $SearchResults.Count -or $Selection -notmatch "^\d+$") {
            $Selection = Read-Host -Prompt "Select number the desired object"
        }
        $SearchResults = $SearchResults[$Selection - 1]
    }

    # If the user wants the results in a object format, then return the results to the user.
    return $SearchResults
# End of the Search-ADUser function.
}

function Enable-OldWindowsTLS12 {
    # TLS 1.2 must be enabled on older versions of Windows.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

Function Get-DatePickerGui {
    <#
    .SYNOPSIS
        A GUI date picker function that returns the selected date.

    .DESCRIPTION
        A GUI date picker function that returns the selected date.

    .EXAMPLE
        $Date = Get-DatePickerGui

    .NOTES
        This core code of this function was taken from https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-a-graphical-date-picker?view=powershell-7.4

    #>
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object Windows.Forms.Form -Property @{
        StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
        Size          = New-Object Drawing.Size 243, 230
        Text          = 'Select a Date'
        Topmost       = $true
    }

    $calendar = New-Object Windows.Forms.MonthCalendar -Property @{
        ShowTodayCircle   = $false
        MaxSelectionCount = 1
    }
    $form.Controls.Add($calendar)

    $okButton = New-Object Windows.Forms.Button -Property @{
        Location     = New-Object Drawing.Point 38, 165
        Size         = New-Object Drawing.Size 75, 23
        Text         = 'OK'
        DialogResult = [Windows.Forms.DialogResult]::OK
    }
    $form.AcceptButton = $okButton
    $form.Controls.Add($okButton)

    $cancelButton = New-Object Windows.Forms.Button -Property @{
        Location     = New-Object Drawing.Point 113, 165
        Size         = New-Object Drawing.Size 75, 23
        Text         = 'Cancel'
        DialogResult = [Windows.Forms.DialogResult]::Cancel
    }
    $form.CancelButton = $cancelButton
    $form.Controls.Add($cancelButton)

    $result = $form.ShowDialog()

    if ($result -eq [Windows.Forms.DialogResult]::OK) {
        $date = $calendar.SelectionStart
        return $date
    }
    $form.Dispose()
}

function Show-Menu {
    <#
    .Synopsis
        Show a Menu.
    .DESCRIPTION
        User passes in a menu name, and a dictionary of menu items. The menu item will be displayed to the user.
        The user will be asked to select a menu item. Oncea selection has been made, the function will return the
        selected dictonary item.

    .PARAMETER MenuName
        The name(string) of the menu to be displayed.

    .PARAMETER MenuItems
        A dictionary of menu items to be displayed.

    .EXAMPLE
        $Menu = @{}
        $i = 1
        $CurrentlyLockedAdAccount | ForEach-Object {
            $Menu.Add($i, $_.DistinguishedName)
            $i++
        }
        $Selection = Show-Menu -MenuName "Select an account to unlock" -MenuItems $Menu

    .NOTES
    #>
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$MenuName,
        [Parameter(Mandatory=$True,Position=2)]
        [hashtable]$MenuItems
    )

    # Display the menu name
    Write-Host "Menu: $MenuName" -ForegroundColor Yellow
    # Display the menu items
    $MenuItems.GetEnumerator() | ForEach-Object {
        Write-Host "$($_.Key): $($_.Value)"
    }

    # Ask the user in a loop to select a menu item, until a valid menu item is selected, or the user types "Q" to quit.
    while ($true) {
        # Ask the user to select a menu item.
        [string]$Selection = Read-Host "Select a menu item or type 'Q' to quit."
        # If the user types "Q" or "q", then exit the loop.
        if ($Selection -eq "Q" -or $Selection -eq "q") {
            break
        }
        # If the user selects a menu item that is not in the menu, then ask the user to select a valid menu item.
        if (-not $MenuItems.ContainsKey([int]$Selection)) {
            Write-Host "Error: The menu item selected is not valid." -ForegroundColor Red
            continue
        }
        # If the user selects a valid menu item, then return the selected menu item.
        $Selected = $MenuItems[[int]$Selection]
        return $Selected
    }
}

Function Get-WordWrap {
    <#
    .SYNOPSIS
    Wraps a string of text at word boundaries and returns an array of padded lines.

    .DESCRIPTION
    Splits input text into lines that do not exceed the specified width. Each output
    line is prefixed with the specified indent string. Single words longer than the
    available width are placed alone on their own line rather than truncated.

    .PARAMETER Text
    The text string to wrap.

    .PARAMETER Width
    Maximum total line length including indent. Defaults to 78.

    .PARAMETER Indent
    String prepended to every output line. Defaults to four spaces.

    .EXAMPLE
    Get-WordWrap -Text "This is a long sentence." -Width 40 -Indent "    "
    #>
    Param(
        [string]$Text,
        [int]$Width    = 78,
        [string]$Indent = '    '
    )

    $Lines   = [System.Collections.Generic.List[string]]::new()
    $Words   = ($Text -replace '\s+', ' ').Trim() -split ' '
    $Current = $Indent

    foreach ($Word in $Words) {
        if ($Word.Length -eq 0) { continue }
        if (($Current.Length + $Word.Length) -gt $Width -and $Current.Length -gt $Indent.Length) {
            $Lines.Add($Current.TrimEnd())
            $Current = $Indent + $Word + ' '
        } else {
            $Current += $Word + ' '
        }
    }
    if ($Current.Trim().Length -gt 0) { $Lines.Add($Current.TrimEnd()) }
    return $Lines
}

Function Get-SystemRole {
    <#
    .SYNOPSIS
        Returns the Windows system role of the local computer.

    .DESCRIPTION
        Queries Win32_OperatingSystem.ProductType via CIM and returns one of three
        role strings: 'DomainController', 'MemberServer', or 'Workstation'. On any
        CIM query error the function defaults to 'Workstation'.

    .OUTPUTS
        [string] 'DomainController', 'MemberServer', or 'Workstation'.

    .EXAMPLE
        $Role = Get-SystemRole
        if ($Role -eq 'DomainController') { Write-Host "This is a DC." }
    #>
    try {
        $ProductType = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType
        switch ($ProductType) {
            2 { return 'DomainController' }
            3 { return 'MemberServer' }
            default { return 'Workstation' }
        }
    } catch {
        return 'Workstation'
    }
}

Function Write-WrappedText {
    <#
    .SYNOPSIS
        Writes a labeled text block to the console with word-wrapping.

    .DESCRIPTION
        Writes a console line in the form "Indent + Label + text". When the text
        exceeds the available width it wraps to continuation lines indented to align
        the text under the end of the label. Useful for formatted help pages and
        diagnostic output where labels and body text must stay visually aligned.

    .PARAMETER Label
        Text prepended to the first line. Continuation lines are indented by this
        many spaces to keep the body text aligned under the label.

    .PARAMETER Text
        The text to wrap and write. Leading and trailing whitespace is stripped.

    .PARAMETER Indent
        String prepended to every line before the label. Defaults to nine spaces.

    .PARAMETER ForegroundColor
        Console foreground color for all output. Defaults to 'Gray'.

    .PARAMETER MaxWidth
        Maximum total line width in characters. Defaults to 100.

    .EXAMPLE
        Write-WrappedText -Label 'Expected: ' -Text 'Success and Failure' -ForegroundColor Gray
    .EXAMPLE
        Write-WrappedText -Label 'Note: ' -Text $LongDescription -Indent '    ' -MaxWidth 80
    #>
    Param(
        [string]$Label,
        [string]$Text,
        [string]$Indent          = '         ',
        [string]$ForegroundColor = 'Gray',
        [int]$MaxWidth           = 100
    )
    if ([string]::IsNullOrWhiteSpace($Text)) { return }

    $ContIndent = $Indent + (' ' * $Label.Length)
    $FirstMax   = $MaxWidth - $Indent.Length - $Label.Length
    $ContMax    = $MaxWidth - $ContIndent.Length
    if ($FirstMax -lt 20) { $FirstMax = 20 }
    if ($ContMax  -lt 20) { $ContMax  = 20 }

    $Words   = ($Text.Trim()) -split '\s+'
    $Line    = ''
    $IsFirst = $true

    foreach ($Word in $Words) {
        $Max = if ($IsFirst) { $FirstMax } else { $ContMax }
        if ($Line -eq '') {
            $Line = $Word
        } elseif (($Line.Length + 1 + $Word.Length) -le $Max) {
            $Line = "$Line $Word"
        } else {
            $Prefix = if ($IsFirst) { "$Indent$Label" } else { $ContIndent }
            Write-Host "$Prefix$Line" -ForegroundColor $ForegroundColor
            $IsFirst = $false
            $Line    = $Word
        }
    }
    if ($Line -ne '') {
        $Prefix = if ($IsFirst) { "$Indent$Label" } else { $ContIndent }
        Write-Host "$Prefix$Line" -ForegroundColor $ForegroundColor
    }
}

Function Show-AuditReport {
    <#
    .SYNOPSIS
    Displays a formatted, color-coded security findings report in the terminal and
    optionally writes the same content as plain text to a file.

    .DESCRIPTION
    Renders an array of PSCustomObject findings as structured cards grouped by
    severity (Critical, High, Medium, Info). Each card shows compact key/value
    header fields and optional multi-line wrapped detail fields with their labels.

    Output is built as a parallel list of (text, color) pairs. The terminal receives
    colored output; the file receives the same text without color codes. Both targets
    are written from one pass through the data, so they are always identical in content.

    When RiskField is set to an empty string, grouping is disabled and all items
    are displayed in order without severity badges -- suitable for inventory data.

    .PARAMETER Data
    Array of PSCustomObjects to display. May be empty.

    .PARAMETER Title
    Report title shown in the section header.

    .PARAMETER HeaderFields
    Property names to display as compact 'Label : Value' pairs at the top of
    each card.

    .PARAMETER DetailFields
    Property names to display as wrapped multi-line labeled paragraphs below the
    divider. Intended for long text such as SecurityImpact or ExploitScenario.

    .PARAMETER RiskField
    Property name used for severity grouping and color coding. Set to an empty
    string to disable grouping (all items displayed flat in order).

    .PARAMETER FieldLabels
    Optional hashtable mapping property names to human-readable display labels.
    These merge with and override the built-in label map.

    .PARAMETER OutputFile
    Optional file path. When provided, the plain-text content of the report is
    appended to this file. The caller is responsible for creating or clearing the
    file before the first call; subsequent calls from the same scan run append.

    .EXAMPLE
    Show-AuditReport -Data $Results -Title "SYSVOL Permissions" `
        -HeaderFields @('ObjectPath','ObjectType','Identity','FileSystemRights') `
        -OutputFile "$global:ReportsPath\report.txt"

    .EXAMPLE
    Show-AuditReport -Data $PermFindings -Title "External Path Permissions" `
        -HeaderFields @('ExternalPath','ObjectType','Identity','FileSystemRights','Note') `
        -DetailFields @('SecurityImpact','ExploitScenario','AccessRequired','LeastPrivDev') `
        -OutputFile $ReportFile
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$Data,

        [Parameter(Mandatory=$True)]
        [string]$Title,

        [Parameter(Mandatory=$False)]
        [string[]]$HeaderFields = @(),

        [Parameter(Mandatory=$False)]
        [string[]]$DetailFields = @(),

        [Parameter(Mandatory=$False)]
        [string]$RiskField = 'RiskLevel',

        [Parameter(Mandatory=$False)]
        [hashtable]$FieldLabels = @{},

        [Parameter(Mandatory=$False)]
        [string]$OutputFile = ''
    )

    $Width  = if ($global:OptionsMaxTextLength -gt 0) { [int]$global:OptionsMaxTextLength } else { 82 }
    $Sep    = '=' * $Width
    $SubSep = '-' * $Width

    $ColorMap = @{ 'Critical' = 'Red'; 'High' = 'Yellow'; 'Medium' = 'Cyan'; 'Info' = 'DarkGray' }

    $LabelMap = @{
        'ExternalPath'      = 'Path'
        'ObjectType'        = 'Type'
        'FileName'          = 'File'
        'FullName'          = 'Path'
        'ObjectPath'        = 'Path'
        'FilePath'          = 'Path'
        'FileSystemRights'  = 'Rights'
        'AccessControlType' = 'ACL Type'
        'SecurityImpact'    = 'Impact'
        'ExploitScenario'   = 'Exploit Scenario'
        'AccessRequired'    = 'Access Required'
        'LeastPrivDev'      = 'Least Privilege Deviation'
        'GPOName'           = 'GPO Name'
        'GPOGuid'           = 'GPO GUID'
        'GPOStatus'         = 'GPO Status'
        'MatchedPattern'    = 'Pattern'
        'LineContent'       = 'Line Content'
        'LineNumber'        = 'Line'
        'ReferencedShare'   = 'Referenced Path'
        'LinkedToTier0'     = 'Tier 0 Linked'
        'TrusteeType'       = 'Trustee Type'
        'TrusteeSid'        = 'Trustee SID'
        'ValuePresent'      = 'Value Present'
        'GppFileType'       = 'GPP File'
        'LastWriteTime'     = 'Modified'
        'SizeBytes'         = 'Size (bytes)'
        'ScriptType'          = 'Script Type'
        'IsExternal'          = 'External'
        'Location'            = 'Location'
        'RiskLevel'           = 'Risk'
        'Permission'          = 'Permission'
        'Extension'           = 'Extension'
        'VulnerabilityDetail' = 'Vulnerability'
        'Impact'              = 'Impact'
        'Remediation'         = 'Remediation'
        'IdentitiesAndRights' = 'Identities & Rights'
        'SourceGPOName'       = 'Source GPO'
        'SourceGPOGuid'       = 'Source GPO GUID'
        'GPOSetting'          = 'GPO Setting'
        'CustomRights'        = 'Custom Rights Detail'
    }
    foreach ($K in $FieldLabels.Keys) { $LabelMap[$K] = $FieldLabels[$K] }

    $AllHeaderLabels = $HeaderFields | ForEach-Object { if ($LabelMap.ContainsKey($_)) { $LabelMap[$_] } else { $_ } }
    $MaxLabelLen = ($AllHeaderLabels | Measure-Object -Property Length -Maximum).Maximum
    if (-not $MaxLabelLen -or $MaxLabelLen -lt 6) { $MaxLabelLen = 6  }
    if ($MaxLabelLen -gt 22)                      { $MaxLabelLen = 22 }

    $DataArray = @($Data | Where-Object { $_ -ne $null })
    $Total     = $DataArray.Count

    $UseRisk   = ($RiskField -ne '')
    $RiskOrder = @('Critical','High','Medium','Info')
    $Groups    = [ordered]@{}

    if ($UseRisk) {
        foreach ($Item in $DataArray) {
            $Risk = 'Unknown'
            if ($Item.PSObject.Properties[$RiskField]) {
                $R = [string]$Item.$RiskField
                if (-not [string]::IsNullOrWhiteSpace($R)) { $Risk = $R }
            }
            if (-not $Groups.Contains($Risk)) { $Groups[$Risk] = [System.Collections.Generic.List[object]]::new() }
            $Groups[$Risk].Add($Item)
        }
        $SortedRisks = @($RiskOrder | Where-Object { $Groups.Contains($_) }) +
                       @($Groups.Keys | Where-Object { $_ -notin $RiskOrder } | Sort-Object)
    } else {
        $Groups['__all'] = [System.Collections.Generic.List[object]]::new()
        foreach ($Item in $DataArray) { $Groups['__all'].Add($Item) }
        $SortedRisks = @('__all')
    }

    # Build parallel text/color lists -- terminal gets colors, file gets plain text.
    $PT = [System.Collections.Generic.List[string]]::new()   # text
    $PC = [System.Collections.Generic.List[string]]::new()   # color ('' = default)

    $PT.Add('');     $PC.Add('')
    $PT.Add($Sep);   $PC.Add('DarkGray')

    if ($Total -eq 0) {
        $PT.Add(" $Title  --  No findings");  $PC.Add('DarkGray')
        $PT.Add($Sep);                         $PC.Add('DarkGray')
        $PT.Add('');                           $PC.Add('')
    } else {
        if ($UseRisk) {
            $SummaryParts = @()
            foreach ($R in $RiskOrder) {
                if ($Groups.Contains($R) -and $Groups[$R].Count -gt 0) { $SummaryParts += "$($Groups[$R].Count) $R" }
            }
            $PT.Add(" $Title  --  $Total finding(s):  $($SummaryParts -join ', ')");  $PC.Add('White')
        } else {
            $PT.Add(" $Title  --  $Total item(s)");  $PC.Add('White')
        }
        $PT.Add($Sep);  $PC.Add('DarkGray')

        $ItemNum = 0
        foreach ($Risk in $SortedRisks) {
            $Color  = if ($ColorMap.ContainsKey($Risk)) { $ColorMap[$Risk] } else { 'White' }
            $IsFlat = ($Risk -eq '__all')

            foreach ($Item in $Groups[$Risk]) {
                $ItemNum++
                $PT.Add('');  $PC.Add('')

                if ($IsFlat) {
                    $PT.Add("  Item $ItemNum of $Total");                          $PC.Add('DarkGray')
                } else {
                    $PT.Add("  [$($Risk.ToUpper())]  Finding $ItemNum of $Total"); $PC.Add($Color)
                }
                $PT.Add($SubSep);  $PC.Add('DarkGray')

                foreach ($Field in $HeaderFields) {
                    if (-not $Item.PSObject.Properties[$Field]) { continue }
                    $Label = if ($LabelMap.ContainsKey($Field)) { $LabelMap[$Field] } else { $Field }
                    $Value = [string]$Item.$Field
                    if ([string]::IsNullOrWhiteSpace($Value)) { continue }
                    $PT.Add(("  {0,-$MaxLabelLen} : {1}" -f $Label, $Value));  $PC.Add('')
                }

                if ($DetailFields.Count -gt 0) {
                    $HasDetail = $false
                    foreach ($Field in $DetailFields) {
                        if ($Item.PSObject.Properties[$Field] -and ([string]$Item.$Field).Trim().Length -gt 0) {
                            $HasDetail = $true; break
                        }
                    }
                    if ($HasDetail) {
                        $PT.Add($SubSep);  $PC.Add('DarkGray')
                        foreach ($Field in $DetailFields) {
                            if (-not $Item.PSObject.Properties[$Field]) { continue }
                            $Label = if ($LabelMap.ContainsKey($Field)) { $LabelMap[$Field] } else { $Field }
                            $Value = ([string]$Item.$Field).Trim()
                            if ([string]::IsNullOrWhiteSpace($Value)) { continue }
                            $PT.Add("  $Label");  $PC.Add($(if ($IsFlat) { 'DarkGray' } else { $Color }))
                            $Wrapped = Get-WordWrap -Text $Value -Width ($Width - 4) -Indent '    '
                            foreach ($Line in $Wrapped) { $PT.Add($Line); $PC.Add('') }
                            $PT.Add('');  $PC.Add('')
                        }
                    }
                }
            }
        }

        $PT.Add($Sep);  $PC.Add('DarkGray')
        $PT.Add('');    $PC.Add('')
    }

    # Flush to terminal with colors
    for ($i = 0; $i -lt $PT.Count; $i++) {
        if ($PC[$i]) { Write-Host $PT[$i] -ForegroundColor $PC[$i] }
        else         { Write-Host $PT[$i] }
    }

    # Flush plain text to file (append; caller creates/clears the file before first call)
    if (-not [string]::IsNullOrWhiteSpace($OutputFile)) {
        [System.IO.File]::AppendAllLines($OutputFile, $PT.ToArray(), [System.Text.Encoding]::ASCII)
    }
}

function Get-AdOuSearch {
    <#
    .SYNOPSIS
    Hierarchical AD OU browser that lets the user drill down the OU tree level by level.

    .DESCRIPTION
    Starts at the domain root and displays the direct child OUs at the current level.
    The user can drill into a child OU by number, step back up with U, select the current
    location with S, or cancel with Q. Returns the DistinguishedName of the selected location,
    or an empty string if the user cancels.

    .EXAMPLE
    [string]$OuDN = Get-AdOuSearch
    #>
    [OutputType([string])]
    param()

    try {
        [string]$DomainDN = (Get-ADDomain -ErrorAction Stop).DistinguishedName
    } catch {
        Write-Host "  ERROR: Could not query Active Directory: $_" -ForegroundColor Red
        return ''
    }

    [string]$CurrentDN = $DomainDN

    while ($true) {
        try {
            $ChildOUs = @(Get-ADOrganizationalUnit -SearchBase $CurrentDN -SearchScope OneLevel -Filter * -Properties Name, DistinguishedName -ErrorAction Stop | Sort-Object Name)
        } catch {
            Write-Host "  ERROR: Could not list OUs under '$CurrentDN': $_" -ForegroundColor Red
            return ''
        }

        [bool]$AtRoot = ($CurrentDN -eq $DomainDN)

        Write-Host ""
        Write-Host ("  Location: {0}" -f $CurrentDN) -ForegroundColor Cyan
        Write-Host ""

        if ($ChildOUs.Count -gt 0) {
            for ($i = 0; $i -lt $ChildOUs.Count; $i++) {
                Write-Host ("  {0,3}. {1}" -f ($i + 1), $ChildOUs[$i].Name)
            }
            Write-Host ""
        } else {
            Write-Host "  (no child OUs)" -ForegroundColor DarkGray
            Write-Host ""
        }

        [string]$DrillHint   = if ($ChildOUs.Count -gt 0) { 'number=drill down  ' } else { '' }
        [string]$SelectLabel = if ($AtRoot) { 'S=select domain root' } else { 'S=select this OU' }
        [string]$UpHint      = if (-not $AtRoot) { '  U=go up' } else { '' }
        Write-Host ("  Options: {0}{1}{2}  Q=cancel" -f $DrillHint, $SelectLabel, $UpHint) -ForegroundColor Cyan

        [string]$Choice = Read-Host "  Select"

        switch ($Choice.ToUpper()) {
            'S' { return $CurrentDN }
            'Q' { return '' }
            'U' {
                if ($AtRoot) {
                    Write-Host "  Already at domain root." -ForegroundColor Yellow
                } else {
                    $CurrentDN = $CurrentDN -replace '^[^,]+,', ''
                }
            }
            default {
                [int]$Selection = 0
                if ([Int32]::TryParse($Choice, [ref]$Selection) -and $Selection -ge 1 -and $Selection -le $ChildOUs.Count) {
                    $CurrentDN = $ChildOUs[$Selection - 1].DistinguishedName
                } else {
                    if ($ChildOUs.Count -gt 0) {
                        Write-Host ("  Invalid option. Enter 1-{0}, S, U, or Q." -f $ChildOUs.Count) -ForegroundColor Yellow
                    } else {
                        Write-Host "  Invalid option. Enter S, U, or Q." -ForegroundColor Yellow
                    }
                }
            }
        }
    }
}

Function Test-PasswordIsComplex {
    <#
    .SYNOPSIS
    Tests whether a string meets Windows default password complexity requirements.

    .DESCRIPTION
    Returns $true when the string contains characters from at least three of the four
    categories (upper, lower, digit, symbol) and is at least eight characters long.
    Matches the Windows built-in complexity policy documented at:
    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements

    .PARAMETER StringToTest
    The password string to evaluate.

    .EXAMPLE
    Test-PasswordIsComplex -StringToTest "Password123!"
    #>
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [String]$StringToTest
    )
    Process {
        $criteriaMet = 0
        If ($StringToTest -cmatch '[A-Z]') {$criteriaMet++}
        If ($StringToTest -cmatch '[a-z]') {$criteriaMet++}
        If ($StringToTest -match '\d') {$criteriaMet++}
        If ($StringToTest -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}
        If ($criteriaMet -lt 3) {Return $false}
        If ($StringToTest.Length -lt 8) {Return $false}
        Return $true
    }
}

Function New-RandomPassword {
    <#
    .SYNOPSIS
    Generates a cryptographically random password that meets Windows complexity requirements.

    .DESCRIPTION
    Uses RNGCryptoServiceProvider with byte-rejection sampling (no modulo bias) to build a
    password from printable ASCII characters (33-126). Retries until Test-PasswordIsComplex
    passes; exits after 20 failed attempts. Returns a plain string by default or a SecureString
    when -AsSecureString is specified.

    .PARAMETER Length
    Number of characters in the generated password. Default is 64.

    .PARAMETER AsSecureString
    When set, the password is returned as a SecureString instead of a plain string.

    .EXAMPLE
    $plain  = New-RandomPassword
    $plain  = New-RandomPassword -Length 32
    $secure = New-RandomPassword -Length 32 -AsSecureString
    #>
    param(
        [Parameter(Mandatory=$false)][int]$Length = 64,
        [switch]$AsSecureString
    )
    Process {
        $Iterations = 0
        Do {
            If ($Iterations -ge 20) { EXIT }
            $Iterations++
            $pwdBytes = @()
            $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
            Do {
                [byte[]]$byte = [byte]1
                $rng.GetBytes($byte)
                If ($byte[0] -lt 33 -or $byte[0] -gt 126) { CONTINUE }
                $pwdBytes += $byte[0]
            } While ($pwdBytes.Count -lt $Length)
            $rng.Dispose()
            $NewPassword = ([char[]]$pwdBytes) -join ''
        } Until (Test-PasswordIsComplex $NewPassword)

        if ($AsSecureString) {
            return ConvertTo-SecureString $NewPassword -AsPlainText -Force
        }
        return $NewPassword
    }
}

Function Set-SettingsFileValue {
    <#
    .SYNOPSIS
    Applies a targeted regex replacement for one variable in the settings file content string.

    .DESCRIPTION
    Takes the full raw content of AD-PowerAdmin_settings.ps1 and replaces the value of the
    named variable. Supports six VarType modes covering every declaration style used in the
    settings file. Returns the modified content string; the caller is responsible for writing
    the file back to disk.

    .PARAMETER Content
    The full raw text of the settings file.

    .PARAMETER VarName
    The bare variable name without '$global:' (e.g. 'ADAdminEmail').

    .PARAMETER NewValue
    The replacement value. For bool types pass 'true' or 'false' (no dollar sign).
    For array-ou-locations pass the pre-built inner block string.

    .PARAMETER VarType
    One of: bool | int | string-single | string-double | string-varref | array-ou-locations
    #>
    param(
        [Parameter(Mandatory=$true)][string]$Content,
        [Parameter(Mandatory=$true)][string]$VarName,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$NewValue,
        [Parameter(Mandatory=$true)]
        [ValidateSet('bool','int','string-single','string-double','string-varref','array-ou-locations')]
        [string]$VarType
    )
    switch ($VarType) {
        'bool' {
            # \s* handles column-aligned declarations like KerberosKRBTGTAudit
            $Content = $Content -replace "(\[bool\]\`$global:$VarName\s*=\s*\`$)(true|false)", ('${1}' + $NewValue)
        }
        'int' {
            # (?i)int handles both [int] and [Int]
            $Content = $Content -replace "(\[(?i)int\]\`$global:$VarName\s*=\s*)\d+", ('${1}' + $NewValue)
        }
        'string-single' {
            $Content = $Content -replace "(\[string\]\`$global:$VarName\s*=\s*')[^']*('|`$)", ('${1}' + $NewValue + '${2}')
        }
        'string-double' {
            $Content = $Content -replace "(\[string\]\`$global:$VarName\s*=\s*`")[^`"]*(`"|\r?`n)", ('${1}' + $NewValue + '${2}')
        }
        'string-varref' {
            # Replaces the entire value (which may be $global:OtherVar) with a literal string
            $Content = $Content -replace "(\[string\]\`$global:$VarName\s*=\s*)[^\r\n]+", ('${1}' + "'" + $NewValue + "'")
        }
        'array-ou-locations' {
            # (?sm) = dotall + multiline so . matches newlines and ^ anchors to line start
            $EscapedName = [regex]::Escape($VarName)
            $Content = $Content -replace "(?sm)(\[array\]\`$global:$EscapedName\s*=\s*@\().*?(^\))", ('${1}' + "`n" + $NewValue + "`n" + '${2}')
        }
    }
    return $Content
}

Function Get-ResolvedDomain {
    <#
    .SYNOPSIS
        Returns an AD domain name for use in GroupPolicy and ActiveDirectory cmdlets.

    .DESCRIPTION
        Returns the caller-supplied domain string if provided and non-empty; otherwise falls
        back to the current user's DNS domain ($env:USERDNSDOMAIN). Used by modules that
        accept an optional -Domain parameter so they do not need to duplicate this fallback.

    .PARAMETER Domain
        Optional. The domain FQDN to use. If empty or omitted, the current user's DNS domain
        is returned.

    .OUTPUTS
        [string] The resolved domain name.
    #>
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain = ''
    )
    if (-not [string]::IsNullOrWhiteSpace($Domain)) {
        return $Domain
    }
    return $env:USERDNSDOMAIN
}

Function Get-ConfirmYesNo {
    <#
    .SYNOPSIS
        Prompts the user with a Yes/No question and returns the answer as a boolean.

    .DESCRIPTION
        Displays a Yes/No prompt with an explicit default. Pressing Enter accepts the default.
        Any input other than y/yes/n/no is rejected and the prompt is repeated.

        When the session is not interactive (for example, a scheduled task running under the sMSA
        account), no prompt is displayed and the default answer is returned immediately. Callers
        must therefore only use this function for choices where the default is safe to apply
        without a human present.

    .PARAMETER Question
        The question text to display. The "(Default:Y, Y/n)" hint is appended automatically.

    .PARAMETER DefaultYes
        $true (default) makes Yes the default answer; $false makes No the default answer.

    .EXAMPLE
        if (Get-ConfirmYesNo -Question "Search all of Active Directory instead?") { ... }

    .EXAMPLE
        if (Get-ConfirmYesNo -Question "Delete the report file?" -DefaultYes $false) { ... }

    .OUTPUTS
        [bool] $true for Yes, $false for No.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Question,
        [Parameter(Mandatory=$false,Position=2)]
        [bool]$DefaultYes = $true
    )

    # Non-interactive sessions cannot answer a prompt. Return the default so unattended runs
    # never block waiting on input that will never arrive.
    if (-not [Environment]::UserInteractive) {
        return $DefaultYes
    }

    [string]$Hint = if ($DefaultYes) { '(Default:Y, Y/n)' } else { '(Default:N, y/N)' }

    while ($true) {
        [string]$Answer = Read-Host "$Question $Hint"
        $Answer = $Answer.Trim()

        if ($Answer -eq '') { return $DefaultYes }

        switch -Regex ($Answer) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host "  Invalid response. Enter 'y' or 'n', or press Enter for the default." -ForegroundColor Yellow }
        }
    }
# End of Get-ConfirmYesNo function
}

Function Test-AdContainerPath {
    <#
    .SYNOPSIS
        Tests whether a DistinguishedName exists in AD and can hold user/computer objects.

    .DESCRIPTION
        Returns $true only when the given DistinguishedName resolves to an object that can act as
        a search base or a move target: an organizationalUnit, a container (such as CN=Computers),
        the domain root (domainDNS), or the Builtin container.

        This is used instead of a bare Get-ADOrganizationalUnit lookup because a valid, correctly
        configured search base is not always an OU. The domain root ('DC=EXAMPLE,DC=COM') and the
        default 'CN=Computers' container are both legitimate values, and an OU-only check reports
        them as non-existent.

        An empty or whitespace-only path returns $false, which is how an unconfigured setting is
        distinguished from a configured but incorrect one by the caller.

    .PARAMETER DistinguishedName
        The DistinguishedName to test. May be empty.

    .EXAMPLE
        if (Test-AdContainerPath -DistinguishedName 'OU=Desktops,DC=EXAMPLE,DC=COM') { ... }

    .OUTPUTS
        [bool] $true if the path exists and is a container-type object; otherwise $false.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $false }

    try {
        $AdObject = Get-ADObject -Identity $DistinguishedName -Properties objectClass -ErrorAction Stop
    } catch {
        return $false
    }

    if ($null -eq $AdObject) { return $false }

    return ($AdObject.objectClass -in @('organizationalUnit', 'container', 'domainDNS', 'builtinDomain'))
# End of Test-AdContainerPath function
}

Function Get-AdObjectGroupMembership {
    <#
    .SYNOPSIS
        Gets the direct group memberships of an AD principal, tolerating objects that
        Get-ADPrincipalGroupMembership cannot process.

    .DESCRIPTION
        Get-ADPrincipalGroupMembership asks the DC to resolve every membership SID for a principal.
        When any one of those SIDs cannot be resolved, the whole call throws:

            "The server was unable to process the request due to an internal error."

        and the caller receives nothing for that account. Common triggers are a membership that
        references a Foreign Security Principal, an orphaned SID left behind by a deleted or
        external domain, a group reached through a broken or unavailable trust, or a primaryGroupID
        that points at an unresolvable group.

        Losing the result entirely is the real problem. In an audit it produces a false negative --
        a disabled account keeps a privileged group membership and is never reported. In a
        decommission path it means group removal is silently skipped while the account is still
        disabled and moved, so the account is "decommissioned" with its access intact.

        This function keeps the native cmdlet as the fast path, then falls back to reading the
        'memberOf' attribute directly when it fails. 'memberOf' is a plain DN-valued attribute, so
        it requires no SID resolution and is unaffected by unresolvable or foreign SIDs.

        'memberOf' does not include the account's primary group, so the fallback reconstructs it
        from primaryGroupID and the account's own domain SID. That also closes a real blind spot:
        an account's primary group can be set to a privileged group to hide the membership from
        'memberOf', and the reconstruction surfaces it.

        Groups that cannot be resolved individually are skipped rather than discarding the whole
        set, so a single bad membership never costs the caller the remaining good ones.

    .PARAMETER Identity
        The DistinguishedName of the user, computer, or group whose memberships are returned.

    .EXAMPLE
        $Groups = Get-AdObjectGroupMembership -Identity $AdUser.DistinguishedName

    .OUTPUTS
        [array] ADGroup objects with Name and DistinguishedName. Empty array if none resolve.
    #>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Identity
    )

    # Fast path. Returns full ADGroup objects and already includes the primary group.
    try {
        return @(Get-ADPrincipalGroupMembership -Identity $Identity -ErrorAction Stop)
    } catch {
        Write-Verbose "Get-ADPrincipalGroupMembership failed for '$Identity'; falling back to memberOf. Reason: $_"
    }

    try {
        $AdObject = Get-ADObject -Identity $Identity -Properties memberOf, primaryGroupID, objectSid -ErrorAction Stop
    } catch {
        Write-Host "[WARN] Could not read group memberships for '$Identity': $_" -ForegroundColor Yellow
        Write-Host "       This account was skipped and may still hold group memberships." -ForegroundColor Yellow
        return @()
    }

    [System.Collections.Generic.List[object]]$ResolvedGroups = New-Object System.Collections.Generic.List[object]

    # Resolve each direct membership DN. Skip individual failures instead of losing the whole set.
    foreach ($GroupDn in @($AdObject.memberOf)) {
        try {
            $ResolvedGroups.Add((Get-ADGroup -Identity $GroupDn -ErrorAction Stop))
        } catch {
            Write-Verbose "Skipping unresolvable group '$GroupDn' for '$Identity': $_"
        }
    }

    # Rebuild the primary group, which never appears in memberOf. The primary group SID is the
    # account's own domain SID with primaryGroupID as the RID.
    if ($null -ne $AdObject.objectSid -and $null -ne $AdObject.primaryGroupID) {
        try {
            $DomainSid = $AdObject.objectSid.AccountDomainSid
            if ($null -ne $DomainSid) {
                $PrimaryGroupSid = "$($DomainSid.Value)-$($AdObject.primaryGroupID)"
                $PrimaryGroup = Get-ADGroup -Identity $PrimaryGroupSid -ErrorAction Stop
                if ($ResolvedGroups.DistinguishedName -notcontains $PrimaryGroup.DistinguishedName) {
                    $ResolvedGroups.Add($PrimaryGroup)
                }
            }
        } catch {
            Write-Verbose "Could not resolve the primary group for '$Identity': $_"
        }
    }

    return @($ResolvedGroups)
# End of Get-AdObjectGroupMembership function
}

Function Assert-ADPAModuleDependency {
    <#
    .SYNOPSIS
        Verifies required AD-PowerAdmin modules are loaded; imports them if not.

    .DESCRIPTION
        Called from Initialize-Module of any dependent module. For each required module name:
        1. If already loaded (Get-Module), pass immediately.
        2. If not loaded, attempt Import-Module from $global:ModulesPath.
        3. If still not loaded after the import attempt, write a [FAIL] message and set the
           return value to $false.
        Returns $true only when all named modules are confirmed available.

    .PARAMETER RequiredModules
        One or more AD-PowerAdmin module names (e.g. 'AD-PowerAdmin_GPOMgr').

    .OUTPUTS
        [bool] $true if all dependencies are met; $false if any module could not be loaded.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string[]]$RequiredModules
    )
    $AllMet = $true
    foreach ($Mod in $RequiredModules) {
        if (Get-Module -Name $Mod) { continue }
        $PsdPath = Join-Path $global:ModulesPath "$Mod.psd1"
        if (Test-Path $PsdPath) {
            try { Import-Module $PsdPath -Force -ErrorAction Stop } catch { }
        }
        if (-not (Get-Module -Name $Mod)) {
            Write-Host "[FAIL] Module '$Mod' is required but could not be loaded." -ForegroundColor Red
            Write-Host "       Verify the module files exist in: $global:ModulesPath" -ForegroundColor Red
            Write-Host "       If '$Mod' requires RSAT, install Group Policy Management Tools first." -ForegroundColor Red
            $AllMet = $false
        }
    }
    return $AllMet
}