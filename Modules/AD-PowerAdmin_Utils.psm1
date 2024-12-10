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

Function New-ScheduledTask {
    <#
    .SYNOPSIS
    Function that will create a scheduled task that runs a command at a specified time.

    .DESCRIPTION
    Create a scheduled task that runs a command at a specified time.

    .EXAMPLE
    New-ScheduledTask -ActionString "Taskmgr.exe" -ActionArguments "/q" -ScheduleRunTime "09:00" -Recurring Once -TaskName "Test" -TaskDiscription "Just a Test"

    .INPUTS
    New-ScheduledTask does not take pipeline input, but requires the following parameters: ActionString, ActionArguments, ScheduleRunTime, Recurring, TaskName, TaskDiscription

    .OUTPUTS
    New-ScheduledTask will output the following: None

    .NOTES
    This function is used by AD-PowerAdmin_Main.ps1 to create a scheduled task.

    #>
    Param(
        [Parameter(Mandatory=$True,Position=1)]
        [string]$ActionString,
        [Parameter(Mandatory=$True,Position=2)]
        [string]$ActionArguments,
        [Parameter(Mandatory=$True,Position=3)]
        [string]$ScheduleRunTime,
        [Parameter(Mandatory=$True,Position=4)][ValidateSet("Daliy","Weekly","Monthly","Once")]
        [string]$Recurring,
        [Parameter(Mandatory=$True,Position=5)]
        [string]$TaskName,
        [Parameter(Mandatory=$True,Position=6)]
        [string]$TaskDiscription
    )

    # Get the current user's name
    [string]$UserName = "$env:UserDomain\$env:UserName"

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

    try {
        $Action          = New-ScheduledTaskAction -Execute $ActionString -Argument $ActionArguments -WorkingDirectory "$global:ThisScriptDir"
        $Settings        = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
        $DomainNameShort = Get-ADDomain | Select-Object Name | Select-Object -ExpandProperty Name | Select-Object -First 1
        $UserId          = "$DomainNameShort`\$global:MsaAccountName`$"
        $Principal       = New-ScheduledTaskPrincipal -UserID "$UserId" -LogonType Password -RunLevel Highest

        Register-ScheduledTask -TaskName "$TaskName" -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "$TaskDiscription" | Out-Null

        # Confirm the task was created
        if (Get-ScheduledTask -TaskName "$TaskName") {
            Write-Host "Task created successfully." -ForegroundColor Green
        }
        else {
            throw "Task creation failed."
        }
    }
    catch {
        Write-Host "Unable to create schedule task."
        Write-Output $_
        break
    }

    #End of New-ScheduledTask function
}

Function Send-Email {
    <#
    .SYNOPSIS
        Function to send an email.

    .DESCRIPTION
        # A Function that takes in "TO" and "FROM" email addresses and a subject line and sends an email with the contents of the $ReportData variable.

    #>
    # Parameters for this function.
    Param(
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ToEmail,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$FromEmail,
        [Parameter(Mandatory=$false,Position=3)]
        [string]$CcEmail,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$Subject,
        [Parameter(Mandatory=$true,Position=4)]
        [string]$Body,
        [Parameter(Mandatory=$false,Position=5)]
        [string]$SmtpServer,
        [Parameter(Mandatory=$false,Position=6)]
        [string]$SmtpPort,
        [Parameter(Mandatory=$false,Position=7)]
        [string]$SmtpUser,
        [Parameter(Mandatory=$false,Position=8)]
        [string]$SmtpPass,
        [Parameter(Mandatory=$false,Position=9)]
        [bool]$DebugEmail
    )
    # Set the email Security Protocol to TLS 1.2.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Build the email sending variables.
    $EmailServerParam = @{}

    # If $SMTPServer is not empty, then use the $global:SmtpServer variable. If the $global:SmtpServer is empty, then display an error and exit the function.
    if ($SmtpServer -ne '') {
        $EmailServerParam.SmtpServer = $SmtpServer
    } elseif ($global:SmtpServer -ne '') {
        $EmailServerParam.SmtpServer = $global:SMTPServer
    } else {
        Write-Host "Error: The SMTP Server is not set. Please set the SMTP Server in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # If $SMTPPort is not empty, then use the $global:SmtpPort variable. If the $global:SmtpPort is empty, then display an warning and continue.
    if ($SmtpPort -ne '') {
        $EmailServerParam.Port = $SmtpPort
    } elseif ($global:SmtpPort -ne '') {
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

    # If $CcEmail is not empty or null, then add the $CcEmail to the email.
    if ($CcEmail -ne '' -and $CcEmail -ne $null) {
        $Message.CC.Add($CcEmail);
    }

    $Smtp = New-Object Net.Mail.SmtpClient($EmailServerParam.SmtpServer, $EmailServerParam.Port);
    # SSL is always used.
    $Smtp.EnableSSL = [bool]$global:SmtpEnableSSL;

    # If $SMTPUser and $SMTPPass is not empty or null, then use the $global:SMTPUser and $global:SMTPPassword variables. If the $global:SMTPUser or $global:SMTPPassword is empty, then display an warning and continue.
    # If either is not empty, then use the $global:SMTPUser and $global:SMTPPassword to build $Smtp.Credentials object variable.
    if (($SmtpUser -ne '') -and ($SmtpPass -ne '')) {
        $Smtp.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPass);
    }
    if (($global:SMTPUser -ne '') -and ($global:SMTPPassword -ne '')) {
        $Smtp.Credentials = New-Object System.Net.NetworkCredential($global:SMTPUser, $global:SMTPPassword);
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

Function Send-EmailTest {
    <#
    .SYNOPSIS
        Function to send a test email.

    .DESCRIPTION
        A To ask a user for the variable for the Send-Email function. With the gathered information, the function will send an email to the user.
    #>
    [string]$Subject = "ADPowerAdmin: Test Email"
    [string]$Body = "This is a test email from the ADPowerAdmin script. If you are reading this, then the email was sent successfully."
    Write-Host "You can leave any of the following fields blank and the script will use the default settings from the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
    # Ask the user for the email address to send the test email to.
    [string]$ToEmail = Read-Host "Enter the email address to send the test email to"
    # Ask the user for the email address to send the test email from.
    [string]$FromEmail = Read-Host "Enter the email address to send the test email from"
    # Ask the user for the SMTP Server to send the test email from.
    [string]$SmtpServer = Read-Host "Enter the SMTP Server to send the test email"
    # Ask the user for the SMTP Port to send the test email from.
    [string]$SmtpPort = Read-Host "Enter the SMTP Port to send the test email"
    # Ask the user for the SMTP User to send the test email from.
    [string]$SmtpUser = Read-Host "Enter the SMTP User to send the test email"
    # Ask the user for the SMTP Password to send the test email from.
    [string]$SmtpPass = Read-Host "Enter the SMTP Password to send the test email"

    $SendTestEmailParam = @{}

    # If $SMTPServer is not empty, then use the $global:SmtpServer variable for $SMTPServer. If the $global:SmtpServer is empty, then display an error and exit the function.
    # If $SMTPServer is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpServer -ne '') {
        $SendTestEmailParam.SmtpServer = "$SmtpServer"
    } elseif ($global:SmtpServer -ne '') {
        $SendTestEmailParam.SmtpServer = "$global:SMTPServer"
    } else {
        Write-Host "Error: The SMTP Server is not set. Please set the SMTP Server in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # If $SMTPPort is not empty, then use the $global:SmtpPort variable for $SMTPPort. If the $global:SmtpServer is empty, then display a warning and continue.
    # If $SMTPPort is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpPort -ne '') {
        $SendTestEmailParam.SmtpPort = "$SmtpPort"
    } elseif ($global:SmtpPort -ne '') {
        $SendTestEmailParam.SmtpPort = "$global:SMTPPort"
    } else {
        Write-Host "Warning: The SMTP Port is not set. Please Check the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
        Write-Host "Trying to send email with default SMTP Port." -ForegroundColor Yellow
    }

    # If $SmtpUser is not empty, then use the $global:SmtpPort variable for $SmtpUser. If the $global:SmtpServer is empty, then display a warning and continue.
    # If $SmtpUser is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpUser -ne '') {
        $SendTestEmailParam.SmtpUser = "$SmtpUser"
    } elseif ($global:SMTPUsername -ne '') {
        $SendTestEmailParam.SmtpUser = "$global:SMTPUsername"
    } else {
        Write-Host "Warning: The SMTP User is not set. Please Check the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
        Write-Host "Trying to send email without SMTP User." -ForegroundColor Yellow
    }

    # If $SmtpPass is not empty, then use the $global:SmtpPort variable for $SmtpPass. If the $global:SmtpServer is empty, then display a warning and continue.
    # If $SmtpPass is not empty add it to the $SendTestEmailParam variable.
    if ($SmtpPass -ne '') {
        $SendTestEmailParam.SmtpPass = "$SmtpPass"
    } elseif ($global:SMTPPassword -ne '') {
        $SendTestEmailParam.SmtpPass = "$global:SMTPPassword"
    } else {
        Write-Host "Warning: The SMTP Password is not set. Please Check the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Yellow
        Write-Host "Trying to send email without SMTP Password." -ForegroundColor Yellow
    }

    # If $ToEmail is not empty, then use the $global:ToEmail variable for $ToEmail. If the $global:ToEmail is empty, then display an error and exit the function.
    # If $ToEmail is not empty add it to the $SendTestEmailParam variable.
    if ($ToEmail -ne '') {
        [string]$ToEmail = "$ToEmail"
    } elseif ($global:ADAdminEmail -ne '') {
        [string]$ToEmail = "$global:ADAdminEmail"
    } else {
        Write-Host "Error: The To Email is not set. Please set the To Email in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # If $FromEmail is not empty, then use the $global:FromEmail variable for $FromEmail. If the $global:FromEmail is empty, then display an error and exit the function.
    # If $FromEmail is not empty add it to the $SendTestEmailParam variable.
    if ($FromEmail -ne '') {
        [string]$FromEmail = "$FromEmail"
    } elseif ($global:FromEmail -ne '') {
        [string]$FromEmail = "$global:FromEmail"
    } else {
        Write-Host "Error: The From Email is not set. Please set the From Email in the 'AD-PowerAdmin_settings.ps1' file." -ForegroundColor Red
        return
    }

    # Enabele debugging.
    $SendTestEmailParam.DebugEmail = $true

    # Try to send the email.
    Send-Email -ToEmail "$ToEmail" -FromEmail "$FromEmail" -Subject "$Subject" -Body "$Body" @SendTestEmailParam
    return
# End of the Send-EmailTest function.
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