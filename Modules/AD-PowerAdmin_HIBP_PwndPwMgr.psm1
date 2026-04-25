Function Initialize-Module {
    <#
    .SYNOPSIS
        Register HIBP module menu and unattended job entries.

    .DESCRIPTION
        Adds a single "Manage HIBP Database" entry to the main menu that opens a
        submenu via Enter-SubMenu. The submenu exposes install, update, and test
        actions. Also registers an unattended job for scheduled hash-file updates.
    #>

    $global:Menu += @{
        'HibpManageDatabase' = @{
            Title    = "Manage HIBP Database"
            Label    = "Install, update, and verify the Have I Been Pwned NTLM password hash database used for breach detection in password audits."
            Module   = "AD-PowerAdmin_HIBP_PwndPwMgr"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'HibpManageDatabase'"
        }
    }

    $global:SubMenus += @{
        'HibpManageDatabase' = @{
            Title = "Manage Have I Been Pwned Database"
            Items = @{
                'HibpInstall' = @{
                    Title   = "Install HIBP Tools"
                    Label   = "Install the .NET SDK and Have I Been Pwned downloader executable required to fetch the NTLM hash database."
                    Command = "Install-HibpHashDownloader"
                }
                'HibpUpdate' = @{
                    Title   = "Update HIBP Database"
                    Label   = "Download or refresh the NTLM hash database (~70 GB) and weak password list. The HIBP tool performs incremental updates after the first download."
                    Command = "Get-HibpPasswordHashesFiles"
                }
                'HibpWeakPw' = @{
                    Title   = "Update Weak Passwords"
                    Label   = "Download the latest weak password list from weakpasswords.net into the weak-passwords.txt file used by the password audit."
                    Command = "Get-WeakPasswordsList"
                }
                'HibpTest' = @{
                    Title   = "Test HIBP Installation"
                    Label   = "Verify that the .NET SDK and Have I Been Pwned downloader executable are installed and ready to use."
                    Command = "Test-HibpToolsInstalled"
                }
                'HibpUninstall' = @{
                    Title   = "Uninstall HIBP Tools"
                    Label   = "Remove the Have I Been Pwned downloader and the local .NET SDK installation from this system."
                    Command = "Uninstall-HibpTools"
                }
            }
        }
    }

    $global:UnattendedJobs += @{
        'HibpUpdateHashes' = @{
            Title    = "Update HIBP Database"
            Label    = "Weekly refresh of the HIBP NTLM hash database and weak password list. Incremental after the first full download."
            Module   = "AD-PowerAdmin_HIBP_PwndPwMgr"
            Function = "Get-HibpPasswordHashesFiles"
            Daily    = $false
            Command  = "Get-HibpPasswordHashesFiles"
        }
        'HibpUpdateWeakPw' = @{
            Title    = "Update Weak Passwords List"
            Label    = "Weekly download of the latest weak password list from weakpasswords.net."
            Module   = "AD-PowerAdmin_HIBP_PwndPwMgr"
            Function = "Get-WeakPasswordsList"
            Daily    = $false
            Command  = "Get-WeakPasswordsList"
        }
    }
}

# Call the Initialize-Module function. This needs to run to load all the data we need from the module.
Initialize-Module

Function Test-DotnetInstalled {
    <#
    .SYNOPSIS
        Test whether the .NET SDK is installed and executable.

    .DESCRIPTION
        Checks both $env:PATH and the local install directory used by Install-DotnetSdk.
        Returns $true only when 'dotnet --version' exits with code 0.

    .OUTPUTS
        [bool]
    #>
    try {
        # Resolve the dotnet binary path: prefer PATH, fall back to local install dir.
        [string]$dotnetPath = $null
        $DotnetCmd = Get-Command dotnet -ErrorAction SilentlyContinue

        if ($DotnetCmd) {
            $dotnetPath = $DotnetCmd.Source
        } else {
            [string]$LocalDotnetDir = "$global:ModulesPath\.dotnet"
            [string]$LocalDotnet   = "$LocalDotnetDir\dotnet.exe"
            if (Test-Path $LocalDotnet) {
                # Found in local install dir.
                # PATH: lets subsequent 'dotnet' name calls (nuget, tool install) resolve it.
                if ($env:PATH -notlike "*$LocalDotnetDir*") {
                    $env:PATH = "$LocalDotnetDir;$env:PATH"
                }
                # DOTNET_ROOT: tells .NET app hosts (like the HIBP exe) where the runtime is.
                # Without this, the app host searches only system-wide locations and fails.
                if ($env:DOTNET_ROOT -ne $LocalDotnetDir) {
                    $env:DOTNET_ROOT = $LocalDotnetDir
                }
                # DOTNET_ROLL_FORWARD: allows apps compiled against an older major version
                # (e.g. .NET 9) to run on a newer installed runtime (e.g. .NET 10).
                # The HIBP tool targets .NET 9; the install script installs the latest LTS.
                $env:DOTNET_ROLL_FORWARD = 'Major'
                $dotnetPath = $LocalDotnet
            }
        }

        if (-not $dotnetPath) {
            Write-Host "The .NET SDK is not installed." -ForegroundColor Red
            return $false
        }

        # Call the resolved binary directly so we never rely on PATH lookup here.
        $null = & "$dotnetPath" --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "The .NET SDK is installed." -ForegroundColor Green
            return $true
        }

        Write-Host "The .NET SDK was found but failed to execute (exit code $LASTEXITCODE)." -ForegroundColor Red
        return $false
    }
    catch {
        Write-Host "Error checking .NET SDK: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

Function Install-DotnetSdk {
    <#
    .SYNOPSIS
        Download and install the .NET SDK using the official Microsoft install script.

    .DESCRIPTION
        Uses the Microsoft dotnet-install.ps1 script to install the latest LTS .NET SDK
        into a local directory under $global:ModulesPath\.dotnet. After installation the
        directory is prepended to $env:PATH for the current session so subsequent dotnet
        calls succeed without restarting.

        Reference: https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-install-script

    .OUTPUTS
        [bool] $true on success, $false on failure.
    #>
    try {
        if (Test-DotnetInstalled) {
            return $true
        }

        Write-Host "The .NET SDK is not installed. Downloading and installing the .NET SDK." -ForegroundColor Yellow

        $DotnetInstallDir = "$global:ModulesPath\.dotnet"
        if (-not (Test-Path -Path $DotnetInstallDir)) {
            New-Item -Path $DotnetInstallDir -ItemType Directory -Force | Out-Null
        }

        Write-Host "Downloading the .NET SDK install script from Microsoft..." -ForegroundColor Yellow
        Enable-OldWindowsTLS12
        Invoke-Expression "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; &([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing 'https://dot.net/v1/dotnet-install.ps1'))) -InstallDir `"$DotnetInstallDir`""

        # PATH: lets subsequent 'dotnet' name calls (nuget, tool install) resolve it.
        if ($env:PATH -notlike "*$DotnetInstallDir*") {
            $env:PATH = "$DotnetInstallDir;$env:PATH"
        }
        # DOTNET_ROOT: tells .NET app hosts (like the HIBP exe) where the runtime lives.
        if ($env:DOTNET_ROOT -ne $DotnetInstallDir) {
            $env:DOTNET_ROOT = $DotnetInstallDir
        }
        # DOTNET_ROLL_FORWARD: allows apps compiled against an older major version
        # (e.g. .NET 9) to run on a newer installed runtime (e.g. .NET 10).
        $env:DOTNET_ROLL_FORWARD = 'Major'

        if (-not (Test-DotnetInstalled)) {
            Write-Host "Failed to install the .NET SDK." -ForegroundColor Red
            return $false
        }

        return $true
    }
    catch {
        Throw "Failed to install the .NET SDK: $($_.Exception.Message)"
        return $false
    }
}

Function Install-HibpHashDownloader {
    <#
    .SYNOPSIS
        Install the Have I Been Pwned downloader tool.

    .DESCRIPTION
        Ensures the .NET SDK is installed, then installs the haveibeenpwned-downloader
        .NET tool into $global:ModulesPath using 'dotnet tool install --tool-path'.
        Safe to call when the tool is already installed; exits cleanly with $true.

    .OUTPUTS
        [bool] $true if the downloader is present after the function completes.
    #>
    $HibpExecutable = "$global:ModulesPath\haveibeenpwned-downloader.exe"

    if (Test-Path -Path $HibpExecutable) {
        Write-Host "The HIBP Hash Downloader is already installed." -ForegroundColor Green
        # Still run the dotnet check so PATH and DOTNET_ROOT are configured for this
        # session - the exe will fail at runtime without DOTNET_ROOT when dotnet is
        # installed locally but not system-wide.
        Test-DotnetInstalled | Out-Null
        return $true
    }

    if (-not (Install-DotnetSdk)) {
        Write-Host "Cannot install HIBP downloader: .NET SDK installation failed." -ForegroundColor Red
        return $false
    }

    try {
        # Add nuget.org source only if not already registered.
        [string]$sources = (& dotnet nuget list source 2>&1) -join ' '
        if ($sources -notmatch 'nuget\.org') {
            Write-Host "Adding nuget.org package source..." -ForegroundColor Yellow
            & dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org | Out-Null
        }

        Write-Host "Installing haveibeenpwned-downloader tool..." -ForegroundColor Yellow
        [string]$toolOutput = (& dotnet tool install haveibeenpwned-downloader --tool-path "$global:ModulesPath" 2>&1) -join ' '

        # dotnet tool install exits 1 when the tool is already installed; that is not a failure.
        if ($LASTEXITCODE -ne 0 -and $toolOutput -notmatch 'already installed') {
            Write-Host "Failed to install the HIBP downloader tool." -ForegroundColor Red
            Write-Host $toolOutput -ForegroundColor Red
            return $false
        }

        if (-not (Test-Path -Path $HibpExecutable)) {
            Write-Host "Install reported success but the executable was not found at: $HibpExecutable" -ForegroundColor Red
            return $false
        }

        Write-Host "The HIBP Hash Downloader has been installed." -ForegroundColor Green
        return $true
    }
    catch {
        Throw "Error installing HIBP downloader: $($_.Exception.Message)"
    }
}

Function Test-HibpToolsInstalled {
    <#
    .SYNOPSIS
        Verify that the .NET SDK and HIBP downloader executable are present and functional.

    .DESCRIPTION
        Calls Test-DotnetInstalled and checks for haveibeenpwned-downloader.exe in
        $global:ModulesPath. Reports any missing components and returns $false if either
        is absent.

    .OUTPUTS
        [bool] $true when both tools are ready; $false otherwise.
    #>
    [bool]$dotnetOk = Test-DotnetInstalled
    [string]$hibpExe = "$global:ModulesPath\haveibeenpwned-downloader.exe"
    [bool]$hibpOk   = Test-Path -Path $hibpExe

    if (-not $dotnetOk) {
        Write-Host "dotnet SDK not found. Run 'Install HIBP Tools' to install it." -ForegroundColor Red
    }
    if (-not $hibpOk) {
        Write-Host "haveibeenpwned-downloader.exe not found at: $hibpExe" -ForegroundColor Red
        Write-Host "Run 'Install HIBP Tools' to install it." -ForegroundColor Red
    }
    if ($dotnetOk -and $hibpOk) {
        Write-Host "HIBP tools are installed and ready." -ForegroundColor Green
        return $true
    }
    return $false
}

Function Get-WeakPasswordsList {
    <#
    .SYNOPSIS
        Download the weak password list from weakpasswords.net.

    .DESCRIPTION
        Fetches the weak password word list from https://weakpasswords.net/ and saves it
        to $global:ThisScriptDir\$global:WeakPassDictFile. This file is consumed by the
        password audit functions in AD-PowerAdmin_PasswordsCtl as a dictionary of known
        weak passwords.

        This function is also called automatically by Get-HibpPasswordHashesFiles as part
        of the combined weekly update.

    .OUTPUTS
        [bool] $true on success, $false on failure.
    #>
    [string]$OutFile = "$global:ThisScriptDir\$global:WeakPassDictFile"
    try {
        Write-Host "Downloading weak password list from weakpasswords.net..." -ForegroundColor Yellow
        Write-Host "Output file: $OutFile" -ForegroundColor Yellow
        Enable-OldWindowsTLS12
        Invoke-WebRequest -Uri 'https://weakpasswords.net/' -UseBasicParsing -OutFile $OutFile
        Write-Host "Weak password list downloaded successfully." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to download weak password list: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

Function Get-HibpPasswordHashesFiles {
    <#
    .SYNOPSIS
        Download or update the Have I Been Pwned NTLM password hash file and weak password list.

    .DESCRIPTION
        Ensures the HIBP downloader tool is installed, then runs it to download or
        incrementally update the NTLM hash list into $global:ThisScriptDir. The output
        filename matches $global:NtlmHashDataFile so AD-PowerAdmin_PasswordsCtl finds it.

        After the HIBP download completes, also calls Get-WeakPasswordsList to refresh
        the weak password dictionary from weakpasswords.net.

        WARNING: As of 2026 the full NTLM hash database is approximately 70 GB. The
        haveibeenpwned-downloader tool performs incremental updates after the first
        download, so subsequent weekly runs only fetch changed hash ranges.

        Tool usage reference (from haveibeenpwned-downloader --help):
            haveibeenpwned-downloader [outputFile] [OPTIONS]
            -n  Fetch NTLM hashes (default is SHA1)
            -o  Overwrite existing output file
            -s  Write to a single file (default: true)
            -p  Parallelism (default: 8 * processor count)

    .OUTPUTS
        [bool] $true when both downloads succeed, $false if either fails.
    #>
    [string]$HibpExecutable = "$global:ModulesPath\haveibeenpwned-downloader.exe"
    [string]$OriginalWorkingDir = (Get-Location).Path

    try {
        if (-not (Install-HibpHashDownloader)) {
            Write-Host "Failed to install the HIBP Hash Downloader. Cannot download hash file." -ForegroundColor Red
            return $false
        }

        # Warn about download size on first run (file does not exist yet).
        [string]$HashFilePath = "$global:ThisScriptDir\$global:NtlmHashDataFile"
        if (-not (Test-Path $HashFilePath)) {
            Write-Host ""
            Write-Host "WARNING: As of 2026, the full HIBP NTLM hash database is approximately 70 GB." -ForegroundColor Yellow
            Write-Host "Subsequent weekly updates are incremental and much smaller." -ForegroundColor Yellow
            Write-Host ""
            $confirm = Read-Host "This is a large download. Continue? (y/N)"
            if ($confirm -ne 'y' -and $confirm -ne 'Y') {
                Write-Host "Download cancelled." -ForegroundColor Yellow
                return $false
            }
        }

        # The tool appends .txt to the output name automatically.
        # Strip the extension from the global setting so the produced filename matches exactly.
        [string]$outputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($global:NtlmHashDataFile)

        # Change to the script root so the file lands where PasswordsCtl expects it.
        Set-Location -Path $global:ThisScriptDir

        Write-Host "Downloading HIBP NTLM password hash file. This may take a long time..." -ForegroundColor Yellow
        Write-Host "Output file: $HashFilePath" -ForegroundColor Yellow

        & "$HibpExecutable" $outputBaseName -n -o

        if ($LASTEXITCODE -ne 0) {
            Write-Host "The HIBP downloader exited with code $LASTEXITCODE." -ForegroundColor Red
            Set-Location -Path $OriginalWorkingDir
            return $false
        }

        Write-Host "The HIBP password hash file has been downloaded and updated." -ForegroundColor Green
        Set-Location -Path $OriginalWorkingDir

        # Also refresh the weak password list as part of the combined update.
        Write-Host ""
        [bool]$weakPwOk = Get-WeakPasswordsList
        return $weakPwOk
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Set-Location -Path $OriginalWorkingDir
        return $false
    }
}

Function Uninstall-HibpTools {
    <#
    .SYNOPSIS
        Remove the HIBP downloader and the local .NET SDK installed by this module.

    .DESCRIPTION
        Deletes the following items created by Install-HibpHashDownloader and
        Install-DotnetSdk:
            - haveibeenpwned-downloader.exe  ($global:ModulesPath)
            - .dotnet\                        (local .NET SDK, $global:ModulesPath)
            - .store\                         (dotnet tool store metadata, $global:ModulesPath)
            - .config\                        (dotnet tool manifest, $global:ModulesPath)
        Also clears DOTNET_ROOT and removes the local dotnet dir from PATH in the
        current session.

        Optionally removes the downloaded NTLM hash file from $global:ThisScriptDir.
        That file can be 30+ GB so the user is prompted separately before it is deleted.
    #>

    Write-Host ""
    Write-Host "This will remove the following from $global:ModulesPath:" -ForegroundColor Yellow
    Write-Host "  - haveibeenpwned-downloader.exe" -ForegroundColor Yellow
    Write-Host "  - .dotnet\  (local .NET SDK)" -ForegroundColor Yellow
    Write-Host "  - .store\   (dotnet tool metadata)" -ForegroundColor Yellow
    Write-Host "  - .config\  (dotnet tool manifest)" -ForegroundColor Yellow
    Write-Host ""
    $Confirm = Read-Host "Are you sure you want to uninstall HIBP tools? (y/N)"
    if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
        Write-Host "Uninstall cancelled." -ForegroundColor Yellow
        return
    }

    [bool]$anyError = $false

    # Remove the HIBP downloader executable.
    [string]$HibpExe = "$global:ModulesPath\haveibeenpwned-downloader.exe"
    if (Test-Path $HibpExe) {
        try {
            Remove-Item -Path $HibpExe -Force
            Write-Host "Removed: haveibeenpwned-downloader.exe" -ForegroundColor Green
        } catch {
            Write-Host "Failed to remove haveibeenpwned-downloader.exe: $($_.Exception.Message)" -ForegroundColor Red
            $anyError = $true
        }
    } else {
        Write-Host "Not found (already removed): haveibeenpwned-downloader.exe" -ForegroundColor Gray
    }

    # Remove directories created by dotnet tool install and dotnet-install.ps1.
    foreach ($dir in @('.dotnet', '.store', '.config')) {
        [string]$dirPath = "$global:ModulesPath\$dir"
        if (Test-Path $dirPath) {
            try {
                Remove-Item -Path $dirPath -Recurse -Force
                Write-Host "Removed: $dir\" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove $dir\: $($_.Exception.Message)" -ForegroundColor Red
                $anyError = $true
            }
        } else {
            Write-Host "Not found (already removed): $dir\" -ForegroundColor Gray
        }
    }

    # Clear session environment so the removed runtime is not referenced again.
    [string]$LocalDotnetDir = "$global:ModulesPath\.dotnet"
    if ($env:DOTNET_ROOT -eq $LocalDotnetDir) {
        Remove-Item Env:\DOTNET_ROOT -ErrorAction SilentlyContinue
        Write-Host "Cleared: DOTNET_ROOT environment variable." -ForegroundColor Green
    }
    if ($env:PATH -like "*$LocalDotnetDir*") {
        $env:PATH = ($env:PATH -split ';' | Where-Object { $_ -ne $LocalDotnetDir }) -join ';'
        Write-Host "Removed local dotnet dir from session PATH." -ForegroundColor Green
    }
    Remove-Item Env:\DOTNET_ROLL_FORWARD -ErrorAction SilentlyContinue

    # Offer to remove the large NTLM hash file separately (can be 30+ GB).
    [string]$HashFile = "$global:ThisScriptDir\$global:NtlmHashDataFile"
    if (Test-Path $HashFile) {
        Write-Host ""
        $confirmHash = Read-Host "Also delete the NTLM hash file '$global:NtlmHashDataFile' (~70 GB)? (y/N)"
        if ($confirmHash -eq 'y' -or $confirmHash -eq 'Y') {
            try {
                Remove-Item -Path $HashFile -Force
                Write-Host "Removed: $global:NtlmHashDataFile" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove hash file: $($_.Exception.Message)" -ForegroundColor Red
                $anyError = $true
            }
        } else {
            Write-Host "Hash file kept at: $HashFile" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    if ($anyError) {
        Write-Host "Uninstall completed with errors. Review messages above." -ForegroundColor Yellow
    } else {
        Write-Host "HIBP tools uninstalled successfully." -ForegroundColor Green
    }
}

Function Uninstall-DotnetSdk {
    <#
    .SYNOPSIS
        Uninstall all .NET SDK versions found in the Windows registry.

    .DESCRIPTION
        Queries HKLM for installed Microsoft .NET SDK entries and runs msiexec /x
        against each one. This removes SDKs installed system-wide via the MSI installer.
        SDKs installed via dotnet-install.ps1 to a local directory should be removed
        by deleting that directory directly.
    #>
    $dotNetSDKs = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" |
        Get-ItemProperty |
        Where-Object { $_.DisplayName -match "Microsoft .NET SDK" }

    if ($dotNetSDKs.Count -eq 0) {
        Write-Host "No .NET SDKs found in the registry on this system." -ForegroundColor Yellow
        return
    }

    foreach ($sdk in $dotNetSDKs) {
        [string]$uninstallString = $sdk.UninstallString
        if ($uninstallString) {
            Write-Host "Uninstalling $($sdk.DisplayName)..." -ForegroundColor Yellow
            Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $uninstallString /qn" -Wait
            Write-Host "$($sdk.DisplayName) uninstalled." -ForegroundColor Green
        } else {
            Write-Host "No uninstall string found for $($sdk.DisplayName). Skipping." -ForegroundColor Red
        }
    }
}
