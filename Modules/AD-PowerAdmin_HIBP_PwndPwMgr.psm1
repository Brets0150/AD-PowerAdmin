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
                'HibpTroubleshoot' = @{
                    Title   = "Troubleshooting Guide"
                    Label   = "Display a step-by-step guide for diagnosing and resolving HIBP downloader failures, including reinstall procedures and an explanation of single-file vs directory mode."
                    Command = "Show-HibpTroubleshootingGuide"
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
        Download or update the Have I Been Pwned NTLM password hash data and weak password list.

    .DESCRIPTION
        Ensures the HIBP downloader tool is installed, then downloads or incrementally
        updates the NTLM hash data into $global:ThisScriptDir.

        Two modes are supported, selected by the $global:NtlmHashDataDir setting:

        SINGLE-FILE MODE ($global:NtlmHashDataDir is empty):
            Downloads all hashes into one sorted text file named by $global:NtlmHashDataFile.
            The full initial download is approximately 70 GB. Subsequent runs overwrite the
            entire file (-o flag), so every update re-downloads the full dataset.

        DIRECTORY MODE ($global:NtlmHashDataDir is set to a directory name):
            Downloads hashes as individual range files (PREFIX.txt) inside the named directory.
            Only changed range files are fetched on subsequent runs -- making weekly updates
            far more efficient than replacing the full single file. Recommended for ongoing use.

        After the HIBP download completes, also calls Get-WeakPasswordsList to refresh
        the weak password dictionary from weakpasswords.net.

        Tool usage reference (from haveibeenpwned-downloader --help):
            haveibeenpwned-downloader [outputFile] [OPTIONS]
            -n             Fetch NTLM hashes (default is SHA1)
            -o             Overwrite existing output file (single-file mode)
            --single false Write range files to a directory instead of a single file
            -p             Parallelism (default: 8 * processor count)

    .OUTPUTS
        [bool] $true when both downloads succeed, $false if either fails.
    #>
    [string]$HibpExecutable    = "$global:ModulesPath\haveibeenpwned-downloader.exe"
    [string]$OriginalWorkingDir = (Get-Location).Path

    try {
        if (-not (Install-HibpHashDownloader)) {
            Write-Host "Failed to install the HIBP Hash Downloader. Cannot download hash file." -ForegroundColor Red
            return $false
        }

        # Determine mode based on whether a directory name has been configured.
        [bool]$DirectoryMode = ($global:NtlmHashDataDir -ne '' -and $null -ne $global:NtlmHashDataDir)

        # Get free disk space on the drive where the hash data will be stored.
        try {
            [string]$DriveRoot = [System.IO.Path]::GetPathRoot($global:ThisScriptDir)
            $DriveInfo = [System.IO.DriveInfo]::new($DriveRoot)
            [string]$FreeSpaceStr = "$([math]::Round($DriveInfo.AvailableFreeSpace / 1GB, 2)) GB free on $($DriveInfo.Name)"
        } catch {
            [string]$FreeSpaceStr = "disk space unknown"
        }

        if ($DirectoryMode) {
            # --- DIRECTORY MODE (incremental range files) ---
            [string]$TargetDir = "$global:ThisScriptDir\$global:NtlmHashDataDir"

            # First-run: directory missing or empty of range files.
            [bool]$IsFirstRun = (-not (Test-Path $TargetDir -PathType Container)) -or
                                 ((Get-ChildItem -Path $TargetDir -Filter '*.txt' -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)

            if ($IsFirstRun) {
                Write-Host ""
                Write-Host "WARNING: As of 2026, the full HIBP NTLM hash database is approximately 70 GB." -ForegroundColor Yellow
                Write-Host "Subsequent incremental updates will only download changed ranges (much smaller)." -ForegroundColor Yellow
                Write-Host "Available disk space: $FreeSpaceStr" -ForegroundColor Yellow
                Write-Host ""
                [string]$Confirm = Read-Host "This is a large first-time download. Continue? (y/N)"
                if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
                    Write-Host "Download cancelled." -ForegroundColor Yellow
                    return $false
                }
            }

            Set-Location -Path $global:ThisScriptDir

            Write-Host "Downloading HIBP NTLM hash range files (directory mode)..." -ForegroundColor Yellow
            Write-Host "Output directory: $TargetDir" -ForegroundColor Yellow

            # Limit the number of threads to 4. Having more then that can trigger CloudFlare to block our connections. 
            & "$HibpExecutable" $global:NtlmHashDataDir --single false -n -p 4

            if ($LASTEXITCODE -ne 0) {
                Write-Host "The HIBP downloader exited with code $LASTEXITCODE." -ForegroundColor Red
                Set-Location -Path $OriginalWorkingDir
                return $false
            }

            Write-Host "HIBP NTLM hash range files updated successfully." -ForegroundColor Green

        } else {
            # --- SINGLE-FILE MODE (full sorted file) ---
            [string]$HashFilePath = "$global:ThisScriptDir\$global:NtlmHashDataFile"

            if (-not (Test-Path $HashFilePath)) {
                Write-Host ""
                Write-Host "WARNING: As of 2026, the full HIBP NTLM hash database is approximately 70 GB." -ForegroundColor Yellow
                Write-Host "Subsequent updates will re-download the entire file. Consider enabling directory" -ForegroundColor Yellow
                Write-Host "mode via `$global:NtlmHashDataDir in AD-PowerAdmin_settings.ps1 for incremental updates." -ForegroundColor Yellow
                Write-Host "Available disk space: $FreeSpaceStr" -ForegroundColor Yellow
                Write-Host ""
                [string]$Confirm = Read-Host "This is a large download. Continue? (y/N)"
                if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
                    Write-Host "Download cancelled." -ForegroundColor Yellow
                    return $false
                }
            }

            # The tool appends .txt automatically; strip the extension from the global setting.
            [string]$OutputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($global:NtlmHashDataFile)

            Set-Location -Path $global:ThisScriptDir

            Write-Host "Downloading HIBP NTLM password hash file (single-file mode)..." -ForegroundColor Yellow
            Write-Host "Output file: $HashFilePath" -ForegroundColor Yellow

            & "$HibpExecutable" $OutputBaseName -n -o

            if ($LASTEXITCODE -ne 0) {
                Write-Host "The HIBP downloader exited with code $LASTEXITCODE." -ForegroundColor Red
                Set-Location -Path $OriginalWorkingDir
                return $false
            }

            Write-Host "The HIBP password hash file has been downloaded and updated." -ForegroundColor Green
        }

        Set-Location -Path $OriginalWorkingDir

        # Also refresh the weak password list as part of the combined update.
        Write-Host ""
        [bool]$WeakPwOk = Get-WeakPasswordsList
        return $WeakPwOk
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

Function Show-HibpTroubleshootingGuide {
    <#
    .SYNOPSIS
        Display a troubleshooting guide for the HIBP downloader toolchain.

    .DESCRIPTION
        Prints a structured plain-text guide covering:
          - Common failure scenarios and their root causes
          - Step-by-step removal, reinstall, and test procedures
          - Why the module uses directory-based incremental downloads
            instead of a single monolithic file
          - Environment variables used internally by the module

        Intended as a built-in reference for administrators and future
        contributors who were not involved in developing this module.
    #>

    [string]$Sep  = "=" * 78
    [string]$Sep2 = "-" * 78

    Write-Host ""
    Write-Host $Sep -ForegroundColor Cyan
    Write-Host "  HIBP DOWNLOADER -- TROUBLESHOOTING GUIDE" -ForegroundColor Cyan
    Write-Host $Sep -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This guide covers common failures with the Have I Been Pwned (HIBP) NTLM"
    Write-Host "password hash downloader, procedures for removing and reinstalling the"
    Write-Host "toolchain, and the rationale for the directory-based download model."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 1: COMMON FAILURES AND ROOT CAUSES" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "1. 'dotnet' is not recognized as a command"
    Write-Host "   CAUSE: Install-DotnetSdk installs .NET locally under Modules\.dotnet\,"
    Write-Host "   which is not on the system PATH. New PowerShell sessions started after"
    Write-Host "   the install do not inherit the updated PATH automatically."
    Write-Host "   FIX: The module sets PATH, DOTNET_ROOT, and DOTNET_ROLL_FORWARD at"
    Write-Host "   runtime whenever it detects the local install. Running Install-HibpHash-"
    Write-Host "   Downloader or Test-HibpToolsInstalled triggers this environment setup."
    Write-Host ""

    Write-Host "2. haveibeenpwned-downloader.exe fails: '.NET location: Not found'"
    Write-Host "   CAUSE: The exe is a .NET application host. It searches standard system"
    Write-Host "   registry locations for the runtime. A locally installed .NET (not in the"
    Write-Host "   system registry) is invisible to the app host unless DOTNET_ROOT is set."
    Write-Host "   FIX: The module sets DOTNET_ROOT to Modules\.dotnet\ for the current"
    Write-Host "   session. Re-run Install-HibpHashDownloader to ensure DOTNET_ROOT is set."
    Write-Host ""

    Write-Host "3. 'Framework: Microsoft.NETCore.App 9.0.0 not found' (version mismatch)"
    Write-Host "   CAUSE: The HIBP exe was compiled against .NET 9. The module installs the"
    Write-Host "   latest .NET LTS (currently 10). By default .NET does not allow an app"
    Write-Host "   compiled for version 9 to run on a higher major version."
    Write-Host "   FIX: The module sets DOTNET_ROLL_FORWARD=Major, which permits a .NET 9"
    Write-Host "   application to run on .NET 10+. No manual action is required."
    Write-Host ""

    Write-Host "4. NuGet source registration error during install"
    Write-Host "   CAUSE: 'dotnet nuget add source' returns an error when nuget.org is"
    Write-Host "   already registered. This is a known dotnet CLI behavior, not a failure."
    Write-Host "   FIX: The installer checks for an existing nuget.org source and skips the"
    Write-Host "   add step when it is already present. No manual action is required."
    Write-Host ""

    Write-Host "5. 'dotnet tool install' exits with code 1 and says 'already installed'"
    Write-Host "   CAUSE: The dotnet CLI exits with code 1 when the tool is already present."
    Write-Host "   This is expected behavior, not an error."
    Write-Host "   FIX: The installer recognises the 'already installed' message and treats"
    Write-Host "   it as success. Environment variables are still configured correctly."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 2: STEP-BY-STEP RESOLUTION PROCEDURE" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Follow these steps in order when the downloader is not functioning."
    Write-Host ""

    Write-Host "  Step 1 -- Check current state"
    Write-Host "    Select 'Test HIBP Installation' from this submenu."
    Write-Host "    This runs Test-HibpToolsInstalled and reports whether dotnet and the"
    Write-Host "    downloader exe are present and working. Note which component fails."
    Write-Host ""

    Write-Host "  Step 2 -- Uninstall everything cleanly"
    Write-Host "    Select 'Uninstall HIBP Tools' from this submenu."
    Write-Host "    Removes haveibeenpwned-downloader.exe and the local .NET directories"
    Write-Host "    (.dotnet\, .store\, .config\) from the Modules folder. Also clears"
    Write-Host "    DOTNET_ROOT, DOTNET_ROLL_FORWARD, and the local path from PATH."
    Write-Host "    You are asked separately whether to delete the ~70 GB hash data."
    Write-Host ""

    Write-Host "  Step 3 -- Reinstall the toolchain"
    Write-Host "    Select 'Install HIBP Tools' from this submenu."
    Write-Host "    Installs the .NET SDK locally and then installs the downloader exe via"
    Write-Host "    dotnet tool install. PATH, DOTNET_ROOT, and DOTNET_ROLL_FORWARD are"
    Write-Host "    configured automatically for the current session."
    Write-Host ""

    Write-Host "  Step 4 -- Verify the installation"
    Write-Host "    Select 'Test HIBP Installation' again."
    Write-Host "    Both dotnet and the exe should now be reported as ready."
    Write-Host ""

    Write-Host "  Step 5 (advanced) -- Remove a conflicting system-wide .NET SDK"
    Write-Host "    If a system-wide .NET installation is causing conflicts, run from an"
    Write-Host "    elevated PowerShell prompt:"
    Write-Host "      Uninstall-DotnetSdk"
    Write-Host "    This queries the registry for installed .NET SDK MSI packages and"
    Write-Host "    removes each one via msiexec. Then repeat Steps 2-4."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 3: SINGLE-FILE VS DIRECTORY MODE (WHY WE CHANGED)" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "SINGLE-FILE MODE (original)"
    Write-Host "  The downloader was originally run with the -o flag, producing one large"
    Write-Host "  sorted flat file (e.g. pwned-passwords-ntlm-ordered-by-hash-v8.txt)."
    Write-Host "  As of 2026 this file is approximately 70 GB. The password audit module"
    Write-Host "  passed it to DSInternals via Test-PasswordQuality -WeakPasswordHashesSorted-"
    Write-Host "  File for breach detection."
    Write-Host ""
    Write-Host "  PROBLEM: Every weekly update re-downloads the entire 70 GB file even when"
    Write-Host "  only a small fraction of hashes have changed. This is highly inefficient."
    Write-Host ""

    Write-Host "DIRECTORY MODE (current, recommended)"
    Write-Host "  The downloader's --single false flag writes hashes as individual range"
    Write-Host "  files named by their 5-character hex prefix (e.g. A3B4C.txt). Each file"
    Write-Host "  contains SUFFIX:count lines for all hashes in that prefix range."
    Write-Host ""
    Write-Host "  On subsequent runs the tool compares each range file's ETag with the"
    Write-Host "  server and downloads only the files that have changed. A typical weekly"
    Write-Host "  refresh transfers a small fraction of the total 70 GB dataset."
    Write-Host ""
    Write-Host "  To enable directory mode, set this in AD-PowerAdmin_settings.ps1:"
    Write-Host "    `$global:NtlmHashDataDir = 'hibp-ntlm-hashes'"
    Write-Host "  Leave `$global:NtlmHashDataDir = '' to stay in single-file mode."
    Write-Host "  Both modes are fully supported; the module auto-detects based on the"
    Write-Host "  setting."
    Write-Host ""

    Write-Host "AUDIT LOGIC IN DIRECTORY MODE"
    Write-Host "  DSInternals Test-PasswordQuality requires a single sorted file, so it"
    Write-Host "  cannot be used directly with directory-mode range files. A custom function"
    Write-Host "  (Test-NtlmHashesInDirectory in AD-PowerAdmin_PasswordsCtl.psm1) handles"
    Write-Host "  directory-mode lookups."
    Write-Host ""
    Write-Host "  That function groups all AD accounts by their 5-character NTLM hash"
    Write-Host "  prefix, reads each corresponding range file exactly once, and returns the"
    Write-Host "  SamAccountName of each breached account. Results are merged into the"
    Write-Host "  PasswordQualityTestResult object's WeakPasswordHashes property so that"
    Write-Host "  Invoke-WeakPwdProcess sends notification emails and schedules follow-up"
    Write-Host "  tasks identically in both modes."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 4: ENVIRONMENT VARIABLES REFERENCE" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "  DOTNET_ROOT"
    Write-Host "    Tells .NET application hosts where the runtime is installed. Required"
    Write-Host "    when using a locally installed .NET that is not in the system registry."
    Write-Host "    Set by Test-DotnetInstalled and Install-DotnetSdk."
    Write-Host ""

    Write-Host "  DOTNET_ROLL_FORWARD=Major"
    Write-Host "    Allows a .NET 9-compiled application to run on a .NET 10 (or later)"
    Write-Host "    runtime. Without this flag the app host rejects a higher major version."
    Write-Host "    Set by Test-DotnetInstalled and Install-DotnetSdk."
    Write-Host ""

    Write-Host "  PATH"
    Write-Host "    Must include the dotnet executable directory for 'dotnet' commands to"
    Write-Host "    resolve. Updated for the current session by Test-DotnetInstalled and"
    Write-Host "    Install-DotnetSdk. System-wide PATH changes require a system-level"
    Write-Host "    installer or a manual registry edit."
    Write-Host ""

    Write-Host $Sep -ForegroundColor Cyan
    Write-Host "  End of troubleshooting guide." -ForegroundColor Cyan
    Write-Host $Sep -ForegroundColor Cyan
    Write-Host ""
# End of Show-HibpTroubleshootingGuide function
}
