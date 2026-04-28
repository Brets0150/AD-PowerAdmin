Function Initialize-Module {
    <#
    .SYNOPSIS
        Register HIBP module menu and unattended job entries.

    .DESCRIPTION
        Adds a single "Manage HIBP Database" entry to the main menu that opens a
        submenu via Enter-SubMenu. The submenu exposes update, test, remove, and
        troubleshoot actions. Also registers unattended jobs for scheduled updates.
    #>

    $global:Menu += @{
        'HibpManageDatabase' = @{
            Title    = "Manage HIBP Database"
            Label    = "Download and maintain the Have I Been Pwned NTLM password hash database used for breach detection in password audits."
            Module   = "AD-PowerAdmin_HIBP_PwndPwMgr"
            Function = "Enter-SubMenu"
            Command  = "Enter-SubMenu 'HibpManageDatabase'"
        }
    }

    $global:SubMenus += @{
        'HibpManageDatabase' = @{
            Title = "Manage Have I Been Pwned Database"
            Items = @{
                'HibpUpdate' = @{
                    Title   = "Update HIBP Database"
                    Label   = "Download or refresh the NTLM hash database (~70 GB first run, then incremental updates only) and the weak password list."
                    Command = "Get-HibpPasswordHashesFiles"
                }
                'HibpWeakPw' = @{
                    Title   = "Update Weak Passwords"
                    Label   = "Download the latest weak password list from weakpasswords.net into the weak-passwords.txt file used by the password audit."
                    Command = "Get-WeakPasswordsList"
                }
                'HibpTest' = @{
                    Title   = "Test HIBP Readiness"
                    Label   = "Verify that the HIBP downloader is ready: checks API reachability and whether local hash data has been downloaded."
                    Command = "Test-HibpToolsInstalled"
                }
                'HibpUninstall' = @{
                    Title   = "Remove HIBP Hash Data"
                    Label   = "Delete the downloaded NTLM hash database files from this system to reclaim disk space (~70 GB)."
                    Command = "Uninstall-HibpTools"
                }
                'HibpTroubleshoot' = @{
                    Title   = "Troubleshooting Guide"
                    Label   = "Display a step-by-step guide for diagnosing and resolving HIBP downloader failures, including configuration and single-file vs directory mode explanation."
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

# ==============================================================
# PRIVATE HELPER FUNCTIONS -- Not listed in FunctionsToExport
# ==============================================================

Function Initialize-HibpTls12 {
    <#
    .SYNOPSIS
        Force TLS 1.2 for HIBP API connections in the current session.
    .DESCRIPTION
        Windows PowerShell 5.1 can default to older TLS settings. HIBP/Cloudflare requires a
        modern TLS negotiation. This function explicitly enables TLS 1.2 in the current session.
        It is also re-declared inside every Start-Job worker scriptblock via a Local copy.
    #>
    try {
        $tls12 = [Enum]::Parse([Net.SecurityProtocolType], 'Tls12')
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $tls12
        [Net.ServicePointManager]::Expect100Continue = $false
    }
    catch {
        # If this fails, let the web request surface the real connection error.
    }
}

Function Resolve-HibpLocalPath {
    <#
    .SYNOPSIS
        Resolve a PowerShell provider path to a local filesystem absolute path.
    .PARAMETER Path
        The path to resolve.
    .OUTPUTS
        [string] Absolute filesystem path.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

Function ConvertTo-HibpPrefix {
    <#
    .SYNOPSIS
        Normalize and validate a single HIBP prefix value.
    .PARAMETER Value
        A prefix value: 5-character hex string, short hex string (left-padded), or decimal integer.
    .OUTPUTS
        [string] Uppercase 5-character hexadecimal prefix.
    #>
    param([Parameter(Mandatory = $true)][object]$Value)

    $raw = ([string]$Value).Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "Invalid empty prefix."
    }

    if ($raw -match '^[0-9]+$') {
        $raw = ('{0:X5}' -f [int]$raw)
    }
    elseif ($raw -match '^[0-9A-F]{1,5}$') {
        $raw = $raw.PadLeft(5, '0')
    }

    if ($raw -notmatch '^[0-9A-F]{5}$') {
        throw "Invalid prefix '$Value'. Prefixes must be exactly 5 hexadecimal characters after normalization. Example: '00000','ABCDE','FFFFF'. Range syntax: '00000-000FF'."
    }

    return $raw
}

Function Expand-HibpPrefixes {
    <#
    .SYNOPSIS
        Expand a list of prefix values and ranges into a full array of 5-character hex prefixes.
    .PARAMETER PrefixValues
        Array of prefix values or inclusive ranges ('00000-000FF'). If null or empty, returns all
        1,048,576 prefixes (00000 through FFFFF).
    .OUTPUTS
        [string[]] Array of unique uppercase 5-character hex prefix strings.
    #>
    param([string[]]$PrefixValues)

    $output = New-Object 'System.Collections.Generic.List[string]'

    if ($null -eq $PrefixValues -or $PrefixValues.Count -eq 0) {
        for ($i = 0; $i -le 0xFFFFF; $i++) {
            [void]$output.Add(('{0:X5}' -f $i))
        }
        return $output.ToArray()
    }

    foreach ($item in $PrefixValues) {
        $token = ([string]$item).Trim()
        if ($token -match '^(.+)-(.+)$') {
            $startPrefix = ConvertTo-HibpPrefix $Matches[1]
            $endPrefix   = ConvertTo-HibpPrefix $Matches[2]
            $start = [Convert]::ToInt32($startPrefix, 16)
            $end   = [Convert]::ToInt32($endPrefix,   16)
            if ($end -lt $start) {
                throw "Invalid prefix range '$token'. End prefix is lower than start prefix."
            }
            for ($i = $start; $i -le $end; $i++) {
                [void]$output.Add(('{0:X5}' -f $i))
            }
        }
        else {
            [void]$output.Add((ConvertTo-HibpPrefix $token))
        }
    }

    return @($output.ToArray() | Select-Object -Unique)
}

Function Get-HibpRangeUri {
    <#
    .SYNOPSIS
        Build the HIBP API URL for a given prefix.
    .PARAMETER Prefix
        5-character hex prefix.
    .PARAMETER UseNtlm
        If true, append ?mode=ntlm to the URL.
    .OUTPUTS
        [string] Full HIBP range API URL.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][bool]$UseNtlm
    )

    if ($UseNtlm) {
        return "https://api.pwnedpasswords.com/range/$Prefix`?mode=ntlm"
    }

    return "https://api.pwnedpasswords.com/range/$Prefix"
}

Function Get-HibpHeaderValue {
    <#
    .SYNOPSIS
        Safely read a single HTTP response header value.
    .PARAMETER Headers
        The response headers collection.
    .PARAMETER Name
        Header name to read.
    .OUTPUTS
        [string] Header value, or null if not present.
    #>
    param(
        [Parameter(Mandatory = $false)]$Headers,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $Headers) { return $null }

    try {
        $value = $Headers[$Name]
        if ($null -eq $value) { return $null }
        if ($value -is [array]) { return [string]$value[0] }
        return [string]$value
    }
    catch {
        return $null
    }
}

Function Invoke-HibpRangeDownload {
    <#
    .SYNOPSIS
        Download a single HIBP range to a .part file with retry logic.
    .DESCRIPTION
        Uses System.Net.HttpWebRequest directly for reliable large-payload downloads.
        Supports ETag-based conditional GET (If-None-Match). Returns a result object
        with StatusCode 304 when the server confirms the range is unchanged.
    .PARAMETER Uri
        Full HIBP range API URL.
    .PARAMETER OutFile
        Path to write the downloaded content (typically a .part file).
    .PARAMETER ETag
        Optional ETag value for conditional GET.
    .PARAMETER TimeoutSeconds
        Request and read timeout in seconds.
    .PARAMETER Retries
        Number of retry attempts on failure.
    .OUTPUTS
        [PSCustomObject] with StatusCode, ETag, LastModified, OutFile, Error properties.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [string]$ETag,
        [int]$TimeoutSeconds = 120,
        [int]$Retries = 10
    )

    $attempt     = 0
    $maxAttempts = $Retries + 1
    $lastError   = $null

    while ($attempt -lt $maxAttempts) {
        $attempt++
        if (Test-Path -LiteralPath $OutFile) {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        }

        $response     = $null
        $inputStream  = $null
        $outputStream = $null

        try {
            $request                    = [System.Net.HttpWebRequest]::Create($Uri)
            $request.Method             = 'GET'
            $request.UserAgent          = 'hibp-powershell-downloader-v3.4/1.0'
            $request.Timeout            = $TimeoutSeconds * 1000
            $request.ReadWriteTimeout   = $TimeoutSeconds * 1000
            $request.KeepAlive          = $true
            try { $request.AutomaticDecompression = ([System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate) } catch { }

            if (-not [string]::IsNullOrWhiteSpace($ETag)) {
                $request.Headers['If-None-Match'] = $ETag
            }

            $response    = $request.GetResponse()
            $statusCode  = [int]$response.StatusCode

            $inputStream  = $response.GetResponseStream()
            $outputStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $buffer       = New-Object byte[] 65536
            while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $outputStream.Write($buffer, 0, $read)
            }
            $outputStream.Flush()

            return [pscustomobject]@{
                StatusCode   = $statusCode
                ETag         = Get-HibpHeaderValue -Headers $response.Headers -Name 'ETag'
                LastModified = Get-HibpHeaderValue -Headers $response.Headers -Name 'Last-Modified'
                OutFile      = $OutFile
                Error        = $null
            }
        }
        catch [System.Net.WebException] {
            $lastError   = $_
            $webResponse = $null
            try { $webResponse = $_.Exception.Response } catch { $webResponse = $null }
            if ($null -ne $webResponse) {
                try {
                    $statusCode = [int]$webResponse.StatusCode
                    if ($statusCode -eq 304) {
                        if (Test-Path -LiteralPath $OutFile) {
                            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
                        }
                        return [pscustomobject]@{
                            StatusCode   = 304
                            ETag         = Get-HibpHeaderValue -Headers $webResponse.Headers -Name 'ETag'
                            LastModified = Get-HibpHeaderValue -Headers $webResponse.Headers -Name 'Last-Modified'
                            OutFile      = $null
                            Error        = $null
                        }
                    }
                }
                catch { }
            }
            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            if ($attempt -lt $maxAttempts) {
                $delay = [Math]::Min(10, [Math]::Max(1, $attempt * 2))
                Start-Sleep -Seconds $delay
            }
        }
        catch {
            $lastError = $_
            if (Test-Path -LiteralPath $OutFile) {
                Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
            }
            if ($attempt -lt $maxAttempts) {
                $delay = [Math]::Min(10, [Math]::Max(1, $attempt * 2))
                Start-Sleep -Seconds $delay
            }
        }
        finally {
            if ($null -ne $outputStream) { $outputStream.Dispose() }
            if ($null -ne $inputStream)  { $inputStream.Dispose() }
            if ($null -ne $response)     { $response.Dispose() }
        }
    }

    throw $lastError
}

Function Test-HibpRangeFile {
    <#
    .SYNOPSIS
        Validate that a range file contains correctly formatted HIBP suffix:count lines.
    .PARAMETER Path
        Path to the range file to validate.
    .PARAMETER UseNtlm
        If true, validate NTLM (27-char suffix); otherwise SHA-1 (35-char suffix).
    .OUTPUTS
        [PSCustomObject] with Valid (bool), LineCount (int), Message (string).
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$UseNtlm
    )

    $suffixLength = 35
    if ($UseNtlm) { $suffixLength = 27 }
    $pattern   = '^[0-9A-F]{' + $suffixLength + '}:[0-9]+$'
    $lineCount = 0
    $reader    = $null

    try {
        $reader = New-Object System.IO.StreamReader($Path)
        while (($line = $reader.ReadLine()) -ne $null) {
            if ($line.Length -eq 0) { continue }
            if ($line -notmatch $pattern) {
                return [pscustomobject]@{
                    Valid     = $false
                    LineCount = $lineCount
                    Message   = "Invalid line format: $line"
                }
            }
            $lineCount++
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }

    return [pscustomobject]@{
        Valid     = $true
        LineCount = $lineCount
        Message   = ''
    }
}

Function Import-HibpManifest {
    <#
    .SYNOPSIS
        Read the HIBP range manifest TSV file into a hashtable keyed by prefix.
    .PARAMETER ManifestPath
        Path to the manifest TSV file.
    .OUTPUTS
        [hashtable] Empty hashtable if the file does not exist.
    #>
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $map = @{}
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        return $map
    }

    $rows = Import-Csv -LiteralPath $ManifestPath -Delimiter "`t"
    foreach ($row in $rows) {
        if ($row.Prefix) {
            $map[$row.Prefix] = $row
        }
    }
    return $map
}

Function Export-HibpManifest {
    <#
    .SYNOPSIS
        Write the HIBP range manifest hashtable to a TSV file atomically.
    .DESCRIPTION
        Writes to a .part file first, then moves it into place to prevent a partially
        written manifest from being read as valid after an interrupted run.
    .PARAMETER Manifest
        Hashtable of manifest entries keyed by prefix.
    .PARAMETER ManifestPath
        Destination TSV file path.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    $dir = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $tmp  = "$ManifestPath.part"
    $rows = foreach ($key in ($Manifest.Keys | Sort-Object)) {
        $Manifest[$key]
    }
    $rows | Export-Csv -LiteralPath $tmp -Delimiter "`t" -NoTypeInformation -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $ManifestPath -Force
}

Function Split-HibpPrefixBuckets {
    <#
    .SYNOPSIS
        Distribute a list of prefix strings evenly across N worker buckets.
    .PARAMETER Items
        Array of prefix strings to distribute.
    .PARAMETER BucketCount
        Number of buckets (worker count).
    .OUTPUTS
        Array of List[string] objects, one per bucket.
    #>
    param(
        [Parameter(Mandatory = $true)][string[]]$Items,
        [Parameter(Mandatory = $true)][int]$BucketCount
    )

    $buckets = @()
    for ($i = 0; $i -lt $BucketCount; $i++) {
        $buckets += ,(New-Object 'System.Collections.Generic.List[string]')
    }

    for ($i = 0; $i -lt $Items.Count; $i++) {
        [void]$buckets[$i % $BucketCount].Add($Items[$i])
    }

    return $buckets
}

Function Invoke-HibpDirectoryDownload {
    <#
    .SYNOPSIS
        Download or update HIBP range files into a directory using parallel Start-Job workers.
    .DESCRIPTION
        Creates one .txt file per 5-character HIBP prefix in the specified range directory.
        Uses Start-Job for PowerShell 5.1-compatible parallelism. Each worker processes a
        subset of prefixes and writes TSV result files that the parent aggregates after
        all workers complete. Supports first-run, ETag-based incremental update, and
        verify-only mode. Writes failure logs to $global:ReportsPath.
    .PARAMETER Prefixes
        Array of 5-character hex prefix strings to process.
    .PARAMETER RangeDirectory
        Directory where range .txt files are stored.
    .PARAMETER ManifestPath
        Path to the manifest TSV file.
    .PARAMETER UseNtlm
        If true, download NTLM hashes.
    .PARAMETER DoUpdate
        If true, send ETags for conditional GET (304 = skip re-download).
    .PARAMETER DoVerifyOnly
        If true, validate existing files without downloading.
    .PARAMETER DoOverwrite
        If true, overwrite existing range files when not in update mode.
    .PARAMETER WorkerCount
        Number of parallel Start-Job workers.
    .PARAMETER TimeoutSeconds
        Per-request timeout in seconds.
    .PARAMETER RetryCount
        Retry attempts per prefix.
    .PARAMETER AllowContinueOnError
        If true, return stats even when some ranges failed.
    .OUTPUTS
        [PSCustomObject] with download statistics (Checked, Downloaded, Updated, Unchanged304, etc.).
    #>
    param(
        [string[]]$Prefixes,
        [string]$RangeDirectory,
        [string]$ManifestPath,
        [bool]$UseNtlm,
        [bool]$DoUpdate,
        [bool]$DoVerifyOnly,
        [bool]$DoOverwrite,
        [int]$WorkerCount,
        [int]$TimeoutSeconds,
        [int]$RetryCount,
        [bool]$AllowContinueOnError
    )

    if (-not (Test-Path -LiteralPath $RangeDirectory)) {
        New-Item -ItemType Directory -Path $RangeDirectory -Force | Out-Null
    }
    $manifestDir = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $manifestDir)) {
        New-Item -ItemType Directory -Path $manifestDir -Force | Out-Null
    }

    $manifest = Import-HibpManifest -ManifestPath $ManifestPath
    $etagMap  = @{}
    foreach ($key in $manifest.Keys) {
        $etagMap[$key] = $manifest[$key].ETag
    }

    $jobRoot = Join-Path $manifestDir ("jobs-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $jobRoot -Force | Out-Null

    # Worker scriptblock: fully self-contained.
    # Start-Job creates a new PowerShell process that does not inherit the parent module's
    # functions. All helpers are re-declared here with a Local suffix.
    $workerScript = {
        param(
            [string[]]$WorkerPrefixes,
            [string]$WorkerRangeDirectory,
            [bool]$WorkerUseNtlm,
            [bool]$WorkerDoUpdate,
            [bool]$WorkerDoVerifyOnly,
            [bool]$WorkerDoOverwrite,
            [hashtable]$WorkerEtagMap,
            [int]$WorkerTimeoutSeconds,
            [int]$WorkerRetryCount,
            [string]$WorkerResultPath,
            [string]$WorkerFailurePath
        )

        Set-StrictMode -Version 2.0
        $ErrorActionPreference = 'Stop'

        function Initialize-HibpTls12Local {
            try {
                $tls12 = [Enum]::Parse([Net.SecurityProtocolType], 'Tls12')
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $tls12
                [Net.ServicePointManager]::Expect100Continue = $false
            }
            catch { }
        }

        Initialize-HibpTls12Local

        function Get-HeaderValueLocal {
            param($Headers, [string]$Name)
            if ($null -eq $Headers) { return $null }
            try {
                $value = $Headers[$Name]
                if ($null -eq $value) { return $null }
                if ($value -is [array]) { return [string]$value[0] }
                return [string]$value
            }
            catch { return $null }
        }

        function Get-HibpRangeUriLocal {
            param([string]$Prefix, [bool]$UseNtlm)
            if ($UseNtlm) { return "https://api.pwnedpasswords.com/range/$Prefix`?mode=ntlm" }
            return "https://api.pwnedpasswords.com/range/$Prefix"
        }

        function Invoke-HibpDownloadToFileLocal {
            param([string]$Uri, [string]$OutFile, [string]$ETag, [int]$TimeoutSeconds, [int]$Retries)
            $attempt     = 0
            $maxAttempts = $Retries + 1
            $lastError   = $null

            while ($attempt -lt $maxAttempts) {
                $attempt++
                if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }

                $response     = $null
                $inputStream  = $null
                $outputStream = $null

                try {
                    $request                  = [System.Net.HttpWebRequest]::Create($Uri)
                    $request.Method           = 'GET'
                    $request.UserAgent        = 'hibp-powershell-downloader-v3.4/1.0'
                    $request.Timeout          = $TimeoutSeconds * 1000
                    $request.ReadWriteTimeout = $TimeoutSeconds * 1000
                    $request.KeepAlive        = $true
                    try { $request.AutomaticDecompression = ([System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate) } catch { }
                    if (-not [string]::IsNullOrWhiteSpace($ETag)) { $request.Headers['If-None-Match'] = $ETag }

                    $response    = $request.GetResponse()
                    $statusCode  = [int]$response.StatusCode
                    $inputStream  = $response.GetResponseStream()
                    $outputStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    $buffer       = New-Object byte[] 65536
                    while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $outputStream.Write($buffer, 0, $read)
                    }
                    $outputStream.Flush()

                    return [pscustomobject]@{
                        StatusCode   = $statusCode
                        ETag         = (Get-HeaderValueLocal $response.Headers 'ETag')
                        LastModified = (Get-HeaderValueLocal $response.Headers 'Last-Modified')
                        OutFile      = $OutFile
                    }
                }
                catch [System.Net.WebException] {
                    $lastError   = $_
                    $webResponse = $null
                    try { $webResponse = $_.Exception.Response } catch { $webResponse = $null }
                    if ($null -ne $webResponse) {
                        try {
                            $statusCode = [int]$webResponse.StatusCode
                            if ($statusCode -eq 304) {
                                if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
                                return [pscustomobject]@{
                                    StatusCode   = 304
                                    ETag         = (Get-HeaderValueLocal $webResponse.Headers 'ETag')
                                    LastModified = (Get-HeaderValueLocal $webResponse.Headers 'Last-Modified')
                                    OutFile      = $null
                                }
                            }
                        }
                        catch { }
                    }
                    if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
                    if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds ([Math]::Min(10, [Math]::Max(1, $attempt * 2))) }
                }
                catch {
                    $lastError = $_
                    if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
                    if ($attempt -lt $maxAttempts) { Start-Sleep -Seconds ([Math]::Min(10, [Math]::Max(1, $attempt * 2))) }
                }
                finally {
                    if ($null -ne $outputStream) { $outputStream.Dispose() }
                    if ($null -ne $inputStream)  { $inputStream.Dispose() }
                    if ($null -ne $response)     { $response.Dispose() }
                }
            }
            throw $lastError
        }

        function Test-HibpRangeFileLocal {
            param([string]$Path, [bool]$UseNtlm)
            $suffixLength = 35
            if ($UseNtlm) { $suffixLength = 27 }
            $pattern   = '^[0-9A-F]{' + $suffixLength + '}:[0-9]+$'
            $lineCount = 0
            $reader    = $null
            try {
                $reader = New-Object System.IO.StreamReader($Path)
                while (($line = $reader.ReadLine()) -ne $null) {
                    if ($line.Length -eq 0) { continue }
                    if ($line -notmatch $pattern) {
                        return [pscustomobject]@{ Valid = $false; LineCount = $lineCount; Message = "Invalid line format: $line" }
                    }
                    $lineCount++
                }
            }
            finally {
                if ($null -ne $reader) { $reader.Dispose() }
            }
            return [pscustomobject]@{ Valid = $true; LineCount = $lineCount; Message = '' }
        }

        function Write-TsvLineLocal {
            param([string]$Path, [object[]]$Values, [bool]$Create = $false)
            $safe = foreach ($v in $Values) {
                if ($null -eq $v) { '' } else { ([string]$v).Replace("`t", ' ').Replace("`r", ' ').Replace("`n", ' ') }
            }
            $bytes  = [System.Text.Encoding]::UTF8.GetBytes(($safe -join "`t") + "`n")
            $mode   = if ($Create) { [System.IO.FileMode]::Create } else { [System.IO.FileMode]::Append }
            $fs     = $null
            try {
                $fs = [System.IO.File]::Open($Path, $mode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $fs.Write($bytes, 0, $bytes.Length)
            } finally {
                if ($null -ne $fs) { $fs.Dispose() }
            }
        }

        Write-TsvLineLocal $WorkerResultPath  @('Prefix','Status','Bytes','ETag','LastModified','Length','Sha256','LineCount','DownloadedUtc','Message') -Create $true
        Write-TsvLineLocal $WorkerFailurePath @('Prefix','Error') -Create $true

        foreach ($prefix in $WorkerPrefixes) {
            $finalPath = Join-Path $WorkerRangeDirectory ("$prefix.txt")
            $partPath  = Join-Path $WorkerRangeDirectory ("$prefix.txt.part")
            $exists    = Test-Path -LiteralPath $finalPath

            try {
                if ($WorkerDoVerifyOnly) {
                    if (-not $exists) { throw "Missing range file." }
                    $validation = Test-HibpRangeFileLocal -Path $finalPath -UseNtlm $WorkerUseNtlm
                    if (-not $validation.Valid) { throw $validation.Message }
                    $fileInfo = Get-Item -LiteralPath $finalPath
                    $sha      = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash
                    Write-TsvLineLocal $WorkerResultPath @($prefix, 'Verified', 0, $WorkerEtagMap[$prefix], '', $fileInfo.Length, $sha, $validation.LineCount, '', '')
                    continue
                }

                if (-not $WorkerDoUpdate -and $exists -and -not $WorkerDoOverwrite) {
                    $validation = Test-HibpRangeFileLocal -Path $finalPath -UseNtlm $WorkerUseNtlm
                    if (-not $validation.Valid) { throw $validation.Message }
                    $fileInfo = Get-Item -LiteralPath $finalPath
                    $sha      = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash
                    Write-TsvLineLocal $WorkerResultPath @($prefix, 'SkippedExisting', 0, $WorkerEtagMap[$prefix], '', $fileInfo.Length, $sha, $validation.LineCount, '', '')
                    continue
                }

                $etag = $null
                if ($WorkerDoUpdate -and $exists -and $WorkerEtagMap.ContainsKey($prefix)) {
                    $etag = [string]$WorkerEtagMap[$prefix]
                }

                $uri      = Get-HibpRangeUriLocal -Prefix $prefix -UseNtlm $WorkerUseNtlm
                $response = Invoke-HibpDownloadToFileLocal -Uri $uri -OutFile $partPath -ETag $etag -TimeoutSeconds $WorkerTimeoutSeconds -Retries $WorkerRetryCount

                if ($response.StatusCode -eq 304) {
                    Write-TsvLineLocal $WorkerResultPath @($prefix, 'Unchanged304', 0, $response.ETag, $response.LastModified, '', '', '', '', '')
                    continue
                }

                $validation = Test-HibpRangeFileLocal -Path $partPath -UseNtlm $WorkerUseNtlm
                if (-not $validation.Valid) { throw $validation.Message }

                $partInfo = Get-Item -LiteralPath $partPath
                $length   = $partInfo.Length
                $sha      = (Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash
                $status   = 'Downloaded'
                if ($exists -and $WorkerDoUpdate) { $status = 'Updated' }

                Move-Item -LiteralPath $partPath -Destination $finalPath -Force
                Write-TsvLineLocal $WorkerResultPath @($prefix, $status, $length, $response.ETag, $response.LastModified, $length, $sha, $validation.LineCount, ([DateTime]::UtcNow.ToString('o')), '')
            }
            catch {
                if (Test-Path -LiteralPath $partPath) { Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue }
                Write-TsvLineLocal $WorkerResultPath  @($prefix, 'Failed', 0, '', '', '', '', '', '', $_.Exception.Message)
                Write-TsvLineLocal $WorkerFailurePath @($prefix, $_.Exception.Message)
            }
        }
    }

    $workerCount = [Math]::Max(1, [Math]::Min($WorkerCount, $Prefixes.Count))
    $buckets     = Split-HibpPrefixBuckets -Items $Prefixes -BucketCount $workerCount
    $jobs        = @()
    $resultPaths = @()
    $modeName    = if ($UseNtlm) { 'ntlm' } else { 'sha1' }

    for ($i = 0; $i -lt $workerCount; $i++) {
        $bucketArray = @($buckets[$i].ToArray())
        if ($bucketArray.Count -eq 0) { continue }
        $resultPath  = Join-Path $jobRoot ("worker-$i-results.tsv")
        $failurePath = Join-Path $jobRoot ("worker-$i-failures.tsv")
        $resultPaths += $resultPath
        $jobs += Start-Job -ScriptBlock $workerScript -ArgumentList @(
            $bucketArray,
            $RangeDirectory,
            $UseNtlm,
            $DoUpdate,
            $DoVerifyOnly,
            $DoOverwrite,
            $etagMap,
            $TimeoutSeconds,
            $RetryCount,
            $resultPath,
            $failurePath
        )
    }

    [datetime]$progressStart = [DateTime]::UtcNow
    [int]$totalPrefixes      = $Prefixes.Count
    do {
        [int]$activeJobs = @($jobs | Where-Object { $_.State -notin @('Completed','Failed','Stopped') }).Count
        [int]$doneCount  = 0
        foreach ($rf in $resultPaths) {
            if (Test-Path -LiteralPath $rf) {
                try {
                    $fs = [System.IO.File]::Open($rf, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                    try {
                        $sr        = New-Object System.IO.StreamReader($fs)
                        $lineCount = 0
                        while ($null -ne $sr.ReadLine()) { $lineCount++ }
                        $sr.Dispose()
                    } finally {
                        $fs.Dispose()
                    }
                    if ($lineCount -gt 1) { $doneCount += $lineCount - 1 }
                } catch { }
            }
        }
        [int]$pct       = if ($totalPrefixes -gt 0) { [Math]::Min(99, [int](($doneCount / $totalPrefixes) * 100)) } else { 0 }
        $elapsedSec     = ([DateTime]::UtcNow - $progressStart).TotalSeconds
        [int]$eta       = -1
        if ($doneCount -gt 10 -and $elapsedSec -gt 0) {
            $eta = [int](($totalPrefixes - $doneCount) / ($doneCount / $elapsedSec))
        }
        Write-Progress -Activity "Downloading HIBP range files ($modeName)" `
                       -Status ("{0:N0} of {1:N0} prefixes  |  {2}%  |  {3} worker(s) active" -f $doneCount, $totalPrefixes, $pct, $activeJobs) `
                       -PercentComplete $pct `
                       -SecondsRemaining $eta
        if ($activeJobs -gt 0) { Start-Sleep -Seconds 2 }
    } while ($activeJobs -gt 0)
    Write-Progress -Activity "Downloading HIBP range files ($modeName)" -Completed

    foreach ($job in $jobs) {
        Receive-Job -Job $job | Out-Null
        Remove-Job  -Job $job -Force
    }

    $stats = [ordered]@{
        Checked         = $Prefixes.Count
        Downloaded      = 0
        Updated         = 0
        Unchanged304    = 0
        SkippedExisting = 0
        Verified        = 0
        Invalid         = 0
        Failed          = 0
        BytesDownloaded = [int64]0
    }

    $failureLog  = Join-Path $global:ReportsPath ("{0}-hibp-failures-{1}.log" -f $modeName, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $failureLines = New-Object 'System.Collections.Generic.List[string]'

    Get-ChildItem -LiteralPath $jobRoot -Filter '*-results.tsv' | ForEach-Object {
        $rows = Import-Csv -LiteralPath $_.FullName -Delimiter "`t"
        foreach ($row in $rows) {
            switch ($row.Status) {
                'Downloaded'      { $stats.Downloaded++ }
                'Updated'         { $stats.Updated++ }
                'Unchanged304'    { $stats.Unchanged304++ }
                'SkippedExisting' { $stats.SkippedExisting++ }
                'Verified'        { $stats.Verified++ }
                'Failed'          { $stats.Failed++ }
                default { }
            }
            if ($row.Status -eq 'Failed') {
                [void]$failureLines.Add(("{0}: {1}" -f $row.Prefix, $row.Message))
                continue
            }
            if ($row.Status -in @('Downloaded', 'Updated', 'Verified', 'SkippedExisting')) {
                $manifest[$row.Prefix] = [pscustomobject]@{
                    Prefix        = $row.Prefix
                    Mode          = $(if ($UseNtlm) { 'NTLM' } else { 'SHA1' })
                    ETag          = $row.ETag
                    LastModified  = $row.LastModified
                    Length        = $row.Length
                    Sha256        = $row.Sha256
                    LineCount     = $row.LineCount
                    DownloadedUtc = $row.DownloadedUtc
                }
            }
            elseif ($row.Status -eq 'Unchanged304') {
                if ($manifest.ContainsKey($row.Prefix)) {
                    if (-not [string]::IsNullOrWhiteSpace($row.ETag))          { $manifest[$row.Prefix].ETag          = $row.ETag }
                    if (-not [string]::IsNullOrWhiteSpace($row.LastModified))  { $manifest[$row.Prefix].LastModified  = $row.LastModified }
                }
            }
            $bytes = 0L
            [void][int64]::TryParse([string]$row.Bytes, [ref]$bytes)
            $stats.BytesDownloaded += $bytes
        }
    }

    Export-HibpManifest -Manifest $manifest -ManifestPath $ManifestPath
    Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue

    if ($failureLines.Count -gt 0) {
        $failureLines | Set-Content -LiteralPath $failureLog -Encoding UTF8
        Write-Warning "Some ranges failed. Failure log: $failureLog"
    }

    return [pscustomobject]$stats
}

Function Invoke-HibpSingleFileDownload {
    <#
    .SYNOPSIS
        Download all HIBP prefixes sequentially into a single monolithic text file.
    .DESCRIPTION
        Each range is downloaded, validated, and appended to a streaming writer with the
        full hash (prefix + suffix) on each line. Writes to a .part file first; moves
        into place only after all prefixes complete successfully. Does not maintain a manifest.
    .PARAMETER Prefixes
        Array of 5-character hex prefix strings to process.
    .PARAMETER OutputPath
        Destination file path (including .txt extension).
    .PARAMETER UseNtlm
        If true, download NTLM hashes.
    .PARAMETER DoOverwrite
        If true, allow overwriting an existing output file.
    .PARAMETER TimeoutSeconds
        Per-request timeout in seconds.
    .PARAMETER RetryCount
        Retry attempts per prefix.
    .OUTPUTS
        [PSCustomObject] with download statistics.
    #>
    param(
        [string[]]$Prefixes,
        [string]$OutputPath,
        [bool]$UseNtlm,
        [bool]$DoOverwrite,
        [int]$TimeoutSeconds,
        [int]$RetryCount
    )

    if ((Test-Path -LiteralPath $OutputPath) -and -not $DoOverwrite) {
        throw "Output file '$OutputPath' already exists. Use -Overwrite to replace it."
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $partOutput = "$OutputPath.part"
    $tempRange  = "$OutputPath.range.part"
    if (Test-Path -LiteralPath $partOutput) { Remove-Item -LiteralPath $partOutput -Force }
    if (Test-Path -LiteralPath $tempRange)  { Remove-Item -LiteralPath $tempRange  -Force }

    $stats = [ordered]@{
        Checked         = $Prefixes.Count
        Downloaded      = 0
        Updated         = 0
        Unchanged304    = 0
        SkippedExisting = 0
        Verified        = 0
        Invalid         = 0
        Failed          = 0
        BytesDownloaded = [int64]0
    }

    [int]$totalPrefixes  = $Prefixes.Count
    [int]$doneCount      = 0
    [string]$modeLabel   = if ($UseNtlm) { 'NTLM' } else { 'SHA1' }
    [datetime]$progressStart = [DateTime]::UtcNow

    $writer = $null
    try {
        $writer = New-Object System.IO.StreamWriter($partOutput, $false, [System.Text.Encoding]::ASCII, 1048576)
        foreach ($prefix in $Prefixes) {
            try {
                $uri      = Get-HibpRangeUri -Prefix $prefix -UseNtlm $UseNtlm
                $response = Invoke-HibpRangeDownload -Uri $uri -OutFile $tempRange -TimeoutSeconds $TimeoutSeconds -Retries $RetryCount
                if ($response.StatusCode -ne 200) {
                    throw "Unexpected HTTP status in single-file mode: $($response.StatusCode)"
                }
                $validation = Test-HibpRangeFile -Path $tempRange -UseNtlm $UseNtlm
                if (-not $validation.Valid) { throw $validation.Message }

                $fileInfo = Get-Item -LiteralPath $tempRange
                $stats.BytesDownloaded += $fileInfo.Length
                $reader = $null
                try {
                    $reader = New-Object System.IO.StreamReader($tempRange)
                    while (($line = $reader.ReadLine()) -ne $null) {
                        if ($line.Length -gt 0) {
                            $writer.WriteLine("$prefix$line")
                        }
                    }
                }
                finally {
                    if ($null -ne $reader) { $reader.Dispose() }
                }
                $stats.Downloaded++
                $doneCount++
                [int]$pct   = if ($totalPrefixes -gt 0) { [Math]::Min(99, [int](($doneCount / $totalPrefixes) * 100)) } else { 0 }
                $elapsedSec = ([DateTime]::UtcNow - $progressStart).TotalSeconds
                [int]$eta   = -1
                if ($doneCount -gt 0 -and $elapsedSec -gt 0) {
                    $eta = [int](($totalPrefixes - $doneCount) / ($doneCount / $elapsedSec))
                }
                Write-Progress -Activity "Downloading HIBP single file ($modeLabel)" `
                               -Status ("{0:N0} of {1:N0} prefixes  |  {2}% complete" -f $doneCount, $totalPrefixes, $pct) `
                               -PercentComplete $pct `
                               -SecondsRemaining $eta
                Remove-Item -LiteralPath $tempRange -Force -ErrorAction SilentlyContinue
            }
            catch {
                $stats.Failed++
                if (Test-Path -LiteralPath $tempRange) { Remove-Item -LiteralPath $tempRange -Force -ErrorAction SilentlyContinue }
                throw "Failed prefix $prefix in single-file mode: $($_.Exception.Message)"
            }
        }
    }
    finally {
        if ($null -ne $writer) { $writer.Dispose() }
    }
    Write-Progress -Activity "Downloading HIBP single file ($modeLabel)" -Completed

    Move-Item -LiteralPath $partOutput -Destination $OutputPath -Force
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        throw "Single-file mode completed but expected output file was not found: $OutputPath"
    }

    return [pscustomobject]$stats
}

# ==============================================================
# PUBLIC FUNCTIONS
# ==============================================================

Function Start-HibpDownload {
    <#
    .SYNOPSIS
        Download or update the Have I Been Pwned NTLM password hash database.

    .DESCRIPTION
        Pure PowerShell 5.1 HIBP downloader. No .NET SDK, no external executables, and
        no external modules required. Supports ETag-based incremental updates and parallel
        Start-Job workers.

        Two storage modes are available:

        Single-file mode (-Single, the default):
          Downloads all prefixes into one monolithic .txt file. Every run re-downloads the
          full dataset. Useful when a downstream tool requires one large sorted file.

        Directory mode (-Single:$false):
          Downloads one small .txt file per prefix (e.g. 00000.txt ... FFFFF.txt) and
          maintains a manifest. On subsequent runs with -Update, only changed prefix ranges
          are re-downloaded (304 Not Modified responses skip the body entirely). Recommended
          for ongoing maintenance -- typically only a small fraction of the ~70 GB dataset
          changes between weekly updates.

        This function is called by Get-HibpPasswordHashesFiles using parameters derived from
        $global:NtlmHashDataDir and $global:NtlmHashDataFile. It can also be called directly
        for advanced scenarios such as downloading a specific prefix range or verifying data.

    .PARAMETER OutputFile
        Output path. In single-file mode: base name (appends .txt if absent).
        In directory mode: directory path for range files and the _manifest folder.

    .PARAMETER Parallelism
        Number of parallel worker jobs for directory mode. 0 = auto (2x CPU count, min 2).
        Max 256. Recommend 4 to avoid CloudFlare rate limiting on large downloads.

    .PARAMETER Overwrite
        Allow overwriting an existing single-file output file.

    .PARAMETER Single
        Default $true (single-file mode). Use -Single:$false for directory/range mode.

    .PARAMETER Ntlm
        Download NTLM hashes instead of SHA-1. Required for Active Directory password audits.

    .PARAMETER Update
        ETag-based incremental update. Only valid with -Single:$false. Sends If-None-Match
        headers; 304 responses skip re-downloading that range entirely.

    .PARAMETER VerifyOnly
        Validate existing local range files without contacting HIBP. Only valid with
        -Single:$false. Useful after interrupted downloads or storage maintenance.

    .PARAMETER Prefix
        Limit processing to specific prefixes or inclusive ranges.
        Examples: '00000', '00000-000FF', '00000','ABCDE','FFFFF'.

    .PARAMETER RequestTimeoutSeconds
        Per-request timeout in seconds. Default 120. Use 180+ on slow or filtered networks.

    .PARAMETER Retries
        Per-prefix retry count on failure. Default 10.

    .PARAMETER ContinueOnError
        Return stats even if some prefixes failed instead of throwing at the end.

    .OUTPUTS
        [PSCustomObject] with download statistics (Checked, Downloaded, Updated, Unchanged304,
        SkippedExisting, Verified, Invalid, Failed, BytesDownloaded).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$OutputFile = "pwnedpasswords",

        [Alias("p")]
        [ValidateRange(0, 256)]
        [int]$Parallelism = 0,

        [Alias("o")]
        [switch]$Overwrite,

        [Alias("s")]
        [switch]$Single = $true,

        [Alias("n")]
        [switch]$Ntlm,

        [switch]$Update,

        [switch]$VerifyOnly,

        [string[]]$Prefix,

        [ValidateRange(5, 3600)]
        [int]$RequestTimeoutSeconds = 120,

        [ValidateRange(0, 100)]
        [int]$Retries = 10,

        [switch]$ContinueOnError
    )

    Set-StrictMode -Version 2.0

    if ($Update -and $Single) {
        throw "Update mode is only supported with directory/range mode. Use -Single:`$false for ETag-based incremental updates. Single-file mode is a straight monolithic download."
    }
    if ($VerifyOnly -and $Single) {
        throw "VerifyOnly is only supported with directory/range mode. Use -Single:`$false."
    }

    if ($Parallelism -lt 2) {
        $Parallelism = [Math]::Max([Environment]::ProcessorCount * 2, 2)
    }

    Initialize-HibpTls12

    $prefixes = Expand-HibpPrefixes -PrefixValues $Prefix
    $modeName = if ($Ntlm) { 'NTLM' } else { 'SHA1' }
    $timer    = [Diagnostics.Stopwatch]::StartNew()

    if ($Single) {
        $exportPath = $OutputFile
        if (-not $exportPath.EndsWith('.txt', [System.StringComparison]::OrdinalIgnoreCase)) {
            $exportPath = "$exportPath.txt"
        }
        $exportPath = Resolve-HibpLocalPath $exportPath

        Write-Host "HIBP Pwned Passwords Downloader - Pure PowerShell v3.4"
        Write-Host "Mode:                  $modeName"
        Write-Host "Storage mode:          Single monolithic file"
        Write-Host "Export path:           $exportPath"
        Write-Host "Update available:      False"
        Write-Host "Prefix count:          $($prefixes.Count)"
        Write-Host "Parallelism:           not used in single-file mode"
        Write-Host "Request timeout:       $RequestTimeoutSeconds seconds"
        Write-Host "Retries:               $Retries"
        Write-Host ""

        $stats = Invoke-HibpSingleFileDownload -Prefixes $prefixes -OutputPath $exportPath -UseNtlm ([bool]$Ntlm) -DoOverwrite ([bool]$Overwrite) -TimeoutSeconds $RequestTimeoutSeconds -RetryCount $Retries
        $timer.Stop()
        Write-Host ""
        Write-Host "Single-file download complete." -ForegroundColor Green
    }
    else {
        $rangeDirectory = Resolve-HibpLocalPath $OutputFile
        $manifestDir    = Join-Path $rangeDirectory '_manifest'
        $manifestPath   = Join-Path $manifestDir ("{0}-manifest.tsv" -f ($(if ($Ntlm) { 'ntlm' } else { 'sha1' })))

        Write-Host "HIBP Pwned Passwords Downloader - Pure PowerShell v3.4"
        Write-Host "Mode:                  $modeName"
        Write-Host "Storage mode:          Directory/range cache"
        Write-Host "Range cache:           $rangeDirectory"
        Write-Host "Manifest:              $manifestPath"
        Write-Host "Update available:      True"
        Write-Host "Prefix count:          $($prefixes.Count)"
        Write-Host "Parallelism:           $Parallelism"
        Write-Host "Request timeout:       $RequestTimeoutSeconds seconds"
        Write-Host "Retries:               $Retries"
        Write-Host "Update mode:           $([bool]$Update)"
        Write-Host "Verify only:           $([bool]$VerifyOnly)"
        Write-Host ""

        $stats = Invoke-HibpDirectoryDownload -Prefixes $prefixes -RangeDirectory $rangeDirectory -ManifestPath $manifestPath -UseNtlm ([bool]$Ntlm) -DoUpdate ([bool]$Update) -DoVerifyOnly ([bool]$VerifyOnly) -DoOverwrite ([bool]$Overwrite) -WorkerCount $Parallelism -TimeoutSeconds $RequestTimeoutSeconds -RetryCount $Retries -AllowContinueOnError ([bool]$ContinueOnError)
        $timer.Stop()
        Write-Host ""
        Write-Host "Range operation complete." -ForegroundColor Green
    }

    Write-Host ("Checked:          {0:N0}" -f $stats.Checked)
    Write-Host ("Downloaded:       {0:N0}" -f $stats.Downloaded)
    Write-Host ("Updated:          {0:N0}" -f $stats.Updated)
    Write-Host ("Unchanged 304:    {0:N0}" -f $stats.Unchanged304)
    Write-Host ("Skipped existing: {0:N0}" -f $stats.SkippedExisting)
    Write-Host ("Verified:         {0:N0}" -f $stats.Verified)
    Write-Host ("Invalid:          {0:N0}" -f $stats.Invalid)
    Write-Host ("Failed:           {0:N0}" -f $stats.Failed)
    Write-Host ("Bytes downloaded: {0:N0}" -f $stats.BytesDownloaded)
    Write-Host ("Elapsed:          {0}"    -f $timer.Elapsed)

    if ($stats.Failed -gt 0 -and -not $ContinueOnError) {
        throw "One or more ranges failed. Use -ContinueOnError to allow completion despite failures."
    }

    if ($Update -and -not $Single) {
        Write-Host ""
        Write-Host "Directory/range update completed. No single-file export was built." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Done." -ForegroundColor Green

    return $stats
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
        Download or refresh the Have I Been Pwned NTLM hash database and weak password list.

    .DESCRIPTION
        Settings-aware wrapper around Start-HibpDownload. Reads $global:NtlmHashDataDir
        and $global:NtlmHashDataFile to determine download mode and output path.

        Directory mode ($global:NtlmHashDataDir is non-empty):
          Downloads range files into the named directory. The first run is detected by
          the absence of the manifest file. Subsequent runs use -Update for ETag-based
          incremental downloads -- only changed ranges are re-downloaded.

        Single-file mode ($global:NtlmHashDataDir is empty):
          Downloads one monolithic file named by $global:NtlmHashDataFile. Every run
          re-downloads the full dataset (~70 GB as of 2026).

        After the HIBP download completes, also calls Get-WeakPasswordsList to refresh
        the weak password dictionary from weakpasswords.net.

    .OUTPUTS
        [bool] $true when both downloads succeed; $false if either fails.
    #>
    try {
        [bool]$DirectoryMode = ($global:NtlmHashDataDir -ne '' -and $null -ne $global:NtlmHashDataDir)

        # Show available free disk space on the drive where hash data will be stored.
        try {
            [string]$DriveRoot    = [System.IO.Path]::GetPathRoot($global:ThisScriptDir)
            $DriveInfo            = [System.IO.DriveInfo]::new($DriveRoot)
            [string]$FreeSpaceStr = "$([math]::Round($DriveInfo.AvailableFreeSpace / 1GB, 2)) GB free on $($DriveInfo.Name)"
        }
        catch {
            [string]$FreeSpaceStr = "disk space unknown"
        }

        if ($DirectoryMode) {
            [string]$TargetDir    = "$global:ThisScriptDir\$global:NtlmHashDataDir"
            [string]$ManifestPath = "$TargetDir\_manifest\ntlm-manifest.tsv"
            [bool]$IsFirstRun     = -not (Test-Path $ManifestPath)

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

            Write-Host "Downloading HIBP NTLM hash range files (directory mode)..." -ForegroundColor Yellow
            Write-Host "Output directory: $TargetDir" -ForegroundColor Yellow

            $stats = Start-HibpDownload -OutputFile $TargetDir -Single:$false -Ntlm -Update:(-not $IsFirstRun) -Parallelism 4 -RequestTimeoutSeconds 180 -Retries 10 -ContinueOnError

            if ($stats.Failed -gt 0) {
                Write-Host "Warning: $($stats.Failed) prefix ranges failed. Re-run 'Update HIBP Database' to retry." -ForegroundColor Yellow
            }
            else {
                Write-Host "HIBP NTLM hash range files updated successfully." -ForegroundColor Green
            }

        }
        else {
            [string]$HashFilePath   = "$global:ThisScriptDir\$global:NtlmHashDataFile"
            [string]$OutputBaseName = [System.IO.Path]::GetFileNameWithoutExtension($global:NtlmHashDataFile)
            [string]$OutputBasePath = "$global:ThisScriptDir\$OutputBaseName"

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

            Write-Host "Downloading HIBP NTLM password hash file (single-file mode)..." -ForegroundColor Yellow
            Write-Host "Output file: $HashFilePath" -ForegroundColor Yellow

            $null = Start-HibpDownload -OutputFile $OutputBasePath -Ntlm -Overwrite -Parallelism 4 -RequestTimeoutSeconds 180 -Retries 10

            Write-Host "The HIBP password hash file has been downloaded and updated." -ForegroundColor Green
        }

        # Also refresh the weak password list as part of the combined update.
        Write-Host ""
        [bool]$WeakPwOk = Get-WeakPasswordsList
        return $WeakPwOk
    }
    catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

Function Test-HibpToolsInstalled {
    <#
    .SYNOPSIS
        Verify that the HIBP downloader is ready and hash data has been downloaded.

    .DESCRIPTION
        Checks two things:
          1. API reachability -- attempts a live NTLM request to api.pwnedpasswords.com for
             prefix 00000. A 200 or 304 response confirms connectivity. Any failure is reported.
          2. Hash data presence -- checks whether the configured file or directory exists and
             reports its current state. Absence means the download has not been run yet.

        Returns $true only when the API is reachable. Data presence is informational.

    .OUTPUTS
        [bool] $true if the HIBP API is reachable; $false on connectivity failure.
    #>
    [bool]$allOk = $true

    # --- API reachability check ---
    Write-Host "Checking HIBP API reachability..." -ForegroundColor Yellow
    Initialize-HibpTls12
    try {
        $testUri                  = "https://api.pwnedpasswords.com/range/00000?mode=ntlm"
        $request                  = [System.Net.HttpWebRequest]::Create($testUri)
        $request.Method           = 'GET'
        $request.UserAgent        = 'hibp-powershell-downloader-v3.4/1.0'
        $request.Timeout          = 30000
        $response                 = $request.GetResponse()
        [int]$statusCode          = [int]$response.StatusCode
        $response.Dispose()
        Write-Host "HIBP API is reachable. HTTP $statusCode" -ForegroundColor Green
    }
    catch [System.Net.WebException] {
        $webResponse = $null
        try { $webResponse = $_.Exception.Response } catch { }
        if ($null -ne $webResponse -and [int]$webResponse.StatusCode -eq 304) {
            Write-Host "HIBP API is reachable. HTTP 304 Not Modified" -ForegroundColor Green
        }
        else {
            Write-Host "HIBP API is not reachable: $($_.Exception.Message)" -ForegroundColor Red
            $allOk = $false
        }
    }
    catch {
        Write-Host "HIBP API connectivity check failed: $($_.Exception.Message)" -ForegroundColor Red
        $allOk = $false
    }

    # --- Hash data presence check ---
    Write-Host ""
    [bool]$DirectoryMode = ($global:NtlmHashDataDir -ne '' -and $null -ne $global:NtlmHashDataDir)

    if ($DirectoryMode) {
        [string]$TargetDir    = "$global:ThisScriptDir\$global:NtlmHashDataDir"
        [string]$ManifestPath = "$TargetDir\_manifest\ntlm-manifest.tsv"
        if (Test-Path $TargetDir) {
            [int]$fileCount = (Get-ChildItem -Path $TargetDir -Filter '*.txt' -ErrorAction SilentlyContinue | Measure-Object).Count
            Write-Host "Hash data directory: $TargetDir ($fileCount range files)" -ForegroundColor Green
            if (Test-Path $ManifestPath) {
                Write-Host "Manifest found -- subsequent runs will use incremental update." -ForegroundColor Green
            }
            else {
                Write-Host "No manifest found -- the initial full download has not completed yet." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "Hash data directory not found: $TargetDir" -ForegroundColor Yellow
            Write-Host "Run 'Update HIBP Database' to perform the initial download." -ForegroundColor Yellow
        }
    }
    else {
        [string]$HashFilePath = "$global:ThisScriptDir\$global:NtlmHashDataFile"
        if (Test-Path $HashFilePath) {
            $fileInfo         = Get-Item $HashFilePath
            [string]$sizeGB   = [math]::Round($fileInfo.Length / 1GB, 2)
            Write-Host "Hash file found: $HashFilePath ($sizeGB GB)" -ForegroundColor Green
        }
        else {
            Write-Host "Hash file not found: $HashFilePath" -ForegroundColor Yellow
            Write-Host "Run 'Update HIBP Database' to download it." -ForegroundColor Yellow
        }
    }

    return $allOk
}

Function Uninstall-HibpTools {
    <#
    .SYNOPSIS
        Delete the downloaded HIBP NTLM hash database files to reclaim disk space.

    .DESCRIPTION
        Identifies hash data based on $global:NtlmHashDataDir and $global:NtlmHashDataFile
        and prompts for confirmation before deleting. The embedded PowerShell downloader
        functions are part of this module and require no uninstallation -- only the
        downloaded hash data files (~70 GB) are removed here.
    #>
    [bool]$DirectoryMode = ($global:NtlmHashDataDir -ne '' -and $null -ne $global:NtlmHashDataDir)

    Write-Host ""

    if ($DirectoryMode) {
        [string]$TargetDir = "$global:ThisScriptDir\$global:NtlmHashDataDir"
        if (-not (Test-Path $TargetDir)) {
            Write-Host "Hash data directory not found: $TargetDir" -ForegroundColor Yellow
            Write-Host "Nothing to remove." -ForegroundColor Yellow
            return
        }
        [int]$fileCount = (Get-ChildItem -Path $TargetDir -Filter '*.txt' -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "This will permanently delete the HIBP hash data directory and all range files:" -ForegroundColor Yellow
        Write-Host "  $TargetDir  ($fileCount range files, approximately 70 GB)" -ForegroundColor Yellow
        Write-Host ""
        [string]$Confirm = Read-Host "Are you sure? This cannot be undone. (y/N)"
        if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
            Write-Host "Removal cancelled." -ForegroundColor Yellow
            return
        }
        try {
            Remove-Item -Path $TargetDir -Recurse -Force
            Write-Host "Removed: $TargetDir" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove directory: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        [string]$HashFilePath = "$global:ThisScriptDir\$global:NtlmHashDataFile"
        if (-not (Test-Path $HashFilePath)) {
            Write-Host "Hash file not found: $HashFilePath" -ForegroundColor Yellow
            Write-Host "Nothing to remove." -ForegroundColor Yellow
            return
        }
        $fileInfo       = Get-Item $HashFilePath
        [string]$sizeGB = [math]::Round($fileInfo.Length / 1GB, 2)
        Write-Host "This will permanently delete the HIBP hash file:" -ForegroundColor Yellow
        Write-Host "  $HashFilePath  ($sizeGB GB)" -ForegroundColor Yellow
        Write-Host ""
        [string]$Confirm = Read-Host "Are you sure? This cannot be undone. (y/N)"
        if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
            Write-Host "Removal cancelled." -ForegroundColor Yellow
            return
        }
        try {
            Remove-Item -Path $HashFilePath -Force
            Write-Host "Removed: $HashFilePath" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to remove file: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "Hash data removed. Run 'Update HIBP Database' to re-download when needed." -ForegroundColor Yellow
}

Function Show-HibpTroubleshootingGuide {
    <#
    .SYNOPSIS
        Display a troubleshooting guide for the HIBP downloader.

    .DESCRIPTION
        Prints a structured plain-text guide covering:
          - Common failure scenarios and their root causes
          - Step-by-step resolution procedures
          - Why the module uses directory-based incremental downloads
            instead of a single monolithic file
          - How the embedded Pure PowerShell downloader works
    #>

    [string]$Sep  = "=" * 78
    [string]$Sep2 = "-" * 78

    Write-Host ""
    Write-Host $Sep  -ForegroundColor Cyan
    Write-Host "  HIBP DOWNLOADER -- TROUBLESHOOTING GUIDE" -ForegroundColor Cyan
    Write-Host $Sep  -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This guide covers common failures with the Have I Been Pwned (HIBP) NTLM"
    Write-Host "password hash downloader, procedures for resolving them, and the rationale"
    Write-Host "for the directory-based download model."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 1: COMMON FAILURES AND ROOT CAUSES" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "1. API connectivity failure"
    Write-Host "   CAUSE: Network filtering, DNS failure, or HIBP service unavailability."
    Write-Host "   FIX: Run 'Test HIBP Readiness' to check connectivity. Verify that"
    Write-Host "   api.pwnedpasswords.com is reachable on port 443 from the server."
    Write-Host ""

    Write-Host "2. CloudFlare rate limiting during a large download"
    Write-Host "   CAUSE: Too many parallel connections trigger CloudFlare's throttling."
    Write-Host "   FIX: Get-HibpPasswordHashesFiles passes -Parallelism 4 by default."
    Write-Host "   If calling Start-HibpDownload directly, keep -Parallelism at 4 or lower"
    Write-Host "   for full-dataset runs. Use higher values only for small prefix ranges."
    Write-Host ""

    Write-Host "3. Network timeout on a large first-run download"
    Write-Host "   CAUSE: Individual prefix downloads exceed the request timeout."
    Write-Host "   FIX: Get-HibpPasswordHashesFiles passes -RequestTimeoutSeconds 180."
    Write-Host "   The downloader also retries each prefix up to 10 times with backoff."
    Write-Host "   If failures persist, re-run the update -- the manifest preserves progress"
    Write-Host "   and only missing or failed ranges are re-downloaded."
    Write-Host ""

    Write-Host "4. Partial download or interrupted job"
    Write-Host "   CAUSE: Session ended, network dropped, or the server rebooted mid-run."
    Write-Host "   FIX: The downloader writes to .part files and only moves them into place"
    Write-Host "   after validation succeeds. Interrupted .part files are cleaned up on the"
    Write-Host "   next run. Simply re-run 'Update HIBP Database' to continue from where"
    Write-Host "   it stopped (in directory mode, already-complete ranges are skipped)."
    Write-Host ""

    Write-Host "5. Output file already exists error (single-file mode)"
    Write-Host "   CAUSE: The monolithic .txt file exists and -Overwrite was not passed."
    Write-Host "   FIX: Get-HibpPasswordHashesFiles always passes -Overwrite in single-file"
    Write-Host "   mode. If calling Start-HibpDownload directly, add -Overwrite."
    Write-Host ""

    Write-Host "6. 'Update mode is only supported with directory/range mode' error"
    Write-Host "   CAUSE: -Update was passed with the default -Single mode."
    Write-Host "   FIX: Use -Single:`$false when specifying -Update. Or use Get-HibpPassword-"
    Write-Host "   HashesFiles, which selects the correct flags automatically."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 2: STEP-BY-STEP RESOLUTION PROCEDURE" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Follow these steps in order when the downloader is not functioning correctly."
    Write-Host ""

    Write-Host "  Step 1 -- Check current state"
    Write-Host "    Select 'Test HIBP Readiness' from this submenu."
    Write-Host "    Checks API reachability and reports whether hash data is present."
    Write-Host ""

    Write-Host "  Step 2 -- Re-run the download"
    Write-Host "    Select 'Update HIBP Database' from this submenu."
    Write-Host "    In directory mode, the manifest preserves completed ranges. A re-run"
    Write-Host "    skips already-downloaded prefixes and retries only missing or failed ones."
    Write-Host ""

    Write-Host "  Step 3 (advanced) -- Remove and re-download from scratch"
    Write-Host "    Select 'Remove HIBP Hash Data' to delete the local database."
    Write-Host "    Then select 'Update HIBP Database' to start a fresh full download."
    Write-Host "    Note: a full re-download is approximately 70 GB."
    Write-Host ""

    Write-Host "  Step 4 -- Check the failure log"
    Write-Host "    If failures occurred, a log file is written to the Reports directory:"
    Write-Host "    $global:ReportsPath"
    Write-Host "    The log file is named ntlm-hibp-failures-YYYYMMDD-HHMMSS.log and lists"
    Write-Host "    each failed prefix and its error message."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 3: SINGLE-FILE VS DIRECTORY MODE (WHY WE CHANGED)" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "SINGLE-FILE MODE (original approach)"
    Write-Host "  All hashes are downloaded into one large sorted flat file, for example:"
    Write-Host "    pwned-passwords-ntlm-ordered-by-hash-v8.txt"
    Write-Host "  As of 2026 this file is approximately 70 GB. The password audit module"
    Write-Host "  passes it to DSInternals via Test-PasswordQuality -WeakPasswordHashesSorted-"
    Write-Host "  File for breach detection."
    Write-Host ""
    Write-Host "  PROBLEM: Every update re-downloads the entire 70 GB file even when only a"
    Write-Host "  small fraction of hashes changed. This is extremely inefficient for regular"
    Write-Host "  weekly maintenance."
    Write-Host ""

    Write-Host "DIRECTORY MODE (current, recommended)"
    Write-Host "  Hashes are stored as individual range files named by their 5-character hex"
    Write-Host "  prefix (e.g. A3B4C.txt). Each file contains SUFFIX:count lines for all"
    Write-Host "  hashes in that prefix range. There are 1,048,576 prefix ranges in total."
    Write-Host ""
    Write-Host "  On subsequent runs with -Update, the downloader sends the stored ETag for"
    Write-Host "  each prefix. The server returns 304 Not Modified for unchanged ranges --"
    Write-Host "  no response body is downloaded. A typical weekly refresh transfers only a"
    Write-Host "  small fraction of the full 70 GB dataset."
    Write-Host ""
    Write-Host "  To enable directory mode, set this in AD-PowerAdmin_settings.ps1:"
    Write-Host "    `$global:NtlmHashDataDir = 'hibp-ntlm-hashes'"
    Write-Host "  Leave `$global:NtlmHashDataDir = '' to stay in single-file mode."
    Write-Host "  Both modes are fully supported. The module auto-detects from the setting."
    Write-Host ""

    Write-Host "AUDIT LOGIC IN DIRECTORY MODE"
    Write-Host "  DSInternals Test-PasswordQuality requires a single sorted file and cannot"
    Write-Host "  be used directly with directory-mode range files. A custom function"
    Write-Host "  (Test-NtlmHashesInDirectory in AD-PowerAdmin_PasswordsCtl.psm1) handles"
    Write-Host "  directory-mode lookups instead."
    Write-Host ""
    Write-Host "  That function groups all AD accounts by their 5-character NTLM hash prefix,"
    Write-Host "  reads each corresponding range file exactly once, and returns the"
    Write-Host "  SamAccountName of each breached account. Results are merged into the"
    Write-Host "  PasswordQualityTestResult object so that Invoke-WeakPwdProcess sends"
    Write-Host "  notification emails and schedules follow-up tasks identically in both modes."
    Write-Host ""

    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host "  SECTION 4: HOW THE PURE POWERSHELL DOWNLOADER WORKS" -ForegroundColor Yellow
    Write-Host $Sep2 -ForegroundColor Yellow
    Write-Host ""

    Write-Host "The downloader is embedded directly in this module (no separate executable"
    Write-Host "or .NET SDK required). Key design points:"
    Write-Host ""
    Write-Host "  - Uses System.Net.HttpWebRequest for downloads (not Invoke-WebRequest)."
    Write-Host "    This avoids PowerShell's built-in HTTP client limitations with large"
    Write-Host "    payloads and provides direct access to response headers (ETag)."
    Write-Host ""
    Write-Host "  - Directory mode uses Start-Job for parallelism (PS 5.1 compatible)."
    Write-Host "    Each worker gets a subset of prefixes, writes intermediate TSV result"
    Write-Host "    files, and the parent aggregates results after all workers complete."
    Write-Host ""
    Write-Host "  - TLS 1.2 is explicitly enabled in each worker process because Start-Job"
    Write-Host "    creates new PowerShell processes that do not inherit the parent session's"
    Write-Host "    ServicePointManager settings."
    Write-Host ""
    Write-Host "  - Downloads write to .part files first. A .part file is only renamed to"
    Write-Host "    the final .txt file after format validation succeeds. Interrupted"
    Write-Host "    downloads never leave corrupt range files in place."
    Write-Host ""
    Write-Host "  - Failure logs (if any) are written to:"
    Write-Host "    $global:ReportsPath"
    Write-Host ""

    Write-Host $Sep  -ForegroundColor Cyan
    Write-Host "  End of troubleshooting guide." -ForegroundColor Cyan
    Write-Host $Sep  -ForegroundColor Cyan
    Write-Host ""
}
