#requires -Version 5.1
<#
.SYNOPSIS
    Pure PowerShell 5.1 downloader for the Have I Been Pwned Pwned Passwords range API.

.DESCRIPTION
    Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 is a pure PowerShell implementation of a
    Have I Been Pwned Pwned Passwords downloader. It is intended to provide similar
    command-line behavior to the original HIBP downloader while fixing several operational
    problems that can occur with very large downloads.

    This script was intentionally written for Windows PowerShell 5.1 compatibility.

    Important design goals:
      - No Add-Type.
      - No embedded C#.
      - No external modules.
      - No PowerShell 7-only syntax.
      - Works in standard Windows PowerShell 5.1 environments.
      - Uses TLS 1.2 explicitly in the parent session and worker jobs.
      - Supports NTLM mode with the same endpoint behavior as the original downloader.
      - Supports safe resumable directory/range-cache downloads.
      - Supports ETag-based bandwidth-saving updates in directory/range-cache mode.
      - Keeps single-file mode as a straight monolithic download only.

    The script supports two storage modes:

    1. Single-file mode
       This mode creates one large monolithic text file.

       Example output:
         .\pwnedpasswords.txt
         .\pwnedpasswords-ntlm.txt

       In this mode, the script streams each selected HIBP prefix range into one final
       output file. Each output line is expanded to the full hash plus count:

         <FULL_HASH>:<COUNT>

       For NTLM, the remote response contains a 27-character suffix and count. The script
       prepends the 5-character prefix to produce the full 32-character NTLM hash.

       For SHA-1, the remote response contains a 35-character suffix and count. The script
       prepends the 5-character prefix to produce the full 40-character SHA-1 hash.

       Single-file mode does not support -Update. This is intentional. A monolithic file is
       not efficient to incrementally update because a change to one prefix range can alter
       byte offsets and line counts throughout the combined export. Supporting safe in-place
       updates would require a separate complex index and rewrite logic. To keep the tool
       readable and safe, single-file mode is treated as a straight download/export only.

    2. Directory/range-cache mode
       This mode creates one small file per 5-character HIBP range prefix.

       Example output:
         .\pwnedpasswords-ntlm-ranges\
           00000.txt
           00001.txt
           00002.txt
           ...
           FFFFF.txt
           _manifest\
             ntlm-manifest.tsv
             ntlm-failures-YYYYMMDD-HHMMSS.log
             jobs-YYYYMMDD-HHMMSS\
               worker-1-results.tsv
               worker-1-failures.tsv
               ...

       In this mode, each range file stores the raw HIBP range response for that prefix:

         <SUFFIX>:<COUNT>

       The prefix is represented by the file name. For example, 00000.txt contains suffixes
       that belong to prefix 00000.

       Directory/range-cache mode is the authoritative mode for ongoing maintenance. It is
       the only mode that supports -Update because the script can use one ETag per prefix
       range and can replace only the range files that changed.

    Update behavior:
       -Update is only valid with -Single:$false.

       During an update, the script reads the manifest and attempts to use the stored ETag
       for each prefix. It sends the ETag back to the HIBP range endpoint using:

         If-None-Match: <stored-etag>

       If the server returns:
         304 Not Modified
           The local range file is considered unchanged.
           No response body is downloaded.
           Bandwidth usage for that prefix is effectively avoided.

         200 OK
           The range changed, or no usable ETag was available.
           The script downloads a new .part file, validates it, replaces the old .txt file,
           and updates the manifest metadata.

       If a range download fails:
           The existing final .txt file is preserved.
           The failed range is logged.
           The script retries according to -Retries.
           If failures remain and -ContinueOnError is not used, the script exits with an error.

    Safety behavior:
       Directory/range-cache mode writes downloads to temporary .part files first.
       A .part file is only moved into place as the final .txt file after validation succeeds.
       This prevents partial or interrupted downloads from being mistaken for complete files.

       Single-file mode writes to a temporary .part file and renames it to the final .txt file
       only after all selected ranges have completed successfully.

    Validation behavior:
       The HIBP range API returns suffix:count lines. The script validates that every non-empty
       line in a downloaded range file matches the expected mode-specific format.

       SHA-1 mode:
         Full hash length:   40 hex characters
         Prefix length:       5 hex characters
         Suffix length:      35 hex characters
         Expected line:      ^[0-9A-F]{35}:[0-9]+$

       NTLM mode:
         Full hash length:   32 hex characters
         Prefix length:       5 hex characters
         Suffix length:      27 hex characters
         Expected line:      ^[0-9A-F]{27}:[0-9]+$

    Manifest behavior:
       Directory/range-cache mode stores a tab-separated manifest under the _manifest folder.
       The manifest records local integrity and remote caching metadata, including:
         - Prefix
         - Mode
         - Path
         - ETag
         - LastModified
         - Length
         - Sha256
         - LineCount
         - DownloadedUtc

       The ETag is what enables bandwidth-saving updates. The SHA256, length, and line count
       values are used for local verification and operational auditing.

    Parallelism behavior:
       Directory/range-cache mode uses Start-Job worker jobs for PowerShell 5.1-compatible
       parallel downloads. Each worker gets a subset of prefixes, writes worker result logs,
       and returns summary data to the parent process.

       Single-file mode is intentionally sequential. This avoids building a full range cache
       as temporary data and avoids keeping two copies of the database on disk. The tradeoff is
       that single-file mode is slower than directory/range-cache mode.

    TLS behavior:
       Windows PowerShell 5.1 can default to older TLS settings. HIBP/Cloudflare requires a
       modern TLS negotiation. This script explicitly enables TLS 1.2 in the parent session
       and again inside every Start-Job worker process.

.PARAMETER OutputFile
    Output target name or path.

    In single-file mode, OutputFile is treated as the base name for the final text file.
    If the value does not end in .txt, the script appends .txt.

    Example:
      -OutputFile .\pwnedpasswords-ntlm

    Produces:
      .\pwnedpasswords-ntlm.txt

    In directory/range-cache mode, OutputFile is treated as the directory that stores the
    per-prefix range files and the _manifest folder.

    Example:
      -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges

    Produces:
      .\pwnedpasswords-ntlm-ranges\00000.txt
      .\pwnedpasswords-ntlm-ranges\00001.txt
      .\pwnedpasswords-ntlm-ranges\_manifest\ntlm-manifest.tsv

.PARAMETER Parallelism
    Alias: -p

    Number of parallel worker jobs to use in directory/range-cache mode.
    If omitted or less than 2, the script chooses a default based on CPU count.

    Recommended starting values:
      -p 4   conservative
      -p 8   normal
      -p 16  faster, but more network and server pressure

    This value is intentionally capped to prevent accidental excessive concurrency.
    Single-file mode does not use parallel workers.

.PARAMETER Overwrite
    Alias: -o

    Allows the script to overwrite an existing single-file output file or existing range
    files during a non-update directory download.

    Without -Overwrite:
      - Single-file mode refuses to replace an existing final output file.
      - Directory/range-cache mode can skip existing complete files when not updating.

    In update mode, changed range files are replaced as part of the update process after
    validation succeeds.

.PARAMETER Single
    Alias: -s

    Controls storage mode.

    Default:
      -Single is enabled by default, matching the original downloader's general behavior.

    Use:
      -Single:$false

    to select directory/range-cache mode.

    Single-file mode:
      - Creates one monolithic .txt file.
      - Does not support -Update.
      - Does not maintain a range cache.

    Directory/range-cache mode:
      - Creates one .txt file per prefix.
      - Maintains a manifest.
      - Supports ETag-based -Update.
      - Is the recommended mode for ongoing NTLM database maintenance.

.PARAMETER Ntlm
    Alias: -n

    Downloads the NTLM version of the HIBP Pwned Passwords dataset.

    When this switch is used, requests are made with:

      ?mode=ntlm

    NTLM mode expects a 32-character full hash:
      5-character prefix + 27-character suffix

    Without -Ntlm, the script downloads SHA-1 mode by default.

.PARAMETER Update
    Performs an ETag-based incremental update.

    This parameter is only supported with directory/range-cache mode:

      -Single:$false -Update

    It is intentionally blocked in single-file mode.

    In update mode, the script:
      - Loads the manifest.
      - Sends If-None-Match for prefixes that have stored ETags.
      - Treats 304 Not Modified as unchanged.
      - Downloads and replaces only ranges that return 200 OK.
      - Preserves existing final files when an update attempt fails.

.PARAMETER VerifyOnly
    Verifies existing local range files against expected formatting.

    This parameter is only supported with directory/range-cache mode.
    It does not download new remote data.

    Use this to check local cache health after interrupted jobs, disk events, copies,
    backups, or other maintenance.

.PARAMETER Prefix
    Limits processing to one or more specific prefixes or inclusive prefix ranges.

    Valid HIBP prefixes are 5 hexadecimal characters from 00000 through FFFFF.

    Examples:
      -Prefix '00000'
      -Prefix '00000','00001','ABCDE','FFFFF'
      -Prefix '00000-000FF'
      -Prefix '0-FF'

    Short numeric-looking prefixes are normalized by left-padding to 5 characters.
    For reliability in Windows PowerShell, quote ranges:

      -Prefix '00000-000FF'

    If -Prefix is omitted, the script processes all 1,048,576 prefixes.

.PARAMETER RequestTimeoutSeconds
    Timeout in seconds for each HTTP request.

    Default:
      120

    Recommended for large jobs:
      180 or higher on slower or filtered networks

    This replaces the flawed short timeout behavior that can cause large download jobs to
    report errors or partial completion under slow network conditions.

.PARAMETER Retries
    Number of retry attempts per prefix after a failed request or validation error.

    Default:
      10

    The script waits briefly between retries and then tries the same prefix again.
    If all retries fail, the prefix is logged as failed.

.PARAMETER ContinueOnError
    Allows the script to finish and return summary output even if some prefixes failed.

    Without this switch, the script throws at the end if any ranges failed.

    This is useful for large long-running jobs where you want to collect a failure list,
    then rerun only failed or missing ranges later.

.EXAMPLE
    .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges -Prefix '00000-000FF' -p 8 -RequestTimeoutSeconds 180 -Retries 12

    Downloads NTLM prefixes 00000 through 000FF into a directory/range cache.

.EXAMPLE
    .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges -Prefix '00000-000FF' -Update -p 8 -RequestTimeoutSeconds 180 -Retries 12

    Performs an ETag-based update for the same NTLM range cache. Unchanged ranges should
    return 304 Not Modified and consume no body-download bandwidth.

.EXAMPLE
    .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -OutputFile .\pwnedpasswords-ntlm -Prefix '00000-000FF' -p 8 -RequestTimeoutSeconds 180 -Retries 12 -o

    Creates a single monolithic NTLM output file for prefixes 00000 through 000FF.
    The -p value is accepted for command compatibility, but single-file mode is sequential.

.EXAMPLE
    .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges -Update -p 8 -RequestTimeoutSeconds 180 -Retries 12

    Performs a full NTLM update across all 1,048,576 prefixes using the existing manifest
    and range cache.

.EXAMPLE
    .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges -VerifyOnly

    Validates the existing NTLM range cache without contacting HIBP.

.NOTES
    Version: 3.4
    Target PowerShell: Windows PowerShell 5.1
    External modules: None
    Embedded C#: None
    Add-Type usage: None

    Recommended operational model:
      Use directory/range-cache mode for the maintained local NTLM database.
      Use single-file mode only when a downstream tool specifically requires one giant file.

    Recommended NTLM directory/range-cache command:
      .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges -p 8 -RequestTimeoutSeconds 180 -Retries 12

    Recommended NTLM update command:
      .\Invoke-HibpPwnedPasswordsDownload-v3.4.ps1 -n -Single:$false -OutputFile .\pwnedpasswords-ntlm-ranges -Update -p 8 -RequestTimeoutSeconds 180 -Retries 12

    Do not use the HIBP Add-Padding option for offline mirroring. Padded responses can contain
    random zero-count records and are designed for privacy-preserving live lookups, not stable
    deterministic offline range files.

    A full dataset run processes 1,048,576 prefix ranges. Test smaller ranges first before
    running the full NTLM dataset.
.LINK
	https://github.com/Brets0150/AD-PowerAdmin

.NOTES
	Author: Bret.s AKA: CyberGladius / License: MIT
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
$ErrorActionPreference = 'Stop'

function Initialize-HibpTls12 {
    <#
        Windows PowerShell 5.1 often defaults to older TLS settings, and Start-Job
        launches separate PowerShell processes that do not inherit the parent
        session's ServicePointManager settings. HIBP/Cloudflare requires a modern
        TLS negotiation, so every process/runspace that performs Invoke-WebRequest
        must explicitly enable TLS 1.2.
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

Initialize-HibpTls12

function Resolve-LocalPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function ConvertTo-HibpPrefix {
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
        throw "Invalid prefix '$Value'. Prefixes must be exactly 5 hexadecimal characters after normalization. Example: -Prefix '00000','00001','ABCDE','FFFFF'. Range syntax is also supported: -Prefix '00000-000FF'."
    }

    return $raw
}

function Expand-HibpPrefixes {
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
            $endPrefix = ConvertTo-HibpPrefix $Matches[2]
            $start = [Convert]::ToInt32($startPrefix, 16)
            $end = [Convert]::ToInt32($endPrefix, 16)
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

function Get-HibpRangeUri {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][bool]$UseNtlm
    )

    if ($UseNtlm) {
        return "https://api.pwnedpasswords.com/range/$Prefix`?mode=ntlm"
    }

    return "https://api.pwnedpasswords.com/range/$Prefix"
}

function Get-HeaderValue {
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

function Invoke-HibpDownloadToFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [string]$ETag,
        [int]$TimeoutSeconds = 120,
        [int]$Retries = 10
    )

    $attempt = 0
    $maxAttempts = $Retries + 1
    $lastError = $null

    while ($attempt -lt $maxAttempts) {
        $attempt++
        if (Test-Path -LiteralPath $OutFile) {
            Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue
        }

        $response = $null
        $inputStream = $null
        $outputStream = $null

        try {
            $request = [System.Net.HttpWebRequest]::Create($Uri)
            $request.Method = 'GET'
            $request.UserAgent = 'hibp-powershell-downloader-v3.3/1.0'
            $request.Timeout = $TimeoutSeconds * 1000
            $request.ReadWriteTimeout = $TimeoutSeconds * 1000
            $request.KeepAlive = $true
            try { $request.AutomaticDecompression = ([System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate) } catch { }

            if (-not [string]::IsNullOrWhiteSpace($ETag)) {
                $request.Headers['If-None-Match'] = $ETag
            }

            $response = $request.GetResponse()
            $statusCode = [int]$response.StatusCode

            $inputStream = $response.GetResponseStream()
            $outputStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $buffer = New-Object byte[] 65536
            while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $outputStream.Write($buffer, 0, $read)
            }
            $outputStream.Flush()

            return [pscustomobject]@{
                StatusCode   = $statusCode
                ETag         = Get-HeaderValue -Headers $response.Headers -Name 'ETag'
                LastModified = Get-HeaderValue -Headers $response.Headers -Name 'Last-Modified'
                OutFile      = $OutFile
                Error        = $null
            }
        }
        catch [System.Net.WebException] {
            $lastError = $_
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
                            ETag         = Get-HeaderValue -Headers $webResponse.Headers -Name 'ETag'
                            LastModified = Get-HeaderValue -Headers $webResponse.Headers -Name 'Last-Modified'
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
            if ($null -ne $inputStream) { $inputStream.Dispose() }
            if ($null -ne $response) { $response.Dispose() }
        }
    }

    throw $lastError
}

function Test-HibpRangeFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$UseNtlm
    )

    $suffixLength = 35
    if ($UseNtlm) { $suffixLength = 27 }
    $pattern = '^[0-9A-F]{' + $suffixLength + '}:[0-9]+$'

    $lineCount = 0
    $reader = $null
    try {
        $reader = New-Object System.IO.StreamReader($Path)
        while (($line = $reader.ReadLine()) -ne $null) {
            if ($line.Length -eq 0) { continue }
            if ($line -notmatch $pattern) {
                return [pscustomobject]@{
                    Valid = $false
                    LineCount = $lineCount
                    Message = "Invalid line format: $line"
                }
            }
            $lineCount++
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }

    return [pscustomobject]@{
        Valid = $true
        LineCount = $lineCount
        Message = ''
    }
}

function Load-HibpManifest {
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

function Save-HibpManifest {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Manifest,
        [Parameter(Mandatory = $true)][string]$ManifestPath
    )

    $dir = Split-Path -Parent $ManifestPath
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $tmp = "$ManifestPath.part"
    $rows = foreach ($key in ($Manifest.Keys | Sort-Object)) {
        $Manifest[$key]
    }
    $rows | Export-Csv -LiteralPath $tmp -Delimiter "`t" -NoTypeInformation -Encoding UTF8
    Move-Item -LiteralPath $tmp -Destination $ManifestPath -Force
}

function Split-ArrayEvenly {
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

function Invoke-DirectoryMode {
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

    $manifest = Load-HibpManifest -ManifestPath $ManifestPath
    $etagMap = @{}
    foreach ($key in $manifest.Keys) {
        $etagMap[$key] = $manifest[$key].ETag
    }

    $jobRoot = Join-Path $manifestDir ("jobs-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $jobRoot -Force | Out-Null

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
            $attempt = 0
            $maxAttempts = $Retries + 1
            $lastError = $null

            while ($attempt -lt $maxAttempts) {
                $attempt++
                if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }

                $response = $null
                $inputStream = $null
                $outputStream = $null

                try {
                    $request = [System.Net.HttpWebRequest]::Create($Uri)
                    $request.Method = 'GET'
                    $request.UserAgent = 'hibp-powershell-downloader-v3.3/1.0'
                    $request.Timeout = $TimeoutSeconds * 1000
                    $request.ReadWriteTimeout = $TimeoutSeconds * 1000
                    $request.KeepAlive = $true
                    try { $request.AutomaticDecompression = ([System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate) } catch { }
                    if (-not [string]::IsNullOrWhiteSpace($ETag)) { $request.Headers['If-None-Match'] = $ETag }

                    $response = $request.GetResponse()
                    $statusCode = [int]$response.StatusCode

                    $inputStream = $response.GetResponseStream()
                    $outputStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                    $buffer = New-Object byte[] 65536
                    while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                        $outputStream.Write($buffer, 0, $read)
                    }
                    $outputStream.Flush()

                    return [pscustomobject]@{ StatusCode = $statusCode; ETag = (Get-HeaderValueLocal $response.Headers 'ETag'); LastModified = (Get-HeaderValueLocal $response.Headers 'Last-Modified'); OutFile = $OutFile }
                }
                catch [System.Net.WebException] {
                    $lastError = $_
                    $webResponse = $null
                    try { $webResponse = $_.Exception.Response } catch { $webResponse = $null }
                    if ($null -ne $webResponse) {
                        try {
                            $statusCode = [int]$webResponse.StatusCode
                            if ($statusCode -eq 304) {
                                if (Test-Path -LiteralPath $OutFile) { Remove-Item -LiteralPath $OutFile -Force -ErrorAction SilentlyContinue }
                                return [pscustomobject]@{ StatusCode = 304; ETag = (Get-HeaderValueLocal $webResponse.Headers 'ETag'); LastModified = (Get-HeaderValueLocal $webResponse.Headers 'Last-Modified'); OutFile = $null }
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
                    if ($null -ne $inputStream) { $inputStream.Dispose() }
                    if ($null -ne $response) { $response.Dispose() }
                }
            }
            throw $lastError
        }

        function Test-HibpRangeFileLocal {
            param([string]$Path, [bool]$UseNtlm)
            $suffixLength = 35
            if ($UseNtlm) { $suffixLength = 27 }
            $pattern = '^[0-9A-F]{' + $suffixLength + '}:[0-9]+$'
            $lineCount = 0
            $reader = $null
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
            param([string]$Path, [object[]]$Values)
            $safe = foreach ($v in $Values) {
                if ($null -eq $v) { '' } else { ([string]$v).Replace("`t", ' ').Replace("`r", ' ').Replace("`n", ' ') }
            }
            Add-Content -LiteralPath $Path -Encoding UTF8 -Value ($safe -join "`t")
        }

        Set-Content -LiteralPath $WorkerResultPath -Encoding UTF8 -Value "Prefix`tStatus`tBytes`tETag`tLastModified`tLength`tSha256`tLineCount`tDownloadedUtc`tMessage"
        Set-Content -LiteralPath $WorkerFailurePath -Encoding UTF8 -Value "Prefix`tError"

        foreach ($prefix in $WorkerPrefixes) {
            $finalPath = Join-Path $WorkerRangeDirectory ("$prefix.txt")
            $partPath = Join-Path $WorkerRangeDirectory ("$prefix.txt.part")
            $exists = Test-Path -LiteralPath $finalPath

            try {
                if ($WorkerDoVerifyOnly) {
                    if (-not $exists) { throw "Missing range file." }
                    $validation = Test-HibpRangeFileLocal -Path $finalPath -UseNtlm $WorkerUseNtlm
                    if (-not $validation.Valid) { throw $validation.Message }
                    $fileInfo = Get-Item -LiteralPath $finalPath
                    $sha = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash
                    Write-TsvLineLocal $WorkerResultPath @($prefix, 'Verified', 0, $WorkerEtagMap[$prefix], '', $fileInfo.Length, $sha, $validation.LineCount, '', '')
                    continue
                }

                if (-not $WorkerDoUpdate -and $exists -and -not $WorkerDoOverwrite) {
                    $validation = Test-HibpRangeFileLocal -Path $finalPath -UseNtlm $WorkerUseNtlm
                    if (-not $validation.Valid) { throw $validation.Message }
                    $fileInfo = Get-Item -LiteralPath $finalPath
                    $sha = (Get-FileHash -LiteralPath $finalPath -Algorithm SHA256).Hash
                    Write-TsvLineLocal $WorkerResultPath @($prefix, 'SkippedExisting', 0, $WorkerEtagMap[$prefix], '', $fileInfo.Length, $sha, $validation.LineCount, '', '')
                    continue
                }

                $etag = $null
                if ($WorkerDoUpdate -and $exists -and $WorkerEtagMap.ContainsKey($prefix)) {
                    $etag = [string]$WorkerEtagMap[$prefix]
                }

                $uri = Get-HibpRangeUriLocal -Prefix $prefix -UseNtlm $WorkerUseNtlm
                $response = Invoke-HibpDownloadToFileLocal -Uri $uri -OutFile $partPath -ETag $etag -TimeoutSeconds $WorkerTimeoutSeconds -Retries $WorkerRetryCount

                if ($response.StatusCode -eq 304) {
                    Write-TsvLineLocal $WorkerResultPath @($prefix, 'Unchanged304', 0, $response.ETag, $response.LastModified, '', '', '', '', '')
                    continue
                }

                $validation = Test-HibpRangeFileLocal -Path $partPath -UseNtlm $WorkerUseNtlm
                if (-not $validation.Valid) { throw $validation.Message }

                $partInfo = Get-Item -LiteralPath $partPath
                $length = $partInfo.Length
                $sha = (Get-FileHash -LiteralPath $partPath -Algorithm SHA256).Hash
                $status = 'Downloaded'
                if ($exists -and $WorkerDoUpdate) { $status = 'Updated' }

                Move-Item -LiteralPath $partPath -Destination $finalPath -Force
                Write-TsvLineLocal $WorkerResultPath @($prefix, $status, $length, $response.ETag, $response.LastModified, $length, $sha, $validation.LineCount, ([DateTime]::UtcNow.ToString('o')), '')
            }
            catch {
                if (Test-Path -LiteralPath $partPath) { Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue }
                Write-TsvLineLocal $WorkerResultPath @($prefix, 'Failed', 0, '', '', '', '', '', '', $_.Exception.Message)
                Write-TsvLineLocal $WorkerFailurePath @($prefix, $_.Exception.Message)
            }
        }
    }

    $workerCount = [Math]::Max(1, [Math]::Min($WorkerCount, $Prefixes.Count))
    $buckets = Split-ArrayEvenly -Items $Prefixes -BucketCount $workerCount
    $jobs = @()

    for ($i = 0; $i -lt $workerCount; $i++) {
        $bucketArray = @($buckets[$i].ToArray())
        if ($bucketArray.Count -eq 0) { continue }
        $resultPath = Join-Path $jobRoot ("worker-$i-results.tsv")
        $failurePath = Join-Path $jobRoot ("worker-$i-failures.tsv")
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

    Wait-Job -Job $jobs | Out-Null
    foreach ($job in $jobs) {
        Receive-Job -Job $job | Out-Null
        Remove-Job -Job $job -Force
    }

    $stats = [ordered]@{
        Checked = $Prefixes.Count
        Downloaded = 0
        Updated = 0
        Unchanged304 = 0
        SkippedExisting = 0
        Verified = 0
        Invalid = 0
        Failed = 0
        BytesDownloaded = [int64]0
    }

    $failureLog = Join-Path $manifestDir ("{0}-failures-{1}.log" -f ($(if ($UseNtlm) { 'ntlm' } else { 'sha1' }), (Get-Date -Format 'yyyyMMdd-HHmmss')))
    $failureLines = New-Object 'System.Collections.Generic.List[string]'

    Get-ChildItem -LiteralPath $jobRoot -Filter '*-results.tsv' | ForEach-Object {
        $rows = Import-Csv -LiteralPath $_.FullName -Delimiter "`t"
        foreach ($row in $rows) {
            switch ($row.Status) {
                'Downloaded' { $stats.Downloaded++ }
                'Updated' { $stats.Updated++ }
                'Unchanged304' { $stats.Unchanged304++ }
                'SkippedExisting' { $stats.SkippedExisting++ }
                'Verified' { $stats.Verified++ }
                'Failed' { $stats.Failed++ }
                default { }
            }
            if ($row.Status -eq 'Failed') {
                [void]$failureLines.Add(("{0}: {1}" -f $row.Prefix, $row.Message))
                continue
            }
            if ($row.Status -in @('Downloaded','Updated','Verified','SkippedExisting')) {
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
                    if (-not [string]::IsNullOrWhiteSpace($row.ETag)) { $manifest[$row.Prefix].ETag = $row.ETag }
                    if (-not [string]::IsNullOrWhiteSpace($row.LastModified)) { $manifest[$row.Prefix].LastModified = $row.LastModified }
                }
            }
            $bytes = 0L
            [void][int64]::TryParse([string]$row.Bytes, [ref]$bytes)
            $stats.BytesDownloaded += $bytes
        }
    }

    Save-HibpManifest -Manifest $manifest -ManifestPath $ManifestPath
    Remove-Item -LiteralPath $jobRoot -Recurse -Force -ErrorAction SilentlyContinue

    if ($failureLines.Count -gt 0) {
        $failureLines | Set-Content -LiteralPath $failureLog -Encoding UTF8
        Write-Warning "Some ranges failed. Failure log: $failureLog"
    }

    return [pscustomobject]$stats
}

function Invoke-SingleFileMode {
    param(
        [string[]]$Prefixes,
        [string]$OutputPath,
        [bool]$UseNtlm,
        [bool]$DoOverwrite,
        [int]$TimeoutSeconds,
        [int]$RetryCount
    )

    if ((Test-Path -LiteralPath $OutputPath) -and -not $DoOverwrite) {
        throw "Output file '$OutputPath' already exists. Use -o or -Overwrite to replace it."
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $partOutput = "$OutputPath.part"
    $tempRange = "$OutputPath.range.part"
    if (Test-Path -LiteralPath $partOutput) { Remove-Item -LiteralPath $partOutput -Force }
    if (Test-Path -LiteralPath $tempRange) { Remove-Item -LiteralPath $tempRange -Force }

    $stats = [ordered]@{
        Checked = $Prefixes.Count
        Downloaded = 0
        Updated = 0
        Unchanged304 = 0
        SkippedExisting = 0
        Verified = 0
        Invalid = 0
        Failed = 0
        BytesDownloaded = [int64]0
    }

    $writer = $null
    try {
        $writer = New-Object System.IO.StreamWriter($partOutput, $false, [System.Text.Encoding]::ASCII, 1048576)
        foreach ($prefix in $Prefixes) {
            try {
                $uri = Get-HibpRangeUri -Prefix $prefix -UseNtlm $UseNtlm
                $response = Invoke-HibpDownloadToFile -Uri $uri -OutFile $tempRange -TimeoutSeconds $TimeoutSeconds -Retries $RetryCount
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

    Move-Item -LiteralPath $partOutput -Destination $OutputPath -Force
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        throw "Single-file mode completed but expected output file was not found: $OutputPath"
    }

    return [pscustomobject]$stats
}

# Main validation
if ($Update -and $Single) {
    throw "Update mode is only supported with directory/range mode. Use -Single:`$false for ETag-based incremental updates. Single-file mode is a straight monolithic download and cannot be incrementally updated."
}
if ($VerifyOnly -and $Single) {
    throw "VerifyOnly is only supported with directory/range mode. Use -Single:`$false."
}

if ($Parallelism -lt 2) {
    $Parallelism = [Math]::Max([Environment]::ProcessorCount * 2, 2)
}

$prefixes = Expand-HibpPrefixes -PrefixValues $Prefix
$modeName = if ($Ntlm) { 'NTLM' } else { 'SHA1' }
$timer = [Diagnostics.Stopwatch]::StartNew()

if ($Single) {
    $exportPath = $OutputFile
    if (-not $exportPath.EndsWith('.txt', [System.StringComparison]::OrdinalIgnoreCase)) {
        $exportPath = "$exportPath.txt"
    }
    $exportPath = Resolve-LocalPath $exportPath

    Write-Host "HIBP Pwned Passwords Downloader - Pure PowerShell v3.3"
    Write-Host "Mode:                  $modeName"
    Write-Host "Storage mode:          Single monolithic file"
    Write-Host "Export path:           $exportPath"
    Write-Host "Update available:      False"
    Write-Host "Prefix count:          $($prefixes.Count)"
    Write-Host "Parallelism:           not used in single-file mode"
    Write-Host "Request timeout:       $RequestTimeoutSeconds seconds"
    Write-Host "Retries:               $Retries"
    Write-Host "Single-file mode:      True"
    Write-Host ""

    $stats = Invoke-SingleFileMode -Prefixes $prefixes -OutputPath $exportPath -UseNtlm ([bool]$Ntlm) -DoOverwrite ([bool]$Overwrite) -TimeoutSeconds $RequestTimeoutSeconds -RetryCount $Retries
    $timer.Stop()
    Write-Host ""
    Write-Host "Single-file download complete."
}
else {
    $rangeDirectory = Resolve-LocalPath $OutputFile
    $manifestDir = Join-Path $rangeDirectory '_manifest'
    $manifestPath = Join-Path $manifestDir ("{0}-manifest.tsv" -f ($(if ($Ntlm) { 'ntlm' } else { 'sha1' })))

    Write-Host "HIBP Pwned Passwords Downloader - Pure PowerShell v3.3"
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
    Write-Host "Single-file mode:      False"
    Write-Host ""

    $stats = Invoke-DirectoryMode -Prefixes $prefixes -RangeDirectory $rangeDirectory -ManifestPath $manifestPath -UseNtlm ([bool]$Ntlm) -DoUpdate ([bool]$Update) -DoVerifyOnly ([bool]$VerifyOnly) -DoOverwrite ([bool]$Overwrite) -WorkerCount $Parallelism -TimeoutSeconds $RequestTimeoutSeconds -RetryCount $Retries -AllowContinueOnError ([bool]$ContinueOnError)
    $timer.Stop()
    Write-Host ""
    Write-Host "Range operation complete."
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
Write-Host ("Elapsed:          {0}" -f $timer.Elapsed)

if ($stats.Failed -gt 0 -and -not $ContinueOnError) {
    throw "One or more ranges failed. Use -ContinueOnError to allow completion despite failures."
}

if ($Update -and -not $Single) {
    Write-Host ""
    Write-Host "Directory/range update completed. No single-file export was built."
}

Write-Host ""
Write-Host "Done."
