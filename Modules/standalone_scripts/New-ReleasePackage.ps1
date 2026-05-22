#Requires -Version 5
<#
.SYNOPSIS
    Packages AD-PowerAdmin into a versioned release zip for GitHub distribution.

.DESCRIPTION
    Calculates the current AD-PowerAdmin version using the same algorithm as
    Get-ADPAVersion in AD-PowerAdmin.ps1, then assembles a release zip containing:

      AD-PowerAdmin.ps1
      AD-PowerAdmin_settings.ps1  (skipped with a warning if the file is absent)
      README.md
      Modules\  (filtered by channel -- see -Beta below)
      MANIFEST.txt  (SHA256 hash of every included file, sha256sum-compatible)

    By default only modules with Channel = 'Production' are included.
    Use -Beta to also include modules with Channel = 'Beta'.
    Modules with Channel = 'Alpha' are never included in any release package.
    Modules with no Channel field are also excluded.

    Output: <ProjectRoot>\Releases\ADPowerAdmin_V<version>.zip
            <ProjectRoot>\Releases\ADPowerAdmin_V<version>-beta.zip  (when -Beta)

    The Releases\ folder is created at the project root if it does not exist.
    If a zip with the same version name already exists, the script prompts before
    overwriting.

    Run this script whenever a release is ready to be packaged for GitHub.

.PARAMETER Beta
    Include modules marked Channel = 'Beta' in addition to Production modules.
    The output zip filename will include a -beta suffix.

.EXAMPLE
    pwsh -File .\Modules\standalone_scripts\New-ReleasePackage.ps1

.EXAMPLE
    pwsh -File .\Modules\standalone_scripts\New-ReleasePackage.ps1 -Beta

.NOTES
    Author:  CyberGladius
    License: MIT
    Can be run from any working directory -- all paths are resolved from the
    script's own location.
#>

param(
    [switch]$Beta
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Path resolution
# This script lives at:  Modules/standalone_scripts/New-ReleasePackage.ps1
# Project root is two levels up:  standalone_scripts -> Modules -> root
# ---------------------------------------------------------------------------
$ModulesDir  = Split-Path -Parent $PSScriptRoot
$ProjectRoot = Split-Path -Parent $ModulesDir
$ModulesPath = Join-Path $ProjectRoot 'Modules'
$MainScript  = Join-Path $ProjectRoot 'AD-PowerAdmin.ps1'

# ---------------------------------------------------------------------------
# Base version: read from main script, fall back to constant
# ---------------------------------------------------------------------------
[System.Version]$BaseVersion = '1.2.0'
$VersionLine = Get-Content -Path $MainScript -ErrorAction SilentlyContinue |
    Select-String -Pattern '\[System\.Version\]\$global:Version'
if ($VersionLine) {
    $ParsedBase = ($VersionLine.ToString() -split '"')[1]
    if ($ParsedBase) {
        try { $BaseVersion = [System.Version]$ParsedBase } catch { }
    }
}

# ---------------------------------------------------------------------------
# Version calculation -- mirrors Get-ADPAVersion in AD-PowerAdmin.ps1
# ---------------------------------------------------------------------------
$ModulePsd1Files = Get-ChildItem -Path $ModulesPath -Filter '*.psd1' -File
if (-not $ModulePsd1Files) {
    Write-Error "No .psd1 module files found in: $ModulesPath"
    exit 1
}

# ---------------------------------------------------------------------------
# Channel filtering -- determine which modules to include
# Alpha is never included. Beta is included only when -Beta is specified.
# ---------------------------------------------------------------------------
$AllowedChannels = @('Production')
if ($Beta) { $AllowedChannels += 'Beta' }

$FilteredPsd1Files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
$ExcludedModules   = [System.Collections.Generic.List[string]]::new()

foreach ($Psd1 in $ModulePsd1Files) {
    $ChannelLine = Get-Content $Psd1.FullName |
        Select-String -Pattern 'Channel\s*=' | Select-Object -First 1
    $ModChannel = if ($ChannelLine) {
        ($ChannelLine.ToString() -split '=')[1].Trim().Trim("'")
    } else { 'Unknown' }

    if ($ModChannel -in $AllowedChannels) {
        $FilteredPsd1Files.Add($Psd1)
    } else {
        $ExcludedModules.Add("$($Psd1.BaseName) [$ModChannel]")
    }
}

if ($FilteredPsd1Files.Count -eq 0) {
    Write-Error "No modules matched the selected channels: $($AllowedChannels -join ', ')"
    exit 1
}

if ($ExcludedModules.Count -gt 0) {
    Write-Host "Excluded modules (channel not in this release):"
    $ExcludedModules | ForEach-Object { Write-Host "  Skipped : $_" }
    Write-Host ""
}

[float]$VersionAccumulator = 0
Get-Content -Path ($FilteredPsd1Files | Select-Object -ExpandProperty FullName) |
    Select-String -Pattern 'ModuleVersion' | ForEach-Object {
        $VersionAccumulator += ($_.ToString()).Split('=')[1].Trim().Trim("'")
    }
$CumulativeVersion = [System.Version]$VersionAccumulator

[System.Version]$OverallVersion = '{0}.{1}.{2}' -f $BaseVersion.Major,
    ($BaseVersion.Minor + $CumulativeVersion.Major),
    ($BaseVersion.Build + $CumulativeVersion.Minor)

# ---------------------------------------------------------------------------
# Channel calculation -- Alpha < Beta < Production (from filtered set only)
# ---------------------------------------------------------------------------
$OverallChannel = 'Unknown'
Get-Content -Path ($FilteredPsd1Files | Select-Object -ExpandProperty FullName) |
    Select-String -Pattern 'Channel' | Select-String -Pattern '=' | ForEach-Object {
        $Channel = ($_.ToString()).Split('=')[1].Trim().Trim("'")
        if ($Channel -eq 'Alpha') {
            $OverallChannel = 'Alpha'
        }
        if ($Channel -eq 'Beta' -and $OverallChannel -ne 'Alpha') {
            $OverallChannel = 'Beta'
        }
        if ($Channel -eq 'Production' -and $OverallChannel -ne 'Alpha' -and $OverallChannel -ne 'Beta') {
            $OverallChannel = 'Production'
        }
    }

Write-Host "AD-PowerAdmin version : $OverallVersion  ($OverallChannel)"
Write-Host ""

# ---------------------------------------------------------------------------
# Zip output path
# ---------------------------------------------------------------------------
$ReleasesDir = Join-Path $ProjectRoot 'Releases'
if (-not (Test-Path -LiteralPath $ReleasesDir)) {
    New-Item -ItemType Directory -Path $ReleasesDir | Out-Null
    Write-Host "Created Releases\ directory at project root."
}

$BetaSuffix = if ($Beta) { '-beta' } else { '' }
$ZipName    = "ADPowerAdmin_V$OverallVersion$BetaSuffix.zip"
$ZipPath = Join-Path $ReleasesDir $ZipName

if (Test-Path -LiteralPath $ZipPath) {
    $Confirm = Read-Host "[$ZipName] already exists. Overwrite? (y/N)"
    if ($Confirm -notmatch '^[Yy]$') {
        Write-Host "Aborted."
        exit 0
    }
    Remove-Item -LiteralPath $ZipPath -Force
}

# ---------------------------------------------------------------------------
# Stage files in a temp directory, build the manifest, then zip
# ---------------------------------------------------------------------------
$StagingDir  = Join-Path ([System.IO.Path]::GetTempPath()) ('ADPowerAdmin_stage_' + [System.IO.Path]::GetRandomFileName())
$StagedCount = 0

try {
    New-Item -ItemType Directory -Path $StagingDir | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $StagingDir 'Modules') | Out-Null

    # Root files
    foreach ($RootFile in @('AD-PowerAdmin.ps1', 'AD-PowerAdmin_settings.ps1', 'README.md')) {
        $Src = Join-Path $ProjectRoot $RootFile
        if (Test-Path -LiteralPath $Src) {
            Copy-Item -LiteralPath $Src -Destination (Join-Path $StagingDir $RootFile) -Force
            $StagedCount++
            Write-Host "  Staged : $RootFile"
        } else {
            Write-Warning "File not found, skipping: $RootFile"
        }
    }

    # Module files -- only include .psd1/.psm1 pairs for channel-filtered modules
    $IncludedModuleNames = $FilteredPsd1Files |
        ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_.Name) }

    Get-ChildItem -Path $ModulesPath -File | Where-Object {
        [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -in $IncludedModuleNames
    } | ForEach-Object {
        $DestFile = Join-Path (Join-Path $StagingDir 'Modules') $_.Name
        Copy-Item -LiteralPath $_.FullName -Destination $DestFile -Force
        $StagedCount++
    }
    Write-Host "  Staged : Modules\ ($((Get-ChildItem -Path (Join-Path $StagingDir 'Modules') -File).Count) files)"

    # Build MANIFEST.txt -- SHA256 of every staged file.
    # Comment lines prefixed with # are ignored by sha256sum -c on Linux/macOS.
    $ManifestPath  = Join-Path $StagingDir 'MANIFEST.txt'
    $ManifestLines = [System.Collections.Generic.List[string]]::new()
    $ManifestLines.Add('# AD-PowerAdmin Release Manifest')
    $ManifestLines.Add("# Version : $OverallVersion  Channel : $OverallChannel")
    $ManifestLines.Add("# Generated: $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')) UTC")
    $ManifestLines.Add('#')
    $ManifestLines.Add('# Format : SHA256HASH  relative/path/in/zip')
    $ManifestLines.Add('# Verify : sha256sum -c MANIFEST.txt  (Linux / macOS)')
    $ManifestLines.Add('#')

    Get-ChildItem -Path $StagingDir -Recurse -File | Sort-Object FullName | ForEach-Object {
        $RelPath = $_.FullName.Substring($StagingDir.Length + 1) -replace '\\', '/'
        $Hash    = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        $ManifestLines.Add("$Hash  $RelPath")
    }

    [System.IO.File]::WriteAllLines($ManifestPath, $ManifestLines, [System.Text.Encoding]::ASCII)
    Write-Host "  Staged : MANIFEST.txt"

    # Create the zip
    Compress-Archive -Path (Join-Path $StagingDir '*') -DestinationPath $ZipPath -Force
}
finally {
    if (Test-Path -LiteralPath $StagingDir) {
        Remove-Item -LiteralPath $StagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$ZipInfo    = Get-Item -LiteralPath $ZipPath
$TotalFiles = $StagedCount + 1  # +1 for MANIFEST.txt

Write-Host ""
Write-Host "Release package created."
Write-Host "  Path    : $ZipPath"
Write-Host "  Size    : $([Math]::Round($ZipInfo.Length / 1KB, 1)) KB"
Write-Host "  Files   : $TotalFiles (includes MANIFEST.txt)"
Write-Host "  Version : $OverallVersion - $OverallChannel"
