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
      Modules\  (direct files only -- no subdirectories)
      MANIFEST.txt  (SHA256 hash of every included file, sha256sum-compatible)

    Output: <ProjectRoot>\Releases\ADPowerAdmin_V<version>.zip

    The Releases\ folder is created at the project root if it does not exist.
    If a zip with the same version name already exists, the script prompts before
    overwriting.

    Run this script whenever a release is ready to be packaged for GitHub.

.EXAMPLE
    pwsh -File .\Modules\standalone_scripts\New-ReleasePackage.ps1

.NOTES
    Author:  CyberGladius
    License: MIT
    Can be run from any working directory -- all paths are resolved from the
    script's own location.
#>

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

[float]$VersionAccumulator = 0
Get-Content -Path $ModulePsd1Files.FullName |
    Select-String -Pattern 'ModuleVersion' | ForEach-Object {
        $VersionAccumulator += ($_.ToString()).Split('=')[1].Trim().Trim("'")
    }
$CumulativeVersion = [System.Version]$VersionAccumulator

[System.Version]$OverallVersion = '{0}.{1}.{2}' -f $BaseVersion.Major,
    ($BaseVersion.Minor + $CumulativeVersion.Major),
    ($BaseVersion.Build + $CumulativeVersion.Minor)

# ---------------------------------------------------------------------------
# Channel calculation -- Alpha < Beta < Production
# ---------------------------------------------------------------------------
$OverallChannel = 'Unknown'
Get-Content -Path $ModulePsd1Files.FullName |
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

$ZipName = "ADPowerAdmin_V$OverallVersion.zip"
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

    # Module files -- direct children only, no subdirectories
    Get-ChildItem -Path $ModulesPath -File | ForEach-Object {
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
