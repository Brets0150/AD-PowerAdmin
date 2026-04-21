#Requires -Version 7
<#
.SYNOPSIS
    Local PowerShell syntax and lint checker for AD-PowerAdmin development.

.DESCRIPTION
    Runs two levels of analysis on a local .ps1 or .psm1 file without executing it:
      1. PowerShell AST parser  — catches syntax errors
      2. PSScriptAnalyzer       — catches bugs, bad practices, and style issues

    Also validates .psd1 manifests: checks that every function listed in
    FunctionsToExport actually exists in the paired .psm1 file.

    No Active Directory connection or remote session required.

.PARAMETER Path
    Path to the .ps1, .psm1, or .psd1 file to check. Relative paths are resolved
    from the current working directory.

.PARAMETER Severity
    PSScriptAnalyzer severity filter. Default: Warning,Error (omits Information).
    Valid values: Information, Warning, Error

.EXAMPLE
    pwsh -File ./.claude/tools/check-syntax.ps1 -Path ./Modules/AD-PowerAdmin_Audits.psm1

.EXAMPLE
    pwsh -File ./.claude/tools/check-syntax.ps1 -Path ./AD-PowerAdmin.ps1 -Severity Error
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Information', 'Warning', 'Error')]
    [string[]]$Severity = @('Warning', 'Error')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Resolve and validate the target file
# ---------------------------------------------------------------------------
$ResolvedPath = Resolve-Path -Path $Path -ErrorAction SilentlyContinue
if (-not $ResolvedPath) {
    Write-Error "File not found: $Path"
    exit 1
}
$FilePath = $ResolvedPath.Path
$Extension = [System.IO.Path]::GetExtension($FilePath).ToLower()

if ($Extension -notin @('.ps1', '.psm1', '.psd1')) {
    Write-Error "Unsupported file type '$Extension'. Only .ps1, .psm1, and .psd1 are supported."
    exit 1
}

Write-Host ""
Write-Host "=== AD-PowerAdmin Syntax Checker ===" -ForegroundColor Cyan
Write-Host "File: $FilePath" -ForegroundColor Cyan
Write-Host ""

$OverallPass = $true

# ---------------------------------------------------------------------------
# Step 1 — AST syntax parse (no execution)
# ---------------------------------------------------------------------------
Write-Host "-- Step 1: AST Syntax Parse" -ForegroundColor White

if ($Extension -eq '.psd1') {
    # .psd1 files are data files — use Import-PowerShellDataFile for parse check
    try {
        $null = Import-PowerShellDataFile -Path $FilePath -ErrorAction Stop
        Write-Host "   PASS  No syntax errors detected." -ForegroundColor Green
    } catch {
        Write-Host "   FAIL  $($_.Exception.Message)" -ForegroundColor Red
        $OverallPass = $false
    }
} else {
    $ParseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile(
        $FilePath,
        [ref]$null,
        [ref]$ParseErrors
    )

    if ($ParseErrors.Count -eq 0) {
        Write-Host "   PASS  No syntax errors detected." -ForegroundColor Green
    } else {
        $OverallPass = $false
        foreach ($err in $ParseErrors) {
            Write-Host ("   FAIL  Line {0}: {1}" -f $err.Extent.StartLineNumber, $err.Message) -ForegroundColor Red
        }
    }
}

Write-Host ""

# ---------------------------------------------------------------------------
# Step 2 — PSScriptAnalyzer lint (skip for .psd1 — not meaningful)
# ---------------------------------------------------------------------------
if ($Extension -ne '.psd1') {
    Write-Host "-- Step 2: PSScriptAnalyzer (Severity: $($Severity -join ', '))" -ForegroundColor White

    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Host "   SKIP  PSScriptAnalyzer is not installed." -ForegroundColor Yellow
        Write-Host "         Run: Install-Module PSScriptAnalyzer -Scope CurrentUser -Force" -ForegroundColor Yellow
    } else {
        $AnalyzerResults = Invoke-ScriptAnalyzer -Path $FilePath -Severity $Severity -ErrorAction SilentlyContinue

        if ($null -eq $AnalyzerResults -or $AnalyzerResults.Count -eq 0) {
            Write-Host "   PASS  No issues found." -ForegroundColor Green
        } else {
            foreach ($finding in $AnalyzerResults) {
                $Color = if ($finding.Severity -eq 'Error') { 'Red' } else { 'Yellow' }
                Write-Host ("   {0,-8} Line {1,-5} [{2}] {3}" -f `
                    $finding.Severity.ToString().ToUpper(),
                    $finding.Line,
                    $finding.RuleName,
                    $finding.Message
                ) -ForegroundColor $Color

                if ($finding.Severity -eq 'Error') { $OverallPass = $false }
            }
        }
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step 3 — Manifest cross-check (only when a .psd1 is the target)
# ---------------------------------------------------------------------------
if ($Extension -eq '.psd1') {
    Write-Host "-- Step 3: Manifest FunctionsToExport cross-check" -ForegroundColor White

    try {
        $Manifest = Import-PowerShellDataFile -Path $FilePath -ErrorAction Stop
        $ExportedFunctions = $Manifest.FunctionsToExport

        if (-not $ExportedFunctions -or $ExportedFunctions.Count -eq 0) {
            Write-Host "   SKIP  FunctionsToExport is empty or not defined." -ForegroundColor Yellow
        } else {
            # Find the paired .psm1
            $PsmPath = [System.IO.Path]::ChangeExtension($FilePath, '.psm1')
            if (-not (Test-Path $PsmPath)) {
                Write-Host "   SKIP  Paired .psm1 not found at: $PsmPath" -ForegroundColor Yellow
            } else {
                # Parse the .psm1 to extract defined function names
                $PsmAst = [System.Management.Automation.Language.Parser]::ParseFile(
                    $PsmPath, [ref]$null, [ref]$null
                )
                $DefinedFunctions = $PsmAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                }, $true) | ForEach-Object { $_.Name }

                $AllGood = $true
                foreach ($fn in $ExportedFunctions) {
                    if ($fn -notin $DefinedFunctions) {
                        Write-Host ("   WARN  '{0}' is in FunctionsToExport but not defined in the .psm1" -f $fn) -ForegroundColor Yellow
                        $AllGood = $false
                    }
                }
                if ($AllGood) {
                    Write-Host "   PASS  All $($ExportedFunctions.Count) exported functions exist in the .psm1." -ForegroundColor Green
                }
            }
        }
    } catch {
        Write-Host "   ERROR $_" -ForegroundColor Red
        $OverallPass = $false
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------------
if ($OverallPass) {
    Write-Host "=== RESULT: PASS ===" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=== RESULT: FAIL ===" -ForegroundColor Red
    exit 1
}
