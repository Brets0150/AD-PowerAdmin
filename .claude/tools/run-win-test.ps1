#Requires -Version 7
<#
.SYNOPSIS
    Remote Windows test runner for AD-PowerAdmin development.

.DESCRIPTION
    Executes a pre-approved PowerShell test script on the Windows test server over
    PowerShell remoting. The test name must exist in tools/allowed-tests.json.
    Credentials are loaded from PowerShell SecretManagement — never hardcoded.

.PARAMETER TestName
    Friendly name of the test to run. Must match a key in allowed-tests.json.

.EXAMPLE
    pwsh -File ./tools/run-win-test.ps1 -TestName Smoke-AdConnection

.NOTES
    Setup required before first use:
      1. Install SecretManagement modules (once per machine):
           pwsh -Command "Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force"
      2. Register a vault and store the Windows password:
           pwsh -Command "Register-SecretVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore"
           pwsh -Command "Set-Secret -Name WinTestPassword -Secret (Read-Host -AsSecureString 'Windows password')"
      3. Edit the configuration block below to set the correct server and username.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$TestName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==============================================================================
# CONFIGURATION — edit these values before first use
# ==============================================================================
[string]$TargetServer   = 'FL-222'          # Hostname or IP of the Windows test server
[string]$ServiceAccount = 'TDCME.LOC\Bret.admin'  # Domain\Username for remoting
[int]   $WinRmPort      = 5985                      # 5985 = HTTP (default), 5986 = HTTPS

# Optional SSL remoting — uncomment both lines and set $WinRmPort = 5986 to enable
# [bool]$UseSSL           = $true
# $SessionOptions         = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
# ==============================================================================

# Resolve paths relative to this script so it works from any working directory
$ScriptDir       = Split-Path -Parent $MyInvocation.MyCommand.Definition
$AllowListPath   = Join-Path $ScriptDir 'allowed-tests.json'
$SecretName      = 'WinTestPassword'

# ------------------------------------------------------------------------------
# Preflight: SecretManagement module must be installed
# ------------------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name Microsoft.PowerShell.SecretManagement)) {
    Write-Error @"
Microsoft.PowerShell.SecretManagement is not installed.
Run the following to install it, then register your vault and store the password:

  pwsh -Command "Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser -Force"
  pwsh -Command "Register-SecretVault -Name LocalStore -ModuleName Microsoft.PowerShell.SecretStore"
  pwsh -Command "Set-Secret -Name WinTestPassword -Secret (Read-Host -AsSecureString 'Windows password')"
"@
    exit 1
}

# ------------------------------------------------------------------------------
# Load and validate the allow-list
# ------------------------------------------------------------------------------
if (-not (Test-Path $AllowListPath)) {
    Write-Error "Allow-list not found at: $AllowListPath"
    exit 1
}

$AllowList = Get-Content -Raw $AllowListPath | ConvertFrom-Json

if (-not $AllowList.tests.PSObject.Properties.Name -contains $TestName) {
    $ValidNames = ($AllowList.tests.PSObject.Properties.Name | Sort-Object) -join ', '
    Write-Error "Test '$TestName' is not in the allow-list. Valid names: $ValidNames"
    exit 1
}

# Retrieve the approved remote script path — this is the only path that will ever run
[string]$RemoteScriptPath = $AllowList.tests.$TestName

# ------------------------------------------------------------------------------
# Build credential from SecretManagement — password never touches a prompt or log
# ------------------------------------------------------------------------------
try {
    $SecurePassword = Get-Secret -Name $SecretName -AsPlainText:$false
} catch {
    Write-Error "Could not retrieve secret '$SecretName' from SecretManagement vault. $_"
    exit 1
}

$Credential = [System.Management.Automation.PSCredential]::new($ServiceAccount, $SecurePassword)

# ------------------------------------------------------------------------------
# Open remote session and execute the approved script
# ------------------------------------------------------------------------------
$Session = $null
try {
    Write-Host "Connecting to $TargetServer as $ServiceAccount ..." -ForegroundColor Cyan

    $SessionParams = @{
        ComputerName = $TargetServer
        Port         = $WinRmPort
        Credential   = $Credential
        ErrorAction  = 'Stop'
    }

    # Uncomment to enable SSL (requires $UseSSL and $SessionOptions defined above)
    # $SessionParams['UseSSL']        = $UseSSL
    # $SessionParams['SessionOption'] = $SessionOptions

    $Session = New-PSSession @SessionParams

    Write-Host "Running remote test: $TestName  ($RemoteScriptPath)" -ForegroundColor Cyan

    $Result = Invoke-Command -Session $Session -ArgumentList $RemoteScriptPath -ScriptBlock {
        param([string]$ScriptPath)

        # Verify the script exists on the remote host before executing
        if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
            return [PSCustomObject]@{
                ScriptPath = $ScriptPath
                ExitCode   = 127
                Output     = "Remote script not found: $ScriptPath"
                Success    = $false
            }
        }

        # Execute the approved script and capture output
        $Output = & $ScriptPath *>&1 | Out-String
        $ExitCode = $LASTEXITCODE

        return [PSCustomObject]@{
            ScriptPath = $ScriptPath
            ExitCode   = if ($null -eq $ExitCode) { 0 } else { $ExitCode }
            Output     = $Output
            Success    = ($ExitCode -eq 0 -or $null -eq $ExitCode)
        }
    }

    # ------------------------------------------------------------------------------
    # Structured output
    # ------------------------------------------------------------------------------
    $Summary = [PSCustomObject]@{
        TestName         = $TestName
        TargetServer     = $TargetServer
        RemoteScriptPath = $Result.ScriptPath
        ExitCode         = $Result.ExitCode
        Success          = $Result.Success
        Output           = $Result.Output.Trim()
    }

    Write-Host ''
    Write-Host '=== Test Result ===' -ForegroundColor $(if ($Summary.Success) { 'Green' } else { 'Red' })
    $Summary | Format-List
    Write-Host '==================='

    # Also emit as JSON so callers can parse it
    $Summary | ConvertTo-Json -Depth 3

    exit $Result.ExitCode

} catch {
    Write-Error "Remote execution failed: $_"
    exit 1
} finally {
    # Always clean up the session — runs even on error
    if ($null -ne $Session) {
        Remove-PSSession -Session $Session
        Write-Host 'Remote session closed.' -ForegroundColor DarkGray
    }
}
