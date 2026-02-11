<#
.SYNOPSIS
  Remediates “SMB Signing not required” (Tenable/Nessus Plugin ID 57608)
  by enforcing SMB message signing for both SMB Server and SMB Client.

.DESCRIPTION
  Many scanners (e.g., Nessus/Tenable) flag hosts as vulnerable when SMB message signing
  is NOT required. This can allow man-in-the-middle (MITM) attacks and tampering of SMB traffic.

  On Windows, remediation is achieved by enabling the equivalent of:
    - Microsoft network server: Digitally sign communications (always)
    - Microsoft network client: Digitally sign communications (always)

  This script:
    - Ensures it is run as Administrator
    - Detects OS role/capabilities and applies registry-based enforcement (works on PS 5.1)
    - Optionally restarts services (or prompts for reboot) to apply changes
    - Verifies registry values and (where available) verifies via Get-SmbServerConfiguration
    - Outputs a clear remediation + verification summary

.NOTES
    - Requires administrative privileges
    - Tested for compatibility with Windows PowerShell 5.1 (no ternary operator)
    - Author        : Sun Dimitri NFANDA
    - Date Created  : 2026-02-09
    - Last Modified : 2026-02-09
    - Version       : 1.0

.TESTED ON
    Date(s) Tested  : 2026-02-09
    Tested By       : Sun Dimitri NFANDA
    Systems Tested  : Windows (Windows Server 2025 Datacenter - x64 Gen2)
    PowerShell Ver. : 5.1.26100.7462 (Verify your PowerShell version using the command $PSVersionTable)

.USAGE
  Set $secureEnvironment to $true to enforce the mitigation (recommended).
  Set $secureEnvironment to $false to remove the mitigation (restore defaults).

  Example:
    PS C:\> .\Set-SmbSigningRequired.ps1
#>

# =========================
# User configuration
# =========================
$secureEnvironment = $true       # $true = enforce SMB signing requirement, $false = remove
$restartServices   = $false      # $true = attempt to restart LanmanServer/LanmanWorkstation (may disconnect sessions)
$showDetails       = $true       # $true = print detailed checks

# =========================
# Helper functions
# =========================
function Write-Section {
  param([string]$Text)
  Write-Host ""
  Write-Host "=== $Text ===" -ForegroundColor Cyan
}

function Assert-Admin {
  $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
  $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as administrator, then re-run the script."
    exit 1
  }
}

function Ensure-RegistryPath {
  param([string]$Path)
  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}

function Set-DwordValue {
  param(
    [string]$Path,
    [string]$Name,
    [int]$Value
  )
  Ensure-RegistryPath -Path $Path

  $current = $null
  try { $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $current = $null }

  if ($current -eq $Value) {
    return @{ Changed = $false; Previous = $current; Current = $Value; Note = "Already set" }
  }

  if ($null -eq $current) {
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
    return @{ Changed = $true; Previous = $null; Current = $Value; Note = "Created" }
  } else {
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force | Out-Null
    return @{ Changed = $true; Previous = $current; Current = $Value; Note = "Updated" }
  }
}

function Get-DwordValue {
  param([string]$Path, [string]$Name)
  try {
    return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
  } catch {
    return $null
  }
}

function Test-CommandAvailable {
  param([string]$CommandName)
  $cmd = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
  if ($null -eq $cmd) { return $false } else { return $true }
}

# =========================
# Main
# =========================
Assert-Admin

Write-Section "SMB Signing Remediation (Tenable Plugin 57608)"

# Registry locations for SMB signing enforcement
$serverRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$clientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"

# Values:
#   RequireSecuritySignature = 1 => signing REQUIRED (policy: Digitally sign communications (always))
#   RequireSecuritySignature = 0 => signing NOT required
#
# Note: EnableSecuritySignature generally indicates "if agreed" behavior; scanners typically care about Require=1.
# We'll set both to be explicit:
#   EnableSecuritySignature  = 1 when enforcing (allow signing)
#   EnableSecuritySignature  = 0 when removing (default varies; we’ll revert to 1 by default to stay safe/compatible)

if ($secureEnvironment -eq $true) {
  Write-Host "Mode: ENFORCE SMB signing (server + client) -> RequireSecuritySignature=1" -ForegroundColor Green

  $serverRequire = Set-DwordValue -Path $serverRegPath -Name "RequireSecuritySignature" -Value 1
  $serverEnable  = Set-DwordValue -Path $serverRegPath -Name "EnableSecuritySignature"  -Value 1

  $clientRequire = Set-DwordValue -Path $clientRegPath -Name "RequireSecuritySignature" -Value 1
  $clientEnable  = Set-DwordValue -Path $clientRegPath -Name "EnableSecuritySignature"  -Value 1

} else {
  Write-Host "Mode: REMOVE enforcement -> RequireSecuritySignature=0" -ForegroundColor Yellow

  $serverRequire = Set-DwordValue -Path $serverRegPath -Name "RequireSecuritySignature" -Value 0
  $serverEnable  = Set-DwordValue -Path $serverRegPath -Name "EnableSecuritySignature"  -Value 1

  $clientRequire = Set-DwordValue -Path $clientRegPath -Name "RequireSecuritySignature" -Value 0
  $clientEnable  = Set-DwordValue -Path $clientRegPath -Name "EnableSecuritySignature"  -Value 1
}

if ($showDetails -eq $true) {
  Write-Section "Change Log (Registry)"
  Write-Host ("Server  RequireSecuritySignature : {0} -> {1} ({2})" -f $serverRequire.Previous, $serverRequire.Current, $serverRequire.Note)
  Write-Host ("Server  EnableSecuritySignature  : {0} -> {1} ({2})" -f $serverEnable.Previous,  $serverEnable.Current,  $serverEnable.Note)
  Write-Host ("Client  RequireSecuritySignature : {0} -> {1} ({2})" -f $clientRequire.Previous, $clientRequire.Current, $clientRequire.Note)
  Write-Host ("Client  EnableSecuritySignature  : {0} -> {1} ({2})" -f $clientEnable.Previous,  $clientEnable.Current,  $clientEnable.Note)
}

# Optional service restarts (warning: can disrupt SMB sessions)
if ($restartServices -eq $true) {
  Write-Section "Applying Changes (Service Restart)"
  Write-Host "Attempting to restart LanmanServer and LanmanWorkstation..." -ForegroundColor Yellow
  try {
    Restart-Service -Name "LanmanServer" -Force -ErrorAction Stop
    Restart-Service -Name "LanmanWorkstation" -Force -ErrorAction Stop
    Write-Host "Services restarted successfully." -ForegroundColor Green
  } catch {
    Write-Host "WARNING: Could not restart one or more services." -ForegroundColor Yellow
    Write-Host "A reboot is recommended to ensure settings are applied."
  }
} else {
  Write-Section "Apply Notice"
  Write-Host "A reboot is recommended for consistent scanner results." -ForegroundColor Yellow
  Write-Host "Tip: Set `$restartServices = `$true if you prefer attempting service restart (may drop SMB connections)."
}

# =========================
# Verification
# =========================
Write-Section "Verification"

$verServerRequire = Get-DwordValue -Path $serverRegPath -Name "RequireSecuritySignature"
$verServerEnable  = Get-DwordValue -Path $serverRegPath -Name "EnableSecuritySignature"
$verClientRequire = Get-DwordValue -Path $clientRegPath -Name "RequireSecuritySignature"
$verClientEnable  = Get-DwordValue -Path $clientRegPath -Name "EnableSecuritySignature"

Write-Host ("Registry - Server RequireSecuritySignature : {0}" -f $verServerRequire)
Write-Host ("Registry - Server EnableSecuritySignature  : {0}" -f $verServerEnable)
Write-Host ("Registry - Client RequireSecuritySignature : {0}" -f $verClientRequire)
Write-Host ("Registry - Client EnableSecuritySignature  : {0}" -f $verClientEnable)

# If available, also verify via SMB cmdlets
if (Test-CommandAvailable -CommandName "Get-SmbServerConfiguration") {
  try {
    $cfg = Get-SmbServerConfiguration
    Write-Host ""
    Write-Host "Get-SmbServerConfiguration:" -ForegroundColor Cyan
    Write-Host ("  RequireSecuritySignature : {0}" -f $cfg.RequireSecuritySignature)
    Write-Host ("  EnableSecuritySignature  : {0}" -f $cfg.EnableSecuritySignature)
  } catch {
    Write-Host "INFO: Get-SmbServerConfiguration exists but failed to query. Continuing..." -ForegroundColor Yellow
  }
} else {
  Write-Host ""
  Write-Host "INFO: Get-SmbServerConfiguration not available in this environment (common on older builds)." -ForegroundColor Yellow
}

# Summary / pass-fail evaluation for the Nessus finding
Write-Section "Summary"

$expected = 0
if ($secureEnvironment -eq $true) { $expected = 1 } else { $expected = 0 }

$serverOk = ($verServerRequire -eq $expected)
$clientOk = ($verClientRequire -eq $expected)

if ($secureEnvironment -eq $true) {
  if ($serverOk -and $clientOk) {
    Write-Host "PASS: SMB signing is REQUIRED for both Server and Client (should remediate Plugin 57608)." -ForegroundColor Green
  } else {
    Write-Host "FAIL: One or more required settings are not applied as expected." -ForegroundColor Red
  }
  Write-Host "Recommended next step: Reboot, then run a credentialed Nessus scan to confirm."
} else {
  if ($serverOk -and $clientOk) {
    Write-Host "DONE: SMB signing enforcement removed (RequireSecuritySignature=0 on Server and Client)." -ForegroundColor Yellow
  } else {
    Write-Host "WARNING: Expected enforcement removal but values do not match." -ForegroundColor Yellow
  }
  Write-Host "Note: Removing enforcement may reintroduce the Nessus finding."
}

Write-Host ""
Write-Host "Script completed."
