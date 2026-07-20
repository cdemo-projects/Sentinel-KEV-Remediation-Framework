<#
.SYNOPSIS
    Packages a third-party MSI/EXE as an Intune .intunewin Win32 app.

.DESCRIPTION
    Reads a config JSON, downloads the vendor installer, verifies SHA256, then runs
    Microsoft IntuneWinAppUtil.exe to produce the .intunewin payload that Upload-Win32App.ps1
    can ship to Intune.

    Run on a Windows admin VM with internet access. Output is the path to the .intunewin file.

.PARAMETER Config
    Path to the JSON config file (see examples/7zip-2409.json for the expected schema).

.PARAMETER ToolPath
    Optional path to IntuneWinAppUtil.exe. If omitted the script downloads it to the staging
    folder. The tool is signed by Microsoft and lives at:
    https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool

.PARAMETER Force
    Re-download installer and rebuild the .intunewin even if outputs already exist.

.EXAMPLE
    .\Build-Win32Package.ps1 -Config .\examples\7zip-2409.json

.EXAMPLE
    .\Build-Win32Package.ps1 -Config .\examples\7zip-2409.json -ToolPath C:\Tools\IntuneWinAppUtil.exe -Force

.NOTES
    Requires PowerShell 7.0+. Idempotent: skips download/repackage if outputs are current.
#>

#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Config,
    [string]$ToolPath = '',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# ---- Load config ----
if (-not (Test-Path $Config)) { throw "Config file not found: $Config" }
$cfg = Get-Content -Raw -Path $Config | ConvertFrom-Json -Depth 12

$staging = $cfg.package.stagingFolder
$output  = $cfg.package.outputFolder
$msi     = Join-Path $staging $cfg.source.fileName
$intunewinName = [IO.Path]::ChangeExtension($cfg.source.fileName, '.intunewin')
$intunewin     = Join-Path $output $intunewinName

# ---- Ensure folders ----
foreach ($d in @($staging, $output)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

# ---- Tool ----
if (-not $ToolPath) {
    $ToolPath = Join-Path $staging 'IntuneWinAppUtil.exe'
}
if (-not (Test-Path $ToolPath)) {
    Write-Host "[1/5] Downloading IntuneWinAppUtil.exe ..." -ForegroundColor Cyan
    $toolUrl = 'https://github.com/Microsoft/Microsoft-Win32-Content-Prep-Tool/raw/refs/heads/master/IntuneWinAppUtil.exe'
    Invoke-WebRequest -Uri $toolUrl -OutFile $ToolPath -UseBasicParsing
    Write-Host "    Saved: $ToolPath" -ForegroundColor Green
} else {
    Write-Host "[1/5] IntuneWinAppUtil.exe already present at $ToolPath" -ForegroundColor Green
}

# ---- Download vendor installer ----
$needDownload = $Force -or (-not (Test-Path $msi))
if ($needDownload) {
    Write-Host "[2/5] Downloading vendor installer ..." -ForegroundColor Cyan
    Write-Host "      $($cfg.source.vendorUrl)"
    Invoke-WebRequest -Uri $cfg.source.vendorUrl -OutFile $msi -UseBasicParsing
    Write-Host "      Saved: $msi" -ForegroundColor Green
} else {
    Write-Host "[2/5] Installer already downloaded: $msi" -ForegroundColor Green
}

# ---- Verify SHA256 ----
Write-Host "[3/5] Verifying SHA256 ..." -ForegroundColor Cyan
$actual = (Get-FileHash -Algorithm SHA256 -Path $msi).Hash
$expected = $cfg.source.sha256
if ($expected -eq 'REPLACE_ME_WITH_VENDOR_PUBLISHED_HASH') {
    Write-Warning "Config has placeholder SHA256. Computed actual hash:"
    Write-Warning "    $actual"
    Write-Warning "Update the config 'source.sha256' with this value (after confirming against the vendor's published checksum) and re-run."
    throw "Refusing to package an unverified installer."
}
if ($actual -ne $expected) {
    throw "SHA256 mismatch! Expected $expected, got $actual. Aborting."
}
Write-Host "      Hash OK: $actual" -ForegroundColor Green

# ---- Package ----
$needPackage = $Force -or (-not (Test-Path $intunewin)) -or ((Get-Item $intunewin).LastWriteTime -lt (Get-Item $msi).LastWriteTime)
if ($needPackage) {
    Write-Host "[4/5] Running IntuneWinAppUtil ..." -ForegroundColor Cyan
    if (Test-Path $intunewin) { Remove-Item $intunewin -Force }
    $args = @('-c', $staging, '-s', $cfg.source.fileName, '-o', $output, '-q')
    & $ToolPath @args
    if (-not (Test-Path $intunewin)) { throw "IntuneWinAppUtil did not produce expected output: $intunewin" }
    Write-Host "      Built: $intunewin" -ForegroundColor Green
} else {
    Write-Host "[4/5] .intunewin is current, skipping repack." -ForegroundColor Yellow
}

# ---- Summary ----
$info = Get-Item $intunewin
Write-Host "[5/5] Build complete." -ForegroundColor Green
Write-Host ""
Write-Host "  appKey         : $($cfg.appKey)"
Write-Host "  intunewin path : $($info.FullName)"
Write-Host "  size           : $([math]::Round($info.Length / 1MB, 2)) MB"
Write-Host "  next step      : .\Upload-Win32App.ps1 -Config $Config -Cloud Gov  (or -Cloud Commercial)"
Write-Host ""

# Emit the path so callers can pipe it
Write-Output $info.FullName
