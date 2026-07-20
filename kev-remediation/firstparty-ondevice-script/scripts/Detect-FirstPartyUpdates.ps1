#Requires -Version 5.1
<#  Intune Remediation - DETECTION
    Exit 1 (-> run remediation) if any enabled 1st-party component is behind baseline.
    Exit 0 if all current. Runs silently as SYSTEM - no user UI. #>

# ===================== CONFIG (edit these) =====================
$Config = @{
    DefenderMaxSignatureAgeDays = 1
    OfficeTargetVersion         = '16.0.19127.20082'   # your approved M365 Apps build
    EdgeTargetVersion           = '126.0.2592.68'      # your approved Edge build
    WindowsTargetUBR            = 4651                  # UBR of your approved quality KB
    Check  = @{ Defender = $true; Office = $true; Edge = $true; Windows = $true }
    LogDir = "$env:ProgramData\Contoso\1PPatch"        # change 'Contoso'
}
# ==============================================================

$ErrorActionPreference = 'SilentlyContinue'
New-Item -Path $Config.LogDir -ItemType Directory -Force | Out-Null
$log = Join-Path $Config.LogDir 'detect.log'
function Write-Log($m){ "$(Get-Date -f s)  $m" | Out-File $log -Append -Encoding utf8 }

$behind = New-Object System.Collections.Generic.List[string]

if ($Config.Check.Defender) {
    $mp = Get-MpComputerStatus
    if ($mp -and $mp.AntivirusSignatureAge -gt $Config.DefenderMaxSignatureAgeDays) { $behind.Add('DefenderSignatures') }
}
if ($Config.Check.Office) {
    $o = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration').VersionToReport
    if ($o -and [version]$o -lt [version]$Config.OfficeTargetVersion) { $behind.Add('Office') }
}
if ($Config.Check.Edge) {
    $e = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}').pv
    if ($e -and [version]$e -lt [version]$Config.EdgeTargetVersion) { $behind.Add('Edge') }
}
if ($Config.Check.Windows) {
    $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
    if ($ubr -and [int]$ubr -lt $Config.WindowsTargetUBR) { $behind.Add('WindowsQuality') }
}

if ($behind.Count -gt 0) { $out = ($behind -join ','); Write-Log "BEHIND: $out"; Write-Output $out; exit 1 }
else { Write-Log 'COMPLIANT'; Write-Output 'Compliant'; exit 0 }
