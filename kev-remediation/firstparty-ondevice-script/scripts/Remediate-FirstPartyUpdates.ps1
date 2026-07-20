#Requires -Version 5.1
<#  Intune Remediation - REMEDIATION
    Re-detects, then triggers each 1st-party component's NATIVE updater, silently.
    Windows OS quality is flagged only (install handled by Expedite/Logic App). #>

# ===================== CONFIG (keep in sync with detection) =====================
$Config = @{
    DefenderMaxSignatureAgeDays = 1
    OfficeTargetVersion         = '16.0.19127.20082'
    EdgeTargetVersion           = '126.0.2592.68'
    WindowsTargetUBR            = 4651
    Check  = @{ Defender = $true; Office = $true; Edge = $true; Windows = $true }
    LogDir = "$env:ProgramData\Contoso\1PPatch"
}
# ==============================================================================

New-Item -Path $Config.LogDir -ItemType Directory -Force | Out-Null
$log = Join-Path $Config.LogDir 'remediate.log'
function Write-Log($m){ "$(Get-Date -f s)  $m" | Out-File $log -Append -Encoding utf8 }

# Launch any child process completely hidden (no window, no taskbar flash)
function Invoke-Hidden([string]$file,[string]$arguments){
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $file; $psi.Arguments = $arguments
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.WindowStyle = 'Hidden'
    $p = [System.Diagnostics.Process]::Start($psi); $p.WaitForExit(); $p.ExitCode
}

$result = [ordered]@{}; $failed = $false
try {
    if ($Config.Check.Defender) {
        $mp = Get-MpComputerStatus
        if ($mp.AntivirusSignatureAge -gt $Config.DefenderMaxSignatureAgeDays) {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer   # remove -UpdateSource to use configured fallback order
            Write-Log 'Defender: signatures updated'; $result.Defender = 'triggered'
        }
    }
    if ($Config.Check.Office) {
        $o = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' -EA SilentlyContinue).VersionToReport
        if ($o -and [version]$o -lt [version]$Config.OfficeTargetVersion) {
            Invoke-Hidden 'schtasks.exe' '/run /tn "\Microsoft\Office\Office Automatic Updates 2.0"' | Out-Null
            Write-Log 'Office: Automatic Updates 2.0 task triggered'; $result.Office = 'triggered'
        }
    }
    if ($Config.Check.Edge) {
        $e = (Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -EA SilentlyContinue).pv
        if ($e -and [version]$e -lt [version]$Config.EdgeTargetVersion) {
            $edge = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
            if (Test-Path $edge) {
                # NOTE: updates Edge to latest Stable, ignoring any channel-pin policy
                Invoke-Hidden $edge '/silent /install appguid={56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}&appname=Microsoft%20Edge&needsadmin=True' | Out-Null
                Write-Log 'Edge: silent update triggered'; $result.Edge = 'triggered'
            }
        }
    }
    if ($Config.Check.Windows) {
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
        if ([int]$ubr -lt $Config.WindowsTargetUBR) {
            Write-Log "WindowsQuality: BEHIND (UBR $ubr) - flagged for Expedite (no local install)"
            $result.WindowsQuality = 'flag-for-expedite'
            try { (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow() } catch {}  # scan nudge only
        }
    }
}
catch { Write-Log "ERROR: $($_.Exception.Message)"; $failed = $true }

Write-Output ([pscustomobject]$result | ConvertTo-Json -Compress)
if ($failed) { exit 1 } else { exit 0 }
