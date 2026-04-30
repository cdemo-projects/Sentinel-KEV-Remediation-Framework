<#
.SYNOPSIS
    End-to-end verification that the KEV-Remediate playbook actually patched a CVE.

.DESCRIPTION
    Polls four sources of truth to prove the automated remediation loop closes:
      1. Logic App run status — playbook ran successfully
      2. WUfB deployment state — Microsoft Autopatch service progress (KB path)
         OR Intune remediation state — on-demand proactive remediation (third-party path)
      3. Audience member enrollment + delivery state — per-device update status (KB path)
         OR Intune device run state — script execution result (third-party path)
      4. MDETVM_CL in Sentinel — CVE no longer reported on the device

    Run before patching to capture baseline, then re-run periodically to watch
    the loop close. CVE disappearance from MDETVM_CL is the definitive proof.

.PARAMETER DeploymentId
    The WUfB deployment GUID returned by Create_Expedited_Deployment. Required for KB path.

.PARAMETER IntuneRemediationScriptId
    The Intune deviceHealthScript ID for third-party remediation. Required for third-party path.

.PARAMETER CveId
    The CVE being remediated.

.PARAMETER DeviceName
    The device expected to be patched.

.PARAMETER WorkspaceName
    Sentinel workspace name.

.PARAMETER ResourceGroup
    Resource group containing the workspace and Logic App.

.EXAMPLE
    # WUfB / KB path
    .\Verify-Remediation.ps1 -DeploymentId 'a9780478-5a3b-47b4-acdc-a2a4dabbbe57' `
        -CveId 'CVE-2026-21513' -DeviceName 'cdemo' `
        -WorkspaceName '<workspace-name>' -ResourceGroup '<resource-group>'

.EXAMPLE
    # Third-party / Intune path
    .\Verify-Remediation.ps1 -IntuneRemediationScriptId 'a16e5132-9c28-4c2e-9be6-872e2911a72c' `
        -CveId 'CVE-2026-12345' -DeviceName 'cdemo' `
        -WorkspaceName '<workspace-name>' -ResourceGroup '<resource-group>'
#>

param(
    [string] $DeploymentId,
    [string] $IntuneRemediationScriptId,
    [Parameter(Mandatory = $true)] [string] $CveId,
    [Parameter(Mandatory = $true)] [string] $DeviceName,
    [Parameter(Mandatory = $true)] [string] $WorkspaceName,
    [Parameter(Mandatory = $true)] [string] $ResourceGroup,
    [string] $PlaybookName = 'KEV-Remediate'
)

$ErrorActionPreference = 'Stop'

$isThirdParty = -not [string]::IsNullOrWhiteSpace($IntuneRemediationScriptId)
$isWufb = -not [string]::IsNullOrWhiteSpace($DeploymentId)

if (-not $isThirdParty -and -not $isWufb) {
    throw "Specify either -DeploymentId (WUfB/KB path) or -IntuneRemediationScriptId (third-party path)."
}

$pathLabel = if ($isThirdParty) { "Third-Party / Intune Remediation" } else { "WUfB Expedited Deployment" }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  KEV Remediation Verification" -ForegroundColor Cyan
Write-Host "  Path: $pathLabel" -ForegroundColor Cyan
Write-Host "  CVE: $CveId  Device: $DeviceName" -ForegroundColor Cyan
Write-Host "  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$sub = az account show --query id -o tsv
$workspaceId = az monitor log-analytics workspace show -n $WorkspaceName -g $ResourceGroup --query customerId -o tsv

# ---------- 1. Logic App last run ----------
Write-Host "[1/4] Logic App last run" -ForegroundColor Yellow
$wfBase = "https://management.azure.com/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$PlaybookName"
$lastRun = az rest --method GET --url "$wfBase/runs?api-version=2016-06-01" -o json | ConvertFrom-Json
if ($lastRun.value.Count -gt 0) {
    $r = $lastRun.value[0]
    $statusColor = if ($r.properties.status -eq 'Succeeded') { 'Green' } else { 'Red' }
    Write-Host ("    Run id     : {0}" -f $r.name)
    Write-Host ("    Status     : {0}" -f $r.properties.status) -ForegroundColor $statusColor
    Write-Host ("    Started    : {0}" -f $r.properties.startTime)
    Write-Host ("    Ended      : {0}" -f $r.properties.endTime)
} else {
    Write-Host "    No runs found." -ForegroundColor Red
}

# ---------- 2. Remediation deployment state ----------
Write-Host "`n[2/4] Remediation deployment state" -ForegroundColor Yellow
if ($isWufb) {
    try {
        $depRaw = az rest --method GET --url "https://graph.microsoft.com/beta/admin/windows/updates/deployments/$DeploymentId" -o json 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($depRaw)) {
            Write-Host "    Skipped: signed-in user cannot read WUfB deployments. Logic App MI proof is in run history." -ForegroundColor Yellow
        } else {
            $dep = $depRaw | ConvertFrom-Json
            Write-Host ("    Deployment : {0}" -f $dep.id)
            Write-Host ("    Catalog    : {0}" -f $dep.content.catalogEntry.displayName)
            Write-Host ("    State      : {0}" -f $dep.state.effectiveValue) -ForegroundColor Green
            Write-Host ("    Expedited  : {0}" -f $dep.settings.expedite.isExpedited)
            Write-Host ("    Created    : {0}" -f $dep.createdDateTime)
        }
    } catch {
        Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    NOTE: signed-in user needs WindowsUpdates.Read.All" -ForegroundColor Yellow
    }
} else {
    try {
        $scriptRaw = az rest --method GET --url "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$IntuneRemediationScriptId/runSummary" -o json 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($scriptRaw)) {
            Write-Host "    Skipped: signed-in user cannot read Intune remediation data." -ForegroundColor Yellow
        } else {
            $summary = $scriptRaw | ConvertFrom-Json
            Write-Host ("    Script ID          : {0}" -f $IntuneRemediationScriptId)
            Write-Host ("    Issues detected    : {0}" -f $summary.issueDetectedDeviceCount)
            Write-Host ("    Issues remediated  : {0}" -f $summary.issueRemediatedDeviceCount)
            Write-Host ("    Detection errors   : {0}" -f $summary.detectionScriptErrorDeviceCount)
            Write-Host ("    Remediation errors : {0}" -f $summary.remediationScriptErrorDeviceCount)
            Write-Host ("    Last run           : {0}" -f $summary.lastScriptRunDateTime)
            $summaryColor = if ($summary.issueRemediatedDeviceCount -gt 0) { 'Green' } elseif ($summary.issueDetectedDeviceCount -gt 0) { 'Yellow' } else { 'Cyan' }
            Write-Host ("    Summary            : {0} remediated, {1} detected, {2} no issue" -f $summary.issueRemediatedDeviceCount, $summary.issueDetectedDeviceCount, $summary.noIssueDetectedDeviceCount) -ForegroundColor $summaryColor
        }
    } catch {
        Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------- 3. Per-device status ----------
Write-Host "`n[3/4] Per-device remediation status" -ForegroundColor Yellow
if ($isWufb) {
    try {
        $membersRaw = az rest --method GET --url "https://graph.microsoft.com/beta/admin/windows/updates/deployments/$DeploymentId/audience/members" -o json 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($membersRaw)) {
            Write-Host "    Skipped: signed-in user cannot read WUfB audience members. Logic App MI proof is in run history." -ForegroundColor Yellow
        } else {
            $members = $membersRaw | ConvertFrom-Json
            foreach ($m in $members.value) {
                Write-Host ("    Device id  : {0}" -f $m.id)
                Write-Host ("    Quality    : {0}  (last modified: {1})" -f $m.enrollment.quality.enrollmentState, $m.enrollment.quality.lastModifiedDateTime)
                Write-Host ("    Errors     : {0}" -f ($m.errors.Count))
            }
            if ($members.value.Count -eq 0) { Write-Host "    No members in audience." -ForegroundColor Red }
        }
    } catch {
        Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    try {
        $statesRaw = az rest --method GET --url "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$IntuneRemediationScriptId/deviceRunStates" -o json 2>$null
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($statesRaw)) {
            Write-Host "    Skipped: signed-in user cannot read Intune device run states." -ForegroundColor Yellow
        } else {
            $states = ($statesRaw | ConvertFrom-Json).value
            if ($states.Count -eq 0) {
                Write-Host "    No device run states yet." -ForegroundColor Yellow
            } else {
                foreach ($s in $states) {
                    $stateColor = switch ($s.detectionState) { 'success' { 'Green' }; 'scriptError' { 'Red' }; default { 'Yellow' } }
                    $remColor = switch ($s.remediationState) { 'remediationFailed' { 'Red' }; 'skipped' { 'Yellow' }; 'success' { 'Green' }; default { 'Cyan' } }
                    Write-Host ("    Device run : {0}" -f $s.id)
                    Write-Host ("    Detection  : {0}" -f $s.detectionState) -ForegroundColor $stateColor
                    Write-Host ("    Pre-detect : {0}" -f $s.preRemediationDetectionScriptOutput)
                    Write-Host ("    Remediation: {0}" -f $s.remediationState) -ForegroundColor $remColor
                    Write-Host ("    Post-detect: {0}" -f $s.postRemediationDetectionScriptOutput)
                    Write-Host ("    Updated    : {0}" -f $s.lastStateUpdateDateTime)
                }
            }
        }
    } catch {
        Write-Host "    ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ---------- 4. MDETVM_CL — the loop closes here ----------
Write-Host "`n[4/4] MDETVM_CL — does the CVE still affect the device?" -ForegroundColor Yellow
$kql = "let latestDeviceTvm = MDETVM_CL | where deviceName == '$DeviceName' | summarize LatestTime=max(TimeGenerated) by deviceName; MDETVM_CL | join kind=inner latestDeviceTvm on deviceName | where TimeGenerated == LatestTime | summarize LatestSnapshot=max(TimeGenerated), TotalRows=count(), CveRows=countif(cveId == '$CveId'), OsVersion=take_any(osVersion), Kb=take_anyif(recommendedSecurityUpdateId, cveId == '$CveId')"
$result = az monitor log-analytics query -w $workspaceId --analytics-query $kql -o json | ConvertFrom-Json
$rows = @($result)
$cveRows = if ($rows.Count -gt 0) { [int]$rows[0].CveRows } else { 0 }
if ($rows.Count -eq 0 -or $cveRows -eq 0) {
    Write-Host "    *** CVE NO LONGER REPORTED — REMEDIATION CONFIRMED ***" -ForegroundColor Green
    Write-Host "    The device is no longer vulnerable to $CveId per MDVM." -ForegroundColor Green
} else {
    Write-Host ("    CVE still present. Latest snapshot: {0}  Rows: {1}" -f $rows[0].LatestSnapshot, $cveRows) -ForegroundColor Yellow
    Write-Host ("    OS version: {0}  Recommended KB: {1}" -f $rows[0].OsVersion, $rows[0].Kb) -ForegroundColor Yellow
    Write-Host "    Patch not yet installed OR MDVM has not rescanned." -ForegroundColor Yellow
}

Write-Host "`n----------------------------------------" -ForegroundColor Cyan
Write-Host "  Re-run this script after the playbook verification loop ingests fresh TVM data." -ForegroundColor Cyan
Write-Host "  Green in step 4 is the concrete remediation proof." -ForegroundColor Cyan
Write-Host "----------------------------------------`n" -ForegroundColor Cyan
