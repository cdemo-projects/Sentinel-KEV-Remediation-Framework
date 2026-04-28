<#
.SYNOPSIS
    Hardens the AutoClose-KEVIncidents Logic App to require two consecutive
    clean MDETVM snapshots before auto-closing a KEV incident.

.DESCRIPTION
    The default AutoClose Logic App closes a KEV incident if the CVE doesn't
    appear in MDETVM_CL for the affected device. But MDETVM is a single daily
    snapshot - if MDE has a glitch and returns no rows for a device, the
    incident auto-closes even though the CVE is still on the device.

    This patch modifies the auto-close KQL query to require:
      - The CVE+device combo absent from BOTH the most recent and the prior
        snapshot
      - The device having ANY MDETVM rows in either snapshot (proves MDE
        reported on it; protects against agent outages)

    Idempotent.

.PARAMETER SubscriptionId
.PARAMETER ResourceGroupName
.PARAMETER WorkflowName    Default: AutoClose-KEVIncidents

.EXAMPLE
    .\Patch-AutoCloseTwoSnapshots.ps1 `
        -SubscriptionId <subscription-id> `
        -ResourceGroupName <resource-group>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId    = '<subscription-id>',
    [string]$ResourceGroupName = '<resource-group>',
    [string]$WorkflowName      = 'AutoClose-KEVIncidents'
)

$ErrorActionPreference = 'Stop'
az account set --subscription $SubscriptionId | Out-Null

# ── Fetch workflow ──
Write-Host '[1/3] Fetching live workflow...' -ForegroundColor Cyan
$resource = az resource show `
    --resource-group $ResourceGroupName `
    --name $WorkflowName `
    --resource-type Microsoft.Logic/workflows `
    --api-version 2019-05-01 `
    --output json | ConvertFrom-Json -Depth 100

$definition = $resource.properties.definition

# Locate the Run_KQL_Query action (whatever it's named in this version)
$kqlActionName = $definition.actions.PSObject.Properties.Name |
    Where-Object {
        $a = $definition.actions.$_
        $a.type -eq 'ApiConnection' -and $a.inputs.path -like '*queryWorkspace*'
    } | Select-Object -First 1

if (-not $kqlActionName) {
    throw 'Could not find a Log Analytics queryWorkspace action in the workflow. Cannot patch.'
}

$kqlAction = $definition.actions.$kqlActionName
$existingQuery = $kqlAction.inputs.body.query

# ── Sentinel for prior patch ──
$marker = '// HARDENED: requires two consecutive clean snapshots'
if ($existingQuery -like "*$marker*") {
    Write-Host '  Two-snapshot guard already in place. Nothing to do.' -ForegroundColor Yellow
    return
}

# ── Build hardened query ──
Write-Host '[2/3] Replacing query with hardened version...' -ForegroundColor Cyan

$hardenedQuery = @"
$marker
// Returns CVE+device pairs ONLY if absent from BOTH the most recent and prior snapshot,
// AND the device reported at all in either snapshot (protects against MDE outages).
let LookbackHours = 30h;
let SnapshotGap = 24h;
let RecentSnapshot = MDETVM_CL
    | where TimeGenerated > ago(SnapshotGap)
    | summarize arg_max(TimeGenerated, *) by deviceName, cveId;
let PriorSnapshot = MDETVM_CL
    | where TimeGenerated between (ago(LookbackHours) .. ago(SnapshotGap))
    | summarize arg_max(TimeGenerated, *) by deviceName, cveId;
let DevicesReportingRecently = MDETVM_CL
    | where TimeGenerated > ago(LookbackHours)
    | distinct deviceName;
SecurityIncident
| where Status == 'Active'
| where Title has 'CISA KEV' and Title contains 'CVE-'
| extend CveMatch = extract(@'(CVE-\d{4}-\d{4,7})', 1, Title)
| extend DeviceMatch = extract(@'CISA KEV Detected on (\S+)$', 1, Title)
| where isnotempty(CveMatch) and isnotempty(DeviceMatch)
| where DeviceMatch in (DevicesReportingRecently)   // device must have reported - blocks closure during MDE outage
| join kind=leftanti RecentSnapshot on `$left.DeviceMatch == `$right.deviceName, `$left.CveMatch == `$right.cveId
| join kind=leftanti PriorSnapshot  on `$left.DeviceMatch == `$right.deviceName, `$left.CveMatch == `$right.cveId
| project IncidentNumber, IncidentName = Name, CveMatch, DeviceMatch
"@

$kqlAction.inputs.body.query = $hardenedQuery

# ── Submit ──
Write-Host '[3/3] Submitting updated definition...' -ForegroundColor Cyan
$tmp = New-TemporaryFile
($resource | ConvertTo-Json -Depth 100) | Set-Content -Path $tmp -Encoding UTF8

az resource update `
    --ids $resource.id `
    --api-version 2019-05-01 `
    --properties (Get-Content $tmp -Raw) | Out-Null

Remove-Item $tmp

Write-Host '  Hardened query installed.' -ForegroundColor Green
Write-Host "`nAutoClose will now require BOTH the most recent snapshot AND the snapshot from 24h prior to be clean before closing an incident, AND will skip devices that have stopped reporting to MDE." -ForegroundColor White
