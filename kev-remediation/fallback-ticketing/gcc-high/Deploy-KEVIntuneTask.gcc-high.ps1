<#
.SYNOPSIS
    Deploys the KEV-IntuneTask-v1 Logic App (GCC High / DoD) — Phase A: HTTP-triggered minimal PoC.

.DESCRIPTION
    Creates (or updates) a Logic App named KEV-IntuneTask-v1 in the specified resource
    group with a system-assigned managed identity, then loads the workflow definition
    from KEV-IntuneTask-v1.gcc-high.json.

    After this script:
      1. Run Assign-KEVRemediatePermissions.gcc-high.ps1 against THIS Logic App name to grant
         DeviceManagementApps.ReadWrite.All to its new MI.
      2. Test by invoking the workflow's HTTP trigger URL with a sample CVE payload
         (see Test-KEVIntuneTask.gcc-high.ps1).

.PARAMETER ResourceGroupName
    Resource group to deploy into. Defaults to the same RG as KEV-Remediate-v2 (<resource-group>).

.PARAMETER Location
    Azure Government region. Defaults to usgovtexas.

.PARAMETER LogicAppName
    Name of the Logic App. Default: KEV-IntuneTask-v1
#>
[CmdletBinding()]
param(
    [string]$SubscriptionId  = "<subscription-id>",
    [string]$ResourceGroupName = "<resource-group>",
    [string]$Location          = "usgovtexas",
    [string]$LogicAppName      = "KEV-IntuneTask-v1"
)

$ErrorActionPreference = "Stop"

$defPath = Join-Path $PSScriptRoot "KEV-IntuneTask-v1.gcc-high.json"
if (-not (Test-Path $defPath)) { throw "Workflow definition not found: $defPath" }
$definition = Get-Content $defPath -Raw | ConvertFrom-Json

Write-Host "[1/3] Acquiring management token (GCC High / DoD)..." -ForegroundColor Cyan
$token = az account get-access-token --subscription $SubscriptionId --resource https://management.usgovcloudapi.net --query accessToken -o tsv
if (-not $token) { throw "Failed to acquire token. Run: az login --use-device-code" }
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

$laUri = "https://management.usgovcloudapi.net/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/${LogicAppName}?api-version=2016-06-01"

$payload = @{
    location   = $Location
    identity   = @{ type = "SystemAssigned" }
    properties = @{
        state      = "Enabled"
        definition = $definition
        parameters = @{}
    }
}

$body = $payload | ConvertTo-Json -Depth 50

Write-Host "[2/3] PUT $LogicAppName ..." -ForegroundColor Cyan
$result = Invoke-RestMethod -Method Put -Uri $laUri -Headers $headers -Body $body
Write-Host "      provisioningState = $($result.properties.provisioningState)" -ForegroundColor Green
Write-Host "      principalId       = $($result.identity.principalId)" -ForegroundColor Green

# Get HTTP trigger callback URL for testing
Write-Host "[3/3] Fetching HTTP trigger URL..." -ForegroundColor Cyan
$cbUri = "https://management.usgovcloudapi.net/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$LogicAppName/triggers/manual/listCallbackUrl?api-version=2016-06-01"
$cb = Invoke-RestMethod -Method Post -Uri $cbUri -Headers $headers
Write-Host ""
Write-Host "Trigger URL (save this):" -ForegroundColor Yellow
Write-Host $cb.value -ForegroundColor White
Write-Host ""
Write-Host "[Next] Grant Graph permission to new MI:" -ForegroundColor Cyan
Write-Host "  .\Assign-KEVRemediatePermissions.gcc-high.ps1 -LogicAppName $LogicAppName -ResourceGroupName $ResourceGroupName -WorkspaceName <ws> -TenantId <tenant>" -ForegroundColor DarkGray
Write-Host "  (Sentinel Responder + LA Reader assignments will fail-safe if workspace not relevant — OK for this PoC)" -ForegroundColor DarkGray
