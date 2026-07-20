<#
.SYNOPSIS
    Deploys the KEV-ServiceNow-v1 Logic App (GCC High / DoD) — creates ServiceNow incidents from KEV CVE matches.

.DESCRIPTION
    Creates (or updates) Logic App KEV-ServiceNow-v1 in the specified resource group.
    For demo: pass -ServiceNowInstanceUrl pointing at a webhook collector
    (https://webhook.site/<your-uuid>) to see the payload without provisioning ServiceNow.
    For production: pass real ServiceNow instance URL + service account creds.

.PARAMETER ServiceNowInstanceUrl
    ServiceNow base URL or webhook collector URL for demo.

.PARAMETER ServiceNowTable
    Table to POST to. Common: incident, sn_si_incident, sn_vul_vulnerable_item.

.PARAMETER ServiceNowUsername
    ServiceNow service account username for Basic Auth.

.PARAMETER ServiceNowPassword
    Password (plaintext for demo; production should use Key Vault reference).

.EXAMPLE
    # Demo: post to webhook collector to see the JSON
    .\Deploy-KEVServiceNow.gcc-high.ps1 `
        -ServiceNowInstanceUrl "https://webhook.site/abc-123-def" `
        -ServiceNowUsername "demo" `
        -ServiceNowPassword "demo"

.EXAMPLE
    # Real ServiceNow PDI
    .\Deploy-KEVServiceNow.gcc-high.ps1 `
        -ServiceNowInstanceUrl "https://devXXXXX.service-now.com" `
        -ServiceNowUsername "kev-remediate-svc" `
        -ServiceNowPassword "<password>"
#>
[CmdletBinding()]
param(
    [string]$SubscriptionId       = "<subscription-id>",
    [string]$ResourceGroupName    = "<resource-group>",
    [string]$Location             = "usgovtexas",
    [string]$LogicAppName         = "KEV-ServiceNow-v1",

    [Parameter(Mandatory)] [string]$ServiceNowInstanceUrl,
    [string]$ServiceNowTable      = "incident",
    [Parameter(Mandatory)] [string]$ServiceNowUsername,
    [Parameter(Mandatory)] [string]$ServiceNowPassword,
    [string]$AssignmentGroup      = "Endpoint Engineering",
    [string]$DefenderTenantUrl    = "https://security.microsoft.us"
)

$ErrorActionPreference = "Stop"

$defPath = Join-Path $PSScriptRoot "KEV-ServiceNow-v1.gcc-high.json"
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
        parameters = @{
            ServiceNowInstanceUrl   = @{ value = $ServiceNowInstanceUrl }
            ServiceNowTable         = @{ value = $ServiceNowTable }
            ServiceNowUsername      = @{ value = $ServiceNowUsername }
            ServiceNowPasswordKvRef = @{ value = $ServiceNowPassword }
            AssignmentGroup         = @{ value = $AssignmentGroup }
            DefenderTenantUrl       = @{ value = $DefenderTenantUrl }
        }
    }
}

$body = $payload | ConvertTo-Json -Depth 50

Write-Host "[2/3] PUT $LogicAppName ..." -ForegroundColor Cyan
$result = Invoke-RestMethod -Method Put -Uri $laUri -Headers $headers -Body $body
Write-Host "      provisioningState = $($result.properties.provisioningState)" -ForegroundColor Green
Write-Host "      principalId       = $($result.identity.principalId)" -ForegroundColor Green

Write-Host "[3/3] Fetching HTTP trigger URL..." -ForegroundColor Cyan
$cbUri = "https://management.usgovcloudapi.net/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.Logic/workflows/$LogicAppName/triggers/manual/listCallbackUrl?api-version=2016-06-01"
$cb = Invoke-RestMethod -Method Post -Uri $cbUri -Headers $headers
Write-Host ""
Write-Host "Trigger URL (save this):" -ForegroundColor Yellow
Write-Host $cb.value -ForegroundColor White
Write-Host ""
Write-Host "[Test]" -ForegroundColor Cyan
Write-Host "  .\Test-KEVServiceNow.gcc-high.ps1 -TriggerUrl `"$($cb.value)`"" -ForegroundColor DarkGray
