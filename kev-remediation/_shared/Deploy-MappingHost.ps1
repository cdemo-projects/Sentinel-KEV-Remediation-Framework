<#
.SYNOPSIS
    Deploys mapping-host-storage.bicep and uploads Win32-App-Mapping.json to it.

.DESCRIPTION
    One-shot helper that:
      1. Looks up the KEV-Remediate Logic App's MI principalId
      2. Deploys mapping-host-storage.bicep (creates storage account + container + RBAC)
      3. Uploads the local Win32-App-Mapping.json to the container
      4. Prints the blob URL to set on the Logic App's Win32MappingUrl parameter

    Idempotent. Re-running uploads the latest mapping JSON without re-creating infrastructure.

.PARAMETER Cloud
    Commercial or Gov

.PARAMETER ResourceGroup
    RG holding the KEV-Remediate Logic App. Storage account is created here too.

.PARAMETER LogicAppName
    Name of the deployed Logic App. Default: KEV-Remediate

.PARAMETER StorageAccountName
    Globally unique. Default: kevcfg<8-char-hash-of-rg>

.PARAMETER MappingPath
    Local path to Win32-App-Mapping.json. Default: ../shared/Win32-App-Mapping.json

.PARAMETER AllowPublicNetworkAccess
    Pass -AllowPublicNetworkAccess:$false to lock storage to private endpoints (requires VNet integration on the Logic App).

.EXAMPLE
    .\Deploy-MappingHost.ps1 -Cloud Gov -ResourceGroup <your-rg>
#>

#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [Parameter(Mandatory)] [string]$ResourceGroup,
    [string]$LogicAppName = 'KEV-Remediate',
    [string]$StorageAccountName = '',
    [string]$MappingPath = "$PSScriptRoot/Win32-App-Mapping.json",
    [bool]$AllowPublicNetworkAccess = $true
)

$ErrorActionPreference = 'Stop'

$mgmtBase = if ($Cloud -eq 'Gov') { 'https://management.usgovcloudapi.net' } else { 'https://management.azure.com' }
$tokenAud = if ($Cloud -eq 'Gov') { 'https://management.usgovcloudapi.net' } else { 'https://management.azure.com' }
$cliEnv   = if ($Cloud -eq 'Gov') { 'AzureUSGovernment' } else { 'AzureCloud' }

# Confirm CLI is in the right cloud
$current = (az account show --query environmentName -o tsv 2>$null)
if ($current -ne $cliEnv) {
    Write-Host "Switching az CLI to $cliEnv ..." -ForegroundColor Cyan
    az cloud set --name $cliEnv | Out-Null
    az login --use-device-code | Out-Null
}

# Derive default storage name if not provided (deterministic, stays under 24 chars)
if (-not $StorageAccountName) {
    $hash = [BitConverter]::ToString(
        [System.Security.Cryptography.SHA256]::Create().ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($ResourceGroup)
        )
    ).Replace('-','').ToLower().Substring(0, 8)
    $StorageAccountName = "kevcfg$hash"
}

Write-Host "[1/4] Resolving Logic App MI principalId for '$LogicAppName' in '$ResourceGroup'..." -ForegroundColor Cyan
$la = az resource show --resource-group $ResourceGroup --name $LogicAppName --resource-type Microsoft.Logic/workflows --query "{id:id, principalId:identity.principalId}" -o json | ConvertFrom-Json
if (-not $la.principalId) {
    throw "Logic App '$LogicAppName' has no system-assigned managed identity. Enable it first: az logic workflow identity assign -g $ResourceGroup -n $LogicAppName --system-assigned"
}
Write-Host "      principalId: $($la.principalId)" -ForegroundColor Green

Write-Host "[2/4] Deploying mapping-host-storage.bicep ..." -ForegroundColor Cyan
$bicepPath = Join-Path $PSScriptRoot 'mapping-host-storage.bicep'
$deployment = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $bicepPath `
    --parameters storageAccountName=$StorageAccountName `
                 logicAppPrincipalId=$($la.principalId) `
                 allowPublicNetworkAccess=$AllowPublicNetworkAccess `
    --query "properties.outputs" -o json | ConvertFrom-Json
$blobUrl = $deployment.mappingBlobUrl.value
Write-Host "      Blob URL: $blobUrl" -ForegroundColor Green

Write-Host "[3/4] Uploading Win32-App-Mapping.json ..." -ForegroundColor Cyan
if (-not (Test-Path $MappingPath)) { throw "Mapping JSON not found: $MappingPath" }
az storage blob upload `
    --account-name $StorageAccountName `
    --container-name 'kev-config' `
    --name 'Win32-App-Mapping.json' `
    --file $MappingPath `
    --auth-mode login `
    --overwrite `
    --content-type 'application/json' `
    --output none
Write-Host "      Uploaded." -ForegroundColor Green

Write-Host "[4/4] Done." -ForegroundColor Green
Write-Host ""
Write-Host "Set the deployed Logic App's Win32MappingUrl parameter to:" -ForegroundColor Yellow
Write-Host "  $blobUrl" -ForegroundColor White
Write-Host ""
Write-Host "Reminder: the Logic App's HTTP action that reads this URL must use:" -ForegroundColor Yellow
Write-Host "  authentication.type     = ManagedServiceIdentity" -ForegroundColor White
Write-Host "  authentication.audience = https://storage.azure.com" -ForegroundColor White
