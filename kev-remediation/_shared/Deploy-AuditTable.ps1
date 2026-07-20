<#
.SYNOPSIS
    Deploys the KEV remediation audit table (DCR + custom table + DCE + RBAC).

.DESCRIPTION
    One-shot helper that resolves the Logic App MI principalId, deploys audit-table.bicep,
    and prints the DCR ingestion URL the Logic App should POST audit rows to.

.PARAMETER Cloud
    Commercial or Gov.

.PARAMETER ResourceGroup
    RG holding the KEV-Remediate Logic App.

.PARAMETER LogicAppName
    Default: KEV-Remediate

.PARAMETER WorkspaceName
    Sentinel workspace name.

.PARAMETER WorkspaceResourceGroup
    Workspace RG if different.

.EXAMPLE
    .\Deploy-AuditTable.ps1 -Cloud Gov -ResourceGroup <your-rg> -WorkspaceName <ws> -WorkspaceResourceGroup <ws-rg>
#>

#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [Parameter(Mandatory)] [string]$ResourceGroup,
    [string]$LogicAppName = 'KEV-Remediate',
    [Parameter(Mandatory)] [string]$WorkspaceName,
    [string]$WorkspaceResourceGroup = $null
)

$ErrorActionPreference = 'Stop'
if (-not $WorkspaceResourceGroup) { $WorkspaceResourceGroup = $ResourceGroup }
$cliEnv = if ($Cloud -eq 'Gov') { 'AzureUSGovernment' } else { 'AzureCloud' }

$current = (az account show --query environmentName -o tsv 2>$null)
if ($current -ne $cliEnv) {
    Write-Host "Switching az CLI to $cliEnv ..." -ForegroundColor Cyan
    az cloud set --name $cliEnv | Out-Null
    az login --use-device-code | Out-Null
}

Write-Host "[1/3] Resolving Logic App MI ..." -ForegroundColor Cyan
$la = az resource show --resource-group $ResourceGroup --name $LogicAppName --resource-type Microsoft.Logic/workflows --query "identity.principalId" -o tsv
if (-not $la) { throw "Logic App '$LogicAppName' has no system-assigned MI." }
Write-Host "      principalId: $la" -ForegroundColor Green

Write-Host "[2/3] Deploying audit-table.bicep ..." -ForegroundColor Cyan
$bicepPath = Join-Path $PSScriptRoot 'audit-table.bicep'
$out = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $bicepPath `
    --parameters workspaceName=$WorkspaceName workspaceResourceGroup=$WorkspaceResourceGroup logicAppPrincipalId=$la `
    --query "properties.outputs" -o json | ConvertFrom-Json
Write-Host "      Done." -ForegroundColor Green

$endpoint = $out.logsIngestionEndpoint.value
$dcrImmutable = $out.dcrImmutableId.value
$stream = $out.streamName.value
$ingestUrl = "$endpoint/dataCollectionRules/$dcrImmutable/streams/$stream`?api-version=2023-01-01"

Write-Host ""
Write-Host "[3/3] Logic App audit ingestion URL:" -ForegroundColor Green
Write-Host ""
Write-Host "  $ingestUrl" -ForegroundColor White
Write-Host ""
Write-Host "Add this as Logic App parameter 'AuditIngestionUrl' and use ManagedServiceIdentity auth with audience https://monitor.azure.com (commercial) or https://monitor.azure.us (gov)." -ForegroundColor Cyan
