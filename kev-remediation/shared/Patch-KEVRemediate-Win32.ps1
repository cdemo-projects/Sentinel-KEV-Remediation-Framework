<#
.SYNOPSIS
    Patches the deployed KEV-Remediate Logic App's Path_B with the Win32 app assignment scope.

.DESCRIPTION
    Pulls the live Logic App definition, splices the Win32 snippet from
    kev-remediation/<cloud>/KEV-Remediate-Win32-Snippet[.gov].json into Path_B_Third_Party_Approval,
    adds the Win32MappingUrl parameter, and writes the updated definition back.

    DEFAULT MODE: -WhatIf. Prints the diff, writes a backup, but does NOT modify the live Logic App.
    Re-run with -Apply to actually patch.

.PARAMETER Cloud
    Commercial or Gov

.PARAMETER ResourceGroup
    RG holding the KEV-Remediate Logic App.

.PARAMETER LogicAppName
    Default: KEV-Remediate

.PARAMETER Win32MappingUrl
    Blob URL printed by Deploy-MappingHost.ps1.

.PARAMETER Apply
    Apply the patch. Without this flag, runs in dry-run mode and only shows the planned change + backup file.

.EXAMPLE
    # Dry run (always do this first)
    .\Patch-KEVRemediate-Win32.ps1 -Cloud Gov -ResourceGroup <your-rg> -Win32MappingUrl https://<storage>.blob.core.usgovcloudapi.net/kev-config/Win32-App-Mapping.json

.EXAMPLE
    # Apply
    .\Patch-KEVRemediate-Win32.ps1 -Cloud Gov -ResourceGroup <your-rg> -Win32MappingUrl https://... -Apply
#>

#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [Parameter(Mandatory)] [string]$ResourceGroup,
    [string]$LogicAppName = 'KEV-Remediate',
    [Parameter(Mandatory)] [string]$Win32MappingUrl,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$mgmtBase = if ($Cloud -eq 'Gov') { 'https://management.usgovcloudapi.net' } else { 'https://management.azure.com' }
$snippetPath = if ($Cloud -eq 'Gov') {
    Join-Path $PSScriptRoot '..\gov\KEV-Remediate-Win32-Snippet.gov.json'
} else {
    Join-Path $PSScriptRoot '..\commercial\KEV-Remediate-Win32-Snippet.json'
}

if (-not (Test-Path $snippetPath)) { throw "Snippet not found: $snippetPath" }

# ---------- Pull live definition ----------
Write-Host "[1/5] Fetching live Logic App definition..." -ForegroundColor Cyan
$sub = (az account show --query id -o tsv)
$base = "$mgmtBase/subscriptions/$sub/resourceGroups/$ResourceGroup/providers/Microsoft.Logic/workflows/$LogicAppName"
$live = az rest --method get --url "$base`?api-version=2019-05-01" -o json | ConvertFrom-Json -Depth 100
$definition = $live.properties.definition

# ---------- Backup ----------
$backupPath = Join-Path (Get-Location) "KEV-Remediate-backup-$(Get-Date -f yyyyMMdd-HHmmss).json"
$live | ConvertTo-Json -Depth 100 | Set-Content -Path $backupPath -NoNewline
Write-Host "      Backup: $backupPath" -ForegroundColor Green

# ---------- Load snippet ----------
Write-Host "[2/5] Loading Win32 snippet..." -ForegroundColor Cyan
$snippetWrapper = Get-Content -Raw $snippetPath | ConvertFrom-Json -Depth 50
$snippetScope = $snippetWrapper.Path_B_Win32_App_Assignment

# ---------- Locate insertion point ----------
Write-Host "[3/5] Locating Path_B_Third_Party_Approval scope..." -ForegroundColor Cyan
$pathB = $definition.actions.Path_B_Third_Party_Approval
if (-not $pathB) {
    throw "Path_B_Third_Party_Approval scope not found in live Logic App. Cannot proceed - the deployed Logic App structure does not match what the snippet was designed for."
}

# ---------- Splice ----------
Write-Host "[4/5] Splicing snippet (idempotent)..." -ForegroundColor Cyan
# Add the new scope as a sibling action inside Path_B_Third_Party_Approval, running after whatever already runs there.
# This is intentionally additive - the existing Proactive Remediation actions are NOT removed by this script.
# Removing them is a separate, explicit decision.

if ($pathB.actions.PSObject.Properties.Name -contains 'Path_B_Win32_App_Assignment') {
    Write-Host "      Snippet already present - will be replaced." -ForegroundColor Yellow
}
$pathB.actions | Add-Member -MemberType NoteProperty -Name 'Path_B_Win32_App_Assignment' -Value $snippetScope -Force

# ---------- Add Win32MappingUrl parameter ----------
if (-not ($definition.parameters.PSObject.Properties.Name -contains 'Win32MappingUrl')) {
    Write-Host "      Adding Win32MappingUrl parameter to definition..." -ForegroundColor Yellow
    $definition.parameters | Add-Member -MemberType NoteProperty -Name 'Win32MappingUrl' -Value @{
        type = 'string'
        defaultValue = $Win32MappingUrl
    } -Force
} else {
    Write-Host "      Win32MappingUrl parameter exists - updating defaultValue..." -ForegroundColor Yellow
    $definition.parameters.Win32MappingUrl.defaultValue = $Win32MappingUrl
}

# ---------- Apply or dry-run ----------
$payload = @{
    properties = @{
        definition = $definition
        state = $live.properties.state
    }
    location = $live.location
} | ConvertTo-Json -Depth 100 -Compress

$plannedFile = Join-Path (Get-Location) "KEV-Remediate-planned-$(Get-Date -f yyyyMMdd-HHmmss).json"
$payload | Set-Content -Path $plannedFile -NoNewline
Write-Host "      Planned definition: $plannedFile" -ForegroundColor Green

if (-not $Apply) {
    Write-Host ""
    Write-Host "[5/5] DRY-RUN complete. No changes applied to the live Logic App." -ForegroundColor Yellow
    Write-Host "      Review the diff between $backupPath and $plannedFile, then re-run with -Apply." -ForegroundColor Yellow
    return
}

Write-Host "[5/5] Applying patch (PUT to ARM)..." -ForegroundColor Cyan
$tmpBody = [IO.Path]::GetTempFileName()
$payload | Set-Content -Path $tmpBody -NoNewline
az rest --method put --url "$base`?api-version=2019-05-01" --body "@$tmpBody" --headers "Content-Type=application/json" --output none
Remove-Item $tmpBody -Force
Write-Host "      Patch applied. Trigger a test run via Sentinel automation rule to validate." -ForegroundColor Green
