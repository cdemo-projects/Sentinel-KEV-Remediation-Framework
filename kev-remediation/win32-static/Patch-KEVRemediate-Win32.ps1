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
    [Parameter(Mandatory)] [string]$AuditIngestionUrl,
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
# Recursively walk the action tree to find the parent of Path_B_Third_Party_Approval.
# In the gov template, Path_B lives under definition.actions.Check_KB_Exists.else.actions
# instead of definition.actions directly, so we search the whole tree.
function Find-PathBContainer {
    param($Obj)
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        if ($Obj.PSObject.Properties.Name -contains 'Path_B_Third_Party_Approval') { return $Obj }
        foreach ($p in $Obj.PSObject.Properties) {
            $r = Find-PathBContainer $p.Value
            if ($r) { return $r }
        }
    } elseif ($Obj -is [System.Collections.IEnumerable] -and -not ($Obj -is [string])) {
        foreach ($item in $Obj) {
            $r = Find-PathBContainer $item
            if ($r) { return $r }
        }
    }
    return $null
}
$pathBContainer = Find-PathBContainer $definition
if (-not $pathBContainer) {
    throw "Path_B_Third_Party_Approval scope not found anywhere in live Logic App. Cannot proceed - the deployed Logic App structure does not match what the snippet was designed for."
}
$pathB = $pathBContainer.Path_B_Third_Party_Approval
Write-Host "      Found Path_B_Third_Party_Approval (type: $($pathB.type))" -ForegroundColor Green

# ---------- Splice ----------
Write-Host "[4/5] Splicing snippet (idempotent)..." -ForegroundColor Cyan
# Add the new scope as a sibling action inside Path_B_Third_Party_Approval, running after whatever already runs there.
# This is intentionally additive - the existing Proactive Remediation actions are NOT removed by this script.
# Removing them is a separate, explicit decision.

if ($pathB.actions.PSObject.Properties.Name -contains 'Path_B_Win32_App_Assignment') {
    Write-Host "      Snippet already present - will be replaced." -ForegroundColor Yellow
}

# Logic Apps requires InitializeVariable actions to live at workflow root (not nested in scopes),
# AND requires one variable per InitializeVariable action. Extract any 1_Init_Variables (or similar)
# from the snippet, emit each variable as its own root-level Init_<VarName> action that runs after
# the existing Init_DeviceId_Array, and remove the snippet's init.
$snippetInit = $snippetScope.actions.PSObject.Properties | Where-Object { $_.Value.type -eq 'InitializeVariable' } | Select-Object -First 1
if ($snippetInit) {
    Write-Host "      Extracting $($snippetInit.Name) and emitting per-variable root inits..." -ForegroundColor Yellow
    $rootInit = $definition.actions.Init_DeviceId_Array
    if (-not $rootInit) { throw "Logic App has no root Init_DeviceId_Array action; cannot anchor snippet variables." }

    # Find or create a chain anchor (the last Init_* action in the existing root chain)
    $existingInitNames = @($definition.actions.PSObject.Properties.Name | Where-Object { $definition.actions.$_.type -eq 'InitializeVariable' })
    $previousInit = ($existingInitNames | Sort-Object -Descending | Select-Object -First 1)
    if (-not $previousInit) { $previousInit = 'Init_DeviceId_Array' }

    $addedCount = 0
    foreach ($v in $snippetInit.Value.inputs.variables) {
        $newActionName = "Init_$($v.name)"
        if ($definition.actions.PSObject.Properties.Name -contains $newActionName) {
            continue  # already exists from a prior patch run
        }
        $newAction = [PSCustomObject]@{
            type     = 'InitializeVariable'
            runAfter = [PSCustomObject]@{ $previousInit = @('Succeeded') }
            inputs   = [PSCustomObject]@{ variables = @($v) }
        }
        $definition.actions | Add-Member -MemberType NoteProperty -Name $newActionName -Value $newAction -Force
        $previousInit = $newActionName
        $addedCount++
    }
    Write-Host "      Added $addedCount per-variable Init_* actions at root level." -ForegroundColor Green

    # Remove the snippet's init action and any runAfter references to it
    $snippetInitName = $snippetInit.Name
    $snippetScope.actions.PSObject.Properties.Remove($snippetInitName)
    foreach ($p in $snippetScope.actions.PSObject.Properties) {
        if ($p.Value.PSObject.Properties.Name -contains 'runAfter' -and $p.Value.runAfter.PSObject.Properties.Name -contains $snippetInitName) {
            $p.Value.PSObject.Properties.Remove('runAfter')
        }
    }
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

# ---------- Add other snippet parameters (audit ingestion + management base URL) ----------
$auditAudience = if ($Cloud -eq 'Gov') { 'https://monitor.azure.us' } else { 'https://monitor.azure.com' }
$mgmtAudience  = if ($Cloud -eq 'Gov') { 'https://management.usgovcloudapi.net' } else { 'https://management.azure.com' }

$snippetParams = @{
    AuditIngestionUrl       = $AuditIngestionUrl
    AuditIngestionAudience  = $auditAudience
    ManagementBaseUrl       = $mgmtAudience
}
foreach ($k in $snippetParams.Keys) {
    $v = $snippetParams[$k]
    if (-not ($definition.parameters.PSObject.Properties.Name -contains $k)) {
        Write-Host "      Adding $k parameter to definition..." -ForegroundColor Yellow
        $definition.parameters | Add-Member -MemberType NoteProperty -Name $k -Value @{ type='string'; defaultValue=$v } -Force
    } else {
        Write-Host "      $k parameter exists - updating defaultValue..." -ForegroundColor Yellow
        $definition.parameters.$k.defaultValue = $v
    }
}

# ---------- Apply or dry-run ----------
# Strip $-prefixed metadata keys ($comment, $contract, $batchingNote, $pacingNote, etc.) that are
# valid in our source snippet for documentation but are rejected by the Logic Apps deserializer.
function Remove-MetaKeys {
    param($Obj)
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        # Strip $-prefixed metadata keys EXCEPT Logic Apps service-required ones:
        # $schema (root definition), $connections (parameters), $authentication (some triggers)
        $keep = @('$schema', '$connections', '$authentication')
        $toRemove = @($Obj.PSObject.Properties.Name | Where-Object { $_ -like '$*' -and $keep -notcontains $_ })
        foreach ($k in $toRemove) { $Obj.PSObject.Properties.Remove($k) }
        foreach ($p in $Obj.PSObject.Properties) { Remove-MetaKeys $p.Value }
    } elseif ($Obj -is [System.Collections.IList]) {
        foreach ($item in $Obj) { Remove-MetaKeys $item }
    }
}
Remove-MetaKeys $definition

$payload = @{
    properties = @{
        definition = $definition
        parameters = $live.properties.parameters
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
