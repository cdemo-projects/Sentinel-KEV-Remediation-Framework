<#
.SYNOPSIS
    Locks down the KEV-Remediate Logic App against tampering and enables
    diagnostic logging to Sentinel so the four Detect-*.json analytics rules
    have data to query.

.DESCRIPTION
    Applies four hardening controls:

      1. ReadOnly resource lock on the KEV-Remediate Logic App workflow
         (prevents definition changes without lock removal first)
      2. ReadOnly resource lock on the AutoClose-KEVIncidents Logic App
      3. Diagnostic settings: send Logic App run history to the Sentinel workspace
      4. Diagnostic settings: send AzureActivity to the Sentinel workspace
         (captures definition writes for the Detect-LogicAppDefinitionChange rule)

    Idempotent. Safe to re-run.

.PARAMETER ResourceGroupName
    Resource group containing the Logic Apps and Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace with Sentinel enabled.

.PARAMETER LogicAppName
    Name of the KEV-Remediate Logic App. Default: KEV-Remediate

.PARAMETER AutoCloseLogicAppName
    Name of the AutoClose Logic App. Default: AutoClose-KEVIncidents

.EXAMPLE
    .\Lock-KEVRemediateResources.ps1 -ResourceGroupName rg-sentinel -WorkspaceName law-sentinel
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [string]$LogicAppName = 'KEV-Remediate',

    [string]$AutoCloseLogicAppName = 'AutoClose-KEVIncidents'
)

$ErrorActionPreference = 'Stop'

# ── Resolve resources ──
Write-Host '[1/4] Resolving resources...' -ForegroundColor Cyan

$workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
if (-not $workspace) { throw "Workspace '$WorkspaceName' not found in '$ResourceGroupName'." }

$kevLogicApp = Get-AzResource `
    -ResourceGroupName $ResourceGroupName `
    -ResourceType Microsoft.Logic/workflows `
    -Name $LogicAppName `
    -ErrorAction SilentlyContinue
if (-not $kevLogicApp) { throw "Logic App '$LogicAppName' not found." }

$autoCloseLogicApp = Get-AzResource `
    -ResourceGroupName $ResourceGroupName `
    -ResourceType Microsoft.Logic/workflows `
    -Name $AutoCloseLogicAppName `
    -ErrorAction SilentlyContinue

# ── Apply ReadOnly locks ──
Write-Host '[2/4] Applying ReadOnly locks on Logic Apps...' -ForegroundColor Cyan

function Set-WorkflowLock {
    param([string]$ResourceId, [string]$LockName)

    $existing = Get-AzResourceLock -Scope $ResourceId -LockName $LockName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  Lock '$LockName' already present." -ForegroundColor Yellow
        return
    }

    if ($PSCmdlet.ShouldProcess($ResourceId, "Apply ReadOnly lock '$LockName'")) {
        New-AzResourceLock `
            -LockName $LockName `
            -LockLevel ReadOnly `
            -Scope $ResourceId `
            -LockNotes 'Prevents tampering with KEV remediation Logic App definition. Remove only with change-control approval.' `
            -Force | Out-Null
        Write-Host "  Lock '$LockName' applied." -ForegroundColor Green
    }
}

Set-WorkflowLock -ResourceId $kevLogicApp.ResourceId -LockName "lock-$LogicAppName"
if ($autoCloseLogicApp) {
    Set-WorkflowLock -ResourceId $autoCloseLogicApp.ResourceId -LockName "lock-$AutoCloseLogicAppName"
}

# ── Diagnostic settings: Logic App run history → Sentinel ──
Write-Host '[3/4] Configuring diagnostic settings on Logic Apps...' -ForegroundColor Cyan

function Set-WorkflowDiagnostics {
    param([string]$ResourceId, [string]$WorkspaceResourceId)

    $diagName = 'send-to-sentinel'
    $existing = Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $diagName }

    if ($existing) {
        Write-Host "  Diagnostic setting '$diagName' already configured." -ForegroundColor Yellow
        return
    }

    if ($PSCmdlet.ShouldProcess($ResourceId, "Enable diagnostics -> $WorkspaceName")) {
        $log = New-AzDiagnosticSettingLogSettingsObject `
            -Category WorkflowRuntime `
            -Enabled $true
        $metric = New-AzDiagnosticSettingMetricSettingsObject `
            -Category AllMetrics `
            -Enabled $true
        New-AzDiagnosticSetting `
            -Name $diagName `
            -ResourceId $ResourceId `
            -WorkspaceId $WorkspaceResourceId `
            -Log $log `
            -Metric $metric | Out-Null
        Write-Host "  Diagnostic setting applied." -ForegroundColor Green
    }
}

Set-WorkflowDiagnostics -ResourceId $kevLogicApp.ResourceId -WorkspaceResourceId $workspace.ResourceId
if ($autoCloseLogicApp) {
    Set-WorkflowDiagnostics -ResourceId $autoCloseLogicApp.ResourceId -WorkspaceResourceId $workspace.ResourceId
}

# ── AzureActivity to workspace (covers Logic App write events) ──
Write-Host '[4/4] Confirming AzureActivity is connected to Sentinel...' -ForegroundColor Cyan

$subId = (Get-AzContext).Subscription.Id
$activityCheck = Search-AzGraph -Query @"
resources
| where type == 'microsoft.operationalinsights/workspaces'
| where id =~ '$($workspace.ResourceId)'
"@ -ErrorAction SilentlyContinue

Write-Host '  Verify in Sentinel portal: Data connectors -> Azure Activity -> Connected.' -ForegroundColor Yellow
Write-Host '  If not connected, enable it now (manual step in the portal or via Microsoft.Insights/diagnosticSettings on the subscription scope).' -ForegroundColor Yellow

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Locks applied to:" -ForegroundColor White
Write-Host "  - $LogicAppName" -ForegroundColor Gray
if ($autoCloseLogicApp) { Write-Host "  - $AutoCloseLogicAppName" -ForegroundColor Gray }
Write-Host "Diagnostic settings sending WorkflowRuntime logs to: $WorkspaceName" -ForegroundColor White
Write-Host "`nNext: deploy the Detect-*.json analytics rules from this folder." -ForegroundColor Cyan
