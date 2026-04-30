<#
.SYNOPSIS
    Assigns permissions to the KEV-Remediate Logic App managed identity.

.DESCRIPTION
    Grants the Logic App's system-assigned managed identity:
    1. Microsoft Sentinel Responder (on the workspace)
    2. Log Analytics Reader (on the workspace)
    3. Graph API app roles for Windows Updates, Intune remediation, device lookup, and email
    5. Entra role: Windows Update Deployment Administrator

    Run this AFTER deploying the Logic App (KEV-Remediate-LogicApp.json).
    Requires: Az PowerShell module, Global Admin or Privileged Role Admin.

.PARAMETER LogicAppName
    Name of the KEV-Remediate Logic App. Default: KEV-Remediate

.PARAMETER ResourceGroupName
    Resource group containing the Logic App and Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace with Sentinel enabled.

.EXAMPLE
    .\Assign-KEVRemediatePermissions.ps1 -ResourceGroupName "rg-sentinel" -WorkspaceName "law-sentinel"
#>

[CmdletBinding()]
param(
    [string]$LogicAppName = "KEV-Remediate",
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory)]
    [string]$WorkspaceName
)

$ErrorActionPreference = "Stop"

# --- Get the Logic App managed identity ---
Write-Host "[1/5] Getting Logic App managed identity..." -ForegroundColor Cyan
$logicApp = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Logic/workflows" -Name $LogicAppName
$mi = (Get-AzResource -ResourceId $logicApp.ResourceId -ExpandProperties).Identity.PrincipalId
if (-not $mi) { throw "Logic App '$LogicAppName' does not have a system-assigned managed identity." }
Write-Host "  MI Principal ID: $mi" -ForegroundColor Green

# --- Workspace scope ---
$workspaceId = (Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName).ResourceId

# --- 1. Microsoft Sentinel Responder on workspace ---
Write-Host "[2/5] Assigning Microsoft Sentinel Responder on workspace..." -ForegroundColor Cyan
$existing = Get-AzRoleAssignment -ObjectId $mi -Scope $workspaceId -RoleDefinitionName "Microsoft Sentinel Responder" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  Already assigned." -ForegroundColor Yellow
} else {
    New-AzRoleAssignment -ObjectId $mi -Scope $workspaceId -RoleDefinitionName "Microsoft Sentinel Responder" -ObjectType "ServicePrincipal" | Out-Null
    Write-Host "  Assigned." -ForegroundColor Green
}

# --- 2. Log Analytics Reader on workspace ---
Write-Host "[3/5] Assigning Log Analytics Reader on workspace..." -ForegroundColor Cyan
$existing = Get-AzRoleAssignment -ObjectId $mi -Scope $workspaceId -RoleDefinitionName "Log Analytics Reader" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "  Already assigned." -ForegroundColor Yellow
} else {
    New-AzRoleAssignment -ObjectId $mi -Scope $workspaceId -RoleDefinitionName "Log Analytics Reader" -ObjectType "ServicePrincipal" | Out-Null
    Write-Host "  Assigned." -ForegroundColor Green
}

# --- 3 & 4. Graph API app roles ---
Write-Host "[4/5] Assigning Graph API app roles..." -ForegroundColor Cyan

# Microsoft Graph service principal
$graphSp = Get-AzADServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

$graphRoleNames = @(
    "Device.Read.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementScripts.Read.All",
    "DeviceManagementScripts.ReadWrite.All",
    "Mail.Send",
    "WindowsUpdates.ReadWrite.All"
)

foreach ($roleName in $graphRoleNames) {
    $appRole = $graphSp.AppRole | Where-Object { $_.Value -eq $roleName -and $_.AllowedMemberType -contains "Application" }
    if ($appRole) {
        try {
            New-AzADServicePrincipalAppRoleAssignment -ServicePrincipalId $mi -ResourceId $graphSp.Id -AppRoleId $appRole.Id -ErrorAction Stop | Out-Null
            Write-Host "  $roleName assigned." -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -match "already exists") {
                Write-Host "  $roleName already assigned." -ForegroundColor Yellow
            } else { throw }
        }
    } else {
        Write-Warning "  $roleName application role not found on Graph SP. May need admin consent via portal."
    }
}

# --- 5. Entra role: Windows Update Deployment Administrator ---
Write-Host "[5/5] Assigning Entra role: Windows Update Deployment Administrator..." -ForegroundColor Cyan
$roleDefinition = Get-AzADDirectoryRole | Where-Object { $_.DisplayName -eq "Windows Update Deployment Administrator" }
if (-not $roleDefinition) {
    # Activate the role template first
    $roleTemplate = Get-AzADDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Windows Update Deployment Administrator" }
    if ($roleTemplate) {
        Write-Host "  Activating role template..." -ForegroundColor Yellow
        # Use Graph API to activate
        $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
        $body = @{ roleTemplateId = $roleTemplate.Id } | ConvertTo-Json
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -Method POST -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } -Body $body | Out-Null
        $roleDefinition = Get-AzADDirectoryRole | Where-Object { $_.DisplayName -eq "Windows Update Deployment Administrator" }
    }
}

if ($roleDefinition) {
    try {
        $token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
        $body = @{ "@@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$mi" } | ConvertTo-Json
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($roleDefinition.Id)/members/`$ref" -Method POST -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } -Body $body -ErrorAction Stop | Out-Null
        Write-Host "  Windows Update Deployment Administrator assigned." -ForegroundColor Green
    } catch {
        if ($_.Exception.Response.StatusCode -eq 400 -or $_.Exception.Message -match "already exist") {
            Write-Host "  Windows Update Deployment Administrator already assigned." -ForegroundColor Yellow
        } else { throw }
    }
} else {
    Write-Warning "  Could not find or activate 'Windows Update Deployment Administrator' role. Assign manually in Entra ID."
}

Write-Host "`n[Done] All permissions assigned for '$LogicAppName'." -ForegroundColor Green
Write-Host "  Next: Enable the Logic App (it deploys in Disabled state)." -ForegroundColor CyanWrite-Host ""
Write-Host "  IMPORTANT: Mail.Send grants tenant-wide send-as-any-user access." -ForegroundColor Yellow
Write-Host "  Lock it down with an Exchange Application Access Policy:" -ForegroundColor Yellow
Write-Host '  New-ApplicationAccessPolicy -AppId <MI-AppId> -PolicyScopeGroupId <mail-security-group> -AccessRight RestrictAccess -Description "Restrict KEV-Remediate sender"' -ForegroundColor DarkYellow
Write-Host "  Create a mail-enabled security group with only the approved sender address." -ForegroundColor Yellow