# =============================================================================
# Assign-MDVMPermissions.ps1
# =============================================================================
# PURPOSE:
#   Assigns three permissions to the MDETVM Logic App's System Assigned MI:
#   1. Vulnerability.Read.All on WindowsDefenderATP (TVM REST API access)
#   2. AdvancedQuery.Read.All on WindowsDefenderATP (Advanced Hunting API access)
#   3. Monitoring Metrics Publisher on the DCR (Logs Ingestion API access)
#
# WHEN TO RUN:
#   After Step 1 (Deploy MDETVM-LogicApp.json). The Logic App, DCE, DCR, and
#   custom table must all be deployed before running this script.
#
# PREREQUISITES:
#   - Az PowerShell module: Install-Module Az -Scope CurrentUser
#   - Global Admin or Application Administrator role in Entra ID
#   - Owner or User Access Administrator on the resource group (for DCR role)
#
# CREDITS:
#   Original Logic App & permissions approach:
#     Cyberlorians — https://github.com/Cyberlorians/Articles/blob/main/TVMIngestion.md
#   CISA KEV correlation pattern:
#     Matt Zorich (@reprise_99) — https://kqlquery.com/posts/automatic-cisa-vulnerability-notifications/
# =============================================================================

param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory = $false)]
    [string]$LogicAppName = "MDETVM",

    [Parameter(Mandatory = $false)]
    [string]$DcrName = "DCR-MDETVM"
)

# -------------------------------------------------------------------
# CONNECT TO AZURE
# -------------------------------------------------------------------

Write-Host "Connecting to Azure (Tenant: $TenantId)..." -ForegroundColor Cyan
Connect-AzAccount -TenantId $TenantId

# -------------------------------------------------------------------
# GET THE LOGIC APP SYSTEM ASSIGNED MI PRINCIPAL ID
# -------------------------------------------------------------------

Write-Host "Looking up Logic App '$LogicAppName' in resource group '$ResourceGroupName'..." -ForegroundColor Cyan

$logicApp = Get-AzResource `
    -ResourceType "Microsoft.Logic/workflows" `
    -ResourceGroupName $ResourceGroupName `
    -Name $LogicAppName

if ($null -eq $logicApp) {
    Write-Error "Logic App '$LogicAppName' not found in resource group '$ResourceGroupName'."
    exit 1
}

$miPrincipalId = $logicApp.Identity.PrincipalId

if ([string]::IsNullOrWhiteSpace($miPrincipalId)) {
    Write-Error "System Assigned Managed Identity not found on Logic App '$LogicAppName'. Verify the identity is enabled in the Azure Portal."
    exit 1
}

Write-Host "Found managed identity principal ID: $miPrincipalId" -ForegroundColor Green

# -------------------------------------------------------------------
# PERMISSION 1: Vulnerability.Read.All on WindowsDefenderATP
# -------------------------------------------------------------------

Write-Host ""
Write-Host "=== Permissions 1 & 2: Defender API app roles ===" -ForegroundColor Magenta

# AppId for WindowsDefenderATP (same across commercial and GCC tenants)
$wdatpAppId = "fc780465-2017-40d4-a0c5-307022471b92"

Write-Host "Looking up WindowsDefenderATP service principal..." -ForegroundColor Cyan
$resource = Get-AzADServicePrincipal -Filter "AppId eq '$wdatpAppId'"

if ($null -eq $resource) {
    Write-Error "WindowsDefenderATP service principal not found. Verify Microsoft Defender for Endpoint is provisioned in this tenant."
    exit 1
}

Write-Host "Found: $($resource.DisplayName) (Id: $($resource.Id))" -ForegroundColor Green

foreach ($permission in @("Vulnerability.Read.All", "AdvancedQuery.Read.All")) {
    $appRole = $resource.AppRole | Where-Object { $_.Value -eq $permission }

    if ($null -eq $appRole) {
        Write-Error "App role '$permission' not found on WindowsDefenderATP."
        exit 1
    }

    Write-Host "Assigning: $permission (AppRoleId: $($appRole.Id))" -ForegroundColor Yellow

    $body = @{
        principalId = $miPrincipalId
        resourceId  = $resource.Id
        appRoleId   = $appRole.Id
    }

    $response = (Invoke-AzRestMethod `
        -Method POST `
        -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/" + $resource.Id + "/appRoleAssignedTo") `
        -Payload (ConvertTo-Json $body)).Content | ConvertFrom-Json

    if ($response.id) {
        Write-Host "SUCCESS: $permission assigned (Assignment ID: $($response.id))" -ForegroundColor Green
    } else {
        Write-Warning "Unexpected response (may already be assigned): $($response | ConvertTo-Json -Compress)"
    }
}

# -------------------------------------------------------------------
# PERMISSION 2: Monitoring Metrics Publisher on DCR
# -------------------------------------------------------------------

Write-Host ""
Write-Host "=== Permission 3: Monitoring Metrics Publisher on DCR ===" -ForegroundColor Magenta

Write-Host "Looking up DCR '$DcrName' in resource group '$ResourceGroupName'..." -ForegroundColor Cyan

$dcr = Get-AzResource `
    -ResourceType "Microsoft.Insights/dataCollectionRules" `
    -ResourceGroupName $ResourceGroupName `
    -Name $DcrName

if ($null -eq $dcr) {
    Write-Error "Data Collection Rule '$DcrName' not found in resource group '$ResourceGroupName'."
    exit 1
}

Write-Host "Found DCR: $($dcr.Name) ($($dcr.ResourceId))" -ForegroundColor Green

$roleName = "Monitoring Metrics Publisher"
Write-Host "Assigning: $roleName on DCR..." -ForegroundColor Yellow

try {
    New-AzRoleAssignment `
        -ObjectId $miPrincipalId `
        -RoleDefinitionName $roleName `
        -Scope $dcr.ResourceId `
        -ErrorAction Stop | Out-Null
    Write-Host "SUCCESS: $roleName assigned on DCR" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "already exists") {
        Write-Host "Role assignment already exists — skipping." -ForegroundColor Yellow
    } else {
        Write-Error "Failed to assign role: $_"
        exit 1
    }
}

# -------------------------------------------------------------------
# DONE
# -------------------------------------------------------------------

Write-Host ""
Write-Host "All permissions assigned. Next steps:" -ForegroundColor Green
Write-Host "  1. Run the Logic App manually: Logic App > Run Trigger"
Write-Host "  2. Verify MDETVM_CL is populated: run Verify-MDVMTables.kql in Sentinel Logs"
