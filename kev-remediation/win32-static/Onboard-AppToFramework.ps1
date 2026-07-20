<#
.SYNOPSIS
    Onboards one Intune Win32 app into the KEV remediation framework.

.DESCRIPTION
    For each new app the framework should patch on demand:
      1. Verify the Intune app exists and is publishable (mobileApps GET).
      2. Create the per-app AppPatch Entra group: AAD-KEV-AppPatch-<AppKey>.
      3. Create the standing Intune assignment: app -> AppPatch group, intent=required.
      4. Print the JSON block to paste into Win32-App-Mapping.json under apps[].

    Idempotent. Re-running on an existing app updates the assignment to current settings.

.PARAMETER Cloud
    Commercial or Gov.

.PARAMETER TenantId
    Optional tenant GUID for Connect-MgGraph.

.PARAMETER IntuneAppId
    GUID of the mobileApps object in Intune (printed by Upload-Win32App.ps1 or visible in portal URL).

.PARAMETER AppKey
    Stable short id used in group names and audit logs. e.g., 7zip, chrome, notepad-plus-plus.

.PARAMETER SoftwareVendor
    Lowercase vendor token as it appears in MDETVM_CL.softwareVendor. Verify with KQL first.

.PARAMETER SoftwareName
    Lowercase software token as it appears in MDETVM_CL.softwareName.

.PARAMETER GroupNamePrefix
    Prefix for the AppPatch group. Default: AAD-KEV-AppPatch.

.EXAMPLE
    .\Onboard-AppToFramework.ps1 -Cloud Gov `
        -IntuneAppId <your-mobileapps-guid> `
        -AppKey 7zip `
        -SoftwareVendor igor_pavlov `
        -SoftwareName 7-zip
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [string]$TenantId = '',
    [Parameter(Mandatory)] [string]$IntuneAppId,
    [Parameter(Mandatory)] [string]$AppKey,
    [Parameter(Mandatory)] [string]$SoftwareVendor,
    [Parameter(Mandatory)] [string]$SoftwareName,
    [string]$GroupNamePrefix = 'AAD-KEV-AppPatch'
)

$ErrorActionPreference = 'Stop'

$mgEnv     = if ($Cloud -eq 'Gov') { 'USGov' }                  else { 'Global' }
$graphBase = if ($Cloud -eq 'Gov') { 'https://graph.microsoft.us' } else { 'https://graph.microsoft.com' }

# Connect
Write-Host "[1/5] Connect-MgGraph ($Cloud)..." -ForegroundColor Cyan
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Environment -ne $mgEnv -or ($TenantId -and $ctx.TenantId -ne $TenantId)) {
    if ($ctx) { Disconnect-MgGraph | Out-Null }
    $args = @{ Environment = $mgEnv; Scopes = @('Group.ReadWrite.All','DeviceManagementApps.ReadWrite.All'); NoWelcome = $true; UseDeviceCode = $true }
    if ($TenantId) { $args.TenantId = $TenantId }
    Connect-MgGraph @args | Out-Null
    $ctx = Get-MgContext
}
Write-Host "      Tenant: $($ctx.TenantId)" -ForegroundColor Green

# Step 1: verify the Intune app
Write-Host "[2/5] Verifying Intune app $IntuneAppId ..." -ForegroundColor Cyan
try {
    $app = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/beta/deviceAppManagement/mobileApps/$IntuneAppId"
    if ($app.publishingState -ne 'published') {
        throw "App publishingState is '$($app.publishingState)', expected 'published'. Wait for upload to complete or fix the app first."
    }
    Write-Host "      OK - $($app.displayName) (publishingState=published)" -ForegroundColor Green
    $appDisplayName = $app.displayName
    $minRemediatedVersion = $app.msiInformation.productVersion
} catch {
    Write-Host "      FAILED to read mobileApps/$IntuneAppId : $($_.Exception.Message)" -ForegroundColor Red
    throw
}

# Step 2: create the AppPatch group
$groupName = "$GroupNamePrefix-$AppKey"
Write-Host "[3/5] Creating Entra group $groupName ..." -ForegroundColor Cyan
$groupBody = @{
    displayName     = $groupName
    description     = "KEV remediation AppPatch group for Intune app $appDisplayName ($IntuneAppId). Members are devices currently being patched for a CVE affecting this app. Logic App manages membership at incident time."
    mailEnabled     = $false
    mailNickname    = ($groupName -replace '[^a-zA-Z0-9]', '')
    securityEnabled = $true
}
$groupId = $null
try {
    $g = Invoke-MgGraphRequest -Method POST -Uri "$graphBase/v1.0/groups" -Body ($groupBody | ConvertTo-Json -Depth 5 -Compress) -ContentType 'application/json'
    $groupId = $g.id
    Write-Host "      Created. id: $groupId" -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match 'already exists' -or $_.Exception.Response.StatusCode.value__ -eq 409) {
        Write-Host "      Already exists - looking up id ..." -ForegroundColor Yellow
        $existing = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/v1.0/groups?`$filter=displayName eq '$groupName'&`$select=id"
        $groupId = $existing.value[0].id
        Write-Host "      id: $groupId" -ForegroundColor Green
    } else { throw }
}

# Step 3: create the standing Intune assignment
Write-Host "[4/5] Configuring standing Intune assignment (app -> group, intent=required) ..." -ForegroundColor Cyan
$assignmentBody = @{
    '@odata.type' = '#microsoft.graph.mobileAppAssignment'
    intent        = 'required'
    target        = @{
        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
        groupId       = $groupId
        deviceAndAppManagementAssignmentFilterId   = $null
        deviceAndAppManagementAssignmentFilterType = 'none'
    }
    settings      = @{
        '@odata.type'                = '#microsoft.graph.win32LobAppAssignmentSettings'
        notifications                = 'showAll'
        deliveryOptimizationPriority = 'foreground'
        installTimeSettings          = $null
        restartSettings              = $null
    }
}
# Check if assignment already exists for this group
$existingAssignments = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/beta/deviceAppManagement/mobileApps/$IntuneAppId/assignments"
$alreadyAssigned = $existingAssignments.value | Where-Object { $_.target.groupId -eq $groupId }
if ($alreadyAssigned) {
    Write-Host "      Assignment already exists (id: $($alreadyAssigned.id))." -ForegroundColor Yellow
} else {
    Invoke-MgGraphRequest -Method POST -Uri "$graphBase/beta/deviceAppManagement/mobileApps/$IntuneAppId/assignments" -Body ($assignmentBody | ConvertTo-Json -Depth 8 -Compress) -ContentType 'application/json' | Out-Null
    Write-Host "      Assignment created." -ForegroundColor Green
}

# Step 4: print the JSON block
Write-Host ""
Write-Host "[5/5] Done. Add this block to Win32-App-Mapping.json under apps[]:" -ForegroundColor Green
Write-Host ""
$jsonBlock = @{
    appKey                 = $AppKey
    intuneAppId            = $IntuneAppId
    intuneAppDisplayName   = $appDisplayName
    minRemediatedVersion   = $minRemediatedVersion
    intuneAppPatchGroupId  = $groupId
    softwareVendor         = $SoftwareVendor
    softwareName           = $SoftwareName
    cveIds                 = @()
    ringOverrides          = $null
    excludeFromAutomation  = $false
}
Write-Host ($jsonBlock | ConvertTo-Json -Depth 5) -ForegroundColor White
Write-Host ""
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  1. Append the block above to Win32-App-Mapping.json apps[] array."
Write-Host "  2. Add CVE IDs to cveIds[] as KEV publishes them and this app version remediates them."
Write-Host "  3. Re-upload the mapping: .\Deploy-MappingHost.ps1 -Cloud $Cloud -ResourceGroup <rg>"
Write-Host "  4. Verify with KQL that softwareVendor + softwareName match MDETVM_CL exactly:"
Write-Host "     MDETVM_CL | where softwareName == '$SoftwareName' and softwareVendor == '$SoftwareVendor' | take 1"
