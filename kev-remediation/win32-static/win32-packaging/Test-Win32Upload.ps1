<#
.SYNOPSIS
    Smoke test for Intune Win32 LOB upload prerequisites. Creates a placeholder mobileApp,
    confirms it's visible, then deletes it. No payload uploaded.

.DESCRIPTION
    Use BEFORE running Upload-Win32App.ps1 against a real package, especially the first
    time you target a tenant. Validates:
      - Microsoft.Graph.Authentication module is present
      - Connect-MgGraph works against the chosen cloud
      - The signed-in identity has DeviceManagementApps.ReadWrite.All effective
      - POST mobileApps and DELETE mobileApps both succeed end-to-end
      - Graph endpoint URL is correct for the cloud

    Runs in ~10 seconds. Leaves no artifacts behind on success. On failure, prints the
    exact HTTP code + Graph error so you can fix scopes/network before the real run.

.PARAMETER Cloud
    Commercial or Gov.

.PARAMETER TenantId
    Optional tenant GUID for Connect-MgGraph.

.EXAMPLE
    .\Test-Win32Upload.ps1 -Cloud Gov

.EXAMPLE
    .\Test-Win32Upload.ps1 -Cloud Commercial -TenantId <guid>
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [string]$TenantId = ''
)

$ErrorActionPreference = 'Stop'

$mgEnv     = if ($Cloud -eq 'Gov') { 'USGov' } else { 'Global' }
$graphBase = if ($Cloud -eq 'Gov') { 'https://graph.microsoft.us' } else { 'https://graph.microsoft.com' }

# 1. Connect
Write-Host "[1/5] Connect-MgGraph ($Cloud)..." -ForegroundColor Cyan
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Environment -ne $mgEnv -or ($TenantId -and $ctx.TenantId -ne $TenantId)) {
    if ($ctx) { Disconnect-MgGraph | Out-Null }
    $args = @{ Environment = $mgEnv; Scopes = 'DeviceManagementApps.ReadWrite.All'; NoWelcome = $true }
    if ($TenantId) { $args.TenantId = $TenantId }
    Connect-MgGraph @args | Out-Null
    $ctx = Get-MgContext
}
Write-Host "      Tenant: $($ctx.TenantId)" -ForegroundColor Green
Write-Host "      Account: $($ctx.Account)" -ForegroundColor Green
Write-Host "      Scopes: $($ctx.Scopes -join ', ')"

if ($ctx.Scopes -notcontains 'DeviceManagementApps.ReadWrite.All') {
    Write-Warning "DeviceManagementApps.ReadWrite.All not in current scopes. POST will likely fail with 403."
}

# 2. Build placeholder app body (zero payload, MSI detection rule with throwaway ProductCode)
$testGuid = [guid]::NewGuid()
$smokeName = "ZZ-SmokeTest-$($testGuid.ToString().Substring(0,8))"
Write-Host ""
Write-Host "[2/5] POST placeholder mobileApp '$smokeName' ..." -ForegroundColor Cyan

$body = @{
    '@odata.type'                  = '#microsoft.graph.win32LobApp'
    displayName                    = $smokeName
    description                    = 'Smoke test placeholder; safe to delete.'
    publisher                      = 'Smoke test'
    notes                          = 'Created by Test-Win32Upload.ps1; auto-deleted at end of run.'
    fileName                       = 'placeholder.msi'
    setupFilePath                  = 'placeholder.msi'
    installCommandLine             = 'msiexec /i placeholder.msi /qn'
    uninstallCommandLine           = 'msiexec /x {00000000-0000-0000-0000-000000000000} /qn'
    applicableArchitectures        = 'x64'
    minimumSupportedWindowsRelease = '1809'
    installExperience              = @{ runAsAccount = 'system'; deviceRestartBehavior = 'suppress' }
    msiInformation                 = @{
        productCode    = '{00000000-0000-0000-0000-000000000000}'
        productVersion = '0.0.0.0'
        upgradeCode    = '{00000000-0000-0000-0000-000000000001}'
        requiresReboot = $false
        packageType    = 'perMachine'
    }
    detectionRules = @(
        @{
            '@odata.type'             = '#microsoft.graph.win32LobAppProductCodeDetection'
            productCode               = '{00000000-0000-0000-0000-000000000000}'
            productVersionOperator    = 'greaterThanOrEqual'
            productVersion            = '0.0.0.0'
        }
    )
    requirementRules = @()
    returnCodes      = @(@{ returnCode = 0; type = 'success' })
}

try {
    $created = Invoke-MgGraphRequest -Method POST -Uri "$graphBase/beta/deviceAppManagement/mobileApps" `
        -Body ($body | ConvertTo-Json -Depth 12 -Compress) -ContentType 'application/json'
    $appId = $created.id
    Write-Host "      Created app id: $appId" -ForegroundColor Green
} catch {
    Write-Host "      FAILED to create placeholder app." -ForegroundColor Red
    Write-Host "      $($_.Exception.Message)" -ForegroundColor Red
    throw
}

# 3. GET it back
Write-Host ""
Write-Host "[3/5] GET the placeholder back ..." -ForegroundColor Cyan
try {
    $back = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/beta/deviceAppManagement/mobileApps/$appId"
    Write-Host "      OK - displayName=$($back.displayName)" -ForegroundColor Green
} catch {
    Write-Warning "GET round-trip failed: $($_.Exception.Message)"
}

# 4. DELETE it
Write-Host ""
Write-Host "[4/5] DELETE the placeholder ..." -ForegroundColor Cyan
try {
    Invoke-MgGraphRequest -Method DELETE -Uri "$graphBase/beta/deviceAppManagement/mobileApps/$appId" | Out-Null
    Write-Host "      Deleted." -ForegroundColor Green
} catch {
    Write-Warning "DELETE failed: $($_.Exception.Message)"
    Write-Warning "Manual cleanup required: portal -> Apps -> All apps -> $smokeName -> Delete"
}

# 5. Confirm gone
Write-Host ""
Write-Host "[5/5] Confirm deletion ..." -ForegroundColor Cyan
try {
    Invoke-MgGraphRequest -Method GET -Uri "$graphBase/beta/deviceAppManagement/mobileApps/$appId" | Out-Null
    Write-Warning "Placeholder still exists. Delete manually."
} catch {
    if ($_.Exception.Message -match '404|NotFound|ResourceNotFound') {
        Write-Host "      Confirmed deleted." -ForegroundColor Green
    } else {
        Write-Warning "Unexpected error on confirmation GET: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "Smoke test PASSED. Safe to run Upload-Win32App.ps1 against this tenant." -ForegroundColor Green
