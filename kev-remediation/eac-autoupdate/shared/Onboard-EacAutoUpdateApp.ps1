<#
.SYNOPSIS
  Onboards an EAC auto-update app into the KEV remediation framework (one-time, idempotent, admin).
  For each app in eac-apps.json, ensures in Intune:
    1. an Enterprise App Catalog AUTO-UPDATE app  (windowsAutoUpdateCatalogApp -> latest catalog branch)
    2. a device security group  KEV-Remediate-<appKey>
    3. a REQUIRED assignment of the app to that group
  Empty groups stay dormant (no members => no installs). The runtime engine only adds members.

.DESCRIPTION
  EAC analog of Onboard-AppToFramework.ps1 (which onboards static Win32 apps). Uses the Microsoft Graph
  PowerShell SDK with delegated admin scopes (DeviceManagementApps.ReadWrite.All + Group.ReadWrite.All);
  these create-rights live ONLY here, never on the runtime managed identity (least privilege).

  CLOUD: onboarding is cloud-agnostic. GCC Intune IS commercial Intune (graph.microsoft.com), so the same
  run serves Commercial and GCC. (Only the RUNTIME engine's Defender endpoint differs per cloud.)

  LICENSE: requires Intune Suite / Enterprise App Management. Without it the catalog calls 403/404.
  SCHEMA NOTE: the catalog 'package' object is beta and its branch-id property can shift. Run -DumpCatalog
  first to confirm productDisplayName + branch id, then align eac-apps.json. The one create call that
  depends on this is annotated below.

.NOTES
  Drafting assistance: Claude Opus 4.8 (via GitHub Copilot), grounded in Microsoft Learn
  (windowsAutoUpdateCatalogApp create + mobileAppCatalogPackageBranchId, mobileAppAssignment
  groupAssignmentTarget, Microsoft Graph groups).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
  [string]$ConfigPath = (Join-Path $PSScriptRoot 'eac-apps.json'),
  [switch]$DumpCatalog
)
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -Raw $ConfigPath | ConvertFrom-Json

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Connect-MgGraph -Scopes 'DeviceManagementApps.ReadWrite.All', 'Group.ReadWrite.All' -NoWelcome

function GGet([string]$u) { Invoke-MgGraphRequest -Method GET -Uri $u -OutputType PSObject }
function GPost([string]$u, [hashtable]$b) { Invoke-MgGraphRequest -Method POST -Uri $u -Body $b -ContentType 'application/json' -OutputType PSObject }

$B = 'https://graph.microsoft.com/beta/deviceAppManagement'
$V = 'https://graph.microsoft.com/v1.0'

if ($DumpCatalog) {
  Write-Host '== Enterprise App Catalog packages ==' -ForegroundColor Cyan
  (GGet "$B/mobileAppCatalogPackages?`$top=999").value |
    Select-Object productDisplayName, productId, branchDisplayName, mobileAppCatalogPackageBranchId, branchId, versionDisplayName |
    Sort-Object productDisplayName | Format-Table -Auto
  return
}

foreach ($app in $cfg.apps) {
  $appTitle = "$($app.catalogProduct) (KEV Auto-Update)"
  $gName    = "$($cfg.groupPrefix)$($app.appKey)"
  Write-Host "`n== $($app.catalogProduct) ==" -ForegroundColor Cyan

  # 1. resolve the catalog package + its auto-update branch id
  $pkg = (GGet "$B/mobileAppCatalogPackages?`$top=999").value | Where-Object { "$($_.productDisplayName)" -like "*$($app.catalogProduct)*" } | Select-Object -First 1
  if (-not $pkg) { Write-Host "  ! not found in catalog: '$($app.catalogProduct)' (try -DumpCatalog)" -ForegroundColor Red; continue }
  $branchId = $pkg.mobileAppCatalogPackageBranchId; if (-not $branchId) { $branchId = $pkg.branchId }
  if (-not $branchId) { Write-Host '  ! no branch id on package - inspect with -DumpCatalog' -ForegroundColor Red; continue }
  Write-Host "  branchId: $branchId" -ForegroundColor DarkGray

  # 2. find-or-create the auto-update catalog app
  $existingApp = (GGet "$B/mobileApps?`$filter=displayName eq '$appTitle'").value |
    Where-Object { $_.'@odata.type' -match 'windowsAutoUpdateCatalogApp|win32CatalogApp' } | Select-Object -First 1
  if ($existingApp) { $appId = $existingApp.id; Write-Host "  = app exists ($appId)" -ForegroundColor DarkGray }
  elseif ($PSCmdlet.ShouldProcess($appTitle, 'Create windowsAutoUpdateCatalogApp')) {
    # ANNOTATED UNCERTAINTY: mobileAppCatalogPackageBranchId is documented Read-Only yet appears in the
    # create example. If rejected, create via the createCatalogApp action or the Intune portal.
    $created = GPost "$B/mobileApps" @{
      '@odata.type'                   = '#microsoft.graph.windowsAutoUpdateCatalogApp'
      displayName                     = $appTitle
      publisher                       = $app.publisher
      description                     = "EAC auto-update catalog app for $($app.catalogProduct) - KEV remediation target."
      mobileAppCatalogPackageBranchId = $branchId
    }
    $appId = $created.id; Write-Host "  + app created ($appId)" -ForegroundColor Green
  }

  # 3. find-or-create the device security group
  $grp = (GGet "$V/groups?`$filter=displayName eq '$gName'").value | Select-Object -First 1
  if ($grp) { Write-Host "  = group exists ($($grp.id))" -ForegroundColor DarkGray }
  elseif ($PSCmdlet.ShouldProcess($gName, 'Create security group')) {
    $grp = GPost "$V/groups" @{
      displayName     = $gName
      description     = "KEV auto-remediation target for $($app.catalogProduct). Members added by the runtime engine."
      mailEnabled     = $false
      mailNickname    = $app.appKey
      securityEnabled = $true
    }
    Write-Host "  + group created ($($grp.id))" -ForegroundColor Green
  }

  # 4. ensure a REQUIRED assignment app -> group
  if ($appId -and $grp) {
    $hasAsn = (GGet "$B/mobileApps/$appId/assignments").value | Where-Object { $_.target.groupId -eq $grp.id }
    if ($hasAsn) { Write-Host '  = assignment exists (Required)' -ForegroundColor DarkGray }
    elseif ($PSCmdlet.ShouldProcess("$appTitle -> $gName", 'Assign Required')) {
      GPost "$B/mobileApps/$appId/assignments" @{
        '@odata.type' = '#microsoft.graph.mobileAppAssignment'
        intent        = 'required'
        target        = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $grp.id }
      } | Out-Null
      Write-Host '  + assigned Required (auto-update tracks latest catalog branch)' -ForegroundColor Green
    }
  }
}
Write-Host "`nOnboarding complete. Record each branchId into eac-apps.json. Groups stay dormant until the engine adds members." -ForegroundColor Cyan
