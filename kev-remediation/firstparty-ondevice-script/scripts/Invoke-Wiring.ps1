<#
.SYNOPSIS
  End-to-end wiring for the KEV Patch Automation POC (reuses the current 'az login'):
    1. Grants the Logic App managed identity its Graph + Defender app-roles (idempotent).
    2. Creates the Intune Remediation (deviceHealthScript) from the Detect/Remediate scripts.
    3. Emits the scriptPolicyId to wire into the Logic App.
.NOTES
  Run as Global Administrator (app-role assignment + Intune script create require privileged rights).
  az-rest based - no extra modules, no second sign-in. Idempotent - safe to re-run.
  Drafting assistance: Claude Opus 4.8 (via GitHub Copilot), grounded in Microsoft Learn
  (Graph appRoleAssignments, deviceHealthScript create, Defender for Endpoint API audience).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$PrincipalId,
  [string]$ScriptDir   = $PSScriptRoot,
  [switch]$GrantOnly
)
$ErrorActionPreference = 'Continue'

function Invoke-GraphPost([string]$uri,[hashtable]$obj){
  $tmp = New-TemporaryFile
  ($obj | ConvertTo-Json -Depth 8) | Set-Content -Path $tmp.FullName -Encoding utf8
  $raw = az rest --method POST --uri $uri --headers "Content-Type=application/json" --body "@$($tmp.FullName)" 2>&1 | Out-String
  Remove-Item $tmp.FullName -Force
  [pscustomobject]@{ ok = ($LASTEXITCODE -eq 0); raw = $raw }
}

# ---------- 1. Grant managed-identity permissions ----------
Write-Host '== 1. Granting managed-identity app-roles ==' -ForegroundColor Cyan
$grants = @(
  @{ app='00000003-0000-0000-c000-000000000000'; roles=@('DeviceManagementManagedDevices.PrivilegedOperations.All','DeviceManagementConfiguration.ReadWrite.All','WindowsUpdates.ReadWrite.All','Mail.Send') },
  @{ app='fc780465-2017-40d4-a0c5-307022471b92'; roles=@('Vulnerability.Read.All') }
)
$existing = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" 2>$null | ConvertFrom-Json).value
foreach($g in $grants){
  $sp = az ad sp show --id $g.app 2>$null | ConvertFrom-Json
  if(-not $sp){ Write-Host "  SKIP resource $($g.app) - SP not provisioned in tenant" -ForegroundColor Yellow; continue }
  foreach($rv in $g.roles){
    $role = $sp.appRoles | Where-Object { $_.value -eq $rv -and ($_.allowedMemberTypes -contains 'Application') }
    if(-not $role){ Write-Host "  MISSING role $rv on $($sp.displayName)" -ForegroundColor Yellow; continue }
    if($existing | Where-Object { $_.resourceId -eq $sp.id -and $_.appRoleId -eq $role.id }){ Write-Host "  = already: $rv" -ForegroundColor DarkGray; continue }
    $r = Invoke-GraphPost "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" @{ principalId=$PrincipalId; resourceId=$sp.id; appRoleId=$role.id }
    if($r.ok){ Write-Host "  + granted: $rv" -ForegroundColor Green } else { Write-Host "  ! failed: $rv`n$($r.raw)" -ForegroundColor Red }
  }
}

if($GrantOnly){ Write-Host "`n(GrantOnly) Skipping remediation create." -ForegroundColor DarkGray; return }

# ---------- 2. Create the Intune Remediation (deviceHealthScript) ----------
Write-Host "`n== 2. Creating Intune Remediation (deviceHealthScript) ==" -ForegroundColor Cyan
$b64d = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw (Join-Path $ScriptDir 'Detect-FirstPartyUpdates.ps1'))))
$b64r = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((Get-Content -Raw (Join-Path $ScriptDir 'Remediate-FirstPartyUpdates.ps1'))))
$payload = @{
  '@odata.type'            = '#microsoft.graph.deviceHealthScript'
  displayName              = '1st-Party Patch Readiness (KEV POC)'
  description              = 'Detect+update Defender/Office/Edge; flag Windows quality for Expedite'
  publisher                = 'KEV Patch Automation'
  version                  = '1.0'
  runAsAccount             = 'system'
  enforceSignatureCheck    = $false
  runAs32Bit               = $false
  detectionScriptContent   = $b64d
  remediationScriptContent = $b64r
  roleScopeTagIds          = @('0')
}
$resp = Invoke-GraphPost 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts' $payload
if($resp.ok){
  $id = ($resp.raw | ConvertFrom-Json).id
  Write-Host '  + Remediation created.' -ForegroundColor Green
  Write-Host "SCRIPTPOLICYID=$id" -ForegroundColor Green
} else {
  Write-Host '  ! Remediation NOT created (Intune may be unlicensed in this tenant):' -ForegroundColor Red
  Write-Host "    $($resp.raw)" -ForegroundColor DarkYellow
}
