<#
.SYNOPSIS
  Grants the KEV-EAC-Remediate Logic App managed identity its LEAST-PRIVILEGE app-roles. Idempotent.
  Serves BOTH commercial and GCC (GCC uses commercial identity / commercial Entra, so the grants are identical).

.DESCRIPTION
  Runtime identity needs read + group-membership + mail:
    Microsoft Graph (00000003-0000-0000-c000-000000000000)
      - Device.Read.All            (resolve Entra device from aadDeviceId)
      - GroupMember.ReadWrite.All   (add devices to KEV-Remediate-<app> groups)
      - Mail.Send                   (fallback email)
    WindowsDefenderATP (fc780465-2017-40d4-a0c5-307022471b92)
      - Vulnerability.Read.All      (MDVM SoftwareVulnerabilityChangesByMachine delta)
      - Machine.Read.All            (machine.aadDeviceId for MDE -> Entra translation)

  App/group CREATE rights are intentionally NOT granted here - onboarding (Onboard-EacAutoUpdateApp.ps1)
  runs interactively as an admin. Get -PrincipalId from the ARM deployment output 'managedIdentityPrincipalId'.

  SECURITY: Mail.Send (application) can send as ANY mailbox. Scope it to one approved sender with
  security/Lock-MailSendScope-RBAC.ps1 after granting.

.NOTES
  Run as Global Administrator. az-rest based; no extra modules. Safe to re-run.
  Drafting assistance: Claude Opus 4.8 (via GitHub Copilot), grounded in Microsoft Learn
  (Graph appRoleAssignments; Defender app-roles Vulnerability.Read.All / Machine.Read.All).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PrincipalId
)
$ErrorActionPreference = 'Continue'

function Invoke-GraphPost([string]$uri, [hashtable]$obj) {
  $tmp = New-TemporaryFile
  ($obj | ConvertTo-Json -Depth 8) | Set-Content -Path $tmp.FullName -Encoding utf8
  $raw = az rest --method POST --uri $uri --headers "Content-Type=application/json" --body "@$($tmp.FullName)" 2>&1 | Out-String
  Remove-Item $tmp.FullName -Force
  [pscustomobject]@{ ok = ($LASTEXITCODE -eq 0); raw = $raw }
}

Write-Host "== Granting KEV-EAC least-privilege app-roles to MI $PrincipalId ==" -ForegroundColor Cyan
$grants = @(
  @{ app = '00000003-0000-0000-c000-000000000000'; roles = @('Device.Read.All', 'GroupMember.ReadWrite.All', 'Mail.Send') },
  @{ app = 'fc780465-2017-40d4-a0c5-307022471b92'; roles = @('Vulnerability.Read.All', 'Machine.Read.All') }
)
$existing = (az rest --method GET --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" 2>$null | ConvertFrom-Json).value
foreach ($g in $grants) {
  $sp = az ad sp show --id $g.app 2>$null | ConvertFrom-Json
  if (-not $sp) { Write-Host "  SKIP resource $($g.app) - SP not provisioned in tenant" -ForegroundColor Yellow; continue }
  foreach ($rv in $g.roles) {
    $role = $sp.appRoles | Where-Object { $_.value -eq $rv -and ($_.allowedMemberTypes -contains 'Application') }
    if (-not $role) { Write-Host "  MISSING role $rv on $($sp.displayName)" -ForegroundColor Yellow; continue }
    if ($existing | Where-Object { $_.resourceId -eq $sp.id -and $_.appRoleId -eq $role.id }) { Write-Host "  = already: $rv" -ForegroundColor DarkGray; continue }
    $r = Invoke-GraphPost "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" @{ principalId = $PrincipalId; resourceId = $sp.id; appRoleId = $role.id }
    if ($r.ok) { Write-Host "  + granted: $rv" -ForegroundColor Green } else { Write-Host "  ! failed: $rv`n$($r.raw)" -ForegroundColor Red }
  }
}
Write-Host "`nDone. Next: scope Mail.Send with security/Lock-MailSendScope-RBAC.ps1, then enable the Logic App." -ForegroundColor Cyan
