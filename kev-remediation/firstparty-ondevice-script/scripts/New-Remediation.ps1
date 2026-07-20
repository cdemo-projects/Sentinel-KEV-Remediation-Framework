<#
  New-Remediation.ps1 - creates the Intune Remediation (deviceHealthScript) via the
  Microsoft Graph PowerShell SDK using the DeviceManagementScripts.ReadWrite.All scope
  (the Azure CLI app token does not carry that scope, so az rest cannot create it).
  Run as Global Administrator. Prints SCRIPTPOLICYID=<id> on success.
#>
param([string]$ScriptDir = $PSScriptRoot)

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Connect-MgGraph -Scopes 'DeviceManagementScripts.ReadWrite.All' -NoWelcome

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

$created = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts' -Body $payload
Write-Host "SCRIPTPOLICYID=$($created.id)" -ForegroundColor Green
