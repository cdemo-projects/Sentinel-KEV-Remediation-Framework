<#
.SYNOPSIS
    Creates the three universal KEV ring groups (Pilot, Early, Broad) in Microsoft Entra ID.

.DESCRIPTION
    One-time setup script. Provisions the three Entra security groups that the KEV-Remediate Logic App
    intersects with each incident's affected devices to drive ring-based promotion.

    Three group patterns supported:
      - assigned (static membership; admin curates)
      - dynamic-rule (membership rule queried by Entra)
      - hybrid (Pilot/Early static, Broad dynamic = "all Windows devices not in Pilot or Early")

    The default is "hybrid" because that scales without requiring admins to manually add every
    new device to Broad.

    After this script runs, paste the three printed group GUIDs into Win32-App-Mapping.json under
    ringStrategy.{pilotGroupId,earlyGroupId,broadGroupId}, then re-upload the mapping.

.PARAMETER Cloud
    Commercial or Gov.

.PARAMETER TenantId
    Optional tenant GUID for Connect-MgGraph.

.PARAMETER GroupNamePrefix
    Prefix applied to all three groups. Default: AAD-KEV-Ring.
    Final names: <prefix>-Pilot, <prefix>-Early, <prefix>-Broad.

.PARAMETER Pattern
    hybrid (default), assigned, or dynamic-rule.

.PARAMETER PilotMembershipRule
    Used only when Pattern=dynamic-rule. Default: targets a tag pattern customers commonly use.

.PARAMETER WindowsOnly
    When true (default), the dynamic Broad ring is scoped to Windows devices only.

.EXAMPLE
    .\Setup-KEVRingGroups.ps1 -Cloud Gov

.EXAMPLE
    .\Setup-KEVRingGroups.ps1 -Cloud Commercial -GroupNamePrefix "ENT-KEV-Ring" -Pattern assigned
#>

#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Commercial','Gov')] [string]$Cloud,
    [string]$TenantId = '',
    [string]$GroupNamePrefix = 'AAD-KEV-Ring',
    [ValidateSet('hybrid','assigned','dynamic-rule')] [string]$Pattern = 'hybrid',
    [string]$PilotMembershipRule = '(device.deviceTag -contains "kev-ring-pilot")',
    [bool]$WindowsOnly = $true
)

$ErrorActionPreference = 'Stop'

$mgEnv     = if ($Cloud -eq 'Gov') { 'USGov' }                  else { 'Global' }
$graphBase = if ($Cloud -eq 'Gov') { 'https://graph.microsoft.us' } else { 'https://graph.microsoft.com' }

# Connect
Write-Host "[1/5] Connect-MgGraph ($Cloud)..." -ForegroundColor Cyan
$ctx = Get-MgContext
if (-not $ctx -or $ctx.Environment -ne $mgEnv -or ($TenantId -and $ctx.TenantId -ne $TenantId)) {
    if ($ctx) { Disconnect-MgGraph | Out-Null }
    $args = @{ Environment = $mgEnv; Scopes = @('Group.ReadWrite.All','Directory.ReadWrite.All'); NoWelcome = $true; UseDeviceCode = $true }
    if ($TenantId) { $args.TenantId = $TenantId }
    Connect-MgGraph @args | Out-Null
    $ctx = Get-MgContext
}
Write-Host "      Tenant: $($ctx.TenantId)" -ForegroundColor Green

function New-RingGroup {
    param([string]$Name, [string]$Description, [string]$RuleOrNull)
    $body = @{
        displayName     = $Name
        description     = $Description
        mailEnabled     = $false
        mailNickname    = ($Name -replace '[^a-zA-Z0-9]', '')
        securityEnabled = $true
    }
    if ($RuleOrNull) {
        $body.groupTypes = @('DynamicMembership')
        $body.membershipRule = $RuleOrNull
        $body.membershipRuleProcessingState = 'On'
    }
    Write-Host "      Creating $Name ..." -ForegroundColor Yellow
    try {
        $resp = Invoke-MgGraphRequest -Method POST -Uri "$graphBase/v1.0/groups" -Body ($body | ConvertTo-Json -Depth 8 -Compress) -ContentType 'application/json'
        Write-Host "        id: $($resp.id)" -ForegroundColor Green
        return $resp.id
    } catch {
        if ($_.Exception.Message -match 'already exists' -or $_.Exception.Response.StatusCode.value__ -eq 409) {
            Write-Host "        Already exists - looking up id ..." -ForegroundColor Yellow
            $existing = Invoke-MgGraphRequest -Method GET -Uri "$graphBase/v1.0/groups?`$filter=displayName eq '$Name'&`$select=id"
            $id = $existing.value[0].id
            Write-Host "        id: $id" -ForegroundColor Green
            return $id
        }
        throw
    }
}

# Define rules per pattern
$pilotRule = $null; $earlyRule = $null; $broadRule = $null
if ($Pattern -eq 'dynamic-rule') {
    $pilotRule = $PilotMembershipRule
    $earlyRule = $PilotMembershipRule -replace 'kev-ring-pilot','kev-ring-early'
    $broadRule = if ($WindowsOnly) { '(device.deviceOSType -eq "Windows") and -not (device.deviceTag -contains "kev-ring-pilot") and -not (device.deviceTag -contains "kev-ring-early")' } else { '(device.deviceTag -notIn "kev-ring-pilot,kev-ring-early")' }
} elseif ($Pattern -eq 'hybrid') {
    # Pilot and Early are assigned (admin curates)
    # Broad is dynamic
    $broadRule = if ($WindowsOnly) { 'device.deviceOSType -eq "Windows"' } else { 'device.objectId -ne null' }
}

# Provision
Write-Host "[2/5] Pilot ring..." -ForegroundColor Cyan
$pilotId = New-RingGroup "$GroupNamePrefix-Pilot" "KEV remediation Pilot ring. Test devices that receive KEV-driven app updates first." $pilotRule

Write-Host "[3/5] Early ring..." -ForegroundColor Cyan
$earlyId = New-RingGroup "$GroupNamePrefix-Early" "KEV remediation Early ring. Friendly-user devices that receive KEV-driven app updates after Pilot succeeds." $earlyRule

Write-Host "[4/5] Broad ring..." -ForegroundColor Cyan
$broadId = New-RingGroup "$GroupNamePrefix-Broad" "KEV remediation Broad ring. Production devices that receive KEV-driven app updates after Early succeeds." $broadRule

# Output
Write-Host ""
Write-Host "[5/5] Done. Update Win32-App-Mapping.json:" -ForegroundColor Green
Write-Host ""
Write-Host '  "ringStrategy": {' -ForegroundColor White
Write-Host "    `"pilotGroupId`": `"$pilotId`"," -ForegroundColor White
Write-Host "    `"earlyGroupId`": `"$earlyId`"," -ForegroundColor White
Write-Host "    `"broadGroupId`": `"$broadId`"," -ForegroundColor White
Write-Host '    "defaultPilotToEarlyHours": 24,' -ForegroundColor White
Write-Host '    "defaultEarlyToBroadHours": 48,' -ForegroundColor White
Write-Host '    "defaultFailureThreshold": 0.10' -ForegroundColor White
Write-Host '  },' -ForegroundColor White
Write-Host ""
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  - For Pattern=hybrid or assigned: add Pilot/Early member devices via Entra portal or PowerShell."
Write-Host "  - Re-upload mapping JSON: .\Deploy-MappingHost.ps1 -Cloud $Cloud -ResourceGroup <rg>"
Write-Host "  - Onboard each app via .\Onboard-AppToFramework.ps1"
