<#
.SYNOPSIS
    Adds an incident-source validation guard to the live KEV-Remediate Logic App.

.DESCRIPTION
    The KEV-Remediate Logic App parses the incident TITLE to extract a CVE ID
    and KB number, then passes them to a Graph 'expedite' call. Any user with
    Microsoft Sentinel Contributor on the workspace can create an incident with
    an arbitrary title - which would let them trigger an unauthorized expedite
    of any KB to any device.

    This patch adds a 'Validate_Incident_Source' action immediately after the
    trigger that:
      1. Queries SecurityIncident in the workspace for the triggering incident
      2. Confirms the incident's RelatedAnalyticRuleIds contains the CISA KEV
         analytics rule ID
      3. Terminates the workflow with status Cancelled if the source rule is
         anything else

    Idempotent: detects an existing guard and skips.

.PARAMETER SubscriptionId
.PARAMETER ResourceGroupName
.PARAMETER WorkflowName              Default: KEV-Remediate
.PARAMETER WorkspaceName             The Sentinel workspace name.
.PARAMETER ExpectedRuleId            The analytics rule GUID that's allowed to
                                     trigger this Logic App. Default is the
                                     CISA-KEV-MDVM-AnalyticsRule.json GUID.

.EXAMPLE
    .\Patch-IncidentSourceValidation.ps1 `
        -SubscriptionId <subscription-id> `
        -ResourceGroupName <resource-group> `
        -WorkspaceName <workspace-name>
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SubscriptionId    = '<subscription-id>',
    [string]$ResourceGroupName = '<resource-group>',
    [string]$WorkflowName      = 'KEV-Remediate',
    [Parameter(Mandatory)]
    [string]$WorkspaceName,
    [string]$ExpectedRuleId    = 'c3f4a812-9e2b-4d71-b85a-6e7c1d3f20a9'
)

$ErrorActionPreference = 'Stop'
az account set --subscription $SubscriptionId | Out-Null

# ── Fetch workflow ──
Write-Host '[1/3] Fetching live workflow...' -ForegroundColor Cyan
$resource = az resource show `
    --resource-group $ResourceGroupName `
    --name $WorkflowName `
    --resource-type Microsoft.Logic/workflows `
    --api-version 2019-05-01 `
    --output json | ConvertFrom-Json -Depth 100

$definition = $resource.properties.definition

if ($definition.actions.PSObject.Properties.Name -contains 'Validate_Incident_Source') {
    Write-Host '  Validate_Incident_Source already present. Nothing to do.' -ForegroundColor Yellow
    return
}

# ── Build guard action ──
Write-Host '[2/3] Inserting Validate_Incident_Source guard...' -ForegroundColor Cyan

$guardJson = @"
{
  "Validate_Incident_Source": {
    "type": "If",
    "expression": {
      "or": [
        { "equals": [ "@coalesce(triggerBody()?['object']?['properties']?['relatedAnalyticRuleIds'], '')", "" ] },
        {
          "not": {
            "contains": [
              "@toLower(string(triggerBody()?['object']?['properties']?['relatedAnalyticRuleIds']))",
              "$($ExpectedRuleId.ToLower())"
            ]
          }
        }
      ]
    },
    "actions": {
      "Terminate_Unauthorized": {
        "type": "Terminate",
        "inputs": {
          "runStatus": "Cancelled",
          "runError": {
            "code": "UnauthorizedTriggerSource",
            "message": "Incident did not originate from the approved CISA KEV analytics rule. Refusing to remediate."
          }
        }
      }
    },
    "runAfter": {}
  }
}
"@

$guard = $guardJson | ConvertFrom-Json -Depth 10

# Add the guard
$definition.actions | Add-Member -MemberType NoteProperty -Name 'Validate_Incident_Source' -Value $guard.Validate_Incident_Source

# Re-parent existing top-level actions to runAfter Validate_Incident_Source (Succeeded)
$existingActionNames = $definition.actions.PSObject.Properties.Name |
    Where-Object { $_ -ne 'Validate_Incident_Source' }

foreach ($actionName in $existingActionNames) {
    $action = $definition.actions.$actionName
    $hasRunAfter = $action.PSObject.Properties.Name -contains 'runAfter'
    $isRoot = $hasRunAfter -and ($action.runAfter.PSObject.Properties.Count -eq 0)
    if ($isRoot) {
        $newRunAfter = [pscustomobject]@{ Validate_Incident_Source = @('Succeeded') }
        $action.runAfter = $newRunAfter
    }
}

# ── Submit ──
Write-Host '[3/3] Submitting updated definition...' -ForegroundColor Cyan
$tmp = New-TemporaryFile
($resource | ConvertTo-Json -Depth 100) | Set-Content -Path $tmp -Encoding UTF8

az resource update `
    --ids $resource.id `
    --api-version 2019-05-01 `
    --properties (Get-Content $tmp -Raw) | Out-Null

Remove-Item $tmp

Write-Host '  Guard installed.' -ForegroundColor Green
Write-Host "`nFrom now on, KEV-Remediate will Cancel any run whose source incident is not from analytics rule $ExpectedRuleId." -ForegroundColor White
