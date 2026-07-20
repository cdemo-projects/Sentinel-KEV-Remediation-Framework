// =============================================================================
//  KEV Patch Automation - POC Logic App (Consumption)
//  Deploys a Consumption Logic App + system-assigned managed identity.
//  Same template serves Commercial AND true-GCC (worldwide endpoints) via params.
// =============================================================================

@description('Azure region for the Logic App.')
param location string = resourceGroup().location

@description('Name of the Consumption Logic App.')
param logicAppName string = 'la-kev-patch-poc'

@description('Defender for Endpoint API base (worldwide for Commercial + true GCC).')
param mdeResourceBase string = 'https://api.security.microsoft.com'

@description('Token AUDIENCE/resource for the Defender for Endpoint API (legacy resource still required).')
param mdeAudience string = 'https://api.securitycenter.microsoft.com'

@description('Microsoft Graph base (worldwide for Commercial + true GCC).')
param graphBase string = 'https://graph.microsoft.com'

@description('Public CISA Known Exploited Vulnerabilities JSON feed.')
param kevFeedUrl string = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

@description('Intune Remediation (deviceHealthScript) policy ID to run on exposed devices.')
param scriptPolicyId string = '00000000-0000-0000-0000-000000000000'

@description('Look-back window (hours) for the MDVM delta pull. Match the recurrence.')
param sinceHours int = 6

resource logicApp 'Microsoft.Logic/workflows@2019-05-01' = {
  name: logicAppName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: loadJsonContent('../workflow/workflow.json')
    parameters: {
      mdeResourceBase: { value: mdeResourceBase }
      mdeAudience: { value: mdeAudience }
      graphBase: { value: graphBase }
      kevFeedUrl: { value: kevFeedUrl }
      scriptPolicyId: { value: scriptPolicyId }
      sinceHours: { value: sinceHours }
    }
  }
}

@description('Object (principal) ID of the Logic App managed identity - feed this to Grant-GraphPermissions.ps1.')
output managedIdentityPrincipalId string = logicApp.identity.principalId

@description('Logic App resource name.')
output logicAppName string = logicApp.name
