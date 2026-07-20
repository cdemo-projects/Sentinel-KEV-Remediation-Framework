// Storage account + private container that hosts Win32-App-Mapping.json for the KEV-Remediate Logic App.
//
// Deployment model:
//   - Storage account with TLS 1.2 minimum, public network access disabled by default.
//     Override `allowPublicNetworkAccess = true` ONLY if your Logic App can't use a private endpoint.
//   - One blob container `kev-config` (private). The Logic App's managed identity reads via Storage Blob Data Reader RBAC.
//   - Optional VNet integration / private endpoint left to a follow-up template.
//
// Outputs the blob URL the Logic App parameter `Win32MappingUrl` should use.

@description('Resource group location.')
param location string = resourceGroup().location

@description('Storage account name. Must be globally unique, 3-24 chars, lowercase + digits only.')
param storageAccountName string

@description('Object ID of the Logic App managed identity that needs read access.')
param logicAppPrincipalId string

@description('Allow public network access. Set false only if the Logic App is on a VNet that can reach the storage privately.')
param allowPublicNetworkAccess bool = true

var containerName = 'kev-config'
var blobName = 'Win32-App-Mapping.json'

resource sa 'Microsoft.Storage/storageAccounts@2024-01-01' = {
  name: storageAccountName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    publicNetworkAccess: allowPublicNetworkAccess ? 'Enabled' : 'Disabled'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2024-01-01' = {
  parent: sa
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2024-01-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

// Storage Blob Data Reader role definition id (built-in, same in commercial and gov clouds)
var blobReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'

resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: container
  name: guid(container.id, logicAppPrincipalId, blobReaderRoleId)
  properties: {
    principalId: logicAppPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobReaderRoleId)
  }
}

@description('URL the Logic App should use as parameter Win32MappingUrl. Logic App must call this with managed-identity auth, audience https://storage.azure.com (commercial) or https://storage.azure.com (gov also uses storage.azure.com for the OAuth audience).')
output mappingBlobUrl string = '${sa.properties.primaryEndpoints.blob}${containerName}/${blobName}'

output storageAccountName string = sa.name
output containerName string = containerName
output blobName string = blobName
