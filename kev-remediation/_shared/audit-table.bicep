// DCR + custom table for KEV remediation audit trail.
// Logic App POSTs one row per (device, wave, app, cve) event to the DCR's Logs Ingestion API.
//
// Custom table on the workspace is created via a nested deployment scoped to the workspace's RG
// (workspace may live in a different RG from the Logic App). DCR + DCE + RBAC live in this RG.

@description('Resource group location.')
param location string = resourceGroup().location

@description('Existing Log Analytics workspace name.')
param workspaceName string

@description('Resource group of the workspace if different from this RG.')
param workspaceResourceGroup string = resourceGroup().name

@description('Object ID of the KEV-Remediate Logic App MI. Granted Monitoring Metrics Publisher on the DCR.')
param logicAppPrincipalId string

@description('DCE name.')
param dceName string = 'dce-kev-remediation'

@description('DCR name.')
param dcrName string = 'DCR-KEVRemediation'

@description('Custom table name (must end in _CL).')
param tableName string = 'KEVRemediation_CL'

var workspaceResourceId = resourceId(workspaceResourceGroup, 'Microsoft.OperationalInsights/workspaces', workspaceName)

var auditColumns = [
  { name: 'TimeGenerated',         type: 'datetime' }
  { name: 'incidentName',          type: 'string'   }
  { name: 'incidentNumber',        type: 'int'      }
  { name: 'cveId',                 type: 'string'   }
  { name: 'cvssScore',             type: 'real'     }
  { name: 'severity',              type: 'string'   }
  { name: 'appKey',                type: 'string'   }
  { name: 'intuneAppId',           type: 'string'   }
  { name: 'intuneAppDisplayName',  type: 'string'   }
  { name: 'intuneAppPatchGroupId', type: 'string'   }
  { name: 'softwareVendor',        type: 'string'   }
  { name: 'softwareName',          type: 'string'   }
  { name: 'wave',                  type: 'string'   }
  { name: 'deviceId',              type: 'string'   }
  { name: 'deviceName',            type: 'string'   }
  { name: 'action',                type: 'string'   }
  { name: 'outcome',               type: 'string'   }
  { name: 'httpStatusCode',        type: 'int'      }
  { name: 'errorMessage',          type: 'string'   }
  { name: 'logicAppRunId',         type: 'string'   }
  { name: 'failureRate',           type: 'real'     }
  { name: 'thresholdApplied',      type: 'real'     }
]

// Custom table on the workspace - nested deployment to the workspace's RG (may differ)
module customTable 'audit-table-customtable.bicep' = {
  name: 'kev-audit-customtable'
  scope: resourceGroup(workspaceResourceGroup)
  params: {
    workspaceName: workspaceName
    tableName:     tableName
    columns:       auditColumns
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name:     dceName
  location: location
  properties: {
    networkAcls: { publicNetworkAccess: 'Enabled' }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name:     dcrName
  location: location
  kind:     'Direct'
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-${tableName}': { columns: auditColumns }
    }
    destinations: {
      logAnalytics: [
        {
          name:                'sentinel'
          workspaceResourceId: workspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams:      [ 'Custom-${tableName}' ]
        destinations: [ 'sentinel' ]
        outputStream: 'Custom-${tableName}'
        transformKql: 'source'
      }
    ]
  }
  dependsOn: [ customTable ]
}

// Monitoring Metrics Publisher (built-in role id same in commercial + gov)
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'

resource ingestRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: dcr
  name: guid(dcr.id, logicAppPrincipalId, monitoringMetricsPublisherRoleId)
  properties: {
    principalId:      logicAppPrincipalId
    principalType:    'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
  }
}

@description('DCR immutable id. Logic App needs this to construct the ingestion URL.')
output dcrImmutableId string = dcr.properties.immutableId

@description('Logs ingestion URL the Logic App POSTs to.')
output logsIngestionEndpoint string = dce.properties.logsIngestion.endpoint

@description('Stream name the Logic App must use in the URL path.')
output streamName string = 'Custom-${tableName}'

output tableName string = tableName
