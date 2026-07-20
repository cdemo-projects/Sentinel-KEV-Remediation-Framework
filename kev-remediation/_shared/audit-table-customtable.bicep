// Nested module called from audit-table.bicep. Scoped to the workspace's RG.
// Creates the custom table on the workspace.

@description('Workspace name in this RG.')
param workspaceName string

@description('Custom table name (must end in _CL).')
param tableName string

@description('Column schema array.')
param columns array

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name:   tableName
  properties: {
    plan:            'Analytics'
    retentionInDays: 90
    schema: {
      name:    tableName
      columns: columns
    }
  }
}
