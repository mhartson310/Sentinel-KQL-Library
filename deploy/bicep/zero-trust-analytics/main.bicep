targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace with Microsoft Sentinel enabled.')
param workspaceName string

@description('Deploy the rules enabled. Keep false until hunting/tuning is complete.')
param enableRules bool = false

module exposure './modules/ha-zt-001-protected-service-exposure-changed.bicep' = {
  name: 'deploy-ha-zt-001'
  params: {
    workspaceName: workspaceName
    enabled: enableRules
  }
}

module rbac './modules/ha-zt-002-privileged-rbac-assignment-created.bicep' = {
  name: 'deploy-ha-zt-002'
  params: {
    workspaceName: workspaceName
    enabled: enableRules
  }
}

module diagnostics './modules/ha-zt-003-diagnostic-settings-changed.bicep' = {
  name: 'deploy-ha-zt-003'
  params: {
    workspaceName: workspaceName
    enabled: enableRules
  }
}

output ruleResourceIds array = [
  exposure.outputs.ruleResourceId
  rbac.outputs.ruleResourceId
  diagnostics.outputs.ruleResourceId
]
