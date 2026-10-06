targetScope = 'resourceGroup'

param workspaceName string
param enabled bool = false

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

var ruleName = guid(workspace.id, 'HA-ZT-001')

resource rule 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {
  name: ruleName
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'HA-ZT-001 - Protected Service Exposure Changed'
    description: 'Detects successful control-plane writes to protected App Service, Key Vault, or Storage resources that can weaken private-only access or alter network exposure.'
    enabled: enabled
    severity: 'High'
    tactics: [
      'DefenseEvasion'
    ]
    techniques: [
      'T1562'
    ]
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    query: '''
let Lookback = 15m;
AzureActivity
| where TimeGenerated > ago(Lookback)
| where ActivityStatusValue in~ ("Success", "Succeeded")
| where OperationNameValue has_any (
    "MICROSOFT.WEB/SITES/WRITE",
    "MICROSOFT.KEYVAULT/VAULTS/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"
)
| extend ResourceType = case(
    OperationNameValue has "MICROSOFT.WEB/SITES", "App Service",
    OperationNameValue has "MICROSOFT.KEYVAULT/VAULTS", "Key Vault",
    OperationNameValue has "MICROSOFT.STORAGE/STORAGEACCOUNTS", "Storage Account",
    "Other"
)
| project TimeGenerated, ResourceType, Caller, CallerIpAddress, SubscriptionId, ResourceGroup, ResourceId, OperationNameValue, CorrelationId, Properties
| order by TimeGenerated desc
'''
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'Caller'
          }
        ]
      }
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'CallerIpAddress'
          }
        ]
      }
      {
        entityType: 'AzureResource'
        fieldMappings: [
          {
            identifier: 'ResourceId'
            columnName: 'ResourceId'
          }
        ]
      }
    ]
    customDetails: {
      ResourceType: 'ResourceType'
      Operation: 'OperationNameValue'
      CorrelationId: 'CorrelationId'
      SubscriptionId: 'SubscriptionId'
      ResourceGroup: 'ResourceGroup'
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        matchingMethod: 'Selected'
        lookbackDuration: 'PT1H'
        reopenClosedIncident: false
        groupByEntities: [
          'Account'
          'AzureResource'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
  }
}

output ruleResourceId string = rule.id
