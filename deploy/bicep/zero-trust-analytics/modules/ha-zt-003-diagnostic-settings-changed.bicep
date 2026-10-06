targetScope = 'resourceGroup'

param workspaceName string
param enabled bool = false

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

var ruleName = guid(workspace.id, 'HA-ZT-003')

resource rule 'Microsoft.SecurityInsights/alertRules@2025-09-01' = {
  name: ruleName
  scope: workspace
  kind: 'Scheduled'
  properties: {
    displayName: 'HA-ZT-003 - Diagnostic Settings Changed'
    description: 'Detects creation, update, or deletion of Azure Monitor diagnostic settings that can create security telemetry blind spots.'
    enabled: enabled
    severity: 'High'
    tactics: [
      'DefenseEvasion'
    ]
    techniques: [
      'T1562'
    ]
    subTechniques: [
      'T1562.008'
    ]
    queryFrequency: 'PT5M'
    queryPeriod: 'PT10M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT5H'
    query: '''
let Lookback = 10m;
AzureActivity
| where TimeGenerated > ago(Lookback)
| where OperationNameValue has_any (
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"
)
| extend ChangeType = iff(OperationNameValue has "/DELETE", "Delete", "Write")
| extend SeverityHint = iff(ChangeType == "Delete", "High", "Medium")
| project TimeGenerated, SeverityHint, ChangeType, Caller, CallerIpAddress, ActivityStatusValue, SubscriptionId, ResourceGroup, ResourceId, CorrelationId, Properties
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
      ChangeType: 'ChangeType'
      SeverityHint: 'SeverityHint'
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
