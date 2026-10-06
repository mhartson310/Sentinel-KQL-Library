targetScope = 'resourceGroup'

@description('Existing Log Analytics workspace with Microsoft Sentinel enabled.')
param workspaceName string

@description('Resource ID of PB-ZT-001 incident-trigger playbook.')
param exposurePlaybookResourceId string

@description('Resource ID of PB-ZT-002 incident-trigger playbook.')
param rbacPlaybookResourceId string

@description('Resource ID of PB-ZT-003 incident-trigger playbook.')
param diagnosticsPlaybookResourceId string

@description('Enable automation rules only after playbook permissions and connector authentication are validated.')
param enableAutomationRules bool = false

param tenantId string = tenant().tenantId

resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

var exposureAlertRuleId = '${workspace.id}/providers/Microsoft.SecurityInsights/alertRules/${guid(workspace.id, 'HA-ZT-001')}'
var rbacAlertRuleId = '${workspace.id}/providers/Microsoft.SecurityInsights/alertRules/${guid(workspace.id, 'HA-ZT-002')}'
var diagnosticsAlertRuleId = '${workspace.id}/providers/Microsoft.SecurityInsights/alertRules/${guid(workspace.id, 'HA-ZT-003')}'

resource exposureAutomation 'Microsoft.SecurityInsights/automationRules@2025-09-01' = {
  name: guid(workspace.id, 'AUTO-HA-ZT-001')
  scope: workspace
  properties: {
    displayName: 'AUTO-HA-ZT-001 - Exposure Change Response'
    order: 100
    triggeringLogic: {
      isEnabled: enableAutomationRules
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentRelatedAnalyticRuleIds'
            operator: 'Contains'
            propertyValues: [
              exposureAlertRuleId
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: 'High'
          labels: [
            { labelName: 'ZeroTrust' }
            { labelName: 'ExposureChange' }
          ]
        }
      }
      {
        order: 2
        actionType: 'AddIncidentTask'
        actionConfiguration: {
          title: 'Validate private-only exposure'
          description: 'Confirm public access state, private endpoints, private DNS, caller, change approval, and rerun negative-security tests after remediation.'
        }
      }
      {
        order: 3
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: exposurePlaybookResourceId
          tenantId: tenantId
        }
      }
    ]
  }
}

resource rbacAutomation 'Microsoft.SecurityInsights/automationRules@2025-09-01' = {
  name: guid(workspace.id, 'AUTO-HA-ZT-002')
  scope: workspace
  properties: {
    displayName: 'AUTO-HA-ZT-002 - RBAC Assignment Response'
    order: 110
    triggeringLogic: {
      isEnabled: enableAutomationRules
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentRelatedAnalyticRuleIds'
            operator: 'Contains'
            propertyValues: [
              rbacAlertRuleId
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: 'High'
          labels: [
            { labelName: 'ZeroTrust' }
            { labelName: 'PrivilegedAccess' }
          ]
        }
      }
      {
        order: 2
        actionType: 'AddIncidentTask'
        actionConfiguration: {
          title: 'Resolve and validate the new RBAC assignment'
          description: 'Identify assignee, role definition, scope, assigning identity, PIM/change approval, and whether the assignment is permanent or time-bound.'
        }
      }
      {
        order: 3
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: rbacPlaybookResourceId
          tenantId: tenantId
        }
      }
    ]
  }
}

resource diagnosticsAutomation 'Microsoft.SecurityInsights/automationRules@2025-09-01' = {
  name: guid(workspace.id, 'AUTO-HA-ZT-003')
  scope: workspace
  properties: {
    displayName: 'AUTO-HA-ZT-003 - Telemetry Integrity Response'
    order: 120
    triggeringLogic: {
      isEnabled: enableAutomationRules
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
      conditions: [
        {
          conditionType: 'Property'
          conditionProperties: {
            propertyName: 'IncidentRelatedAnalyticRuleIds'
            operator: 'Contains'
            propertyValues: [
              diagnosticsAlertRuleId
            ]
          }
        }
      ]
    }
    actions: [
      {
        order: 1
        actionType: 'ModifyProperties'
        actionConfiguration: {
          severity: 'High'
          labels: [
            { labelName: 'ZeroTrust' }
            { labelName: 'TelemetryIntegrity' }
          ]
        }
      }
      {
        order: 2
        actionType: 'AddIncidentTask'
        actionConfiguration: {
          title: 'Restore and validate diagnostic telemetry'
          description: 'Determine WRITE vs DELETE, validate destination workspace/categories, restore telemetry if weakened, and review the caller for related control changes.'
        }
      }
      {
        order: 3
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: diagnosticsPlaybookResourceId
          tenantId: tenantId
        }
      }
    ]
  }
}

output automationRuleIds array = [
  exposureAutomation.id
  rbacAutomation.id
  diagnosticsAutomation.id
]
