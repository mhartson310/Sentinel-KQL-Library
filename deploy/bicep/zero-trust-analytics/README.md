# Deployable Zero Trust Analytics Rules — Bicep

This deployment package creates the three Zero Trust analytics rules as Microsoft Sentinel **Scheduled** analytics rules.

## Included

- **HA-ZT-001** — Protected Service Exposure Changed
- **HA-ZT-002** — Privileged RBAC Assignment Created
- **HA-ZT-003** — Diagnostic Settings Changed

The rules include:

- severity
- MITRE tactics and techniques
- query frequency and lookback
- entity mappings
- custom details
- incident creation
- incident grouping
- stable deterministic rule IDs

## Safe default

`enableRules` defaults to **false**.

Deploy the rules first, run the underlying KQL as hunting queries, tune approved identities and resource scope, then enable them.

## Deploy

~~~bash
az deployment group create \
  --resource-group <sentinel-workspace-resource-group> \
  --template-file deploy/bicep/zero-trust-analytics/main.bicep \
  --parameters workspaceName=<log-analytics-workspace-name> \
               enableRules=false
~~~

After tuning:

~~~bash
az deployment group create \
  --resource-group <sentinel-workspace-resource-group> \
  --template-file deploy/bicep/zero-trust-analytics/main.bicep \
  --parameters workspaceName=<log-analytics-workspace-name> \
               enableRules=true
~~~

## Prerequisites

- Microsoft Sentinel is enabled on the target Log Analytics workspace.
- `AzureActivity` is populated in the workspace.
- The deployment identity can create/update `Microsoft.SecurityInsights/alertRules` under the workspace.
- The queries have been tested against your tenant schema.

## Why Bicep

Microsoft Sentinel analytics rules are Azure resources. Bicep lets the rules live beside the KQL and architecture as version-controlled infrastructure-as-code.

The modules use the stable `Microsoft.SecurityInsights/alertRules@2025-09-01` API and Scheduled-rule properties including entity mapping, incident configuration, grouping, scheduling, severity, and MITRE mappings.

## Related

- [Zero Trust analytics-rule documentation](../../../rules/zero-trust/)
- [Reusable KQL pack](../../../kql-queries/zero-trust/enterprise-application/)
- [Azure Zero Trust architecture](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/architecture/enterprise-application)
- [Negative-security validation](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/tests/enterprise-application)
