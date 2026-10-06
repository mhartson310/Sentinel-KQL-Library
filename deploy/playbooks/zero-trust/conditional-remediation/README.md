# Second-Stage Conditional Remediation

These playbooks implement the next maturity level of the Zero Trust SOAR design:

**Detection → enrichment → safety gates → explicit analyst approval → remediation → validation → incident update**

## Why these playbooks are manual

Microsoft Sentinel incident-trigger playbooks can be run manually from an incident. That manual run is used here as one approval control, and the playbooks add a second explicit gate: the incident must carry the label:

`RemediationApproved`

These remediation playbooks are **not attached to an automation rule**.

That keeps a detection from directly deleting access or changing production telemetry.

## PB-ZT-002 — Remediate RBAC

Path:

`pb-zt-002-remediate-rbac/azuredeploy.json`

Safety gates:

1. incident already has the `PrivilegedAccess` label from HA-ZT-002 automation;
2. analyst adds `RemediationApproved`;
3. incident contains exactly one `AzureResource` entity;
4. that resource ID is specifically a `Microsoft.Authorization/roleAssignments` resource;
5. playbook verifies the role assignment exists before deletion.

Action:

- deletes only that exact role-assignment resource through Azure Resource Manager using the Logic App managed identity.

Post-action validation:

- performs a GET for the deleted assignment;
- expected result is not found;
- writes the result back to the Sentinel incident.

### Required RBAC

The Logic App managed identity needs the narrowest role that permits:

`Microsoft.Authorization/roleAssignments/delete`

at the protected scope.

Do **not** grant broad subscription-wide access just to make the playbook work. Prefer a custom role at the smallest controlled scope when practical.

## PB-ZT-003 — Restore Diagnostics

Path:

`pb-zt-003-restore-diagnostics/azuredeploy.json`

Safety gates:

1. incident has the `TelemetryIntegrity` label;
2. analyst adds `RemediationApproved`;
3. exactly one diagnostic-setting `AzureResource` entity exists;
4. target belongs to an explicitly supported Zero Trust baseline:
   - Key Vault; or
   - Storage Account.

Action:

- restores the diagnostic setting to the approved Log Analytics workspace;
- Key Vault baseline: `audit` category group + `AllMetrics`;
- Storage Account baseline: `Transaction` metrics.

Post-action validation:

- retrieves the diagnostic setting;
- verifies the configured workspace ID matches the approved workspace;
- writes the outcome to the incident.

### Required RBAC

The Logic App managed identity needs permission to create/update diagnostic settings on only the protected resource scope(s), such as a custom role containing:

`Microsoft.Insights/diagnosticSettings/read`
`Microsoft.Insights/diagnosticSettings/write`

## Deploy

RBAC remediation:

~~~bash
az deployment group create \
  --resource-group <playbook-resource-group> \
  --template-file deploy/playbooks/zero-trust/conditional-remediation/pb-zt-002-remediate-rbac/azuredeploy.json
~~~

Diagnostic restoration:

~~~bash
az deployment group create \
  --resource-group <playbook-resource-group> \
  --template-file deploy/playbooks/zero-trust/conditional-remediation/pb-zt-003-restore-diagnostics/azuredeploy.json \
  --parameters LogAnalyticsWorkspaceResourceId="/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"
~~~

Grant both playbook identities Microsoft Sentinel Responder so they can comment on the incident.

## Analyst workflow

1. HA-ZT-002 or HA-ZT-003 creates an incident.
2. First-stage automation enriches and adds an incident task.
3. Analyst confirms the change is unauthorized.
4. Analyst adds the `RemediationApproved` label.
5. Analyst chooses **Run playbook** on the incident.
6. Analyst runs the matching second-stage playbook.
7. Playbook applies its target/risk gates.
8. Remediation runs only when all gates pass.
9. Post-remediation validation runs.
10. Result is written back into the incident.
11. Analyst runs the architecture negative-security validation suite before closure.

## Important limitation

This is intentionally scoped to the **reference architecture control paths**.

The diagnostics playbook does not guess the correct log categories for arbitrary Azure resource types. Unknown targets fail closed and require manual remediation.

The RBAC playbook only deletes a role-assignment entity surfaced by the HA-ZT-002 incident. It does not search for and remove unrelated role assignments.

That narrow scope is a feature.
