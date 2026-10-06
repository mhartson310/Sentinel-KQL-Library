# Zero Trust Automated Response

This package connects the three Zero Trust Scheduled analytics rules to Microsoft Sentinel **automation rules** and incident-triggered **Logic Apps playbooks**.

## Response design

The first release intentionally automates **triage, labeling, task creation, and analyst guidance** — not destructive remediation.

That is deliberate.

A public-access change, RBAC assignment, or diagnostic-setting change can be legitimate. Automatically removing access or rewriting production configuration without additional confidence can cause an outage.

| Analytics rule | Automation response | Playbook |
|---|---|---|
| HA-ZT-001 | High severity, ZeroTrust/ExposureChange labels, validation task | Adds exposure-remediation guidance to incident |
| HA-ZT-002 | High severity, ZeroTrust/PrivilegedAccess labels, RBAC investigation task | Adds privilege investigation/containment guidance |
| HA-ZT-003 | High severity, ZeroTrust/TelemetryIntegrity labels, telemetry restoration task | Adds logging restoration/investigation guidance |

## Deploy the playbooks

Each folder contains an ARM template for a Consumption Logic App with:

- Microsoft Sentinel incident trigger;
- system-assigned managed identity;
- Microsoft Sentinel connector configured for managed identity;
- automated incident comment containing response guidance.

Deploy:

~~~bash
az deployment group create \
  --resource-group <playbook-resource-group> \
  --template-file deploy/playbooks/zero-trust/pb-zt-001-exposure-change/azuredeploy.json

az deployment group create \
  --resource-group <playbook-resource-group> \
  --template-file deploy/playbooks/zero-trust/pb-zt-002-rbac-assignment/azuredeploy.json

az deployment group create \
  --resource-group <playbook-resource-group> \
  --template-file deploy/playbooks/zero-trust/pb-zt-003-diagnostics-changed/azuredeploy.json
~~~

Capture each Logic App resource ID.

## Required permissions

### Playbook managed identity

Grant each Logic App's system-assigned managed identity **Microsoft Sentinel Responder** on the Sentinel workspace/resource group if the playbook will add comments or update incidents.

Built-in role ID:

`3e150937-b8fe-4cfb-8069-0eaf05ecd056`

### Microsoft Sentinel service account

For automation rules to run incident-triggered playbooks, Microsoft Sentinel's service account needs **Microsoft Sentinel Automation Contributor** on the resource group containing the playbooks.

Built-in role ID:

`f4c81013-99ee-4d62-a7ee-b3f1f648599a`

Microsoft documents this permission as required for automation rules to invoke playbooks.

## Deploy the automation rules

~~~bash
az deployment group create \
  --resource-group <sentinel-workspace-resource-group> \
  --template-file deploy/bicep/zero-trust-automation/main.bicep \
  --parameters \
      workspaceName=<workspace-name> \
      exposurePlaybookResourceId=<pb-zt-001-resource-id> \
      rbacPlaybookResourceId=<pb-zt-002-resource-id> \
      diagnosticsPlaybookResourceId=<pb-zt-003-resource-id> \
      enableAutomationRules=false
~~~

Keep `enableAutomationRules=false` until:

1. the three analytics rules are deployed and generating test incidents;
2. the playbook API connections are healthy;
3. each Logic App managed identity can update Sentinel incidents;
4. Microsoft Sentinel has Automation Contributor permission on the playbook resource group;
5. manual playbook runs succeed.

Then redeploy with:

~~~text
enableAutomationRules=true
~~~

## Why the automation rules match by analytic-rule ID

Each automation rule uses `IncidentRelatedAnalyticRuleIds` rather than matching incident title text.

The analytics rule IDs are deterministic because the Bicep deployment uses:

~~~text
guid(workspace.id, 'HA-ZT-001')
guid(workspace.id, 'HA-ZT-002')
guid(workspace.id, 'HA-ZT-003')
~~~

This makes the architecture → analytics rule → automation rule chain repeatable in CI/CD.

## Next maturity level

After this triage-first version is proven, add **conditional remediation branches** rather than unconditional remediation.

Recommended gates:

- known protected resource;
- no approved change record;
- caller not in approved deployment identities;
- high-risk role or public exposure actually confirmed;
- second signal or analyst approval.

Only then should a playbook automatically remove an RBAC assignment, disable public access, or restore a diagnostic setting.


## Second-stage conditional remediation

The next response layer is now available for HA-ZT-002 and HA-ZT-003:

**[Conditional remediation playbooks](conditional-remediation/README.md)**

These playbooks are deliberately **manual incident playbooks**, not automation-rule actions. An analyst must validate the incident, add the `RemediationApproved` label, and run the playbook from the incident. The playbook then applies additional target/risk gates, performs the narrow remediation, validates the result, and writes the outcome back to the incident.

Current actions:

- **HA-ZT-002:** delete the exact unauthorized Azure RBAC role assignment surfaced as the incident's AzureResource entity.
- **HA-ZT-003:** restore the approved Key Vault or Storage diagnostic-setting baseline and verify the Log Analytics destination.

Unknown or ambiguous targets fail closed.
