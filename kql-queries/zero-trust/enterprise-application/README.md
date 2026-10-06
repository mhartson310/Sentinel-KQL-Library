# Zero Trust Enterprise Application — KQL Detection Pack

This pack operationalizes the controls in the **[Azure Zero Trust Enterprise Application reference architecture](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/architecture/enterprise-application)**.

The architecture defines the trust boundaries. These queries test whether those boundaries are being weakened, bypassed, or behaving unexpectedly.

## Detection coverage

| Detection | What it answers | Primary table |
|---|---|---|
| [Protected service exposure changed](protected-service-exposure-change.kql) | Did a protected App Service, Key Vault, or Storage account receive a control-plane change that could re-enable public access? | `AzureActivity` |
| [Privileged RBAC assignment created](privileged-rbac-assignment-created.kql) | Was a high-impact Azure role granted unexpectedly? | `AzureActivity` |
| [Diagnostic settings changed](diagnostic-settings-changed.kql) | Was security telemetry altered or removed? | `AzureActivity` |
| [Key Vault access anomaly](key-vault-access-anomaly.kql) | Is a principal accessing secrets/keys at unusual volume? | `AzureDiagnostics` |
| [Conditional Access failure spike](conditional-access-failure-spike.kql) | Is one identity repeatedly failing Conditional Access? | `SigninLogs` |

## Architecture mapping

These detections correspond directly to the reference architecture controls:

- **Verify explicitly** → Conditional Access failure patterns
- **Use least privilege** → privileged RBAC changes
- **Assume breach** → private/public exposure changes
- **Continuous validation** → diagnostic-setting changes
- **Protect secrets and data** → Key Vault access anomalies

The deployable infrastructure and validation tests live in the architecture repo:

- [Terraform implementation](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/terraform/enterprise-application)
- [Negative-security validation](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/tests/enterprise-application)
- [Architecture-local Sentinel pack](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/sentinel/enterprise-application)

## Operating guidance

1. Run each query as a hunting query first.
2. Baseline 14–30 days where the table supports it.
3. Exclude approved IaC/deployment identities by object ID.
4. Tune thresholds to the workload.
5. Promote stable queries into scheduled analytics rules.
6. Keep architecture validation and detection tuning linked.

**A detection is an investigation trigger, not proof of compromise.**
