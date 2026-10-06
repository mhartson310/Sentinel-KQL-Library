# Conditional Remediation Decision Model

Use this decision model before adding the `RemediationApproved` label.

| Gate | HA-ZT-002 RBAC | HA-ZT-003 diagnostics |
|---|---|---|
| Correct analytic rule | Required | Required |
| Existing Zero Trust incident label | `PrivilegedAccess` | `TelemetryIntegrity` |
| Approved change exists | STOP — do not remediate | STOP — do not remediate |
| Caller is approved automation | STOP / investigate deployment | STOP / investigate deployment |
| Target is unambiguous | Exactly one role assignment | Exactly one diagnostic setting |
| Target is supported | Role-assignment ARM ID | Key Vault or Storage diagnostic baseline |
| Analyst approval | `RemediationApproved` label + manual playbook run | `RemediationApproved` label + manual playbook run |
| Remediation | Delete exact role assignment | Restore approved diagnostic baseline |
| Verification | Assignment no longer resolves | Workspace destination matches baseline |
| Final validation | Least-privilege negative test | Diagnostic + telemetry validation |

## Fail-closed rules

The playbooks do nothing when:

- approval label is absent;
- the expected first-stage label is absent;
- zero or multiple target entities are present;
- the target resource shape is unexpected;
- diagnostics target is outside the supported Key Vault / Storage baseline.

This is intentional. SOAR should reduce response time without turning uncertainty into production changes.
