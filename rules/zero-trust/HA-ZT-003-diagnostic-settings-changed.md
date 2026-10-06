# HA-ZT-003 — Diagnostic Settings Changed

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0005 Defense Evasion |
| **MITRE Technique** | T1562.008 — Impair Defenses: Disable or Modify Cloud Logs |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 5 minutes, 10 minute lookback |
| **Entity mapping** | Account (Caller), IP (CallerIpAddress), Azure resource (ResourceId) |
| **Architecture** | [Zero Trust Enterprise Application](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/architecture/enterprise-application) |

---

## What it detects

Writes or deletion of Azure Monitor diagnostic settings.

Deleting a diagnostic setting can blind Sentinel to the exact workload or control an attacker plans to abuse next. Writes matter too, because forwarding can be redirected or categories can be reduced.

This is one of the most important Zero Trust detections because continuous validation fails if the telemetry itself disappears.

---

## KQL

```kql
let Lookback = 10m;
AzureActivity
| where TimeGenerated > ago(Lookback)
| where OperationNameValue has_any (
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE",
    "MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE"
)
| extend ChangeType = iff(OperationNameValue has "/DELETE", "Delete", "Write")
| extend SeverityHint = iff(ChangeType == "Delete", "High", "Medium")
| project
    TimeGenerated,
    SeverityHint,
    ChangeType,
    Caller,
    CallerIpAddress,
    ActivityStatusValue,
    SubscriptionId,
    ResourceGroup,
    ResourceId,
    CorrelationId,
    Properties
| order by TimeGenerated desc
```

---

## Scheduling

- **Query frequency:** 5 minutes
- **Lookup period:** 10 minutes
- **Trigger operator:** Greater than
- **Trigger threshold:** 0
- **Suppression:** Off
- **Dynamic severity:** High for DELETE; Medium for WRITE if your deployment tooling supports dynamic severity mapping

---

## Entity mapping

| Sentinel entity | Field |
|---|---|
| Account | `Caller` |
| IP | `CallerIpAddress` |
| Azure resource | `ResourceId` |

---

## Tuning notes

A diagnostic-setting **DELETE** on a protected production resource should be rare.

Writes are more common during:

- Terraform/Bicep rollout;
- workspace migration;
- retention changes;
- category changes;
- policy remediation.

For the highest-fidelity version:

1. maintain a watchlist of critical resource IDs;
2. alert on DELETE immediately;
3. alert on WRITE only when the caller is not approved automation;
4. periodically run an absence check to find resources that should have diagnostics but do not.

The last point matters: this rule detects the *change*. A separate control should detect the *missing state*.

---

## False positives you will actually hit

| Scenario | Handling |
|---|---|
| IaC redeployment | Exclude approved automation object IDs |
| Workspace migration | Dated exception tied to migration window |
| Azure Policy remediation | Verify expected assignment/remediation ID |
| Logging-category optimization | Confirm categories still meet detection requirements |

---

## Response guidance

1. Determine whether the event was WRITE or DELETE.
2. Identify the protected resource whose diagnostic setting changed.
3. Validate the caller against approved IaC/change activity.
4. Inspect the current diagnostic settings and destination workspace.
5. If telemetry was disabled or redirected, restore it immediately.
6. Query the affected resource's other telemetry sources for the blind period.
7. Review the caller's activity during the same window for RBAC, public-access, firewall, Key Vault, or policy changes.
8. Run the architecture's [diagnostic-settings validation](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/tests/enterprise-application).

---

## Related detections

- [HA-ZT-001 — Protected Service Exposure Changed](HA-ZT-001-protected-service-exposure-changed.md)
- [HA-ZT-002 — Privileged RBAC Assignment Created](HA-ZT-002-privileged-rbac-assignment-created.md)
- [HA-SIG-002 — Log Source Stopped Reporting](../signature/HA-SIG-002-log-source-went-dark.md)

---

[← Sentinel KQL Library](../../README.md)
