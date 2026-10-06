# HA-ZT-002 — Privileged RBAC Assignment Created

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactics** | TA0004 Privilege Escalation, TA0003 Persistence |
| **MITRE Technique** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 5 minutes, 10 minute lookback |
| **Entity mapping** | Account (Caller), IP (CallerIpAddress), Azure resource (ResourceId) |
| **Architecture** | [Zero Trust Enterprise Application](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/architecture/enterprise-application) |

---

## What it detects

Successful Azure RBAC role-assignment creation.

A new role assignment is not automatically malicious, but unexpected assignment of Owner, Contributor, User Access Administrator, or sensitive data-plane roles can create an immediate privilege-escalation or persistence path.

This rule is deliberately frequent because privileged access changes are high-value events and usually low-volume compared with ordinary resource writes.

---

## KQL

```kql
let Lookback = 10m;
AzureActivity
| where TimeGenerated > ago(Lookback)
| where ActivityStatusValue in~ ("Success", "Succeeded")
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| project
    TimeGenerated,
    Caller,
    CallerIpAddress,
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
- **Suppression:** Off initially
- **Incident grouping:** Group by `Caller` and target scope when multiple assignments occur in one sequence

---

## Entity mapping

| Sentinel entity | Field |
|---|---|
| Account | `Caller` |
| IP | `CallerIpAddress` |
| Azure resource | `ResourceId` |

For higher-fidelity deployment, enrich the role-assignment resource to extract:

- assignee object ID;
- role definition ID/name;
- assignment scope.

Then raise severity to **Critical** for Owner or User Access Administrator at subscription/management-group scope.

---

## Tuning notes

The base Azure Activity event is reliable for detecting the assignment write, but role-name enrichment varies by tenant and connector shape.

Before promoting broadly:

1. enumerate normal PIM/automation assignments;
2. exclude approved CI/CD identities;
3. enrich role IDs against a high-impact-role watchlist;
4. distinguish permanent assignments from PIM-eligible activation where your telemetry supports it.

This rule is most valuable when paired with your privileged-access architecture and PIM controls.

---

## False positives you will actually hit

| Scenario | Handling |
|---|---|
| Terraform creates workload RBAC | Exclude approved pipeline identity and known scopes |
| New engineer onboarding | Validate against onboarding/change ticket |
| PIM or access-package automation | Baseline approved automation principals |
| Break-glass maintenance | Treat as high priority even when expected |

---

## Response guidance

1. Identify who created the assignment.
2. Resolve the assignee, role definition, and scope.
3. Check whether the assignment is permanent or time-bound.
4. Validate against PIM approval/change records.
5. If unauthorized, remove the assignment immediately.
6. Revoke sessions or credentials for the assigning identity if compromise is suspected.
7. Review all role assignments created by the same caller in the previous 24 hours.
8. Check for follow-on access to Key Vault, Storage, subscriptions, and policy objects.
9. Run the architecture's [least-privilege validation test](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/tests/enterprise-application).

---

## Related detections

- [HA-ZT-001 — Protected Service Exposure Changed](HA-ZT-001-protected-service-exposure-changed.md)
- [HA-ZT-003 — Diagnostic Settings Changed](HA-ZT-003-diagnostic-settings-changed.md)
- [HA-ID-001 — Privileged Role Outside Change Window](../identity/HA-ID-001-privileged-role-outside-change-window.md)

---

[← Sentinel KQL Library](../../README.md)
