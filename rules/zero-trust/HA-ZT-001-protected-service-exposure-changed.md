# HA-ZT-001 — Protected Service Exposure Changed

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0005 Defense Evasion |
| **MITRE Technique** | T1562 — Impair Defenses |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 15 minutes, 15 minute lookback |
| **Entity mapping** | Account (Caller), IP (CallerIpAddress), Azure resource (ResourceId) |
| **Architecture** | [Zero Trust Enterprise Application](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/architecture/enterprise-application) |

---

## What it detects

Successful control-plane writes to protected App Service, Key Vault, or Storage resources that can weaken private-only access or alter network exposure.

This is deliberately a **control-change** detection. It does not assume every write is malicious. It is intended to answer:

> Did someone change a protected service in a way that could reopen public access?

---

## KQL

```kql
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
| project
    TimeGenerated,
    ResourceType,
    Caller,
    CallerIpAddress,
    SubscriptionId,
    ResourceGroup,
    ResourceId,
    OperationNameValue,
    CorrelationId,
    Properties
| order by TimeGenerated desc
```

---

## Scheduling

- **Query frequency:** 15 minutes
- **Lookup period:** 15 minutes
- **Trigger operator:** Greater than
- **Trigger threshold:** 0
- **Suppression:** Off initially
- **Grouping:** Group related events by `ResourceId` and `Caller` during investigation, not at alert creation

---

## Entity mapping

| Sentinel entity | Field |
|---|---|
| Account | `Caller` |
| IP | `CallerIpAddress` |
| Azure resource | `ResourceId` |

If your tenant uses service principals heavily, enrich `Caller` against Entra service-principal metadata or an approved automation watchlist.

---

## Tuning notes

**Expect deployment noise.** Terraform, Bicep, ARM, portal changes, and policy remediation can all generate legitimate writes.

Before enabling as an alert:

1. filter to production or protected subscriptions/resource groups;
2. identify approved CI/CD identities by object ID;
3. correlate with maintenance/change windows;
4. consider narrowing to resources tagged as private-only.

The strongest version of this rule compares the activity event with the resulting resource configuration and only alerts when `publicNetworkAccess` is actually enabled.

---

## False positives you will actually hit

| Scenario | Handling |
|---|---|
| Terraform or Bicep deployment | Exclude approved pipeline object IDs, not display names |
| Planned networking change | Use a dated change-window exception |
| Policy remediation | Verify policy assignment and remediation task |
| App Service configuration update unrelated to exposure | Correlate with resulting resource configuration |

---

## Response guidance

1. Identify the resource and caller.
2. Check the current public-network-access state immediately.
3. Verify the change against an approved deployment or change ticket.
4. If unauthorized, restore the private-only configuration and revoke the caller's sessions/credentials as appropriate.
5. Review related changes from the same caller and correlation ID.
6. Confirm Private Endpoint and Private DNS configuration remain intact.
7. Run the matching [negative-security tests](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/tests/enterprise-application) after remediation.

---

## Related detections

- [HA-ZT-002 — Privileged RBAC Assignment Created](HA-ZT-002-privileged-rbac-assignment-created.md)
- [HA-ZT-003 — Diagnostic Settings Changed](HA-ZT-003-diagnostic-settings-changed.md)
- [Reusable KQL pack](../../kql-queries/zero-trust/enterprise-application/README.md)

---

[← Sentinel KQL Library](../../README.md)
