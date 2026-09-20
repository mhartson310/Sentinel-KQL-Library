# HA-PO-001 — Defender for Cloud Plan Disabled

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0005 Defense Evasion |
| **MITRE Technique** | T1562.008 — Impair Defenses: Disable Cloud Logs |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Account (caller), Azure Resource (subscription) |

---

## What it detects

Someone turning off a Microsoft Defender for Cloud plan on a subscription. This is a defense-evasion move when an attacker does it and a cost-cutting move when finance does it. Both are worth knowing about within the hour rather than at the next quarterly review.

In practice this rule catches the second case far more often than the first — and that is still valuable. Silent plan downgrades are one of the most common reasons a security program's coverage quietly degrades between audits.

---

## KQL

```kql
AzureActivity
| where OperationNameValue =~ "MICROSOFT.SECURITY/PRICINGS/WRITE"
| where ActivityStatusValue in ("Success", "Succeeded")
| extend Props = parse_json(Properties)
| extend RequestBody = parse_json(tostring(Props.requestbody))
| extend PlanTier = tostring(RequestBody.properties.pricingTier)
| extend PlanName = tostring(split(_ResourceId, "/")[-1])
| where PlanTier =~ "Free"
| project
    TimeGenerated,
    SubscriptionId,
    PlanName,
    PlanTier,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    CorrelationId
| order by TimeGenerated desc
```

**Companion hunting query — find plans currently downgraded across all subscriptions:**

```kql
AzureActivity
| where OperationNameValue =~ "MICROSOFT.SECURITY/PRICINGS/WRITE"
| where ActivityStatusValue in ("Success", "Succeeded")
| extend Props = parse_json(Properties)
| extend PlanTier = tostring(parse_json(tostring(Props.requestbody)).properties.pricingTier)
| extend PlanName = tostring(split(_ResourceId, "/")[-1])
| summarize arg_max(TimeGenerated, PlanTier, Caller) by SubscriptionId, PlanName
| where PlanTier =~ "Free"
| order by TimeGenerated desc
```

---

## Tuning notes

**Onboarding is the prerequisite.** `AzureActivity` must be connected for every subscription you care about. This is the single most common reason this rule returns nothing — not a KQL problem, a coverage problem. Verify with:

```kql
AzureActivity | summarize count() by SubscriptionId | order by count_ desc
```

If a subscription is missing from that list, the rule is blind to it.

**Dev and sandbox subscriptions are legitimately Free tier.** Maintain a watchlist of subscriptions where Free is expected and exclude them, rather than suppressing the alert type globally. A hardcoded exclusion list in the query rots; a watchlist can be owned by someone.

**The schema varies.** `requestbody` is not always populated depending on how the change was made (portal vs. ARM vs. Policy remediation). If `PlanTier` comes back empty, fall back to alerting on any `PRICINGS/WRITE` and triaging manually — noisier, but it will not miss.

**Consider inverting it.** In a mature environment, a better rule is "plan state does not match the state Azure Policy should be enforcing." If you deploy Defender plans via Policy, drift is the real signal.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Subscription decommissioning | Correlate with subscription state. A plan disabled on a subscription being torn down is expected. |
| Cost optimization projects | Legitimate, but should still be reviewed. Route to a lower-severity queue rather than suppressing. |
| Azure Policy remediation flapping | If you deploy plans via Policy and someone changes them manually, you will see repeated writes. Fix the process, not the rule. |
| Trial expiry | Defender plan trials ending can generate a write event. Check the caller — automated expiry looks different from a human. |

---

## Response guidance

1. Identify the caller. A human UPN and a service principal warrant different responses.
2. Check whether it was authorized. Change ticket, cost-optimization initiative, or neither.
3. If neither, treat as potential defense evasion. Check what else that identity did in the preceding 24 hours — especially resource creation, role assignments, and network changes.
4. Re-enable the plan. Then ask why it was possible for one person to do this without an approval gate — Azure Policy with a deny effect prevents the whole class of event.

---

## Related rules

- HA-PO-002 — NSG rule opened to the internet on a management port
- HA-PO-004 — Key Vault access granted followed by bulk secret read
- HA-EP-001 — Tamper protection or real-time protection disabled

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
