# HA-ID-004 — Conditional Access Policy Disabled or Weakened

| Field | Value |
|---|---|
| **Severity** | Critical |
| **MITRE Tactic** | TA0005 Defense Evasion |
| **MITRE Technique** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Data source** | Entra ID Audit Logs |
| **Required table** | `AuditLogs` |
| **Suggested frequency** | Every 15 minutes, 15 minute lookback |
| **Entity mapping** | Account (initiator), IP (initiator IP) |

---

## What it detects

Conditional Access policies being deleted, disabled, switched to report-only, or having exclusions added. CA is the control plane for your identity security — an attacker with sufficient privilege weakens it before doing anything else, because it removes MFA as an obstacle for everything that follows.

Adding an exclusion is the subtle version and the one most often missed. The policy still exists, still shows as enabled, and no longer applies to the account the attacker controls.

---

## KQL

```kql
AuditLogs
| where Category == "Policy"
| where OperationName has_any (
    "Add conditional access policy",
    "Update conditional access policy",
    "Delete conditional access policy"
  )
| where Result == "success"
| extend
    PolicyName = tostring(TargetResources[0].displayName),
    Initiator = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorApp = tostring(InitiatedBy.app.displayName),
    InitiatorIP = tostring(InitiatedBy.user.ipAddress),
    ModProps = TargetResources[0].modifiedProperties
| mv-apply Prop = ModProps on (
    extend
        OldValue = tostring(Prop.oldValue),
        NewValue = tostring(Prop.newValue)
  )
| extend
    NowDisabled  = NewValue has '"state":"disabled"' or NewValue has '"state": "disabled"',
    NowReportOnly = NewValue has "enabledForReportingButNotEnforced",
    WasEnabled   = OldValue has '"state":"enabled"' or OldValue has '"state": "enabled"',
    ExclusionAdded = (strlen(NewValue) - strlen(replace_string(NewValue, "excludeUsers", ""))) >
                     (strlen(OldValue) - strlen(replace_string(OldValue, "excludeUsers", "")))
| extend RiskReason = case(
    OperationName has "Delete", "Policy deleted",
    NowDisabled and WasEnabled, "Policy disabled",
    NowReportOnly and WasEnabled, "Switched to report-only",
    ExclusionAdded, "Exclusion added",
    "Policy modified"
  )
| where RiskReason != "Policy modified" or OperationName has "Delete"
| project
    TimeGenerated,
    RiskReason,
    PolicyName,
    Initiator,
    InitiatorApp,
    InitiatorIP,
    OperationName,
    CorrelationId
| order by TimeGenerated desc
```

---

## Tuning notes

**The `modifiedProperties` blob is messy and tenant-dependent.** The string matching above is deliberately loose because the JSON shape varies. Before trusting it, run this and read the raw values in your own tenant:

```kql
AuditLogs
| where OperationName has "conditional access policy"
| take 5
| project TimeGenerated, OperationName, TargetResources
```

**Exclusion detection is heuristic.** The comparison above counts occurrences of `excludeUsers` — crude but effective in practice. If you need precision, parse both old and new policy JSON and diff the exclusion arrays properly. That version is in the full pack.

**Expect noise during CA rollouts.** Any well-run CA deployment goes report-only first, then enforced, in waves. During a rollout this rule will fire constantly. Suppress with a dated exception tied to the project, not permanently.

**Alert on failures separately.** A *failed* attempt to modify CA by a non-admin is a strong signal of an account probing its own privileges.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Planned CA rollout or redesign | Dated exception for the project window. Remove it on completion. |
| Legitimate break-glass exclusion maintenance | Expected — exclusions for emergency accounts are best practice. Verify the excluded account is actually break-glass. |
| Policy template updates from Microsoft | Rare, but Microsoft-managed policies can change. Check the initiator app. |
| Testing in report-only before enforcement | Correct practice. Correlate with your change records. |

---

## Response guidance

1. Check the initiator against your admin roster. An unfamiliar UPN here is an emergency.
2. Pull the initiator's sign-in history for 24 hours. Unfamiliar IP or device suggests the admin account itself is compromised.
3. If unauthorized: restore the policy from your documented baseline, revoke the initiator's sessions, then audit everything else they touched.
4. Keep an exported baseline of your CA policies in source control. Without it you cannot prove what changed.

---

## Related rules

- HA-ID-002 — Successful sign-in using legacy authentication
- HA-ID-003 — Break-glass account activity

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
