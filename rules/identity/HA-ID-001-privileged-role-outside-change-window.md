# HA-ID-001 — Privileged Role Assigned Outside Change Window

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0004 Privilege Escalation |
| **MITRE Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Data source** | Entra ID Audit Logs |
| **Required table** | `AuditLogs` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Account (initiator), Account (target) |

---

## What it detects

Assignment of a privileged Entra ID directory role outside your organization's approved change window. Legitimate privileged role changes almost always happen during business hours through a change process. Assignments at 2am on a Sunday are either an emergency or an attacker establishing persistence.

This catches the persistence step that follows a successful credential compromise — the point where an attacker converts access into durable access.

---

## KQL

```kql
let PrivilegedRoles = dynamic([
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "User Administrator",
    "Conditional Access Administrator",
    "Intune Administrator",
    "Hybrid Identity Administrator"
]);
// Adjust to your change window. Default: weekdays 07:00-19:00 UTC.
let WindowStartHour = 7;
let WindowEndHour = 19;
AuditLogs
| where OperationName has_any ("Add member to role", "Add eligible member to role")
| where Result == "success"
| extend TargetRole = tostring(TargetResources[0].displayName)
| extend RoleFromModified = tostring(parse_json(tostring(TargetResources[0].modifiedProperties))[1].newValue)
| extend RoleName = coalesce(
    tostring(parse_json(RoleFromModified)),
    TargetRole
  )
| where RoleName has_any (PrivilegedRoles)
| extend Initiator = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatorIP = tostring(InitiatedBy.user.ipAddress)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend DayOfWeek = dayofweek(TimeGenerated)
| extend HourOfDay = datetime_part("hour", TimeGenerated)
| where HourOfDay < WindowStartHour
     or HourOfDay >= WindowEndHour
     or DayOfWeek == 0d      // Sunday
     or DayOfWeek == 6d      // Saturday
| project
    TimeGenerated,
    RoleName,
    TargetUser,
    Initiator,
    InitiatorIP,
    OperationName,
    CorrelationId
| order by TimeGenerated desc
```

---

## Tuning notes

**Set your actual change window.** The defaults assume weekdays 07:00–19:00 UTC. If your admin team is distributed across time zones this will generate noise until you widen it or convert to local time. For a single-region org, convert with `datetime_utc_to_local()`.

**Trim the role list to what matters to you.** Twelve roles is a starting point. If your org does not use Intune or SharePoint, remove them. Every role you keep that nobody uses is a rule that never fires — harmless but it makes your coverage map lie.

**Exclude your PIM automation, not your PIM activations.** If you use Privileged Identity Management, just-in-time activations by users are expected and should be excluded. Assignments *made by* an automated process still deserve scrutiny. Add:

```kql
| where Initiator !in ("MS-PIM", "sync_serviceaccount@yourtenant.onmicrosoft.com")
```

**Watch the parsing.** Entra audit log schema for `modifiedProperties` has shifted more than once. If `RoleName` comes back empty, run `AuditLogs | where OperationName has "Add member to role" | take 5 | project TargetResources` and inspect the actual shape in your tenant before assuming the rule is broken.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Emergency access during an incident | Expected. Correlate with your incident tickets rather than suppressing. |
| Offshore or follow-the-sun admin teams | Widen the window, or split into separate rules per team with different windows. |
| Automated provisioning and HR-driven lifecycle jobs | Exclude the service account by UPN, not by display name. |
| Tenant migration or M&A onboarding | Suppress for the duration with a dated exception, then remove it. |

---

## Response guidance

1. Confirm the assignment against your change record. No ticket is the finding.
2. Check the initiator's recent sign-ins — `SigninLogs` for that UPN, 24 hours back. Look for unfamiliar IP, unfamiliar device, absent MFA.
3. If the initiator looks compromised, the role assignment is persistence. Revoke the role, revoke sessions, reset credentials, then investigate what else that account did.
4. If legitimate but undocumented, that is a process finding worth raising. Repeated undocumented privileged changes predict an audit finding.

---

## Related rules

- HA-ID-003 — Break-glass account activity
- HA-ID-004 — Conditional Access policy disabled or weakened
- HA-ID-005 — High-privilege app role granted to service principal

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
