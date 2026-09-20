# HA-SIG-001 — Over-Permissioned AI Agent

> **"We deployed Copilot agents six months ago. Nobody wrote down who owns them or what they can reach."**

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0003 Persistence / TA0004 Privilege Escalation |
| **MITRE Technique** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Data source** | Sentinel data lake — agent identity telemetry |
| **Required tables** | Agent identity connector tables, `AuditLogs` |
| **Suggested frequency** | Daily, 24 hour lookback |
| **Entity mapping** | Account (agent owner), CloudApplication (agent identity) |

---

## What it detects

AI agents holding permissions far beyond what their actual activity requires. Every agent is a workload identity: it authenticates, it holds permissions, it touches data. We spent fifteen years building governance for human identities and are now provisioning non-human ones at ten times the speed with a fraction of the oversight.

This rule joins what an agent *can* do against what it *has* done, and surfaces the gap.

---

## KQL

```kql
// Agent identity telemetry lands in the Sentinel data lake via the agent
// identities connector. Table names vary by tenant — confirm yours first:
//   search "agent" | distinct $table
let LookbackDays = 30d;
let HighRiskScopes = dynamic([
    "Directory.ReadWrite.All", "Files.ReadWrite.All", "Sites.FullControl.All",
    "Mail.ReadWrite", "Mail.Send", "User.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All"
]);
// What each agent is PERMITTED to do
let Granted =
    AuditLogs
    | where OperationName has_any ("Add app role assignment to service principal",
                                   "Add delegated permission grant")
    | where Result == "success"
    | extend AgentAppId = tostring(TargetResources[0].id),
             AgentName  = tostring(TargetResources[0].displayName),
             Owner      = tostring(InitiatedBy.user.userPrincipalName)
    | mv-apply Prop = TargetResources[0].modifiedProperties on (
        extend Scope = replace_string(tostring(Prop.newValue), '"', "")
        | where Scope has_any (HighRiskScopes)
      )
    | summarize GrantedScopes = make_set(Scope, 20),
                GrantedAt     = min(TimeGenerated),
                Owner         = any(Owner)
      by AgentAppId, AgentName;
// What each agent has ACTUALLY done
let Used =
    AADServicePrincipalSignInLogs
    | where TimeGenerated > ago(LookbackDays)
    | summarize SignIns          = count(),
                ResourcesTouched = dcount(ResourceDisplayName),
                Resources        = make_set(ResourceDisplayName, 10),
                LastSeen         = max(TimeGenerated)
      by AgentAppId = AppId;
Granted
| join kind=leftouter Used on AgentAppId
| extend
    DaysSinceGrant = datetime_diff("day", now(), GrantedAt),
    Dormant        = isnull(SignIns) or SignIns == 0,
    ScopeCount     = array_length(GrantedScopes)
| extend Finding = case(
    Dormant and DaysSinceGrant > 30,
      "DORMANT — high-privilege scopes, no activity in 30d",
    ResourcesTouched <= 1 and ScopeCount >= 3,
      "OVER-SCOPED — broad permissions, narrow actual use",
    isempty(Owner),
      "UNOWNED — no identifiable owner on record",
    "Review")
| where Finding != "Review"
| project Finding, AgentName, AgentAppId, Owner, GrantedScopes,
          ScopeCount, SignIns, ResourcesTouched, Resources,
          GrantedAt, DaysSinceGrant, LastSeen
| order by ScopeCount desc
```

---

## Tuning notes

**Table names will not match.** Agent identity telemetry is new and the schema is still moving. Before anything else, find what you actually have:

```kql
search "agent" | distinct $table
```

Then adjust the `Granted` block to whatever your tenant exposes. The *logic* — permitted versus exercised — is the durable part; the table names are not.

**Start with `DORMANT`, not `OVER-SCOPED`.** Dormant agents with high-privilege scopes are unambiguous findings and easy wins. Over-scoped is a judgment call that will generate argument with whoever built the agent, so bring evidence.

**Thirty days is a starting anchor.** Agents tied to quarterly processes will look dormant at 30 days and be entirely legitimate. If your business runs on quarterly cycles, push to 90 and accept the slower signal.

**`UNOWNED` is the finding that matters most and the one nobody wants.** An agent with no owner cannot be reviewed, renewed, or revoked by anyone. It will outlive the person who created it. Treat an empty owner field as a governance defect rather than a detection.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Newly created agent not yet in production | Exclude agents granted in the last 14 days. |
| Seasonal or quarterly automation | Widen `LookbackDays`, or exclude by app ID with a documented reason. |
| Break-glass automation, intentionally idle | Allowlist explicitly — same treatment as break-glass accounts. |
| Agent uses a different identity than the one granted | Real finding disguised as an FP. Trace the chain properly before dismissing. |

---

## Response guidance

1. Find the owner. If there isn't one, that's the first remediation — assign one before touching permissions.
2. Compare granted scopes against 30 days of actual resource access. Scope down to what was used, not to what was requested.
3. For dormant agents: disable first, delete after a defined waiting period. Deleting immediately breaks the quarterly job nobody told you about.
4. Establish the approval gate. Who signs off on an agent, what data it may reach, and what the revocation path is. Most organizations have none of this written down, and the rule keeps firing until they do.

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
