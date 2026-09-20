# HA-ID-003 — Break-Glass Account Activity

| Field | Value |
|---|---|
| **Severity** | Critical |
| **MITRE Tactic** | TA0004 Privilege Escalation |
| **MITRE Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Data source** | Entra ID Sign-in and Audit Logs |
| **Required tables** | `SigninLogs`, `AuditLogs` |
| **Suggested frequency** | Every 5 minutes, 5 minute lookback |
| **Entity mapping** | Account (UserPrincipalName), IP (IPAddress) |

---

## What it detects

Any activity by an emergency access account. These accounts exist to be used roughly never — a tenant-wide Conditional Access lockout, a federation outage, a lost Global Admin. Any sign-in is either a genuine emergency or a serious compromise, and both need someone woken up.

This is the highest signal-to-noise rule in the pack. If tuned correctly it fires a handful of times a year.

---

## KQL

```kql
// Populate a watchlist named "BreakGlassAccounts" with a UPN column.
// Hardcoding works too, but a watchlist can be owned and reviewed.
let BreakGlass = _GetWatchlist("BreakGlassAccounts") | project UPN = tolower(tostring(UPN));
let SignIns =
    SigninLogs
    | extend UPN = tolower(UserPrincipalName)
    | where UPN in (BreakGlass)
    | extend
        Activity = "Sign-in",
        Detail = strcat(AppDisplayName, " / ", ClientAppUsed),
        Outcome = iff(ResultType == 0, "Success", strcat("Failure (", tostring(ResultType), ")")),
        Location = strcat(tostring(LocationDetails.countryOrRegion), " / ", tostring(LocationDetails.city))
    | project TimeGenerated, UPN, Activity, Detail, Outcome, IPAddress, Location;
let Audits =
    AuditLogs
    | extend UPN = tolower(tostring(InitiatedBy.user.userPrincipalName))
    | where UPN in (BreakGlass)
    | extend
        Activity = "Directory change",
        Detail = OperationName,
        Outcome = tostring(Result),
        IPAddress = tostring(InitiatedBy.user.ipAddress),
        Location = ""
    | project TimeGenerated, UPN, Activity, Detail, Outcome, IPAddress, Location;
union SignIns, Audits
| order by TimeGenerated asc
```

**No watchlist yet? Hardcoded fallback:**

```kql
let BreakGlass = dynamic(["emergency01@yourtenant.onmicrosoft.com", "emergency02@yourtenant.onmicrosoft.com"]);
```

---

## Tuning notes

**Do not tune this rule down.** If it is noisy, the problem is that your break-glass accounts are being used for something they should not be. Fix that instead.

**Alert on failures too.** A failed break-glass sign-in means someone is attempting them, and those UPNs are usually guessable. The query above captures both deliberately.

**Route this outside Sentinel as well.** If the emergency is a tenant-wide outage, your SOC may not be able to reach the portal. Send this to a channel that does not depend on the identity provider being healthy — SMS, PagerDuty, a phone tree.

**Scheduled validation is expected activity.** Microsoft's guidance is to test break-glass accounts periodically. Those tests will fire this rule. That is correct behavior — verify against the test schedule rather than suppressing.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Quarterly break-glass validation test | Expected. Verify against the test calendar. Do not suppress. |
| Credential rotation | Expected. Same treatment. |
| Licence assignment or attribute sync touching the account | Filter specific benign `OperationName` values only if they recur. |

---

## Response guidance

1. Treat as an incident until proven otherwise. Call the on-call identity owner directly.
2. Confirm against the emergency: is there an active outage or incident that would justify use?
3. If unexplained: revoke sessions immediately, rotate the credential, and audit every directory change made in the session.
4. After any legitimate use, rotate the credential as standard practice and re-store it.

---

## Related rules

- HA-ID-001 — Privileged role assigned outside change window
- HA-ID-004 — Conditional Access policy disabled or weakened

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
