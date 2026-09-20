# HA-SIG-004 — Dormant Account Suddenly Active

> **"What actually happens to an account after someone leaves? I'd like to believe it's disabled the same day."**

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0001 Initial Access / TA0003 Persistence |
| **MITRE Technique** | T1078.004 — Valid Accounts: Cloud Accounts |
| **Data source** | Entra ID Sign-in Logs |
| **Required table** | `SigninLogs` |
| **Suggested frequency** | Every 4 hours, 4 hour lookback |
| **Entity mapping** | Account (UserPrincipalName), IP (IPAddress) |

---

## What it detects

An account with no sign-in activity for an extended period that suddenly authenticates successfully. Dormant accounts are attractive precisely because nobody is watching them: the owner has left, the manager has moved on, and the credential was never rotated because nobody was using it.

This is also the cheapest detection in the repository to operate. Dormancy is unambiguous, the false-positive rate is low, and the true positives are almost always worth the call.

---

## KQL

```kql
let DormancyPeriod = 60d;   // no successful sign-in for this long
let CheckWindow    = 4h;
// Accounts that have been quiet
let Dormant =
    SigninLogs
    | where TimeGenerated between (ago(DormancyPeriod) .. ago(CheckWindow))
    | where ResultType == 0
    | summarize LastActivity = max(TimeGenerated) by UserPrincipalName
    | where LastActivity < ago(DormancyPeriod - CheckWindow);
// Accounts that just woke up
SigninLogs
| where TimeGenerated > ago(CheckWindow)
| where ResultType == 0
| summarize
    SignIns      = count(),
    IPs          = make_set(IPAddress, 5),
    Apps         = make_set(AppDisplayName, 5),
    Countries    = make_set(tostring(LocationDetails.countryOrRegion), 5),
    Devices      = make_set(tostring(DeviceDetail.displayName), 5),
    ClientApps   = make_set(ClientAppUsed, 5),
    FirstWake    = min(TimeGenerated)
  by UserPrincipalName
| join kind=inner Dormant on UserPrincipalName
| extend DaysDormant = datetime_diff("day", FirstWake, LastActivity)
| extend Risk = case(
    ClientApps has_any ("Other clients", "IMAP4", "POP3", "SMTP"),
      "HIGH — woke up via legacy auth",
    array_length(Countries) > 1,
      "HIGH — multiple countries on first activity",
    "REVIEW — dormant account reactivated")
| project Risk, UserPrincipalName, DaysDormant, LastActivity, FirstWake,
          SignIns, Countries, IPs, Apps, ClientApps, Devices
| order by DaysDormant desc
```

---

## Tuning notes

**`SigninLogs` retention caps your dormancy window.** If you keep 90 days, you cannot detect 120-day dormancy from this table alone. For longer windows, query the data lake or maintain a summary table of last-seen-per-user. That summary rule is three lines and worth building.

**Seasonal staff will fire this every year, correctly.** Interns, contractors on annual engagements, seasonal retail staff. The right handling is a watchlist of expected-seasonal accounts with a documented return window — not a permanent exclusion, because the whole point is that an attacker would look exactly like a returning seasonal employee.

**Sixty days is a starting point.** Thirty catches more and generates more noise from people on extended leave. Ninety is cleaner but gives an attacker a longer runway. Pick from your own leave patterns, not from this document.

**The `HIGH — woke up via legacy auth` case deserves its own rule.** A dormant account reactivating over IMAP is close to a confirmed compromise. If you only implement one branch of this, implement that one.

**Service accounts will pollute this badly.** Exclude them by watchlist, the same one HA-ID-002 uses, or the noise will bury the signal.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Return from parental, medical, or sabbatical leave | The most common FP by far. Cross-reference HR leave data if you can get it. |
| Seasonal and contract staff | Watchlist with an expected return window, reviewed annually. |
| Break-glass and DR accounts | Excluded here, covered properly by HA-ID-003. |
| Rarely-used admin or vendor accounts | Real finding. Rarely-used privileged accounts are exactly the risk. |
| Shared mailboxes and resource accounts | Exclude by account type, not by name pattern. |

---

## Response guidance

1. Check employment status first. This is one of the few detections where the fastest path to an answer is HR, not telemetry.
2. If the person left: this is a confirmed compromise or a failed offboarding. Both require action today.
3. If the person is active: verify the sign-in context matches them — usual device, usual country, usual client. A returning employee signs in from their laptop, not from a residential IP in another country over IMAP.
4. Look at what happened after the sign-in. Mailbox rules, file access, and privilege changes in the following hour tell you the intent.
5. The underlying finding is usually the offboarding process. One dormant account reactivating means there are others; run the companion query across the tenant and fix the process rather than the account.

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
