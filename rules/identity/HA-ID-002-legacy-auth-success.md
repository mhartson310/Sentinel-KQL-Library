# HA-ID-002 — Successful Sign-In Using Legacy Authentication

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0006 Credential Access |
| **MITRE Technique** | T1110 — Brute Force / T1078.004 — Valid Accounts |
| **Data source** | Entra ID Sign-in Logs |
| **Required table** | `SigninLogs` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Account (UserPrincipalName), IP (IPAddress) |

---

## What it detects

A **successful** authentication using a legacy protocol that cannot enforce MFA. Legacy auth is the single most reliable MFA bypass still in wide use, and password spray campaigns target it specifically because a correct password is all that is required.

The key word is successful. Failed legacy auth is background noise on the internet. Successful legacy auth means someone has a working credential and a path around your Conditional Access.

---

## KQL

```kql
let LegacyClients = dynamic([
    "Exchange ActiveSync",
    "Exchange Online PowerShell 2.0",
    "Exchange Web Services",
    "IMAP4",
    "MAPI Over HTTP",
    "Offline Address Book",
    "Other clients",
    "POP3",
    "Reporting Web Services",
    "SMTP",
    "Authenticated SMTP",
    "AutoDiscover"
]);
SigninLogs
| where ResultType == 0                       // success only
| where ClientAppUsed in (LegacyClients)
| extend Location = strcat(tostring(LocationDetails.countryOrRegion), " / ", tostring(LocationDetails.city))
| summarize
    SignInCount = count(),
    DistinctIPs = dcount(IPAddress),
    IPs = make_set(IPAddress, 10),
    Locations = make_set(Location, 5),
    Apps = make_set(AppDisplayName, 5),
    Protocols = make_set(ClientAppUsed, 5),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by UserPrincipalName
| order by SignInCount desc
```

**Hunting companion — is legacy auth still possible at all?**

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed in (LegacyClients)
| summarize
    Successes = countif(ResultType == 0),
    Failures = countif(ResultType != 0),
    Users = dcount(UserPrincipalName)
  by ClientAppUsed
| order by Successes desc
```

---

## Tuning notes

**Run the 30-day hunting query first.** If it returns zero successes, you have already blocked legacy auth and this rule is a tripwire rather than an active detection. That is the goal state. Keep the rule enabled anyway — it catches regressions when someone creates an exclusion.

**Identify your real legacy dependencies before blocking.** Most orgs have two or three: a multifunction printer using SMTP, an old line-of-business app, a legacy mail client on a handful of devices. Find them, move them to modern auth or a scoped exception with a service account, then block the rest.

**"Other clients" is the biggest bucket and the least specific.** It covers anything Entra could not classify. If it is noisy, break it out by `AppDisplayName` and `UserAgent` to find what is actually generating it.

**Exclude approved service accounts by object ID, not UPN.** UPNs get renamed. Object IDs do not.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Multifunction printers and scanners using SMTP | Move to a dedicated relay connector, or exclude the specific service account. |
| Legacy LOB application with a hardcoded connector | Document it, scope a CA exclusion to that app + IP, set a remediation date. |
| Older mobile mail clients on personal devices | Not a false positive. This is exactly the exposure. Migrate them. |
| Mailbox migration tooling | Time-boxed exception for the migration window. |

---

## Response guidance

1. Check whether the IP and location match the user's normal pattern. Legacy auth from an unfamiliar country is an incident, not a hygiene finding.
2. Look for failed attempts against other users from the same IP — that pattern is password spray.
3. If the sign-in looks malicious: revoke sessions, reset the credential, check mailbox rules (attackers create forwarding rules immediately after mail access).
4. Regardless of outcome, the finding is that legacy auth succeeded at all. Fix the Conditional Access gap that allowed it.

---

## Related rules

- HA-ID-004 — Conditional Access policy disabled or weakened
- HA-ID-001 — Privileged role assigned outside change window

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
