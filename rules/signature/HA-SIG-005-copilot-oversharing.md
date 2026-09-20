# HA-SIG-005 — Sensitive Content Surfaced Through Copilot

> **"Copilot didn't give anyone new permissions. So why does it feel like everyone can suddenly see everything?"**

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0009 Collection |
| **MITRE Technique** | T1213 — Data from Information Repositories |
| **Data source** | Microsoft 365 Copilot audit, SharePoint / OneDrive activity |
| **Required tables** | `OfficeActivity`, Copilot audit events |
| **Suggested frequency** | Daily, 24 hour lookback |
| **Entity mapping** | Account (UserId), File (resource) |

---

## What it detects

Users reaching content through Copilot that they had technical access to but would never have found on their own. Copilot grants no new permissions — that part is true and it is the answer every vendor gives. It also removes the practical obscurity that was doing most of the access-control work in your tenant.

A file nobody could find was effectively protected. A file Copilot will summarize on request is not.

---

## KQL

```kql
// Copilot audit schema is still settling. Confirm what you have first:
//   OfficeActivity | where Operation has "Copilot" | distinct Operation
//   search "Copilot" | distinct $table
let LookbackWindow = 24h;
let BaselineWindow = 30d;
let SensitiveHints = dynamic([
    "salary", "compensation", "severance", "acquisition", "merger",
    "layoff", "restructur", "board", "confidential", "legal hold",
    "investigation", "termination", "offer letter", "performance review"
]);
// Baseline: which sites does each user normally touch?
let UserBaseline =
    OfficeActivity
    | where TimeGenerated between (ago(BaselineWindow) .. ago(LookbackWindow))
    | where OfficeWorkload in ("SharePoint", "OneDrive")
    | summarize KnownSites = make_set(Site_Url, 200) by UserId;
OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation has_any ("FileAccessed", "FilePreviewed", "FileDownloaded")
// Copilot-mediated access is flagged in the app or user-agent context —
// adjust this predicate to match your tenant's audit schema.
| where UserAgent has "Copilot" or ClientAppName has "Copilot"
       or AppAccessContext has "Copilot"
| extend FileName = tolower(tostring(SourceFileName))
| summarize
    FilesTouched   = dcount(OfficeObjectId),
    SitesTouched   = dcount(Site_Url),
    Sites          = make_set(Site_Url, 20),
    SensitiveHits  = countif(FileName has_any (SensitiveHints)),
    SensitiveFiles = make_set_if(SourceFileName, FileName has_any (SensitiveHints), 10)
  by UserId
| join kind=leftouter UserBaseline on UserId
| extend NewSites = set_difference(Sites, coalesce(KnownSites, dynamic([])))
| extend NewSiteCount = array_length(NewSites)
| where NewSiteCount > 0 or SensitiveHits > 0
| extend Finding = case(
    SensitiveHits > 0 and NewSiteCount > 0,
      "HIGH — sensitive filenames on sites this user has never visited",
    SensitiveHits > 0,
      "REVIEW — sensitive filenames surfaced via Copilot",
    NewSiteCount >= 5,
      "REVIEW — Copilot surfaced content from many unfamiliar sites",
    "Low")
| where Finding != "Low"
| project Finding, UserId, FilesTouched, SitesTouched, NewSiteCount,
          NewSites, SensitiveHits, SensitiveFiles
| order by SensitiveHits desc, NewSiteCount desc
```

---

## Tuning notes

**Confirm your audit schema before anything else.** Copilot audit events are newer than most of this repository and the field names are still moving. Run the two discovery queries in the comment header and adjust the Copilot predicate to match what your tenant actually emits. If it returns nothing, that is a schema problem, not an absence of risk.

**`SensitiveHints` is a filename heuristic, and a crude one.** It is a stopgap for tenants without a mature labeling program. If you have sensitivity labels deployed, replace the keyword list with the label — it is dramatically more accurate and it is the correct long-term answer. If you do not have labels, this rule firing is your business case for getting them.

**This rule finds permission problems, not Copilot problems.** Every hit represents content the user could already access. Resist the framing that Copilot caused it; the oversharing predates the deployment. The remediation is site permissions and labeling, not turning Copilot off.

**Expect a large first run.** The first execution against 30 days will surface years of accumulated permission sprawl. Work it as a project, not as an alert queue. Rank by sensitivity, fix the top twenty sites, then re-run.

**Baseline drift is real.** People legitimately join new projects and start touching new sites. Recompute the baseline on a schedule rather than letting it calcify.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Genuine project onboarding — new team, new sites | The dominant FP. Cross-reference group membership changes in the same window. |
| Filename keyword collisions ("board meeting agenda") | Refine the keyword list, or switch to sensitivity labels. |
| Executives and legal, who legitimately range widely | Baselining handles them — their normal set is already broad. |
| Migration and archive tooling using a service account | Exclude by UPN once verified. |
| Open-by-design intranet content | Exclude those sites explicitly. If "open by design" isn't documented, that's the finding. |

---

## Response guidance

1. Check the permission, not the prompt. Could this user have opened the file directly? Almost always yes — which makes it an access-control finding.
2. Look at the site, not just the file. One overshared file usually means an overshared site, and the site is the unit of remediation.
3. If the content is genuinely sensitive: restrict the site, apply a label, and check whether it was accessed before Copilot ever surfaced it.
4. Feed the pattern back into your labeling program. Every hit here is a file that should have been labeled and wasn't.
5. Track the count over time. A number that falls quarter over quarter means the labeling program is working. A flat number means it isn't.

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
