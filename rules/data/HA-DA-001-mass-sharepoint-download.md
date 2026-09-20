# HA-DA-001 — Mass Download from SharePoint or OneDrive

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0010 Exfiltration |
| **MITRE Technique** | T1567.002 — Exfiltration to Cloud Storage |
| **Data source** | Microsoft 365 / Office Activity |
| **Required table** | `OfficeActivity` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Account (UserId), IP (ClientIP) |

---

## What it detects

A user downloading files from SharePoint or OneDrive at a volume well above their own normal. Catches two very different things with the same query: a compromised account being emptied, and a departing employee taking the customer list.

The second one is more common and gets less attention than it should. In regulated industries it is also the one that generates the lawsuit.

---

## KQL

```kql
// Behavioral: compares each user against their own 14-day baseline.
let LookbackWindow = 1h;
let BaselineWindow = 14d;
let MinimumFiles = 50;          // floor — ignores low-volume noise
let DeviationFactor = 3.0;      // multiples of the user's own stdev
let Baseline =
    OfficeActivity
    | where TimeGenerated between (ago(BaselineWindow) .. ago(LookbackWindow))
    | where OfficeWorkload in ("SharePoint", "OneDrive")
    | where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
    | summarize HourlyCount = count() by UserId, bin(TimeGenerated, 1h)
    | summarize
        AvgPerHour = avg(HourlyCount),
        StdevPerHour = stdev(HourlyCount)
      by UserId;
OfficeActivity
| where TimeGenerated > ago(LookbackWindow)
| where OfficeWorkload in ("SharePoint", "OneDrive")
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize
    FileCount = count(),
    DistinctFiles = dcount(OfficeObjectId),
    DistinctSites = dcount(Site_Url),
    SampleFiles = make_set(SourceFileName, 10),
    ClientIPs = make_set(ClientIP, 5),
    UserAgents = make_set(UserAgent, 3)
  by UserId
| where FileCount >= MinimumFiles
| join kind=leftouter Baseline on UserId
| extend Threshold = AvgPerHour + (DeviationFactor * StdevPerHour)
| where isnull(Threshold) or FileCount > Threshold
| extend DeviationRatio = round(FileCount / iff(AvgPerHour > 0, AvgPerHour, 1.0), 1)
| project
    UserId,
    FileCount,
    DistinctFiles,
    DistinctSites,
    AvgPerHour = round(AvgPerHour, 1),
    DeviationRatio,
    ClientIPs,
    UserAgents,
    SampleFiles
| order by DeviationRatio desc
```

---

## Tuning notes

**Static thresholds do not work here and that is why most versions of this rule fail.** A finance analyst downloading 200 files on close day is normal. A salesperson downloading 200 files has never happened before. Baselining per user is the only approach that survives contact with a real tenant. That is what the join is doing.

**Set `MinimumFiles` to your environment, not mine.** 50 is a reasonable floor for a mid-size org. In a small tenant, 20. In a large one with heavy OneDrive sync, 200 or you will drown.

**`FileSyncDownloadedFull` is the loud one.** It fires whenever someone sets up a new machine and syncs their OneDrive. If you keep it, expect onboarding noise every Monday. Many teams drop it and accept the coverage gap. Decide deliberately, and write the decision down.

**Layer on context that raises severity.** The rule as written is volume-only. These make it much sharper:

```kql
// Add after the summarize — flags downloads from an unfamiliar IP
| extend IsNewIP = ClientIPs !has_any (KnownCorporateRanges)

// Or correlate with departure — requires an HR watchlist
| lookup kind=leftouter _GetWatchlist("Leavers") on $left.UserId == $right.UPN
| extend DepartingEmployee = isnotempty(TerminationDate)
```

Volume plus a leaver flag plus an unfamiliar IP is an incident. Volume alone is a question.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| New laptop, first OneDrive sync | Drop `FileSyncDownloadedFull`, or exclude users whose device enrolled in the last 7 days. |
| Migration and archive projects | Time-boxed exception with an owner and an expiry date. |
| Executive assistants and legal | Legitimately high-volume roles. Baselining handles them automatically — this is why per-user beats static. |
| Automated backup or DLP scanning tools | Exclude the service account by UPN. Verify it is actually your tool first. |
| Quarter-end and audit periods | Expect a seasonal spike. Do not permanently widen thresholds for a two-week event. |

---

## Response guidance

1. Check the deviation ratio, not the raw count. 200 files from someone who averages 180 is nothing. 60 from someone who averages 2 is everything.
2. Look at the file names in `SampleFiles`. Sensitive-looking content changes the response immediately.
3. Check the IP and user agent against the user's normal pattern. Corporate network and a known browser is very different from a residential IP and a sync client at 11pm.
4. Check employment status before contacting the user. If they are leaving, this becomes an HR and legal matter, and the conversation is very different.
5. If the account looks compromised, revoke sessions first, then investigate. Do not tip off an active intruder by starting with a phone call to the user.

---

## Related rules

- HA-DA-002 — Storage account anonymous access enabled
- HA-DA-003 — Anomalous egress volume from storage
- HA-ID-002 — Successful sign-in using legacy authentication

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
