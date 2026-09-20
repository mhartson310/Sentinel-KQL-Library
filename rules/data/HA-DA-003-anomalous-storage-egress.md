# HA-DA-003 — Anomalous Egress Volume from Storage

| Field | Value |
|---|---|
| **Severity** | Medium |
| **MITRE Tactic** | TA0010 Exfiltration |
| **MITRE Technique** | T1530 — Data from Cloud Storage |
| **Data source** | Storage diagnostics |
| **Required table** | `StorageBlobLogs` |
| **Suggested frequency** | Every 4 hours, 4 hour lookback |
| **Entity mapping** | Account (caller identity), IP (caller IP) |

---

## What it detects

A caller reading substantially more data out of a storage account than that caller normally does. Staged exfiltration from cloud storage looks like ordinary read activity — the only distinguishing feature is volume against a baseline.

Medium severity because volume alone is ambiguous. It becomes High when combined with an unfamiliar IP, an anonymous auth type, or a recently granted identity.

---

## KQL

```kql
let LookbackWindow = 4h;
let BaselineWindow = 14d;
let MinimumBytes = 1073741824;   // 1 GB floor
let DeviationFactor = 3.0;
let Baseline =
    StorageBlobLogs
    | where TimeGenerated between (ago(BaselineWindow) .. ago(LookbackWindow))
    | where OperationName in ("GetBlob", "GetBlobProperties", "ListBlobs")
    | where StatusText has "Success" or StatusCode == 200
    | extend Identity = coalesce(
        tostring(AuthenticationHash),
        tostring(RequesterObjectId),
        tostring(CallerIpAddress)
      )
    | summarize WindowBytes = sum(ResponseBodySize)
        by Identity, AccountName, bin(TimeGenerated, LookbackWindow)
    | summarize
        AvgBytes = avg(WindowBytes),
        StdevBytes = stdev(WindowBytes)
      by Identity, AccountName;
StorageBlobLogs
| where TimeGenerated > ago(LookbackWindow)
| where OperationName in ("GetBlob", "GetBlobProperties", "ListBlobs")
| where StatusText has "Success" or StatusCode == 200
| extend Identity = coalesce(
    tostring(AuthenticationHash),
    tostring(RequesterObjectId),
    tostring(CallerIpAddress)
  )
| summarize
    TotalBytes = sum(ResponseBodySize),
    Operations = count(),
    DistinctBlobs = dcount(Uri),
    AuthTypes = make_set(AuthenticationType, 5),
    CallerIPs = make_set(CallerIpAddress, 10),
    UserAgents = make_set(UserAgentHeader, 3)
  by Identity, AccountName
| where TotalBytes >= MinimumBytes
| join kind=leftouter Baseline on Identity, AccountName
| extend Threshold = AvgBytes + (DeviationFactor * StdevBytes)
| where isnull(Threshold) or TotalBytes > Threshold
| extend
    TotalGB = round(TotalBytes / 1073741824.0, 2),
    BaselineGB = round(AvgBytes / 1073741824.0, 2),
    DeviationRatio = round(TotalBytes / iff(AvgBytes > 0, AvgBytes, 1.0), 1),
    AnonymousAccess = AuthTypes has "Anonymous"
| project
    AccountName,
    Identity,
    TotalGB,
    BaselineGB,
    DeviationRatio,
    Operations,
    DistinctBlobs,
    AnonymousAccess,
    AuthTypes,
    CallerIPs,
    UserAgents
| order by DeviationRatio desc
```

---

## Tuning notes

**This query is expensive.** It reads 14 days of `StorageBlobLogs`, which is one of the highest-volume tables in Azure. On a large estate, run it every 4 hours rather than hourly, or precompute the baseline into a summary table with a summary rule. The full pack includes that pattern.

**Storage diagnostic logging is off by default and costs money.** Enable it on accounts holding sensitive data, not on everything. Deciding *which* accounts is a data classification exercise, and most organizations have not done it — that gap is usually the more important finding.

**Identity resolution is imperfect.** `AuthenticationHash` is stable per credential but opaque. `RequesterObjectId` is populated for Entra-authenticated calls only. SAS token access resolves to neither, which is why the fallback is caller IP. Know which of these your workloads use before trusting the grouping.

**Set `MinimumBytes` to your reality.** 1 GB is a reasonable floor for most. For accounts holding small files with high request counts, weight on `DistinctBlobs` instead of bytes.

**Anonymous access in `AuthTypes` should escalate severity automatically.** If this rule fires with `AnonymousAccess == true`, you have both an exposure (HA-DA-002) and active reads against it. That is an incident, not a review item.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Backup and archival jobs | Exclude by identity once verified. These dominate egress on most accounts. |
| Analytics pipelines reading source data | Baseline handles steady-state; new pipelines will fire once. Expected. |
| Data migration projects | Time-boxed exception with an owner. |
| CDN origin pulls | Exclude the CDN identity. Very high volume, entirely expected. |
| Month-end or quarter-end reporting | Seasonal. Do not permanently raise thresholds for a periodic event. |

---

## Response guidance

1. Check `AnonymousAccess` first. Anonymous plus high volume is an active data breach in progress.
2. Compare `CallerIPs` against known infrastructure ranges. Unfamiliar egress destinations change the assessment immediately.
3. Look at `DeviationRatio`, not raw volume. 50 GB from a pipeline that averages 45 GB is nothing; 3 GB from an identity that averages 10 MB is everything.
4. Identify the data. Blob paths in the logs tell you what container was read.
5. If exfiltration is confirmed: revoke the identity's access, rotate any SAS tokens on the account, and preserve the logs before retention expires.

---

## Related rules

- HA-DA-002 — Storage account anonymous access enabled
- HA-DA-001 — Mass download from SharePoint or OneDrive

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
