# Getting started

## Prerequisites

Before any of these rules return results, the underlying data has to be flowing. Check each:

```kql
// Entra ID sign-in and audit logs
union isfuzzy=true SigninLogs, AuditLogs
| summarize Latest = max(TimeGenerated) by Type

// Azure Activity — per subscription
AzureActivity
| summarize Latest = max(TimeGenerated), Events = count() by SubscriptionId
| order by Latest desc

// Microsoft 365
OfficeActivity
| summarize Latest = max(TimeGenerated) by OfficeWorkload

// Defender XDR device tables
union isfuzzy=true DeviceProcessEvents, DeviceNetworkEvents
| summarize Latest = max(TimeGenerated) by Type
```

If a table returns nothing, the connector isn't on — fix that before debugging KQL.

## The deployment path

Do not paste these straight into an analytics rule. The order that works:

1. **Run as a hunting query.** 30 days back. Look at what comes out.
2. **Tune the exclusions.** Every rule has a tuning notes section. Use it.
3. **Re-run.** Repeat until the results are things you would actually want to see at 3am.
4. **Promote to an analytics rule.** Set frequency and lookback per the metadata block.
5. **Watch it for two weeks.** Track the FP rate. Tune again.

Skipping step 1 is how teams end up disabling rules instead of tuning them.

## A note on cost

Some of these queries scan large tables. Baselining queries especially — HA-DA-001 reads 14 days of `OfficeActivity` on every run.

If you're on a tight ingestion budget:
- Widen the frequency (every 4 hours instead of hourly)
- Shorten the baseline window
- Consider computing baselines on a schedule into a summary table rather than inline

The full pack includes summary-rule templates that do this properly.
