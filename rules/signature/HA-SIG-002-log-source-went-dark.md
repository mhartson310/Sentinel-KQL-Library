# HA-SIG-002 — Log Source Stopped Reporting

> **"If our firewall stopped sending logs on a Friday night, how long until anyone noticed?"**

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0005 Defense Evasion |
| **MITRE Technique** | T1562.008 — Impair Defenses: Disable or Modify Cloud Logs |
| **Data source** | Any — this rule watches every table |
| **Required table** | `Usage` (plus the tables you care about) |
| **Suggested frequency** | Every 4 hours, 4 hour lookback |
| **Entity mapping** | None — this is an infrastructure alert |

---

## What it detects

The absence of data. Every other rule in this repository fires when something happens. This one fires when something *stops* happening, which is the failure mode almost nobody monitors and the one an attacker creates deliberately.

A detection built on a table that stopped receiving data does not fail loudly. It simply never fires again, and your MITRE coverage map keeps showing green.

---

## KQL

```kql
// Compares each table's recent volume against its own 14-day baseline.
let BaselineWindow  = 14d;
let CheckWindow     = 4h;
let DropThreshold   = 0.4;   // fire if volume is below 40% of expected
let MinBaselineGB   = 0.01;  // ignore trivially small tables
let Baseline =
    Usage
    | where TimeGenerated between (ago(BaselineWindow) .. ago(CheckWindow))
    | where IsBillable == true
    | summarize WindowGB = sum(Quantity) / 1024
        by DataType, bin(TimeGenerated, CheckWindow)
    | summarize ExpectedGB = avg(WindowGB), StdevGB = stdev(WindowGB)
        by DataType
    | where ExpectedGB > MinBaselineGB;
let Current =
    Usage
    | where TimeGenerated > ago(CheckWindow)
    | where IsBillable == true
    | summarize ActualGB = sum(Quantity) / 1024 by DataType;
Baseline
| join kind=leftouter Current on DataType
| extend ActualGB = coalesce(ActualGB, 0.0)
| extend Ratio = round(ActualGB / ExpectedGB, 2)
| where Ratio < DropThreshold
| extend Finding = case(
    ActualGB == 0, "SILENT — no data at all in this window",
    Ratio < 0.1,   "SEVERE DROP — under 10% of expected",
    "PARTIAL DROP — investigate collector health")
| project Finding, DataType,
          ExpectedGB = round(ExpectedGB, 3),
          ActualGB   = round(ActualGB, 3),
          Ratio
| order by Ratio asc
```

**Companion — when did each table last report anything at all?**

```kql
Usage
| where TimeGenerated > ago(7d) and IsBillable == true
| summarize LastSeen = max(TimeGenerated), TotalGB = round(sum(Quantity)/1024, 2)
  by DataType
| extend HoursSilent = round(datetime_diff("minute", now(), LastSeen) / 60.0, 1)
| where HoursSilent > 6
| order by HoursSilent desc
```

---

## Tuning notes

**Run the companion query first and read it honestly.** Most teams discover at least one table that stopped reporting weeks ago and nobody noticed. That discovery is worth more than the rule.

**Business-hours tables will false-positive overnight.** Anything driven by human activity — SharePoint, sign-ins in a single-region org — drops legitimately at 2am. Either scope this rule to tables with steady machine-generated volume, or compare against the same 4-hour window from the previous week rather than a flat average.

**`DropThreshold = 0.4` is deliberately loose.** Tighten it to 0.6 for tables where you want early warning; loosen to 0.2 for noisy ones. Tune per table if you can — a single global threshold is a compromise, not an answer.

**Maintain a critical-source list.** Not every table matters equally. A dozen tables feeding zero detections going quiet is a cost saving. Your firewall, your identity logs, and your EDR going quiet is an incident. Watchlist the ones that matter and alert on those at a higher severity.

**This rule should page someone.** Not a daily digest. A source going dark at 6pm Friday and being noticed Monday morning is a 62-hour blind spot.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Overnight and weekend drops on human-driven tables | Compare to the same window last week, not to a flat average. |
| Holiday periods | Expect a week of noise. Do not permanently widen thresholds for it. |
| Intentional DCR filter change reducing volume | Real change, correct alert. Update the baseline after the change lands. |
| Agent upgrade or maintenance window | Suppress for the window, with an expiry date. |
| Newly onboarded table with a thin baseline | Exclude tables with fewer than 14 days of history. |

---

## Response guidance

1. Determine whether it's collection or generation. Is the source still producing logs and failing to ship them, or did the source itself stop?
2. Check the collector: AMA health, the DCR association, the syslog VM, the connector status.
3. Ask what detections depend on that table. Those are dark right now, and that is the actual impact — write it down.
4. If nothing changed on your side and the source is healthy, treat it as potential defense evasion and check who touched the DCR or the diagnostic settings.
5. After restoration, hunt the gap. You lost visibility for a period; assume it was used.

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
