# HA-EP-003 — Suspicious LOLBin Network Activity

| Field | Value |
|---|---|
| **Severity** | Medium |
| **MITRE Tactic** | TA0011 Command and Control |
| **MITRE Technique** | T1105 — Ingress Tool Transfer / T1218 — System Binary Proxy Execution |
| **Data source** | Defender XDR device telemetry |
| **Required tables** | `DeviceNetworkEvents`, `DeviceProcessEvents` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Host (DeviceName), Account, IP (RemoteIP) |

---

## What it detects

Signed Microsoft binaries making outbound network connections they have no business making. Living-off-the-land binaries — certutil, bitsadmin, mshta, regsvr32 and friends — are attractive to attackers precisely because they are signed, present by default, and often allowlisted.

`certutil.exe` exists to manage certificates. When it connects to a random IP on port 443 and writes a file, it is being used as a downloader.

---

## KQL

```kql
let LolBins = dynamic([
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "msbuild.exe", "cmstp.exe", "odbcconf.exe",
    "curl.exe", "wmic.exe", "cscript.exe", "wscript.exe", "hh.exe"
]);
let PrivateRanges = dynamic(["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (LolBins)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt", "ConnectionRequest")
| where isnotempty(RemoteIP)
| where not(ipv4_is_in_any_range(RemoteIP, PrivateRanges))
| extend
    Binary = InitiatingProcessFileName,
    CmdLine = InitiatingProcessCommandLine,
    ParentProcess = InitiatingProcessParentFileName
| extend DownloadIndicators = CmdLine has_any (
    "-urlcache", "-split", "-f http", "/transfer", "http://", "https://",
    "-decode", "-encode", "DownloadFile", "javascript:", "scrobj.dll"
  )
| summarize
    Connections = count(),
    RemoteIPs = make_set(RemoteIP, 10),
    RemoteUrls = make_set(RemoteUrl, 10),
    Ports = make_set(RemotePort, 5),
    CmdLines = make_set(CmdLine, 5),
    Parents = make_set(ParentProcess, 5),
    AnyDownloadIndicator = max(toint(DownloadIndicators)),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DeviceName, Binary, InitiatingProcessAccountUpn
| extend Confidence = case(
    AnyDownloadIndicator == 1, "High - download syntax present",
    Binary in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe"), "Medium - binary rarely needs internet",
    "Low - review context"
  )
| project
    DeviceName,
    Binary,
    Confidence,
    InitiatingProcessAccountUpn,
    Connections,
    RemoteIPs,
    RemoteUrls,
    Ports,
    CmdLines,
    Parents,
    FirstSeen,
    LastSeen
| order by Confidence asc, Connections desc
```

---

## Tuning notes

**`msiexec.exe` and `curl.exe` will generate the most noise.** Both have entirely legitimate reasons to reach the internet on a modern Windows machine. Consider splitting them into a separate, lower-priority rule, or removing them until the rest is tuned.

**The `Confidence` field is there so you can route, not just alert.** High-confidence hits page someone. Low-confidence hits go to a daily hunting queue. A rule that treats all of these the same will be disabled within a month.

**Parent process is the strongest context you have.** `certutil.exe` launched by `cmd.exe` launched by `winword.exe` is a phishing chain. The same binary launched by an SCCM task is a patch. The query surfaces parents specifically for this.

**Private range exclusion matters.** Many of these binaries talk to internal infrastructure constantly — WSUS, SCCM distribution points, internal certificate authorities. Excluding RFC1918 removes most of the volume. Add your own internal public ranges if you have them.

**This rule ages.** New LOLBins are published regularly. Review the binary list against the LOLBAS project quarterly and add what is relevant to your environment.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| `msiexec.exe` downloading installers | Extremely common. Split into its own rule or exclude by known vendor URLs. |
| `curl.exe` in developer workflows | Scope out developer machines, or accept and route to low priority. |
| `certutil.exe` doing actual certificate work | Check the command line — real cert operations do not use `-urlcache`. |
| SCCM and patch management using BITS | Exclude by parent process. |
| Enterprise software auto-update | Exclude by signer and destination. |

---

## Response guidance

1. Read the command line first. Download syntax settles most cases in seconds.
2. Check the parent process chain. Office application in the chain means phishing until proven otherwise.
3. Check the destination — reputation, age of domain, whether other hosts contacted it.
4. Look for what was written to disk afterward: `DeviceFileEvents` on that device around the same time.
5. If confirmed malicious, hunt the destination across the whole fleet before remediating the single host. One beacon is rarely alone.

---

## Related rules

- HA-EP-002 — Encoded PowerShell command execution
- HA-EP-001 — Tamper protection or real-time protection disabled

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
