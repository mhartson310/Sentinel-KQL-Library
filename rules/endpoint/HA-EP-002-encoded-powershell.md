# HA-EP-002 — Encoded PowerShell Command Execution

| Field | Value |
|---|---|
| **Severity** | Medium |
| **MITRE Tactic** | TA0002 Execution |
| **MITRE Technique** | T1059.001 — Command and Scripting Interpreter: PowerShell |
| **Data source** | Defender XDR device telemetry |
| **Required table** | `DeviceProcessEvents` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Host (DeviceName), Account (AccountUpn), Process |

---

## What it detects

PowerShell executed with base64-encoded commands, or with the combination of flags that characterizes automated malicious use — hidden window, bypassed execution policy, no profile, no interaction. Encoding is not inherently malicious, but the *combination* of encoding with evasion flags is a strong indicator.

Medium severity by design. This rule is a lead generator for hunting, not a page-the-SOC alert. The value is in the decoded command, which the query surfaces automatically.

---

## KQL

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any ("-enc", "-e ", "-ec", "-encodedcommand", "/enc")
| extend
    HasHidden = ProcessCommandLine has_any ("-w hidden", "-windowstyle hidden", "-w h"),
    HasBypass = ProcessCommandLine has_any ("-ep bypass", "-executionpolicy bypass", "-exec bypass"),
    HasNoProfile = ProcessCommandLine has_any ("-nop", "-noprofile"),
    HasNonInteractive = ProcessCommandLine has_any ("-noni", "-noninteractive")
| extend EvasionScore = toint(HasHidden) + toint(HasBypass) + toint(HasNoProfile) + toint(HasNonInteractive)
// Extract and decode the base64 payload
| extend B64 = extract(@"(?i)(?:-enc|-e|-ec|-encodedcommand)\s+([A-Za-z0-9+/=]{20,})", 1, ProcessCommandLine)
| extend DecodedRaw = base64_decode_tostring(B64)
| extend Decoded = replace_string(DecodedRaw, "\u0000", "")   // strip UTF-16 nulls
| extend SuspiciousContent = Decoded has_any (
    "DownloadString", "DownloadFile", "Invoke-Expression", "IEX",
    "Net.WebClient", "Invoke-WebRequest", "Start-BitsTransfer",
    "FromBase64String", "Reflection.Assembly", "VirtualAlloc",
    "Add-MpPreference", "New-Object Net.Sockets",
    "bitsadmin", "certutil"
  )
| where EvasionScore >= 2 or SuspiciousContent
| project
    TimeGenerated,
    DeviceName,
    AccountUpn,
    EvasionScore,
    SuspiciousContent,
    Decoded,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ReportId
| order by SuspiciousContent desc, EvasionScore desc, TimeGenerated desc
```

---

## Tuning notes

**The decode is the whole value of this rule.** Analysts triaging encoded PowerShell without decoding it are guessing. `base64_decode_tostring` plus stripping UTF-16 nulls gets you readable text in most cases. Multi-layer encoding will not decode fully — that is itself a signal worth escalating.

**`EvasionScore >= 2` is the tuning dial.** Raise it to 3 if you are drowning. Lower it to 1 only if your environment has very little legitimate PowerShell automation, which is rare. Start at 2 and measure.

**Your own tooling will fire this constantly.** SCCM, Intune, monitoring agents, and most software deployment systems run encoded PowerShell with exactly these flags. Baseline for two weeks, then exclude by `InitiatingProcessFileName` — the parent process is a far more stable identifier than the command line.

**Do not exclude by command-line substring.** Attackers read your exclusions if they get far enough, and command lines are trivially varied. Parent process plus signer is the durable exclusion.

**Consider the inverse rule.** In a locked-down environment, *any* interactive PowerShell on a workstation outside IT is worth alerting on. That is a different rule with much better fidelity if your environment supports it.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| SCCM / Intune / configuration management | Exclude by parent process. Dominant source in most enterprises. |
| Monitoring and backup agents | Same treatment. |
| Developer and admin automation | Common on IT workstations. Consider scoping the rule to exclude the IT OU, or accept the noise there. |
| Legitimate vendor installers | Exclude by signer where possible. |

---

## Response guidance

1. Read the decoded command. It usually answers the question immediately.
2. If it contains a download, extract the URL and check whether the fetch succeeded — `DeviceNetworkEvents` for that device and time.
3. Check the parent process. `winword.exe` or `excel.exe` spawning encoded PowerShell is a phishing payload and an incident.
4. If malicious: isolate, collect the artifacts, and hunt for the same command line across the fleet. Encoded commands are usually reused verbatim across targets.

---

## Related rules

- HA-EP-001 — Tamper protection or real-time protection disabled
- HA-EP-003 — Suspicious LOLBin network activity

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
