# HA-EP-001 — Tamper Protection or Real-Time Protection Disabled

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0005 Defense Evasion |
| **MITRE Technique** | T1562.001 — Impair Defenses: Disable or Modify Tools |
| **Data source** | Defender XDR device telemetry |
| **Required tables** | `DeviceEvents`, `DeviceRegistryEvents`, `DeviceProcessEvents` |
| **Suggested frequency** | Every 15 minutes, 15 minute lookback |
| **Entity mapping** | Host (DeviceName), Account (InitiatingProcessAccountUpn) |

---

## What it detects

Someone turning off Microsoft Defender protections on an endpoint — through the registry, through PowerShell cmdlets, or via `MpCmdRun` exclusion manipulation. Disabling AV is a standard precursor step: it happens before the payload, not after, which makes it one of the few chances to intervene early.

The three detection paths are unioned because attackers use whichever one is not being monitored.

---

## KQL

```kql
let DefenderRegistryKeys = dynamic([
    "DisableAntiSpyware",
    "DisableRealtimeMonitoring",
    "DisableBehaviorMonitoring",
    "DisableIOAVProtection",
    "DisableOnAccessProtection",
    "DisableScanOnRealtimeEnable",
    "TamperProtection"
]);
let RegistryPath =
    DeviceRegistryEvents
    | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
    | where RegistryKey has_any (@"\Windows Defender", @"\Microsoft\Windows Defender")
    | where RegistryValueName has_any (DefenderRegistryKeys)
    | where RegistryValueData in ("1", "0x1", "0")   // disable flags vary by key
    | extend
        Method = "Registry modification",
        Detail = strcat(RegistryValueName, " = ", RegistryValueData),
        Actor = InitiatingProcessAccountUpn,
        Process = InitiatingProcessFileName,
        CmdLine = InitiatingProcessCommandLine
    | project TimeGenerated, DeviceName, Method, Detail, Actor, Process, CmdLine, ReportId;
let PowerShellPath =
    DeviceProcessEvents
    | where ProcessCommandLine has_any (
        "Set-MpPreference",
        "Add-MpPreference",
        "MpCmdRun",
        "Uninstall-WindowsFeature Windows-Defender"
      )
    | where ProcessCommandLine has_any (
        "DisableRealtimeMonitoring $true",
        "DisableRealtimeMonitoring 1",
        "DisableBehaviorMonitoring",
        "DisableIOAVProtection",
        "DisableScriptScanning",
        "ExclusionPath",
        "ExclusionProcess",
        "ExclusionExtension",
        "-RemoveDefinitions",
        "DisableArchiveScanning"
      )
    | extend
        Method = "PowerShell / MpCmdRun",
        Detail = ProcessCommandLine,
        Actor = AccountUpn,
        Process = FileName,
        CmdLine = ProcessCommandLine
    | project TimeGenerated, DeviceName, Method, Detail, Actor, Process, CmdLine, ReportId;
let EventPath =
    DeviceEvents
    | where ActionType has_any (
        "AntivirusDisabled",
        "TamperProtectionSettingUpdated",
        "AntivirusScanCancelled",
        "ExploitGuardNetworkProtectionDisabled"
      )
    | extend
        Method = "Defender event",
        Detail = ActionType,
        Actor = InitiatingProcessAccountUpn,
        Process = InitiatingProcessFileName,
        CmdLine = InitiatingProcessCommandLine
    | project TimeGenerated, DeviceName, Method, Detail, Actor, Process, CmdLine, ReportId;
union RegistryPath, PowerShellPath, EventPath
| summarize
    Methods = make_set(Method, 5),
    Details = make_set(Detail, 10),
    Processes = make_set(Process, 5),
    EventCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
  by DeviceName, Actor
| order by LastSeen desc
```

---

## Tuning notes

**Verify `ActionType` strings against your own tenant.** Defender XDR action type names change between releases. Run `DeviceEvents | where ActionType has "Antivirus" | distinct ActionType` and adjust the list to what actually exists in your environment. This is the most common reason the rule silently returns nothing.

**Exclusion additions are the quiet variant and matter more than people expect.** An attacker rarely disables AV outright on a monitored machine — they add an exclusion for the directory they are about to write to. `ExclusionPath` and `ExclusionProcess` in the PowerShell branch catch that, and it is often the only signal you get.

**Expect legitimate noise from software installs.** Some enterprise applications add Defender exclusions during installation. Baseline for two weeks, identify the installers, then exclude by `InitiatingProcessFileName` plus signer — not by command line, which is trivially altered.

**Security tooling conflicts are common.** If you run a second EDR alongside Defender, it may legitimately disable components. Document that, exclude it explicitly, and revisit whether running both is actually buying you anything.

**Correlate with what happened next.** A disable event alone is suspicious. A disable event followed within minutes by a process launch from a temp directory is an incident. That correlation is in the full pack.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Enterprise app installers adding exclusions | Exclude by initiating process + signer after baselining. |
| IT troubleshooting a performance issue | Real risk. Route to the technician with a re-enable deadline. |
| Third-party EDR managing Defender components | Document and exclude explicitly. |
| Group Policy or Intune pushing configuration | Verify the change originated from your management plane, not a local account. |

---

## Response guidance

1. Isolate the device if the actor is not a known administrator. Defender XDR supports this directly from the incident.
2. Look at what ran in the 30 minutes after the disable. That is where the payload will be.
3. Check whether the account used is compromised — sign-in history, other devices touched.
4. Re-enable protections and run a full scan before returning the device to service.
5. If Tamper Protection was off to begin with, that is the underlying finding. Enable it tenant-wide via Intune — it prevents most of this class of attack outright.

---

## Related rules

- HA-EP-002 — Encoded PowerShell command execution
- HA-EP-003 — Suspicious LOLBin network activity

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
