# HA-PO-002 — NSG Rule Opened to the Internet on a Management Port

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0001 Initial Access |
| **MITRE Technique** | T1190 — Exploit Public-Facing Application |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 15 minutes, 15 minute lookback |
| **Entity mapping** | Account (Caller), Azure Resource (NSG) |

---

## What it detects

A network security group rule created or modified to allow inbound traffic from any source to a management port. RDP and SSH exposed to the internet remain among the most reliable initial access vectors in cloud environments — automated scanners find a new exposed 3389 within minutes.

Usually this is an engineer unblocking themselves at 6pm on a Friday with every intention of reverting it. The intention is not the control.

---

## KQL

```kql
let ManagementPorts = dynamic(["22", "3389", "5985", "5986", "1433", "3306", "5432", "27017", "6379", "9200"]);
let AnySource = dynamic(["*", "0.0.0.0/0", "internet", "Internet", "any", "Any", "0.0.0.0"]);
AzureActivity
| where OperationNameValue has "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS" 
| where OperationNameValue has_any ("SECURITYRULES/WRITE", "/WRITE")
| where ActivityStatusValue in ("Success", "Succeeded")
| extend Body = parse_json(tostring(parse_json(Properties).requestbody))
| extend Rule = Body.properties
| extend
    Direction = tostring(Rule.direction),
    Access = tostring(Rule.access),
    Protocol = tostring(Rule.protocol),
    SourcePrefix = tostring(Rule.sourceAddressPrefix),
    DestPort = tostring(Rule.destinationPortRange),
    DestPortsArray = tostring(Rule.destinationPortRanges),
    Priority = toint(Rule.priority),
    RuleName = tostring(Body.name)
| where Direction =~ "Inbound" and Access =~ "Allow"
| where SourcePrefix in (AnySource)
| extend AllPorts = strcat(DestPort, " ", DestPortsArray)
| where AllPorts has_any (ManagementPorts) or DestPort == "*"
| extend Exposure = iff(DestPort == "*", "ALL PORTS", AllPorts)
| project
    TimeGenerated,
    Exposure,
    RuleName,
    Protocol,
    Priority,
    SourcePrefix,
    ResourceGroup,
    SubscriptionId,
    Caller,
    CallerIpAddress,
    _ResourceId
| order by TimeGenerated desc
```

---

## Tuning notes

**`requestbody` is not always populated.** Portal changes generally include it; some ARM and Terraform paths do not. If `Rule` comes back null, fall back to alerting on all NSG security rule writes and triaging manually — noisier, but it will not silently miss.

**Add your own management ports.** The list above covers SSH, RDP, WinRM, and the common database ports. Add anything else you consider management plane — Kubernetes API, Redis, Elasticsearch, internal admin UIs.

**Priority matters and the query surfaces it.** A permissive rule at priority 100 overrides a deny at 200. A low-priority permissive rule sitting below an existing deny is functionally inert, and treating it as urgent burns credibility with your platform team.

**The better long-term fix is prevention.** Azure Policy with a deny effect on this exact pattern stops it from happening at all. Use this rule to find out how often it is attempted, then build the policy, then keep the rule as a tripwire for policy gaps.

**Pair with a posture check.** Detection catches the change; it does not tell you what is exposed right now. Defender for Cloud's recommendation for management ports, or a periodic Resource Graph query, covers the standing state.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Temporary troubleshooting access | Real risk, not a false positive. Route to the engineer with a revert deadline. |
| Dev/sandbox subscriptions with looser rules | Exclude by subscription via watchlist, never by hardcoded list. |
| Rule created below an existing deny | Check priority. Low-priority permissive rules under a deny are inert — downgrade severity. |
| Azure Bastion or JIT deployments | These create rules legitimately. Exclude by caller service principal. |

---

## Response guidance

1. Determine whether the port is actually reachable — NSG plus any firewall, ASG, or route table in front of it.
2. If reachable, check for exploitation attempts against the target since the change.
3. Contact the caller. Most of the time there is a legitimate need and a better path: Bastion, JIT access, or a VPN.
4. Set an expiry. If the rule must stay, it needs an owner and a review date, recorded somewhere that outlives the ticket.

---

## Related rules

- HA-PO-003 — Public IP attached to a production resource
- HA-PO-001 — Defender for Cloud plan disabled

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
