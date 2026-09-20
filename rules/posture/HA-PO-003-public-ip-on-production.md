# HA-PO-003 — Public IP Attached to a Production Resource

| Field | Value |
|---|---|
| **Severity** | Medium |
| **MITRE Tactic** | TA0001 Initial Access |
| **MITRE Technique** | T1190 — Exploit Public-Facing Application |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Account (Caller), Azure Resource |

---

## What it detects

Creation of a public IP address, or association of one with a network interface, in a subscription or resource group tagged as production. In a mature landing zone, production workloads reach the internet through a controlled egress path and receive traffic through a load balancer or application gateway. A public IP directly on a VM NIC usually means someone routed around the architecture.

Severity is Medium rather than High because a public IP alone is not exposure — the NSG still governs what reaches it. Combined with HA-PO-002 it becomes an incident.

---

## KQL

```kql
// Maintain a watchlist "ProductionSubscriptions" with a SubscriptionId column.
let ProdSubs = _GetWatchlist("ProductionSubscriptions") | project SubscriptionId = tostring(SubscriptionId);
AzureActivity
| where OperationNameValue has_any (
    "MICROSOFT.NETWORK/PUBLICIPADDRESSES/WRITE",
    "MICROSOFT.NETWORK/NETWORKINTERFACES/WRITE"
  )
| where ActivityStatusValue in ("Success", "Succeeded")
| where SubscriptionId in (ProdSubs)
| extend Body = parse_json(tostring(parse_json(Properties).requestbody))
| extend
    ResourceName = tostring(split(_ResourceId, "/")[-1]),
    ResourceType = tostring(split(_ResourceId, "/")[-2]),
    AllocationMethod = tostring(Body.properties.publicIPAllocationMethod),
    HasPublicIPRef = tostring(Body.properties) has "publicIPAddress"
| where OperationNameValue has "PUBLICIPADDRESSES" or HasPublicIPRef == "true"
| project
    TimeGenerated,
    ResourceName,
    ResourceType,
    AllocationMethod,
    ResourceGroup,
    SubscriptionId,
    Caller,
    CallerIpAddress,
    OperationNameValue,
    _ResourceId
| order by TimeGenerated desc
```

**Standing-state companion — run in Azure Resource Graph, not Sentinel:**

```
Resources
| where type =~ "microsoft.network/publicipaddresses"
| where isnotempty(properties.ipConfiguration)
| project name, resourceGroup, subscriptionId, ip = properties.ipAddress,
          attachedTo = properties.ipConfiguration.id
```

---

## Tuning notes

**Use a watchlist for production subscriptions.** Hardcoding subscription GUIDs into a query guarantees it will be wrong within a quarter. A watchlist can be owned by the platform team and reviewed.

**Tag-based scoping is better if your tagging is disciplined.** If every resource carries an `Environment` tag, scope on that instead of subscription. Most orgs' tagging is not disciplined enough to trust for a security control — be honest about which is true for you.

**Expect load balancer and gateway noise.** Application Gateway, Azure Firewall, NAT Gateway, and Bastion all legitimately hold public IPs. Exclude by resource type rather than by name:

```kql
| where ResourceType !in ("applicationGateways", "azureFirewalls", "natGateways", "bastionHosts", "loadBalancers")
```

**This is a governance rule more than a threat rule.** It will mostly surface architectural drift, not attacks. That is still valuable — most cloud breaches trace back to drift, not to a novel technique. Route it to a daily digest rather than a paging alert.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Load balancers, gateways, Bastion, NAT Gateway | Exclude by resource type. |
| Approved public-facing services | Maintain an allowlist of expected public endpoints with owners. |
| Automated deployments from IaC pipelines | If the pipeline is approved and reviewed, exclude the service principal. If it is not reviewed, that is the finding. |
| Dev subscriptions miscategorized as prod | Fix the watchlist. |

---

## Response guidance

1. Check what the resource is and whether it should be internet-reachable.
2. Check the NSG on the attached interface. Public IP plus permissive NSG is an urgent combination.
3. Determine whether a supported alternative exists — Bastion for admin access, App Gateway for web traffic, Private Link for service-to-service.
4. If this recurs from the same team, the fix is a conversation and an Azure Policy, not more alerts.

---

## Related rules

- HA-PO-002 — NSG rule opened to the internet on a management port
- HA-PO-001 — Defender for Cloud plan disabled

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
