# HA-PO-004 — Key Vault Access Granted Followed by Bulk Secret Read

| Field | Value |
|---|---|
| **Severity** | Critical |
| **MITRE Tactic** | TA0006 Credential Access |
| **MITRE Technique** | T1555.006 — Credentials from Password Stores: Cloud Secrets Management |
| **Data source** | Azure Activity Log + Key Vault diagnostics |
| **Required tables** | `AzureActivity`, `AzureDiagnostics` |
| **Suggested frequency** | Every 1 hour, 2 hour lookback |
| **Entity mapping** | Account (Caller), Azure Resource (vault) |

---

## What it detects

An identity granting itself (or being granted) access to a Key Vault, then reading a large number of secrets shortly afterward. The sequence is the signal. Access grants happen routinely. Bulk secret reads happen routinely. The two together inside a short window is the credential-harvesting pattern, and it is one of the highest-fidelity correlations available in Azure.

This is the rule that catches lateral movement before it becomes a breach.

---

## KQL

```kql
let CorrelationWindow = 2h;
let BulkThreshold = 10;          // distinct secrets read
let Grants =
    AzureActivity
    | where OperationNameValue has_any (
        "MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE",
        "MICROSOFT.KEYVAULT/VAULTS/WRITE",
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
      )
    | where ActivityStatusValue in ("Success", "Succeeded")
    | where _ResourceId has "/vaults/" or tostring(parse_json(Properties)) has "KeyVault"
    | extend VaultName = tostring(split(_ResourceId, "/")[-1])
    | project
        GrantTime = TimeGenerated,
        GrantCaller = Caller,
        GrantCallerIP = CallerIpAddress,
        VaultName,
        GrantOperation = OperationNameValue,
        VaultResourceId = _ResourceId;
let Reads =
    AzureDiagnostics
    | where ResourceType == "VAULTS"
    | where OperationName in ("SecretGet", "SecretList", "CertificateGet", "KeyGet")
    | where ResultSignature == "OK" or httpStatusCode_d == 200
    | extend
        Vault = tostring(Resource),
        Requester = coalesce(identity_claim_upn_s, identity_claim_appid_g, tostring(identity_claim_oid_g))
    | summarize
        SecretsRead = dcount(id_s),
        SecretSample = make_set(id_s, 10),
        ReadStart = min(TimeGenerated),
        ReadEnd = max(TimeGenerated),
        CallerIPs = make_set(CallerIPAddress, 5)
      by Vault, Requester
    | where SecretsRead >= BulkThreshold;
Grants
| join kind=inner Reads on $left.VaultName == $right.Vault
| where ReadStart between (GrantTime .. (GrantTime + CorrelationWindow))
| extend MinutesAfterGrant = datetime_diff("minute", ReadStart, GrantTime)
| project
    GrantTime,
    MinutesAfterGrant,
    VaultName,
    GrantCaller,
    GrantCallerIP,
    Requester,
    SecretsRead,
    SecretSample,
    CallerIPs,
    GrantOperation
| order by GrantTime desc
```

---

## Tuning notes

**Key Vault diagnostic logging must be on, per vault.** This is the number one reason this rule returns nothing. Enable `AuditEvent` diagnostics on every vault and send to the workspace. Verify:

```kql
AzureDiagnostics | where ResourceType == "VAULTS" | summarize by Resource
```

Any vault missing from that list is invisible to this rule.

**The schema depends on your diagnostic setting.** Some workspaces land Key Vault logs in `AzureDiagnostics`, others in resource-specific tables (`AZKVAuditLogs`). If the query returns nothing and diagnostics are on, check which table you are actually getting.

**Tune `BulkThreshold` to your application patterns.** An app that reads 40 secrets at startup makes 10 a useless threshold. Baseline first:

```kql
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName == "SecretGet"
| summarize Reads = dcount(id_s) by Requester, bin(TimeGenerated, 1h)
| summarize avg(Reads), max(Reads), percentile(Reads, 95) by Requester
```

**Widen the window if your attacker model is patient.** Two hours catches smash-and-grab. A careful adversary waits days. Running the same correlation at 24h is worth doing as a scheduled hunt even if it is too noisy for an alert.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Application deployment reading its config secrets after RBAC assignment | The most common one. Exclude known deployment service principals by object ID. |
| Secret rotation automation | Exclude the rotation identity. Verify it is actually yours first. |
| A new engineer being onboarded to a team's vault | Legitimate but worth a look. Route to a review queue rather than paging. |
| DR testing and failover drills | Time-boxed exception tied to the drill. |

---

## Response guidance

1. Treat as active credential theft until disproven. The blast radius is every system those secrets protect.
2. Identify what was read. `SecretSample` gives you the names — that tells you which downstream systems are now at risk.
3. Check the grant: was it self-granted? An identity granting itself vault access is a major escalation indicator.
4. If malicious: rotate every secret read, revoke the identity's access and sessions, then work outward to the systems those secrets authenticate to.
5. Longer term, move toward managed identities and reduce the number of standing secrets. Secrets that do not exist cannot be harvested.

---

## Related rules

- HA-ID-005 — High-privilege app role granted to service principal
- HA-ID-001 — Privileged role assigned outside change window

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
