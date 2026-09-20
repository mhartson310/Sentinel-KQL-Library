# HA-DA-002 — Storage Account Anonymous Access Enabled

| Field | Value |
|---|---|
| **Severity** | Critical |
| **MITRE Tactic** | TA0010 Exfiltration |
| **MITRE Technique** | T1530 — Data from Cloud Storage |
| **Data source** | Azure Activity Log |
| **Required table** | `AzureActivity` |
| **Suggested frequency** | Every 15 minutes, 15 minute lookback |
| **Entity mapping** | Account (Caller), Azure Resource (storage account) |

---

## What it detects

A storage account or blob container being configured to allow anonymous public read access. This is the cloud equivalent of an open S3 bucket, and it has the same consequences: the data is readable by anyone who finds the URL, and automated scanners find them constantly.

Severity is Critical because the exposure is immediate, total, and requires no authentication to exploit.

---

## KQL

```kql
AzureActivity
| where OperationNameValue has_any (
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE"
  )
| where ActivityStatusValue in ("Success", "Succeeded")
| extend Body = parse_json(tostring(parse_json(Properties).requestbody))
| extend
    AllowBlobPublicAccess = tostring(Body.properties.allowBlobPublicAccess),
    ContainerPublicAccess = tostring(Body.properties.publicAccess),
    NetworkDefault = tostring(Body.properties.networkAcls.defaultAction),
    HttpsOnly = tostring(Body.properties.supportsHttpsTrafficOnly),
    AccountName = tostring(split(_ResourceId, "/")[8]),
    ContainerName = iff(_ResourceId has "/containers/", tostring(split(_ResourceId, "/")[-1]), "")
| where AllowBlobPublicAccess =~ "true"
     or ContainerPublicAccess in~ ("Blob", "Container")
| extend Finding = case(
    ContainerPublicAccess =~ "Container", "Container-level anonymous LIST + READ (worst case)",
    ContainerPublicAccess =~ "Blob", "Blob-level anonymous READ",
    AllowBlobPublicAccess =~ "true", "Account allows public containers",
    "Public access configured"
  )
| project
    TimeGenerated,
    Finding,
    AccountName,
    ContainerName,
    NetworkDefault,
    HttpsOnly,
    ResourceGroup,
    SubscriptionId,
    Caller,
    CallerIpAddress,
    _ResourceId
| order by TimeGenerated desc
```

---

## Tuning notes

**Distinguish the two levels — the query does this deliberately.** `allowBlobPublicAccess: true` at the account level only makes public containers *possible*. `publicAccess: Container` on an actual container means anonymous users can list and read every blob in it. The second is the real emergency. Do not let a Critical alert for the first one train your SOC to dismiss the second.

**Some storage accounts are legitimately public.** Static websites, public asset CDNs, open datasets. Maintain an allowlist by resource ID with an owner and a documented reason. If nobody will own it, it should not be public.

**Check `networkAcls.defaultAction` too.** An account with public access enabled *and* network default `Allow` is fully open. Public access with a network restriction is meaningfully less bad, and surfacing that distinction makes your triage faster.

**Prevention beats detection here.** Azure Policy can deny `allowBlobPublicAccess` at the management group level with a scoped exemption list. Deploy it, then keep this rule as the tripwire for exemption abuse.

**Storage is not the only path.** The same exposure exists via overly permissive SAS tokens, which do not appear in this rule at all. SAS abuse is covered in the full pack.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Static website hosting | Legitimate. Allowlist by resource ID, not by name pattern. |
| Public CDN origin | Same. Verify the container actually contains only public assets. |
| Open data or research datasets | Allowlist with an owner and an annual review. |
| Dev/test accounts with no real data | Verify "no real data" is true. It frequently is not. |

---

## Response guidance

1. Check immediately whether anonymous reads have already occurred: `StorageBlobLogs` where `AuthenticationType == "Anonymous"`.
2. If yes, treat as a data breach and determine what was read. This drives notification obligations.
3. Disable public access. Do not wait for a change window — the exposure is live.
4. Identify what data was in the container. Regulated data changes the response entirely.
5. Find out how it happened. A portal click, a Terraform default, or a copied template each imply a different fix.

---

## Related rules

- HA-DA-003 — Anomalous egress volume from storage
- HA-DA-001 — Mass download from SharePoint or OneDrive

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
