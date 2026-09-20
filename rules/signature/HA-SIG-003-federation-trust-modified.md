# HA-SIG-003 — Federation Trust or Domain Modified

> **"If someone forged a token against our tenant, would we ever find out?"**

| Field | Value |
|---|---|
| **Severity** | Critical |
| **MITRE Tactic** | TA0006 Credential Access / TA0003 Persistence |
| **MITRE Technique** | T1606.002 — Forge Web Credentials: SAML Tokens |
| **Data source** | Entra ID Audit Logs |
| **Required table** | `AuditLogs` |
| **Suggested frequency** | Every 15 minutes, 15 minute lookback |
| **Entity mapping** | Account (initiator), IP (initiator IP) |

---

## What it detects

Changes to federation settings or domain authentication — the technique behind Golden SAML. An attacker who can modify your federation trust, or add a federated domain, can mint valid tokens for any user in the tenant without ever touching a password, and without generating a single failed sign-in.

There is no legitimate reason for this to happen quietly. In most tenants it should fire roughly never.

---

## KQL

```kql
AuditLogs
| where OperationName has_any (
    "Set federation settings on domain",
    "Set domain authentication",
    "Add unverified domain",
    "Add verified domain",
    "Update domain",
    "Promote tenant to use PTA",
    "Set Company Information"
  )
| where Result == "success"
| extend
    Initiator     = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorApp  = tostring(InitiatedBy.app.displayName),
    InitiatorIP   = tostring(InitiatedBy.user.ipAddress),
    TargetDomain  = tostring(TargetResources[0].displayName)
| mv-apply Prop = TargetResources[0].modifiedProperties on (
    extend PropName = tostring(Prop.displayName),
           OldValue = tostring(Prop.oldValue),
           NewValue = tostring(Prop.newValue)
  )
| extend Finding = case(
    PropName has "IssuerUri",             "FEDERATION ISSUER CHANGED",
    PropName has "SigningCertificate",    "SIGNING CERTIFICATE CHANGED",
    PropName has "LiveType" and NewValue has "Federated",
                                          "DOMAIN SWITCHED TO FEDERATED",
    OperationName has "unverified domain","UNVERIFIED DOMAIN ADDED",
    "Federation configuration modified")
| project TimeGenerated, Finding, TargetDomain, PropName,
          OldValue, NewValue, Initiator, InitiatorApp, InitiatorIP,
          OperationName, CorrelationId
| order by TimeGenerated desc
```

**Companion — the standing state. Run this monthly and diff it.**

```kql
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName has_any ("Set federation settings on domain", "Set domain authentication")
| summarize Changes = count(), LastChange = max(TimeGenerated),
            Initiators = make_set(tostring(InitiatedBy.user.userPrincipalName), 5)
  by Domain = tostring(TargetResources[0].displayName)
| order by LastChange desc
```

---

## Tuning notes

**Do not tune this down.** If it is noisy, something is wrong with your change process, not with the rule. In a stable tenant this fires during a planned identity project and at no other time.

**Know your baseline before you enable it.** Run the companion query over 90 days. If federation settings are being changed regularly by a script, find out why before you start alerting on it.

**`Add unverified domain` matters more than it looks.** Adding a domain is step one; verifying and federating it is step two. Catching step one gives you time. Most rules only watch step two.

**Signing certificate rotation is legitimate and rare.** It should be on a schedule you know about. If a certificate changes and nobody can point to the change ticket, that is the entire finding.

**Route this outside the normal queue.** Federation compromise is a tenant-wide event. It should reach a human by phone, not by dashboard.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| Planned ADFS to cloud-auth migration | Suppress for the project window with a hard expiry. Do not suppress permanently. |
| Scheduled signing certificate rotation | Expected. Verify against the rotation calendar rather than excluding. |
| M&A domain onboarding | Legitimate and high-risk. Review each one; do not blanket-exclude. |
| Tenant hygiene — removing an old domain | Low risk, still worth a look. Downgrade severity rather than filtering. |

---

## Response guidance

1. Verify the initiator against your Global Administrator roster. An unfamiliar UPN here is a tenant-level emergency.
2. Pull the initiator's sign-in history for 48 hours — unfamiliar IP, unfamiliar device, or absent MFA means the admin account itself is compromised.
3. If unauthorized: assume tokens have been forged. Revoke all refresh tokens tenant-wide, restore the federation configuration from your documented baseline, and rotate the signing certificate.
4. Hunt backwards. Token forgery leaves almost no trace in sign-in logs; look instead at what was accessed, especially mailboxes and SharePoint, from the time of the change onward.
5. Keep an exported baseline of your federation configuration in source control. Without it you cannot prove what changed.

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
