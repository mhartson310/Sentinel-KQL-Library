# **Microsoft Sentinel detection rules that ship with the tuning notes.**

Here is one. This is the whole thing — no signup, no "request access," no truncated preview.

---

### HA-PO-004 — Key Vault access granted, then bulk secret read

Someone grants themselves access to a Key Vault, then reads a pile of secrets shortly after. Either half alone is routine. The two together inside a short window is credential harvesting, and it's one of the highest-fidelity correlations available in Azure.

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
    | where _ResourceId has "/vaults/"
    | extend VaultName = tostring(split(_ResourceId, "/")[-1])
    | project GrantTime = TimeGenerated, GrantCaller = Caller,
              GrantCallerIP = CallerIpAddress, VaultName;
let Reads =
    AzureDiagnostics
    | where ResourceType == "VAULTS"
    | where OperationName in ("SecretGet", "SecretList")
    | where ResultSignature == "OK" or httpStatusCode_d == 200
    | extend Vault = tostring(Resource),
             Requester = coalesce(identity_claim_upn_s, identity_claim_appid_g)
    | summarize SecretsRead  = dcount(id_s),
                SecretSample = make_set(id_s, 10),
                ReadStart    = min(TimeGenerated)
      by Vault, Requester
    | where SecretsRead >= BulkThreshold;
Grants
| join kind=inner Reads on $left.VaultName == $right.Vault
| where ReadStart between (GrantTime .. (GrantTime + CorrelationWindow))
| extend MinutesAfterGrant = datetime_diff("minute", ReadStart, GrantTime)
| project GrantTime, MinutesAfterGrant, VaultName, GrantCaller,
          GrantCallerIP, Requester, SecretsRead, SecretSample
| order by GrantTime desc
```

**Before you enable this, three things will break it:**

1. **Key Vault diagnostic logging is off by default, per vault.** This is the number one reason the rule returns nothing. Check which vaults you're actually seeing:
   ```kql
   AzureDiagnostics | where ResourceType == "VAULTS" | summarize by Resource
   ```
   Any vault missing from that list is invisible to this rule.

2. **`BulkThreshold = 10` is probably wrong for you.** An app that reads 40 secrets at startup makes 10 useless. Baseline first:
   ```kql
   AzureDiagnostics
   | where ResourceType == "VAULTS" and OperationName == "SecretGet"
   | summarize Reads = dcount(id_s) by Requester, bin(TimeGenerated, 1h)
   | summarize avg(Reads), max(Reads), percentile(Reads, 95) by Requester
   ```

3. **Your deployment pipelines will fire this constantly.** A service principal gets an RBAC assignment, then reads its config secrets — textbook true-positive shape, entirely benign. Exclude known deployment identities by object ID, not by display name.

**The false positives you'll actually hit:** app deployments reading config after an RBAC grant (most common by far), secret rotation automation, a new engineer onboarded to a team vault, DR failover drills.

**If it's real:** identify what was read — `SecretSample` gives you the names, which tells you which downstream systems are now compromised. Check whether the grant was self-issued; an identity granting itself vault access is a major escalation signal. Rotate every secret read before you do anything else.

---

**→ Deploying these? The [Bicep and Terraform modules](https://mhartson.com/detections) are free.**

---

## That's the format. All 20 rules look like this.

Most rule libraries give you KQL and wish you luck. The KQL is the easy part — you can get that from a language model in ten seconds. What you can't get is someone telling you which table isn't onboarded, which threshold is wrong for your environment, and which benign thing is going to page your analyst at 3am on Sunday.

That's what's in here. Every rule ships with the query, the prerequisites, the tuning dial and what it depends on, a false-positive table, and response guidance.

---

## Signature detections

Five questions security leaders actually ask, and the detection that answers each one. These are the ones worth your attention first — they cover failure modes most rule libraries don't attempt.

### "We deployed Copilot agents six months ago. Nobody wrote down who owns them or what they can reach."
**[HA-SIG-001 — Over-permissioned AI agent](rules/signature/HA-SIG-001-agent-sprawl.md)**
Joins what each agent is *permitted* to do against what it has *actually* done, and surfaces the gap. Flags dormant agents holding high-privilege scopes, and agents with no identifiable owner — which is the finding nobody wants and everybody has.

### "If our firewall stopped sending logs on a Friday night, how long until anyone noticed?"
**[HA-SIG-002 — Log source stopped reporting](rules/signature/HA-SIG-002-log-source-went-dark.md)**
Detects the absence of data. Every other rule fires when something happens; this one fires when something stops. A detection built on a table that went quiet doesn't fail loudly — it just never fires again while your coverage map stays green.

### "If someone forged a token against our tenant, would we ever find out?"
**[HA-SIG-003 — Federation trust or domain modified](rules/signature/HA-SIG-003-federation-trust-modified.md)**
The Golden SAML precondition. An attacker who modifies your federation trust can mint valid tokens for any user without touching a password or generating a single failed sign-in. In a stable tenant this should fire roughly never.

### "What actually happens to an account after someone leaves? I'd like to believe it's disabled the same day."
**[HA-SIG-004 — Dormant account suddenly active](rules/signature/HA-SIG-004-dormant-account-reactivated.md)**
The cheapest detection here to operate. Dormancy is unambiguous, the false-positive rate is low, and the true positives are almost always worth the phone call. The underlying finding is usually your offboarding process.

### "Copilot didn't give anyone new permissions. So why does it feel like everyone can suddenly see everything?"
**[HA-SIG-005 — Sensitive content surfaced through Copilot](rules/signature/HA-SIG-005-copilot-oversharing.md)**
Copilot grants no new access — it removes the practical obscurity that was doing most of the access-control work in your tenant. A file nobody could find was effectively protected. A file Copilot will summarize on request is not.

---

## The rules

### Signature
| ID | Rule | Severity |
|---|---|---|
| [HA-SIG-001](rules/signature/HA-SIG-001-agent-sprawl.md) | Over-permissioned AI agent | High |
| [HA-SIG-002](rules/signature/HA-SIG-002-log-source-went-dark.md) | Log source stopped reporting | High |
| [HA-SIG-003](rules/signature/HA-SIG-003-federation-trust-modified.md) | Federation trust or domain modified | Critical |
| [HA-SIG-004](rules/signature/HA-SIG-004-dormant-account-reactivated.md) | Dormant account suddenly active | High |
| [HA-SIG-005](rules/signature/HA-SIG-005-copilot-oversharing.md) | Sensitive content surfaced through Copilot | High |

### Identity — Entra ID
| ID | Rule | Severity |
|---|---|---|
| [HA-ID-001](rules/identity/HA-ID-001-privileged-role-outside-change-window.md) | Privileged role assigned outside change window | High |
| [HA-ID-002](rules/identity/HA-ID-002-legacy-auth-success.md) | Successful sign-in using legacy authentication | High |
| [HA-ID-003](rules/identity/HA-ID-003-break-glass-activity.md) | Break-glass account activity | Critical |
| [HA-ID-004](rules/identity/HA-ID-004-conditional-access-weakened.md) | Conditional Access policy disabled or weakened | Critical |
| [HA-ID-005](rules/identity/HA-ID-005-app-role-granted-to-service-principal.md) | High-privilege app role granted to service principal | High |

### Posture — Azure & Defender for Cloud
| ID | Rule | Severity |
|---|---|---|
| [HA-PO-001](rules/posture/HA-PO-001-defender-plan-disabled.md) | Defender for Cloud plan disabled | High |
| [HA-PO-002](rules/posture/HA-PO-002-nsg-opened-to-internet.md) | NSG rule opened to the internet on a management port | High |
| [HA-PO-003](rules/posture/HA-PO-003-public-ip-on-production.md) | Public IP attached to a production resource | Medium |
| [HA-PO-004](rules/posture/HA-PO-004-keyvault-grant-then-bulk-read.md) | Key Vault access granted, then bulk secret read | Critical |

### Data
| ID | Rule | Severity |
|---|---|---|
| [HA-DA-001](rules/data/HA-DA-001-mass-sharepoint-download.md) | Mass download from SharePoint or OneDrive | High |
| [HA-DA-002](rules/data/HA-DA-002-storage-anonymous-access-enabled.md) | Storage account anonymous access enabled | Critical |
| [HA-DA-003](rules/data/HA-DA-003-anomalous-storage-egress.md) | Anomalous egress volume from storage | Medium |

### Endpoint — Defender XDR
| ID | Rule | Severity |
|---|---|---|
| [HA-EP-001](rules/endpoint/HA-EP-001-defender-protection-disabled.md) | Tamper protection or real-time protection disabled | High |
| [HA-EP-002](rules/endpoint/HA-EP-002-encoded-powershell.md) | Encoded PowerShell command execution | Medium |
| [HA-EP-003](rules/endpoint/HA-EP-003-lolbin-network-activity.md) | Suspicious LOLBin network activity | Medium |

If you're skimming, start with the five signature detections above. Of the rest, **HA-ID-005** is the one most environments are blind to — app-role grants to service principals are the persistence technique behind several of the largest cloud compromises on record.

---

## How to deploy these without regretting it

Do not paste these into an analytics rule and turn them on. The order that works:

1. **Run it as a hunting query.** 30 days back. Look at what comes out.
2. **Read the tuning notes and apply them.** Every rule has a section telling you what to change.
3. **Re-run until the results are things you'd actually want to see at 3am.**
4. **Then promote to an analytics rule** at the frequency in the metadata block.
5. **Watch it for two weeks.** Track the FP rate. Tune again.

Skipping step 1 is how teams end up disabling rules instead of tuning them.

Prerequisites and connector checks are in [docs/getting-started.md](docs/getting-started.md).

---

## Who wrote these

Mario Worwell — cloud security architect, 15 years across government, fintech, healthcare, and energy. Former Senior Cloud Solution Architect at Microsoft. These come out of real engagements in regulated environments, where a bad detection shows up as an audit finding rather than a blog comment.

[mhartson.com](https://mhartson.com) · [LinkedIn](https://www.linkedin.com/in/YOURHANDLE)

---

## Get the deployment modules — free

You have the rules. Deploying twenty of them by hand through the portal is an afternoon you won't get back, and it isn't repeatable.

**The deployment kit is free, and it's the next step:**

- **Bicep and Terraform modules** — deploy every rule in this repo as a versioned analytics rule
- **Watchlist templates** — `BreakGlassAccounts`, `ServiceAccounts`, `ProductionSubscriptions`, pre-built with the schema these rules expect
- **The onboarding checklist** — every table and connector these rules depend on, as a pre-flight you can run in ten minutes
- **MITRE coverage map** for the twenty rules here, so you can see your gaps before you add anything

**→ [mhartson.com/detections](https://mhartson.com/detections)**

Email required, because that's how you get told when a schema change breaks a rule. Entra and Defender XDR both move; when something here stops working, subscribers hear about it first.

---

## Going further

The detection pack extends this repo to roughly 60 rules with the same tuning depth, plus a Sentinel tuning workbook that shows false-positive rate per rule — so you tune with data instead of vibes.

If you're migrating between SIEMs or standing up Defender XDR, the playbooks cover the work surrounding the detections:

| | |
|---|---|
| **[The SIEM Migration Playbook](https://hartsonm.gumroad.com/l/siem-migration-playbook)** | Splunk ↔ Sentinel, both directions. 56 pages: data mapping, cost modeling, SPL→KQL translation, detection parity, and a gated cutover. |
| **[The Defender XDR Playbook](https://hartsonm.gumroad.com/l/defender-xdr-playbook)** | Deploy, tune, and operate Defender XDR alongside Sentinel — the operating model, not the marketing. |

---

## Contributing

**Found a false positive I didn't document?** That's the most valuable thing you can contribute here. Open an issue with the rule ID, what fired, why it was benign, and the exclusion that fixed it.

**Want a rule that doesn't exist?** Open an issue describing the scenario in plain language. No KQL required.

Full guidelines in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Use them commercially, modify them, ship them in your environment. Attribution appreciated, not required.

## Disclaimer

Test in a non-production workspace first. These are starting points tuned to environments I've worked in, not universal truths about yours. Schema changes on both Entra and Defender XDR will eventually break something here — the tuning notes tell you how to check.
