# HA-ID-005 — High-Privilege App Role Granted to Service Principal

| Field | Value |
|---|---|
| **Severity** | High |
| **MITRE Tactic** | TA0003 Persistence |
| **MITRE Technique** | T1098.003 — Account Manipulation: Additional Cloud Roles |
| **Data source** | Entra ID Audit Logs |
| **Required table** | `AuditLogs` |
| **Suggested frequency** | Every 1 hour, 1 hour lookback |
| **Entity mapping** | Account (initiator), CloudApplication (target SP) |

---

## What it detects

A service principal being granted a high-privilege Microsoft Graph application permission. This is the quietest persistence mechanism in Entra ID: an app registration with `Mail.ReadWrite` or `Directory.ReadWrite.All` does not show up in user access reviews, is not covered by Conditional Access, has no MFA to bypass, and survives every password reset in the tenant.

It is also the technique behind several of the largest cloud compromises on record.

---

## KQL

```kql
let HighPrivGraphRoles = dynamic([
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Mail.Read",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "Sites.FullControl.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "DeviceManagementConfiguration.ReadWrite.All",
    "Exchange.ManageAsApp",
    "full_access_as_app"
]);
AuditLogs
| where OperationName has_any (
    "Add app role assignment to service principal",
    "Add delegated permission grant",
    "Consent to application"
  )
| where Result == "success"
| extend
    Initiator = tostring(InitiatedBy.user.userPrincipalName),
    InitiatorIP = tostring(InitiatedBy.user.ipAddress),
    TargetApp = tostring(TargetResources[0].displayName),
    TargetAppId = tostring(TargetResources[0].id)
| mv-apply Prop = TargetResources[0].modifiedProperties on (
    extend PropName = tostring(Prop.displayName), PropNew = tostring(Prop.newValue)
    | where PropName in ("AppRole.Value", "DelegatedPermissionGrant.Scope", "ConsentAction.Permissions")
    | extend GrantedPermission = replace_string(PropNew, '"', "")
  )
| where GrantedPermission has_any (HighPrivGraphRoles)
| project
    TimeGenerated,
    GrantedPermission,
    TargetApp,
    TargetAppId,
    Initiator,
    InitiatorIP,
    OperationName,
    CorrelationId
| order by TimeGenerated desc
```

---

## Tuning notes

**Curate the role list to your risk model.** Eighteen permissions is a broad net. `Mail.Read` and `Files.ReadWrite.All` are the ones used for data theft; `RoleManagement.ReadWrite.Directory` and `AppRoleAssignment.ReadWrite.All` are the ones used to escalate further — an app with the latter can grant itself anything else.

**Watch for consent grant events specifically.** `Consent to application` captures the illicit consent phishing pattern, where a user is tricked into approving a malicious app. If your tenant allows user consent, that is a separate exposure worth closing: restrict user consent to verified publishers and low-impact permissions.

**Exclude your known integration apps by app ID, not display name.** Display names are attacker-controlled and are routinely chosen to look legitimate ("Microsoft Office 365 Backup", "Azure AD Sync Service").

**Property names shift.** `AppRole.Value` is the common one, but consent events use different property names. If the rule returns nothing after a known grant, inspect `modifiedProperties` directly.

---

## False positives you will actually hit

| Scenario | How to handle |
|---|---|
| New SaaS integration going live | Legitimate but should still be reviewed. This is exactly the review you want to be doing. |
| Backup or security vendor onboarding | Exclude by app ID once verified against the vendor's documented permission list. |
| Microsoft first-party app updates | Check the app ID against Microsoft's published first-party list before dismissing. |
| CI/CD service principals getting scoped permissions | Usually Azure RBAC rather than Graph. If it is Graph, question why. |

---

## Response guidance

1. Identify the app. Does it exist for a documented business reason, with an owner?
2. Check the app registration's credentials — a recently added client secret or certificate alongside a permission grant is a strong compromise indicator.
3. Review the consenting identity. Illicit consent grants come from ordinary users; admin consent comes from admins whose accounts may be compromised.
4. If malicious: remove the app role assignment, delete the service principal's credentials, revoke tokens, then audit what the app accessed using its sign-in logs (`AADServicePrincipalSignInLogs`).
5. Establish a standing quarterly review of app permissions. This is the control that catches the ones the rule missed.

---

## Related rules

- HA-ID-001 — Privileged role assigned outside change window
- HA-ID-004 — Conditional Access policy disabled or weakened

---

[← All rules](../../README.md)  ·  [Deployment modules and the full pack →](https://mhartson.com/detections)
