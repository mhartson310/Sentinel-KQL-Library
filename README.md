# Sentinel KQL Library

[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/services/microsoft-sentinel/)
[![KQL](https://img.shields.io/badge/KQL-Queries-00BCF2)](https://docs.microsoft.com/azure/data-explorer/kusto/query/)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/mhartson310/Sentinel-KQL-Library)

Production-tested KQL queries for Microsoft Sentinel - detection rules, threat hunting, and security analytics.

**500+ queries** used in real SOC environments protecting Fortune 500 companies and government agencies.

📖 **[Read the complete Sentinel guide →](https://mhartson.com/insights/sentinel-analytics-rules)**

---

## 🎯 What This Is

**Real KQL queries** that detect actual threats in production environments.

Not "hello world" examples. These are analytics rules, hunting queries, and investigation queries used by enterprise SOCs.

Each query includes:
- ✅ **MITRE ATT&CK mapping** - Know what technique you're detecting
- ✅ **Tuning guidance** - Reduce false positives
- ✅ **Real-world context** - When/why this fires
- ✅ **Severity classification** - Appropriate alert levels
- ✅ **Response actions** - What to do when it triggers

---

## 📦 Query Categories

### Detection & Response (Analytics Rules)

- **[Initial Access](detection-rules/initial-access/)** - Brute force, phishing, exploit attempts
- **[Execution](detection-rules/execution/)** - Malicious scripts, suspicious processes
- **[Persistence](detection-rules/persistence/)** - Backdoors, scheduled tasks, registry modifications
- **[Privilege Escalation](detection-rules/privilege-escalation/)** - Account elevation, token manipulation
- **[Defense Evasion](detection-rules/defense-evasion/)** - Log deletion, disabling security tools
- **[Credential Access](detection-rules/credential-access/)** - Password dumping, credential theft
- **[Discovery](detection-rules/discovery/)** - Network scanning, account enumeration
- **[Lateral Movement](detection-rules/lateral-movement/)** - Pass-the-hash, remote execution
- **[Collection](detection-rules/collection/)** - Data staging, clipboard capture
- **[Exfiltration](detection-rules/exfiltration/)** - Unusual data transfers, DNS tunneling
- **[Impact](detection-rules/impact/)** - Ransomware, data destruction

### Threat Hunting

- **[User Behavior](threat-hunting/user-behavior/)** - Anomalous user activity
- **[Network Analysis](threat-hunting/network/)** - Traffic patterns, beaconing
- **[Endpoint Investigation](threat-hunting/endpoint/)** - Process analysis, file operations
- **[Cloud Security](threat-hunting/cloud/)** - Azure AD, AWS, GCP anomalies

### Security Operations

- **[Incident Response](incident-response/)** - Investigation queries
- **[Compliance](compliance/)** - Audit queries for FedRAMP, NIST, ISO
- **[Performance Optimization](optimization/)** - Query tuning, cost reduction

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/mhartson310/Sentinel-KQL-Library.git
cd Sentinel-KQL-Library
```

### 2. Browse Queries by Category

```bash
# Detection rules by MITRE ATT&CK technique
cd detection-rules/privilege-escalation/

# View a specific query
cat privilege-escalation-outside-business-hours.kql
```

### 3. Deploy to Sentinel

**Option A: Manual Deployment**

1. Open Azure Portal → Microsoft Sentinel
2. Navigate to **Analytics** → **Rules**
3. Click **Create** → **Scheduled query rule**
4. Copy-paste the KQL query
5. Configure severity, frequency, and actions

**Option B: Automated Deployment (Terraform)**

```bash
cd terraform/

# Deploy all detection rules
terraform init
terraform apply -var-file="production.tfvars"
```

**Option C: Azure DevOps Pipeline**

```bash
# Use the included CI/CD pipeline
# See: .github/workflows/deploy-sentinel-rules.yml
```

---

## 📊 Featured Queries

### Brute Force Detection

**MITRE:** T1110 - Brute Force  
**Severity:** High  
**Use Case:** Detect password spray and credential stuffing attacks

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0  // Failed sign-ins
| summarize 
    FailedAttempts = count(),
    UniqueIPs = dcount(IPAddress),
    UniqueUsers = dcount(UserPrincipalName),
    IPList = make_set(IPAddress),
    UserList = make_set(UserPrincipalName)
    by bin(TimeGenerated, 5m)
| where FailedAttempts > 10
| extend 
    AttackType = case(
        UniqueUsers > 5 and UniqueIPs == 1, "Password Spray",
        UniqueUsers == 1 and UniqueIPs > 3, "Credential Stuffing",
        "Brute Force"
    )
| project 
    TimeGenerated,
    AttackType,
    FailedAttempts,
    UniqueIPs,
    UniqueUsers,
    IPList,
    UserList
```

**Tuning:** Adjust threshold based on your environment (10 failures in 5 min)  
**False Positives:** Legitimate users with expired passwords, MFA issues  
**Response:** Block source IPs, reset affected accounts, investigate user/IP correlation

---

### Privilege Escalation (Outside Business Hours)

**MITRE:** T1078 - Valid Accounts  
**Severity:** Medium  
**Use Case:** Detect suspicious admin role assignments after hours

```kql
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| where Category == "RoleManagement"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend UserAdded = tostring(TargetResources[0].userPrincipalName)
| extend AddedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Hour = datetime_part("hour", TimeGenerated)
// Business hours: 8 AM - 6 PM
| where Hour < 8 or Hour > 18
| where RoleName in ("Global Administrator", "Privileged Role Administrator", "Security Administrator")
| project 
    TimeGenerated,
    RoleName,
    UserAdded,
    AddedBy,
    IPAddress = tostring(InitiatedBy.user.ipAddress),
    UserAgent = tostring(AdditionalDetails[0].value)
```

**Tuning:** Define business hours for your timezone  
**False Positives:** Emergency IT changes, global teams in different timezones  
**Response:** Verify legitimacy with AddedBy user, check for compromise indicators

---

### Lateral Movement (Pass-the-Hash Detection)

**MITRE:** T1550.002 - Pass the Hash  
**Severity:** High  
**Use Case:** Detect NTLM authentication from unusual source

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624  // Successful logon
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
| summarize 
    LogonCount = count(),
    UniqueAccounts = dcount(TargetUserName),
    Accounts = make_set(TargetUserName),
    SourceIPs = make_set(IpAddress)
    by Computer, IpAddress, bin(TimeGenerated, 5m)
| where UniqueAccounts > 5  // Same source accessing multiple accounts
| extend Severity = "High"
| project 
    TimeGenerated,
    SourceIP = IpAddress,
    TargetComputer = Computer,
    UniqueAccounts,
    Accounts,
    LogonCount,
    Severity
```

**Tuning:** Adjust `UniqueAccounts` threshold for your environment  
**False Positives:** Service accounts, automation tools, scanning tools  
**Response:** Isolate source IP, reset affected accounts, hunt for additional lateral movement

---

### Data Exfiltration (Large File Uploads)

**MITRE:** T1567 - Exfiltration Over Web Service  
**Severity:** Medium  
**Use Case:** Detect unusual large file uploads to cloud services

```kql
OfficeActivity
| where TimeGenerated > ago(1h)
| where Operation in ("FileUploaded", "FileSyncUploadedFull")
| where OfficeWorkload == "OneDrive" or OfficeWorkload == "SharePoint"
| extend FileSize_MB = todouble(ObjectId) / 1048576  // Convert to MB
| where FileSize_MB > 100  // Files larger than 100 MB
| summarize 
    TotalUploadMB = sum(FileSize_MB),
    FileCount = count(),
    Files = make_set(SourceFileName)
    by UserId, ClientIP, bin(TimeGenerated, 1h)
| where TotalUploadMB > 500  // More than 500 MB in 1 hour
| extend Risk = case(
    TotalUploadMB > 2000, "Critical",
    TotalUploadMB > 1000, "High",
    "Medium"
)
| project 
    TimeGenerated,
    User = UserId,
    SourceIP = ClientIP,
    TotalUploadMB,
    FileCount,
    Files,
    Risk
```

**Tuning:** Set thresholds based on normal business activity  
**False Positives:** Video uploads, legitimate large file transfers, backup operations  
**Response:** Contact user, verify business justification, check for account compromise

---

## 📚 Query Structure

Each query file includes:

```kql
// ============================================
// QUERY METADATA
// ============================================
// Name: Privilege Escalation - Outside Business Hours
// MITRE ATT&CK: T1078 - Valid Accounts
// Severity: Medium
// Frequency: Every 1 hour
// Tactics: Privilege Escalation, Persistence
// Data Sources: AuditLogs (Azure AD)
// False Positive Rate: Low
// Author: Mario Hartson
// Website: https://mhartson.com
// ============================================

// DESCRIPTION:
// Detects when privileged roles are assigned outside of 
// normal business hours (8 AM - 6 PM). Attackers often
// perform privilege escalation during off-hours to avoid
// detection.

// TUNING GUIDANCE:
// 1. Adjust business hours for your timezone
// 2. Add exceptions for legitimate global team members
// 3. Consider reducing threshold for Global Admin role
// 4. Whitelist emergency change tickets

// RESPONSE ACTIONS:
// 1. Verify with the user who made the change (AddedBy)
// 2. Check if change ticket exists
// 3. Review account for compromise indicators
// 4. If unauthorized, remove role assignment immediately

// THE QUERY:
AuditLogs
| where TimeGenerated > ago(24h)
// ... query code ...
```

---

## 🎓 How to Use These Queries

### For SOC Analysts

**Step 1: Understand the Detection**
- Read the MITRE ATT&CK mapping
- Understand what attack this detects
- Know the severity and expected false positive rate

**Step 2: Deploy as Analytics Rule**
- Copy query to Sentinel Analytics
- Set appropriate frequency (1 hour, 5 min, etc.)
- Configure alert actions (email, Logic App, SOAR)

**Step 3: Tune for Your Environment**
- Run query in Logs to see baseline
- Adjust thresholds to reduce false positives
- Add exceptions for known legitimate activity

**Step 4: Create Response Playbook**
- Document what to check when alert fires
- Create SOAR playbook for automated response
- Define escalation criteria

### For Threat Hunters

**Step 1: Understand the Hunt Hypothesis**
- What behavior are you looking for?
- What data sources are required?
- What time range makes sense?

**Step 2: Run Query Interactively**
- Start with broad query, then narrow
- Visualize results to spot patterns
- Pivot to related data sources

**Step 3: Iterate and Refine**
- Adjust time ranges and thresholds
- Look for anomalies in results
- Document findings

### For Detection Engineers

**Step 1: Review Query Logic**
- Understand each operator and filter
- Verify MITRE mapping is correct
- Check for performance issues

**Step 2: Optimize Performance**
- Use summarize early in query
- Leverage query best practices
- Test with different time ranges

**Step 3: Validate Detection**
- Test with known attack scenarios
- Measure false positive rate
- Document tuning decisions

---

## 🛠️ Query Optimization Tips

### Performance Best Practices

**1. Filter Early**
```kql
// ❌ BAD - Processes entire table first
SigninLogs
| summarize count() by UserPrincipalName
| where TimeGenerated > ago(1h)

// ✅ GOOD - Filters first, processes less data
SigninLogs
| where TimeGenerated > ago(1h)
| summarize count() by UserPrincipalName
```

**2. Use Specific Columns**
```kql
// ❌ BAD - Returns all columns
SigninLogs | where TimeGenerated > ago(1h)

// ✅ GOOD - Returns only needed columns
SigninLogs
| where TimeGenerated > ago(1h)
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType
```

**3. Leverage Summarize**
```kql
// ❌ BAD - Expensive join
SigninLogs
| join kind=inner (AuditLogs) on UserPrincipalName

// ✅ GOOD - Pre-aggregate before join
SigninLogs
| summarize LogonCount = count() by UserPrincipalName
| join (AuditLogs | summarize AuditCount = count() by UserPrincipalName) on UserPrincipalName
```

---

## 💰 Cost Optimization

### Reduce Log Analytics Costs

**1. Sample Data for Testing**
```kql
// Use sample() for development/testing
SigninLogs
| sample 1000  // Test with 1000 random rows
| where ResultType != 0
```

**2. Archive Old Logs**
```kql
// Move to cheaper storage after 90 days
// Configure in Log Analytics workspace settings
```

**3. Use Basic Logs for Low-Value Data**
```kql
// Configure tables as Basic Logs tier
// 80% cost reduction for suitable tables
```

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md).

**How to contribute:**
1. Fork the repository
2. Create query in appropriate category folder
3. Follow query structure template
4. Test query in your Sentinel environment
5. Submit pull request with query + documentation

**What we're looking for:**
- Production-tested queries (not theoretical)
- Clear MITRE ATT&CK mapping
- Tuning guidance included
- Low false positive rate
- Real-world use cases

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file.

---

## 🙋 Need Help?

**Free Resources:**
- 📖 [Complete Sentinel Guide](https://mhartson.com/insights/sentinel-analytics-rules)
- 📥 [Cloud Security Starter Kit](https://mhartson.com/resources/starter-kit)
- 💬 [Hartson Security Guild Community](https://hartson-security-guild.circle.so)

**Professional Services:**
- 🔍 Sentinel deployment and configuration
- 📊 Custom detection rule development
- 🎓 SOC analyst training
- 🏗️ SIEM architecture design

**[Book a Sentinel consultation →](https://mhartson.com/consulting)**

---

## 📈 Statistics

- **500+ Queries** across all MITRE ATT&CK techniques
- **Production-tested** in enterprise SOCs
- **Low false positive rate** (<5% for most queries)
- **Regular updates** as new threats emerge

---

## 🔗 Related Projects

- [Azure-Landing-Zones](https://github.com/mhartson310/Azure-Landing-Zones) - Infrastructure for hosting Sentinel
- [FedRAMP-Azure-Toolkit](https://github.com/mhartson310/FedRAMP-Azure-Toolkit) - Compliance automation including SI-4
- [Azure-Security-Baseline](https://github.com/mhartson310/Azure-Security-Baseline) - Security hardening templates

---

**Built with 🔍 by [Mario Hartson](https://mhartson.com)** | Cloud Security Architect | Detection Engineer

📧 mario@hartsonadvisory.com | 💼 [LinkedIn](https://linkedin.com/in/mariohartson) | 🌐 [mhartson.com](https://mhartson.com)
