# Contributing to Sentinel KQL Library

Thank you for your interest in contributing! This library aims to provide production-quality KQL queries for Microsoft Sentinel.

## 🤝 How to Contribute

### Reporting Issues

- Search existing issues first
- Provide query details: query name, data source, expected vs actual behavior
- Include sample data/results if possible
- Tag appropriately (bug, enhancement, question)

### Suggesting New Queries

We welcome new detection rules! Before submitting:

1. **Check if it already exists** - Search the repository
2. **Test in production** - Query should be validated in real Sentinel environment
3. **Verify low false positives** - Aim for <20% false positive rate
4. **Map to MITRE ATT&CK** - Include technique ID and tactic

### Submitting Queries

1. **Fork the repository**

2. **Create a feature branch**
```bash
   git checkout -b feature/credential-access-kerberoasting
```

3. **Create your query file**
   - Use the query template (see below)
   - Place in appropriate category folder
   - Follow naming convention: `attack-technique-description.kql`

4. **Test thoroughly**
   - Run in your Sentinel environment
   - Verify it detects the intended behavior
   - Document any false positives encountered
   - Include tuning recommendations

5. **Commit with clear message**
```bash
   git commit -m "Add Kerberoasting detection query (T1558.003)"
```

6. **Push and create Pull Request**
```bash
   git push origin feature/credential-access-kerberoasting
```

7. **Describe your PR**
   - What does the query detect?
   - Why is it valuable?
   - What testing did you perform?
   - Any known limitations or false positives?

---

## 📝 Query Template

Every query must follow this structure:

```kql
// ============================================
// QUERY METADATA
// ============================================
// Name: [Clear, descriptive name]
// MITRE ATT&CK: [T1234 - Technique Name]
// Severity: [Critical/High/Medium/Low]
// Frequency: [How often to run: Every 5m, 1h, etc.]
// Tactics: [Initial Access, Persistence, etc.]
// Data Sources: [SigninLogs, SecurityEvent, etc.]
// False Positive Rate: [Low/Medium/High with %]
// Author: [Your Name]
// Website: [Optional]
// ============================================

// DESCRIPTION:
// [2-3 sentences explaining what this detects and why it matters]
//
// [Optional: List specific attack patterns detected]

// TUNING GUIDANCE:
// 1. [Specific tuning recommendation]
// 2. [Another tuning recommendation]
// 3. [Environment-specific adjustments]

// FALSE POSITIVES:
// - [Common false positive scenario 1]
// - [Common false positive scenario 2]
// - [How to exclude legitimate activity]

// RESPONSE ACTIONS:
// 1. [First step when alert fires]
// 2. [Second step]
// 3. [Additional investigation steps]

// REAL-WORLD CASE STUDY: (Optional but encouraged)
// [Brief story of how this query detected a real attack]

// THE QUERY:
[Your KQL query here]

// ADDITIONAL HUNTING: (Optional)
// [Related queries for further investigation]
```

---

## 🎯 Query Quality Standards

### Required Elements

- ✅ **Clear metadata** - All metadata fields completed
- ✅ **MITRE mapping** - Correct technique ID
- ✅ **Tested in production** - Verified in real Sentinel environment
- ✅ **Tuning guidance** - Help users customize for their environment
- ✅ **False positive guidance** - Document known FPs and how to handle
- ✅ **Response actions** - What to do when it triggers

### Code Quality

- ✅ **Efficient** - Use filters early, avoid unnecessary operations
- ✅ **Readable** - Clear variable names, comments where needed
- ✅ **Parameterized** - Use variables for thresholds (easy to tune)
- ✅ **Performant** - Test with large datasets, optimize if needed

### Example - Good Query Structure

```kql
// Metadata (complete and accurate)
let TimeWindow = 15m;  // Parameterized
let FailureThreshold = 10;  // Easy to adjust

SigninLogs
| where TimeGenerated > ago(TimeWindow)  // Filter early
| where ResultType != 0  // Only failures
| summarize 
    FailCount = count(),
    Users = make_set(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 5m)
| where FailCount > FailureThreshold  // Apply threshold
| extend Severity = iff(FailCount > 50, "High", "Medium")
| project TimeGenerated, IPAddress, FailCount, Users, Severity
```

---

## 📂 Repository Structure
