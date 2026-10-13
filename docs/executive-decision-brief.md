# Executive Decision Brief — Sentinel / Defender XDR Operating Model

**Decision requested:** Approve a scoped detection-coverage and operations pilot before choosing a long-term SIEM/XDR operating model.  
**Audience:** SOC director, security engineering lead, IT/security sponsor, and finance partner  
**Status:** PROPOSED — no claim of live incident-handling effectiveness or cost savings

## 1. The Ask

Authorize the SOC and platform teams to compare a Defender XDR-led workflow, a Sentinel-led workflow, and an integrated approach against a prioritized set of threats. Approve a time box and cost cap **before** onboarding additional telemetry; do not approve automated destructive remediation in this phase.

## 2. Why Now

The repository contains [reviewable detections](../rules), [analytics-as-code](../deploy/bicep/zero-trust-analytics/README.md), and [response patterns](../deploy/playbooks/zero-trust/README.md). Their presence does **not** prove live detection fidelity, consistent incident ownership, accurate entity mapping, or safe remediation. Those are the decision-critical gaps before expansion or migration.

## 3. What It Costs

**Budget: not yet priced.** Estimate ingestion by source and table, retention, licensing, analytics, playbook execution, and engineer/analyst time using actual expected event volumes and dated prices. Include dual-run effort, tuning, on-call burden, and initiatives postponed while the pilot runs. No MTTR improvement or cost reduction is presumed.

## 4. Cost of Inaction

Without measured scenario coverage, analyst burden, and telemetry costs, leadership cannot responsibly compare operating models or approve a migration cutover. An untested decision could duplicate alerts or leave detection gaps undiscovered; its incidence and business cost have **not** been quantified.

## 5. What Happens Next

The SOC owner selects high-priority attack scenarios and baselines current response effort; platform/security engineering records connector requirements and a priced pilot plan. Run non-destructive test events, capture rule/incident and entity-mapping evidence, review false positives and costs, and report an architecture recommendation with cutover/rollback gates.

**Safety gate:** No destructive SOAR actions until target identity, approver verification, and independent post-action checks are tested.  
**Supporting detail:** [Architecture decision guide](decision-framework/README.md) · [Conditional-remediation decision model](../deploy/playbooks/zero-trust/conditional-remediation/decision-model.md) · [Zero Trust evidence register](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/blob/main/docs/validation/evidence/README.md).
