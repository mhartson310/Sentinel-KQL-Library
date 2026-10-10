# Architecture Decisions & Business Value — Sentinel and Defender XDR

**Status: Proposed decision guide, not a statement of live SOC performance.**

Use the [reusable framework](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/docs/decision-framework/architecture-decision-framework), [ADR template](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/docs/decision-framework/architecture-decision-framework/ADR-template.md), and [business-case template](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/tree/main/docs/decision-framework/architecture-decision-framework/business-case-template.md).

## Business objective

Reduce material detection gaps and improve incident triage without creating unsustainable alert volume, uncontrolled remediation or unbounded telemetry costs.

## SOC-ADR-001 — Defender XDR, Microsoft Sentinel, or both?

**Alternatives:**
- Defender XDR incident-centric security operations for onboarded Microsoft workloads;
- Sentinel as SIEM for multi-source collection, correlation, long-term investigations and broader SOC workflows;
- integrated operating model, with explicit incident ownership and duplicate-detection handling.

**Trade-offs:** connector coverage and cross-platform analytics versus ingestion cost, operational duplication, personnel skills, response pathways and integration complexity.

**Decision gates:** required data sources, retention/legal requirements, investigations, incident ownership, latency, cost model, analyst workflow and response permissions.

**Decision hypothesis:** Choose the simplest platform arrangement that meets verified detection and operational requirements—not a universal recommendation to deploy both.

## SOC-ADR-002 — Detection coverage vs ingestion volume

**Options:** broad default ingestion; use-case-driven onboarding; hybrid tiered ingestion/retention strategy.

**Trade-offs:** more data may improve investigations but drive costs and noise. Too little data loses necessary context.

**Measured criteria:** MITRE-mapped high-priority scenarios, telemetry prerequisites, detection success on test events, false-positive rates, retention constraints, ingestion volumes and query performance.

**Decision gate:** do not remove an essential evidence source solely to reach a budget target.

## SOC-ADR-003 — Automate triage or remediation?

**Options:** analyst-only review; automated context enrichment, labels and tasks; constrained remediation with human approval.

**Trade-off:** response speed versus blast radius of incorrect automated actions.

**Gate:** validate exact target identity, permission scope, approval provenance, recovery path, error-code-aware verification, and benign-change exclusions.

**Status:** first-stage and conditional playbooks are authored; destructive second-stage execution remains **unverified in an Azure environment**.

## SOC-ADR-004 — SIEM migration cutover gate

**Options:** big-bang migration; phased coexistence/dual-run; maintain incumbent while prerequisites are addressed.

**Decision hypothesis:** Prefer a phased, measurable cutover when business constraints allow, with explicit detection-parity and rollback gates.

**Validation:** compare test-event coverage, entity mapping, analytic fidelity, SOC handling, incident routing, retention and costs before approving cutover.

## Business value and TCO model

| Metric | Baseline required | Success evidence |
|---|---|---|
| Relevant detection coverage | Prioritized scenarios and existing detections | Test scenarios observed end to end |
| Mean triage effort | Representative analyst samples | Comparable incidents measured before/after |
| False positive burden | Alerts and analyst work by rule | Measured change after tuning |
| Data cost | Actual volume by table/tier/retention | Dated pricing × observed ingestion |
| Incident readiness | Ownership, routing, permissions, playbooks | Documented test incident outcomes |
| Migration risk | Existing visibility and cutover blockers | Approved rollback and parity checklist |

Never claim reduced MTTR or savings before collecting observed results.

## Supporting materials

[Detection library](../../rules) · [Zero Trust analytic rules](../../deploy/bicep/zero-trust-analytics/README.md) · [Automated triage](../../deploy/playbooks/zero-trust/README.md) · [Conditional-response decision model](../../deploy/playbooks/zero-trust/conditional-remediation/decision-model.md) · [Architecture validation runbook](https://github.com/mhartson310/Azure-Zero-Trust-Reference-Architectures/blob/main/docs/validation/zero-trust-end-to-end-runbook.md)

## Revisit triggers

Changes to Defender/Sentinel licensing and pricing, incident ownership, data sources, cloud footprint, regulatory retention, critical detections, and measured operational outcomes.
