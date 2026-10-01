# Secure Enterprise RAG KQL

Reusable Microsoft Sentinel / Log Analytics hunting queries for secure enterprise RAG workloads.

These queries are mirrored from the architecture-focused repository:

https://github.com/mhartson310/Azure-Secure-Enterprise-RAG/tree/main/sentinel

Use the architecture repo for the telemetry schema, deployment context, threat model, and operational guidance. Use this library for reusable KQL and broader detection-engineering workflows.

## Queries

- `rag-authorization-denial-spike.kql`
- `rag-no-authorized-context.kql`
- `rag-query-volume-anomaly.kql`
- `rag-source-access-investigation.kql`
- `search-operation-review.kql`

## Expected telemetry

The RAG application queries assume structured JSON events in `ContainerAppConsoleLogs_CL` with JSON stored in `Log_s`.

The Search query assumes Azure AI Search diagnostic telemetry is available in `AzureDiagnostics`.

Adapt table/column names to your workspace if you use resource-specific tables or a different ingestion pattern.

## Detection principle

These queries identify behaviors worth investigation. They do not, by themselves, prove malicious activity.

The canonical architecture and telemetry design remain in the Secure Enterprise RAG repository so this KQL library can stay focused on detection content.
