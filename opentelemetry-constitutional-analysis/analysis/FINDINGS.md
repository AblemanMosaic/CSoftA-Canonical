# FINDINGS: OpenTelemetry Collector Constitutional Analysis
*Wave 4 — System 18 · EAR ceiling: CRYSTALLIZED · Fingerprint: `da4498de15bec79b`*

## Executive Finding
The OpenTelemetry Collector is the corpus's meta-governance case: it is the system that collects and routes the observability data (traces, metrics, logs) that other systems use as their governance evidence. The Collector's own governance surface is CRYSTALLIZED throughout. The profound constitutional finding: the system whose purpose is to govern governance data has governance gaps in its own operation.

Silent span drops under queue pressure — the most common operational failure mode — produce no receipt recording that the drop occurred. The governance data for all downstream systems is degraded with no record of the degradation. This is STRUCTURAL_NONLOCALITY applied to the observability pipeline itself: the governance state of the entire stack cannot be reconstructed from the Collector's own artifacts because some governance events were silently dropped before they reached the Collector's output.

## The Meta-Governance Gap
The Collector occupies a unique position: it is itself a governance system (it collects governance data) but has governance gaps in its own operation. This is a second-order application of the Wave 2 finding (governance technology has EAR states). The OTel Collector is governance technology for governance technology — and its EAR state is CRYSTALLIZED.

Every gap in the Collector's own governance multiplies into gaps in the governance evidence of every system the Collector observes. A Collector drop gap is not one governance event missing — it is a potential gap in the audit trail of every system whose telemetry passes through that Collector pipeline.

## Primary Gap: Drop Logging Not Default
When the Collector's queue fills (under high load, slow exporter, or exporter failure), spans are dropped. The `obsreport` processor can log drops, but it is not enabled by default. Without drop logging, there is no record of what was lost — the governance evidence gap itself is ungoverned.

## Real-World Incident Mapping
The SolarWinds attack (2020): the attacker specifically targeted monitoring and observability infrastructure to avoid detection. While the OTel Collector did not exist in its current form at that time, the constitutional pattern is exact: an attacker who can cause the observability pipeline to drop spans covering their activity achieves governance absence with no record of the absence. Drop-based evasion is structurally equivalent to the Collector's silent drop gap.

OTel Collector queue overflow in production: widely documented operational experience — under load spikes, Collectors drop spans silently, metrics are missing from dashboards, and SRE teams discover that their SLI measurements are based on incomplete data. The constitutional finding: governance decisions (alerting, SLO compliance) made on Collector output are made on potentially incomplete governance evidence.

## The Add-On: `otel-governance-auditor`

A Collector extension and sidecar that receipts the Collector's own governance operations. (1) Intercepts all drop events and writes structured drop receipts (timestamp, reason, span count, affected service, pipeline name) — making the governance evidence gap itself a governance event. (2) Logs every sampling decision with policy name and reason — distinguishes sampled-out from dropped from never-generated. (3) Tracks Collector configuration hashes on startup and every reload — writes configuration change receipt exported as metric and structured log. (4) Exposes governance health endpoint: queue depth, drop rate, exporter backpressure, sampling rate, config hash. (5) Produces gap assertions in CSoftA format for any period where drop rate exceeds configured threshold. Closes the meta-governance gap: the system governing governance data now has constitutive receipts for its own operations.

## Summary
| Family | EAR State | Key gap |
|--------|-----------|---------|
| telemetry_ingestion | CRYSTALLIZED | Receiver ACK not default |
| telemetry_processing | CRYSTALLIZED | Drop log not default |
| telemetry_export | CRYSTALLIZED | Exporter ACK not default |
| pipeline_management | CRYSTALLIZED | Config hash tracking not default |
| sampling_decision | CRYSTALLIZED | Sampling decisions not receipted |
