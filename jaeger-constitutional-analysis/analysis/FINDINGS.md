# FINDINGS: Jaeger Distributed Tracing Constitutional Analysis
*Wave 16 — System 76 · EAR ceiling: CRYSTALLIZED · Fingerprint: `370a8c817aae5a17`*

## Executive Finding
Jaeger completes the distributed observability governance family alongside Prometheus (Wave 6, T1692) and OpenTelemetry (Wave 4, T1632): metrics governance + collection governance + tracing governance. Jaeger is ABSENT authentication by default in open-source deployments — the query UI and API are accessible to any network-reachable client.

The primary constitutional finding specific to distributed tracing: **PII in traces is ABSENT governance by default**. Trace spans capture distributed request context — which frequently includes HTTP request/response bodies, user identifiers, authentication tokens passed as headers, and database query parameters. This data flows from application instrumentation into the Jaeger backend with no mandatory redaction or filtering. The governance of this PII is substantially weaker than the application database holding the same data, despite the data being equivalent.

Jaeger is increasingly superseded in new deployments by the OpenTelemetry Collector (T1632) feeding a backend (Tempo, Jaeger, Zipkin). The constitutional analysis transfers to any tracing backend.

## The Add-On: `jaeger-governance-enforcer`
Validates auth configured; TLS on collectors; PII redaction rules in OTel processor chain; produces `jaeger_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| trace_ingestion | ABSENT (default) | No auth; PII ungoverned by default |
| trace_query | ABSENT (default) | Query API open; spans may contain secrets |
| backend_storage | CRYSTALLIZED | Governed by backend (ES/Cassandra) auth |
| sampling_governance | CRYSTALLIZED | Head/tail sampling policy configurable |
| pii_governance | ABSENT (default) | PII in spans ungoverned without processor |
