# FINDINGS: Elasticsearch / OpenSearch Constitutional Analysis
*Wave 11 — System 51 · EAR ceiling: CRYSTALLIZED · Fingerprint: `7a9fd670c4aa40df`*

## Executive Finding
Elasticsearch is the governance evidence layer — the system where audit logs, security events, and governance receipts from other systems are stored and queried. This creates a constitutional multiplier: when Elasticsearch has ABSENT governance, every piece of governance evidence stored in it — SIEM alerts, CloudTrail-forwarded events, application audit logs — is simultaneously accessible and modifiable by any attacker who can reach port 9200. The governance gap in the evidence store multiplies into governance gaps for every system whose evidence it holds.

Default Elasticsearch (Community / dev mode): no authentication, no TLS, no audit log. Security features were proprietary until version 7.x; even in 8.x the single-node dev mode disables all security. This produced years of documented public Elasticsearch instances exposing millions of records — medical data, financial records, security event logs — accessible to any internet-connected client.

## New Constitutional Concept: Governance Evidence Storage Layer
The corpus previously identified governance-of-governance substrates (CloudTrail for AWS, RBAC for Kubernetes). Elasticsearch introduces a third class: the governance evidence storage layer — the system where governance receipts are sent for retention, search, and analysis. When this layer is ABSENT, the governance evidence itself is unprotected. An attacker who compromises Elasticsearch can not only read stored evidence but also modify or delete it, retroactively altering the governance record of past events.

## Real-World Incidents
Kaduu security team (November 2025): discovered publicly accessible Elasticsearch instance containing production-connected data with no authentication or access control — same core weakness documented hundreds of times since 2015. Elasticsearch's history of public instance disclosures is the most documented ABSENT-default pattern in enterprise software.

CVE-2025-37731 (Elasticsearch PKI realm auth bypass): crafted client certificates with legitimate CA signatures could impersonate any user — NON_ACTIVATION at the PKI certificate validation boundary. CVE-2020-7009 (privilege escalation): API key + authentication token combination allowed privilege escalation beyond declared scope — NON_ACTIVATION at the combined-credential scope boundary.

CVE-2024-12556 (Kibana, CVSS 8.7): prototype pollution leading to code injection when combined with file upload — BYPASS via JavaScript prototype chain.

## The Add-On: `elasticsearch-governance-enforcer`
Security configuration validator and access audit monitor. Validates authentication and TLS enabled; validates audit logging configured; validates RBAC roles follow least-privilege; monitors for unauthenticated access patterns; alerts on bulk document access from unusual principals; produces `es_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| document_index | ABSENT (default) | No auth, no TLS, no audit in default config |
| document_search | ABSENT (default) | Governance evidence storage fully open |
| index_management | ABSENT (default) | Cluster fully open without security stack |
| cluster_management | ABSENT (default) | Admin operations unprotected by default |
| api_key_management | ABSENT (default) | No key management governance by default |
