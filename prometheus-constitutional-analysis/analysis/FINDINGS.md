# FINDINGS: Prometheus / Alertmanager Constitutional Analysis
*Wave 6 — System 30 · EAR ceiling: CRYSTALLIZED · Fingerprint: `4350ffbb45eacbba`*

## Executive Finding
Prometheus completes the observability governance trilogy with OpenTelemetry (Wave 4, T1632) and Falco (Wave 5, T1672). All three are meta-governance systems — they govern the governance data that other systems use for operational and security decisions — and all three have governance gaps in their own operation.

Prometheus has no authentication by default for its HTTP API or scrape endpoints. The default deployment exposes `/metrics`, `/api/v1/query`, and the Alertmanager API without any authentication requirement. Any process that can reach the Prometheus port can query all metrics, modify alert silences, and read all Prometheus configuration — ABSENT access governance by default.

Missed scrapes complete the meta-governance gap: when a scrape target is unavailable, the metric is absent from the time series. Prometheus cannot distinguish "the service is down" from "the scrape failed" from "the network path was unreachable" from its own data alone — STRUCTURAL_NONLOCALITY at the scrape failure level. Organizations making SLO compliance decisions based on Prometheus data may be making those decisions on incomplete governance evidence.

## The Observability Governance Trilogy
Three systems complete the trilogy of observability meta-governance gaps:
- **OpenTelemetry Collector (Wave 4)**: silent span drops with no receipt; drop gap is itself ungoverned
- **Falco (Wave 5)**: security alerts follow events, not constitute them; alert delivery gap
- **Prometheus (Wave 6)**: no default authentication; missed scrapes indistinguishable from target failure

All three systems are used as governance evidence for other systems. All three have governance gaps in their own operation. The constitutional implication: governance evidence produced by these systems is conditionally reliable — reliable when the systems are functioning and governed themselves, unreliable when they are not.

## Real-World Incident Mapping
Prometheus exposed metrics information disclosure (multiple incidents, 2019-2024): publicly accessible Prometheus instances have been discovered exposing internal service topology, request rates, error rates, and in some cases business-sensitive metrics. Prometheus `/federate` endpoint has been used to scrape metrics from internal Prometheus instances when exposed. ABSENT authentication gap confirmed operationally.

CVE-2019-3826 (Prometheus path traversal via redirect, CVSS 6.1): the Prometheus web interface allowed a redirect that could be used to exfiltrate files from the Prometheus host via the query API. The API access governance was ABSENT (no authentication) — the path traversal was exploitable precisely because there was no authentication layer to validate the requester.

Alertmanager webhook receiver exposure: Alertmanager's webhook receiver configuration can expose internal service URLs and alert routing rules. When Alertmanager is exposed without authentication, an attacker can enumerate alert routing, add silences to suppress security alerts, or exfiltrate the alert routing configuration. The CRYSTALLIZED alert delivery classification is confirmed: silencing a Prometheus alert achieves monitoring absence — the governance condition (alert firing) is suppressed without any meta-alert.

## The Add-On: `prometheus-governance-auditor`
Authentication enforcer and meta-governance layer for Prometheus. Validates basic auth or mTLS configured for all Prometheus endpoints; monitors for Prometheus API exposure without authentication; tracks rule version and config hash on reload; monitors for alert silences created outside declared workflows; produces `prom_posture.json` with authentication and coverage status.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| metric_scrape | ABSENT (default) / CRYSTALLIZED | No default authentication; missed scrape indistinguishable |
| alert_evaluation | ABSENT (default) / CRYSTALLIZED | Rule version tracking opt-in |
| alert_delivery | ABSENT (default) / CRYSTALLIZED | Delivery may fail; silences can suppress |
| api_query | ABSENT (default) | No authentication by default |
| config_management | CRYSTALLIZED | Config changes not mandatorily receipted |
