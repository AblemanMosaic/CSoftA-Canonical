# FINDINGS: Grafana Constitutional Analysis
*Wave 14 — System 70 · EAR ceiling: CRYSTALLIZED · Fingerprint: `3f83fd761056a3f0`*

## Executive Finding
Grafana is the visualization and alerting layer over Prometheus, Loki, Tempo, Elasticsearch, and dozens of other backends. It completes the observability stack alongside Prometheus (Wave 6, T1692) and OpenTelemetry (Wave 4, T1632). The constitutional significance: Grafana stores credentials for every backend it queries. Data source configurations include Prometheus URLs, CloudWatch access keys, Elasticsearch passwords, Azure Monitor credentials, and similar backend authentication materials. The observability frontend is simultaneously a credential store for the entire monitoring infrastructure.

This introduces a new constitutional concept: visualization layer as credential store. Compromising Grafana achieves two things simultaneously: read access to all observability data (security events, metrics, logs from every monitored system) and the credentials to access every backend directly. It is the second meta-governance layer the corpus has identified, after Splunk (Wave 13, T1802) and Elasticsearch (Wave 11, T1782), where compromise of the governance evidence layer also yields backend access.

CVE-2025-3260 (dashboard API auth bypass): Grafana's new Dashboard API (`/apis/dashboard.grafana.app/*`) endpoints bypassed folder and dashboard permission checks. Viewers gained read access to all dashboards regardless of folder permissions. The permission model was CRYSTALLIZED (it existed and was evaluated); the new API path was a scope boundary that the permission model did not cover — NON_ACTIVATION at the API endpoint permission boundary.

CVE-2024-1442 (data source wildcard UID): a user with permission to create data sources could set the UID to `*`, granting access to read/query/edit ALL data sources — including their stored credentials. NON_ACTIVATION at the UID validation boundary.

## Real-World Incidents
CVE-2025-3260 (2025): dashboard permission bypass via new API path. CVE-2024-1442 (March 2024): data source wildcard giving credential access to all sources. CVE-2024-1313 (BOLA, 2024): snapshot cross-organization delete via known snapshot key. CVE-2024-9264: SQL injection via DuckDB experimental plugin leading to RCE. The pattern: Grafana's expanding feature surface (new APIs, plugins, integrations) introduces permission bypass vulnerabilities recurrently.

## The Add-On: `grafana-governance-enforcer`
Data source credential scope enforcer and dashboard permission auditor. Validates data source credentials use service accounts with least privilege; validates folder permissions correctly scope dashboard visibility; monitors for credential access via wildcard patterns; produces `grafana_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| dashboard_access | CRYSTALLIZED | RBAC exists; CVE-2025-3260 bypass class recurrent |
| datasource_query | CRYSTALLIZED | Data source RBAC opt-in; credentials accessible |
| datasource_management | CRYSTALLIZED | CVE-2024-1442 wildcard UID bypass class |
| alert_governance | CRYSTALLIZED | Alert rule access controlled by RBAC |
| admin_operation | CRYSTALLIZED | Audit log opt-in; admin ops ungoverned by default |
