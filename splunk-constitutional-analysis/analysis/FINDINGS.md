# FINDINGS: Splunk SIEM Constitutional Analysis
*Wave 13 — System 63 · EAR ceiling: CRYSTALLIZED · Fingerprint: `d0498d59f114d814`*

## Executive Finding
Splunk is the most widely deployed commercial SIEM — the system where governance evidence from all other systems is indexed, searched, and acted upon. Like Elasticsearch (Wave 11, System 51), Splunk is a governance evidence meta-layer. This extends the observability governance trilogy (T1701: OTel + Falco + Prometheus) with a fourth meta-governance case: Splunk stores and governs the governance evidence from the entire security stack.

Splunk's constitutional position is different from Elasticsearch in one critical respect: it is a high-value target with elevated runtime privileges. CVE-2026-20140 (February 2026, CVSS 7.7): Splunk Enterprise running as SYSTEM on Windows; DLL hijacking by low-privileged local user gains SYSTEM privileges. The SIEM itself becomes the escalation target — and the escalation provides SYSTEM-level access alongside all indexed security evidence. Compromising Splunk simultaneously achieves: (1) access to all indexed security events from every monitored system, (2) ability to create false detections or suppress real ones by modifying saved searches and alerts, (3) SYSTEM-level privilege escalation.

The Universal Forwarder is the most critical governance surface. It runs on every monitored host with elevated privileges. An attacker with access to `inputs.conf` on any forwarder can selectively stop forwarding their own activity — achieving governance evidence absence for a specific source without any change to Splunk's central configuration.

## Real-World Incidents
CVE-2026-20140 (February 2026, DLL hijacking → SYSTEM): Splunk splunkd runs as SYSTEM on Windows; low-privileged local user creates malicious DLL in predictable path; SYSTEM access gained on Splunk restart. CVE-2025-20386/20387 (December 2025): incorrect file permissions allow non-admin privilege escalation on Windows during installation/upgrade. Multiple SIEM-targeting APT incidents: documented threat actors specifically targeting SIEM infrastructure to disable logging before attacks — confirming the meta-governance gap where disabling the SIEM achieves evidence absence across the entire monitored fleet.

## The Add-On: `splunk-governance-enforcer`
Forwarder integrity monitor and SIEM self-governance layer. Monitors Splunk service account privileges (should not run as SYSTEM); validates Universal Forwarder inputs.conf integrity; validates TLS on all Splunk communications; monitors for search activity from unusual users against security indexes; produces `splunk_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| search_execution | CRYSTALLIZED | Evidence follows events; RBAC governs access |
| data_ingestion | CRYSTALLIZED | Forwarder auth + TLS; inputs.conf governs coverage |
| alert_action | CRYSTALLIZED | Alert triggers after detection; not constitutive |
| forwarder_management | CRYSTALLIZED | Forwarder compromise = evidence gap for that host |
| admin_operation | CRYSTALLIZED | Audit log opt-in; SIEM as escalation target |
