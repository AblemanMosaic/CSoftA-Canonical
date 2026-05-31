# FINDINGS: AWS CloudTrail Constitutional Analysis
*Wave 8 — System 36 · EAR ceiling: CRYSTALLIZED · Fingerprint: `656fb3fca68867ae`*

## Executive Finding
AWS CloudTrail is the governance-of-governance case for the AWS ecosystem. Every audit receipt in the AWS corpus — IAM operations (Wave 4), S3 data events (Wave 6), KMS API calls (Wave 8), Identity Center logins (Wave 7) — depends on CloudTrail being enabled and delivering logs. CloudTrail is the substrate of the AWS audit layer, and it can be disabled by any principal with `cloudtrail:StopLogging` permission.

Disabling CloudTrail is MITRE ATT&CK T1562.008 — Impair Defenses: Disable Cloud Logs — the canonical AWS defense evasion step. Every attacker operating in a compromised AWS environment targets CloudTrail as a first step. No CloudTrail family reaches ACTIVE because the audit log can always be disabled by a sufficiently privileged principal.

## Data Events: ABSENT by Default
Management events (resource creation, modification, deletion) are logged by CloudTrail for free. Data events (S3 GetObject, PutObject, DeleteObject; Lambda Invoke) are not logged by default and require explicit configuration with additional cost. This means that in the majority of AWS deployments, individual object-level access to S3 is not governed by CloudTrail. The Capital One breach (noted in Wave 6, T1694) was detectable only because Capital One had explicitly enabled S3 data events — confirming that this governance is opt-in, not default.

## Log File Integrity: Opt-In Hash Chain
CloudTrail log file validation creates a SHA-256 hash chain linking each log file to the previous, making post-hoc tampering detectable. But the hash chain is generated after the fact: an attacker who disables CloudTrail creates a logging gap (a period with no events), not a detectable tamper event. The gap between when CloudTrail was disabled and when it was re-enabled is permanently ungoverned.

## Real-World Incident Mapping
MITRE ATT&CK T1562.008 (Impair Defenses: Disable Cloud Logs): documented and actively used by attackers including APT groups. Multiple documented incidents where CloudTrail was disabled during ransomware or data exfiltration operations to prevent detection and forensic reconstruction.

CloudTrail log padding evasion (documented by Elastic Security): attackers pad IAM policy documents with whitespace to exceed CloudTrail's requestParameters logging size limit, causing critical policy details to be omitted from the log. The log entry exists but is incomplete — a NON_ACTIVATION at the log content completeness boundary.

Codefinger ransomware (January 2025): the post-incident analysis confirmed that organizations with CloudTrail S3 data events enabled could reconstruct the attack timeline precisely. Organizations without CloudTrail data events had no visibility into which S3 objects were affected, confirming the ABSENT data event gap and its operational consequence.

## The Add-On: `cloudtrail-governance-enforcer`
Governance-of-governance enforcer for CloudTrail. Alerts on StopLogging/DeleteTrail events; validates multi-region trail enabled; enforces log file validation; validates data events enabled for sensitive buckets; monitors log storage bucket for unauthorized modifications; produces `cloudtrail_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| management_event_logging | CRYSTALLIZED | Logs all mgmt events; trail can be disabled |
| data_event_logging | ABSENT (default) | S3/Lambda data events opt-in |
| log_integrity | CRYSTALLIZED | Hash chain detects tampering; not gaps |
| trail_governance | CRYSTALLIZED | Trail config changes logged; StopLogging possible |
| insight_detection | CRYSTALLIZED | Insights opt-in; anomaly detection post-hoc |
