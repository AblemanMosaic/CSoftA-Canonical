# FINDINGS: AWS GuardDuty Constitutional Analysis
*Wave 9 — System 42 · EAR ceiling: CRYSTALLIZED · Fingerprint: `bee971f5d3e100ea`*

## Executive Finding
AWS GuardDuty completes the AWS security triad: CloudTrail (T1722, audit governance), KMS (T1723, cryptographic governance), GuardDuty (threat detection governance). It is meta-governance case 4 in the corpus (after OTel Wave 4, Falco Wave 5, Prometheus Wave 6). GuardDuty detects threats by analyzing CloudTrail events, VPC Flow Logs, DNS queries, and runtime telemetry from EKS and ECS workloads. All findings are CRYSTALLIZED: GuardDuty cannot prevent the events it detects, only alert after them.

GuardDuty can be disabled — MITRE ATT&CK T1562.008 (Impair Defenses: Disable Cloud Logs) applies identically to GuardDuty as to CloudTrail. An attacker who disables GuardDuty creates a detection gap. Extended Threat Detection (December 2024): correlates multiple signals into critical-severity attack sequence findings, but the correlation is still post-hoc.

## Real-World Incident Mapping
November 2025 cryptomining campaign (AWS and The Hacker News reporting): GuardDuty Extended Threat Detection identified an active cryptomining campaign using compromised IAM credentials. The campaign deployed miners across ECS and EC2 within 10 minutes of initial access. GuardDuty correlated suspicious discovery API calls, DryRun permission probing, and unusual resource creation into a critical-severity attack sequence finding — confirming that Extended Threat Detection operates as designed (CRYSTALLIZED: detected the attack, could not prevent it).

GuardDuty Defense Evasion findings (DefenseEvasion:IAMUser/AnomalousBehavior): GuardDuty detects anomalous API calls consistent with defense evasion tactics, including attempts to disable GuardDuty itself. This is the meta-governance pattern: GuardDuty detects attempts to disable GuardDuty — but only if GuardDuty has not been disabled first.

## The Add-On: `guardduty-governance-enforcer`
Detector health monitor and finding automation. Validates detector enabled in all regions; alerts on detector disable/suspend events; configures EventBridge rules for automated remediation; enables S3 Protection and EKS/ECS protection plans; produces `guardduty_posture.json` with coverage map.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| threat_detection | CRYSTALLIZED | Post-hoc findings; detector can be disabled |
| finding_delivery | CRYSTALLIZED | Delivery to Security Hub / EventBridge |
| detector_governance | CRYSTALLIZED | Config changes audited; disable possible |
| extended_threat_detection | CRYSTALLIZED | Multi-stage correlation; still post-hoc |
| s3_protection | CRYSTALLIZED | S3 data plane monitoring; opt-in plan |
