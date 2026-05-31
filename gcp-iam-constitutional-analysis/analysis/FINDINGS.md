# FINDINGS: GCP IAM / Cloud Audit Logs Constitutional Analysis
*Wave 13 — System 61 · EAR ceiling: CRYSTALLIZED · Fingerprint: `46bafa757de69558`*

## Executive Finding
GCP IAM completes the cloud provider triple alongside AWS IAM (Wave 4) and Azure Entra ID (Wave 11), and confirms two patterns from the existing corpus while introducing a GCP-specific gap form.

Admin Activity audit logs are always on and cannot be disabled — unlike AWS CloudTrail which requires enabling, GCP Admin Activity logging is unconditional. This is constitutionally stronger than AWS for administrative operations. However, Data Access audit logs (who read what data) are ABSENT by default — must be explicitly enabled per service per project. This replicates the CloudTrail data events gap (T1727) at GCP: data reads at scale are ungoverned unless Data Access logs are explicitly configured.

ImageRunner (Tenable, January 2025): identities with `run.services.update` and `iam.serviceAccounts.actAs` could deploy Cloud Run services that pull from private Artifact Registry without explicit registry read permission — NON_ACTIVATION at the permission scope boundary. Same constitutional form as Argo CD CVE-2025-55190 (T1674): governance layer evaluated, scope boundary of authorized permission was exploitable. Tag-based privilege escalation (Mitiga, March 2026): `tagUser + viewer` roles satisfy conditional IAM bindings via tag attachment, granting full admin without modifying IAM policies — NON_ACTIVATION at the conditional binding scope boundary.

## Real-World Incidents
ImageRunner (Tenable, January 2025): Cloud Run revision edit permissions allowed access to private registry images without explicit read role — NON_ACTIVATION at permission scope. Fully deployed as breaking change January 28, 2025. ConfusedFunction (2024): Cloud Build default service account granted escalation paths via Cloud Functions — same inter-service permission scope gap. Rhino Security Labs GCP-IAM-Privilege-Escalation: documented 30+ distinct privilege escalation paths via over-permissive IAM roles — all NON_ACTIVATION at IAM scope boundaries.

## The Add-On: `gcp-iam-governance-enforcer`
Data Access log enforcer and IAM escalation path detector. Validates Data Access logs enabled for all services; validates Organization Policy constraints applied; validates Workload Identity Federation replacing service account keys; detects conditional IAM bindings with tag-based escalation paths; produces `gcp_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| api_authorization | CRYSTALLIZED | Admin Activity always on; Data Access ABSENT default |
| data_access | ABSENT (default) | Data Access logs must be enabled per service |
| service_account_usage | CRYSTALLIZED | WIF available; SA keys remain common |
| organization_policy | CRYSTALLIZED | Constraints declared; enforcement gaps at boundaries |
| privilege_escalation_check | CRYSTALLIZED | Multiple NON_ACTIVATION paths documented |
