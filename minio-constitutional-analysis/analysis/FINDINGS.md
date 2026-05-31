# FINDINGS: MinIO Constitutional Analysis
*Wave 14 — System 68 · EAR ceiling: CRYSTALLIZED · Fingerprint: `04cbd4a7645172b7`*

## Executive Finding
MinIO is the self-hosted analog of AWS S3 (Wave 6, T1694), and the constitutional comparison reveals exactly what the AWS security backstop provides. AWS S3 is backed by GuardDuty (anomaly detection), CloudTrail (unconditional audit), Config (drift detection), and AWS IAM (centralized identity governance). MinIO deployed alone must self-manage all of these. The governance gap is not the absence of mechanisms — MinIO has IAM policies, TLS, bucket versioning, Object Lock, and configurable audit logging — but the absence of the backstop layer that provides detection and monitoring even when MinIO itself is compromised.

CVE-2025-31489 (April 2025, CISA KEV): HMAC signature validation bypass — valid access-key with arbitrary wrong secret passes authorization, allowing arbitrary object writes. BYPASS at the signature validation boundary. The authentication credential is accepted even when the signature is invalid.

CVE-2026-03-17 (March 2026): OIDC JWT algorithm confusion — an attacker knowing the OIDC ClientSecret can forge arbitrary identity tokens and obtain S3 credentials with any policy including `consoleAdmin`. BYPASS at the OIDC token validation boundary — affects all MinIO versions from a 2022 release through March 2026.

Evil MinIO (2023, CISA KEV, active exploitation): CVE-2023-28432 disclosed environment variables including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`; combined with CVE-2023-28434 to redirect the update URL to attacker-controlled server; MinIO replaced its own binary with a backdoored version. Binary update integrity governance: ABSENT.

## The Add-On: `minio-governance-enforcer`
Audit webhook configurator and signature validation monitor. Validates audit log webhook configured; validates TLS on all MinIO connections; validates Object Lock for compliance retention; monitors for signature anomalies (CVE-2025-31489 class); produces `minio_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| object_put | CRYSTALLIZED | Auth + IAM; no AWS backstop; audit opt-in |
| object_get | CRYSTALLIZED | Same as put; CVE-2025-31489 bypass class |
| bucket_management | CRYSTALLIZED | IAM evaluated; audit opt-in |
| object_lock | CRYSTALLIZED | Governance/Compliance mode available |
| iam_management | CRYSTALLIZED | CVE-2025-62506 session policy bypass; CVE-2026-03-17 OIDC |
