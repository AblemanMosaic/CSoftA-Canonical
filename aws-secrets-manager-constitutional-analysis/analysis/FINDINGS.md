# FINDINGS: AWS Secrets Manager Constitutional Analysis
*Wave 9 — System 45 · EAR ceiling: CRYSTALLIZED · Fingerprint: `df58ce790f76cb8f`*

## Executive Finding
AWS Secrets Manager is the AWS-native managed secrets case, complementing HashiCorp Vault (Wave 1, T1652). The critical governance differentiator: Secrets Manager provides automatic secret rotation via Lambda functions — when rotation is configured, the secret is rotated on schedule without operator intervention. This is ACTIVE-adjacent: the rotation happens automatically, but is scheduled (not per-read), so the rotation event is CRYSTALLIZED in governance terms.

Secrets Manager has a KMS dependency chain (T1740 pattern): secrets are encrypted with KMS CMKs or AWS-managed keys. If the KMS CMK is compromised or deleted, encrypted secrets become inaccessible. The CloudTrail dependency (T1737) also applies: Secrets Manager governance depends on CloudTrail recording `GetSecretValue` calls.

## Vault Comparison
Vault (Wave 1, T1652) vs Secrets Manager:
- Vault: self-hosted, dynamic secrets (generated per-request), lease-based, ACTIVE for dynamic secret generation
- Secrets Manager: AWS-managed, static secrets with scheduled rotation, CRYSTALLIZED
- Both: audit trail depends on external logging (Vault audit log, CloudTrail for Secrets Manager)

## Real-World Incident Mapping
GuardDuty finding `CredentialAccess:Secrets/GetSecretValue` (AWS): GuardDuty detects when `GetSecretValue` is called from a known threat actor IP or unusual location — confirms that CloudTrail records secret access and GuardDuty can correlate it. The finding is CRYSTALLIZED: the secret was already read before the finding was generated.

Multiple AWS secrets incidents where `GetSecretValue` was called by compromised IAM credentials: without CloudTrail and GuardDuty, these reads are ungoverned. With CloudTrail data events for Secrets Manager (opt-in), the governance receipt exists but is CRYSTALLIZED.

Rotation gap: secrets that have never been rotated (rotation disabled) are permanent credentials — same risk as static API keys. CIS AWS Benchmark requires rotation enabled for all secrets.

## The Add-On: `secrets-manager-governance-enforcer`
Rotation enforcer and access monitor. Validates rotation enabled for all secrets; enforces CMK encryption; validates cross-account access restricted; monitors for unusual GetSecretValue patterns; produces `secrets_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| secret_read | CRYSTALLIZED | CloudTrail records; GuardDuty detects anomalies |
| secret_rotation | CRYSTALLIZED | Automatic rotation; scheduled not per-read |
| secret_management | CRYSTALLIZED | Policy + CloudTrail governance |
| cross_account_access | CRYSTALLIZED | Resource policy governs; scope may be broad |
| secret_policy_management | CRYSTALLIZED | Policy changes audited |
