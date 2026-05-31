# FINDINGS: AWS KMS Constitutional Analysis
*Wave 8 — System 37 · EAR ceiling: CRYSTALLIZED · KMS governance depends on CloudTrail · Fingerprint: `72d83d52216d1425`*

## Executive Finding
AWS KMS is the cryptographic governance primitive underlying the entire AWS encryption stack. S3 SSE-KMS, EBS encryption, Secrets Manager, RDS encryption, and CloudTrail log encryption all depend on KMS keys. The key policy is the primary access control mechanism — unlike IAM resources, KMS key policies are evaluated first, and IAM policies cannot grant access that a restrictive key policy denies.

KMS governance quality depends entirely on CloudTrail being enabled: all KMS API calls (Encrypt, Decrypt, GenerateDataKey, ScheduleKeyDeletion) are recorded in CloudTrail. When CloudTrail is disabled, KMS governance is ABSENT — the keys may operate correctly but no receipt exists.

## BYOK Ransomware: KMS as Attack Surface
The most significant recent development is the use of KMS-native features for ransomware. In the Codefinger ransomware campaign (January 2025), attackers used SSE-C (Server-Side Encryption with Customer-Provided Keys) — not KMS CMKs — to re-encrypt S3 objects with attacker-controlled key material, then deleted the key material. AWS does not retain SSE-C keys, making decryption permanently impossible.

This is not a KMS vulnerability — it is a KMS governance gap: SSE-C provides no Object Lock equivalent for the encryption key. The "kill switch" value of KMS (the ability to disable a key to block access during a security incident) becomes an attack weapon when used by the attacker: schedule key deletion with a 7-day window, demand payment within 7 days.

## Real-World Incident Mapping
Codefinger ransomware (January 2025): targeted AWS environments with leaked credentials, used SSE-C to re-encrypt S3 objects, scheduled KMS key deletion. Organizations that detected the attack via CloudTrail KMS events within the 7-30 day pending deletion window could cancel the deletion; organizations without CloudTrail S3 data events could not identify which objects were affected.

KMS key with `Principal: *` misconfiguration: a KMS key with an unrestricted key policy is effectively public — any AWS principal including those in other accounts can use it. CIS Benchmark flags this as one of the most severe KMS misconfigurations. The key policy layer is CRYSTALLIZED (evaluated) but the content of the policy may grant overly broad access.

## The Add-On: `kms-governance-enforcer`
Key policy auditor and rotation enforcer. Validates no `Principal: *` without conditions; enforces key rotation enabled; validates deletion protection in key policy for CMKs; alerts on ScheduleKeyDeletion/DisableKey events; validates cross-account access restricted; produces `kms_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| encrypt_decrypt | CRYSTALLIZED | Key policy evaluated; CloudTrail records |
| key_management | CRYSTALLIZED | Pending deletion is constitutive but cancellable |
| key_policy_management | CRYSTALLIZED | Policy changes logged; content may be overly broad |
| grant_management | CRYSTALLIZED | Grants auditable via CloudTrail |
| key_deletion | CRYSTALLIZED | 7-30 day pending period; cancellable |
