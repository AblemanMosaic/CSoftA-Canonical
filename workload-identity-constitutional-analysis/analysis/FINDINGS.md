# FINDINGS: Workload Identity Constitutional Analysis
*Wave 9 — System 44 · credential_exchange: ACTIVE · role_assumption: ACTIVE · Fingerprint: `0e853df656846ad6`*

## Executive Finding
Workload Identity (AWS IRSA, GKE Workload Identity, Azure Workload Identity) is the runtime pod-to-cloud identity federation mechanism that closes the long-lived credential gaps identified across the corpus. Instead of mounting cloud credentials as Kubernetes Secrets, pods receive short-lived OIDC tokens projected by Kubernetes, which are exchanged for cloud provider temporary credentials via STS AssumeRoleWithWebIdentity (AWS) or equivalent.

Both `credential_exchange` and `role_assumption` are ACTIVE: the OIDC token is constitutive of the credential exchange — without a valid projected ServiceAccount token, the cloud provider's STS endpoint rejects the request. This is the credential-as-receipt pattern (T1619) applied at the pod-to-cloud boundary.

## Closing Multiple Prior Gaps
Workload Identity directly closes three previously-identified gaps:
- **T1731** (Crossplane provider credential over-privilege): Workload Identity eliminates long-lived credentials in Kubernetes Secrets; Provider controllers receive short-lived OIDC-based credentials
- **T1724** (Argo Workflows SA scope gap): workflows using Workload Identity receive scoped cloud credentials without needing broad SA permissions to access Secrets
- **T1671** (Terraform provider credentials in state): with IRSA, Terraform/OpenTofu providers receive credentials via OIDC token, not from state-stored secrets

## Real-World Incident Mapping
Multiple cloud breaches where Kubernetes Secrets containing cloud credentials were stolen: AWS access keys in Secrets, GCP service account JSON in Secrets. In every case, Workload Identity would have prevented the credential theft — short-lived OIDC tokens in projected volumes cannot be extracted and reused after expiry. The Toyota telematics breach (Wave 6, T1694) involved cloud storage credentials; Workload Identity scoped to the specific application SA would have prevented broad access.

IAM trust policy misconfiguration (documented across cloud providers): overly broad trust policies (allowing any SA in any namespace) negate the namespace-scoping benefit. The constitutional gap shifts from "credentials in Secrets" to "trust policy scope" — from a secret exfiltration gap to a scope boundary gap.

## The Add-On: `workload-identity-governance-enforcer`
Trust policy auditor and OIDC configuration validator. Validates OIDC issuer configured; validates trust policies restrict to specific namespace/SA combinations; validates token expiry short; monitors for overly broad trust policies; produces `workload_identity_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| credential_exchange | **ACTIVE** | OIDC token constitutive of cloud creds |
| sa_annotation | CRYSTALLIZED | RBAC governs annotation |
| token_projection | CRYSTALLIZED | Token lifetime and audience governed |
| role_assumption | **ACTIVE** | STS AssumeRoleWithWebIdentity constitutive |
| trust_policy_governance | CRYSTALLIZED | Trust policy scope may be overly broad |
