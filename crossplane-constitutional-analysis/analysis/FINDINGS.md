# FINDINGS: Crossplane Constitutional Analysis
*Wave 8 — System 40 · drift_reconciliation: ACTIVE · Fingerprint: `2993063160dcf1a2`*

## Executive Finding
Crossplane is the Kubernetes-native IaC governance case, complementing Terraform (Wave 5, T1671). The constitutional distinction is significant: Crossplane eliminates Terraform's state drift ABSENT gap (T1684). Crossplane continuously reconciles — if a cloud resource is modified outside Crossplane, the reconciliation loop detects the drift and restores the declared state. The drift reconciliation is ACTIVE: the continuous reconciliation is constitutive of the declared state being maintained. If reconciliation fails, Crossplane marks the resource as not ready and alerts — the failure is surfaced, not silent.

Crossplane's provider credentials represent the primary remaining governance gap: cloud credentials (AWS, GCP, Azure) granted to Provider controllers are stored as Kubernetes Secrets and grant the Provider broad cloud access. Workload Identity integration (eliminating long-lived credentials from Secrets) is the mitigation, but is not the default for all providers.

## Closing the T1684 Gap
Terraform's state drift was classified ABSENT: resources modified outside Terraform produce no state update and no gap assertion (T1684). Crossplane closes this by making drift detection continuous and constitutive. The comparison across the corpus:

- **Terraform**: state drift = ABSENT (no detection without `terraform plan`)
- **Crossplane**: state drift = ACTIVE (continuous reconciliation detects and corrects)

This makes drift_reconciliation the corpus's third ACTIVE family derived from a continuous process (alongside Cosign policy-controller and AWS SSO session credential issuance).

## Real-World Incident Mapping
Provider credential over-privilege: documented in multiple Crossplane security assessments. Provider controllers with cluster-admin-equivalent cloud credentials can provision any cloud resource regardless of Composition-declared constraints. An attacker with write access to a ProviderConfig can pivot from Kubernetes to full cloud account access. This is the upstream governance inheritance pattern (T1613) applied to cloud credentials: Crossplane's governance quality is bounded by the cloud credentials' governance.

Crossplane Composition as governance surface: a maliciously crafted Composition can instruct the provider to create resources with configurations that bypass security controls (e.g., public S3 buckets, unrestricted security groups). Composition governance is CRYSTALLIZED — the Composition is reviewed and approved, but this review is not constitutive of what the provider creates.

## The Add-On: `crossplane-governance-enforcer`
Composition governance gate and provider credential auditor. Validates provider credentials use Workload Identity (no long-lived keys); validates Compositions against security policy (no public-exposure patterns); monitors reconciliation health; alerts on provider credential modifications; produces `crossplane_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| resource_provisioning | CRYSTALLIZED | RBAC evaluated; provider creds gap |
| drift_reconciliation | **ACTIVE** | Continuous reconciliation closes T1684 |
| provider_management | CRYSTALLIZED | Credentials stored as K8s Secrets |
| composition_management | CRYSTALLIZED | Composition review not constitutive |
| claim_management | CRYSTALLIZED | RBAC governs claims; approval opt-in |
