# FINDINGS: Cosign / Sigstore Constitutional Analysis
*Wave 8 — System 39 · policy_enforcement: ACTIVE · Fingerprint: `926a43d9730065f4`*

## Executive Finding
Cosign/Sigstore is the corpus's dedicated supply chain signing governance case — it directly addresses the provenance gaps identified in Packer (T1719), Helm (T1708), and GitHub Actions (T1702). Cosign provides container image signing and verification; Sigstore provides the Rekor transparency log; keyless signing via OIDC tokens links signatures to CI/CD identities without long-lived keys.

The constitutional landmark: when Cosign is used with the `policy-controller` admission webhook, image signature verification becomes **ACTIVE** for container deployment. An unsigned image — or an image signed by an untrusted identity — cannot be admitted to the cluster. The admission is constitutive: no valid signature means no deployment. This is the first and only system in the corpus that directly closes a Wave-identified supply chain gap (T1719, T1708, T1702) by making the governance constitutive at the admission point.

## Keyless Signing: The Strongest Identity Binding
Traditional Cosign signing uses a long-lived key (stored in KMS or as a Kubernetes Secret). Keyless signing uses an OIDC token from the CI/CD system (GitHub Actions, GitLab CI, etc.) to generate a short-lived signing certificate from Sigstore's Fulcio CA. The signature is bound to the OIDC identity (`workflow: ci.yml @ repo: org/name @ ref: refs/heads/main`), not to a long-lived key that can be stolen. Keyless signing is the constitutional complement to GitHub Actions OIDC cloud federation (T1686): both use OIDC tokens to produce constitutive governance receipts.

## Real-World Incident Mapping
Chainguard ecosystem adoption (2023-2025): Chainguard's distroless images and wolfi-based images are signed with Cosign and include SLSA provenance attestations. Organizations using Chainguard images with policy-controller enforcement have the supply chain provenance gap (T1719) closed at the admission layer — confirming the ACTIVE classification operationally.

Sigstore Rekor log monitoring: Sigstore monitors the Rekor transparency log for signature anomalies. In 2024, Sigstore's monitoring infrastructure detected several unauthorized signing events and revoked the associated short-lived certificates, preventing the affected images from being verified by policy-controller. This is the meta-governance pattern applied to Cosign itself — consistent with the observability governance trilogy pattern.

## The Add-On: `cosign-policy-enforcer`
policy-controller deployment and policy management for image signing. Configures policy-controller for namespace or cluster; defines ClusterImagePolicy requiring signature from trusted identities; monitors Rekor for signing anomalies; validates all running workloads have verified signatures; produces `cosign_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| image_verification | ABSENT / CRYSTALLIZED | Verification opt-in; ABSENT without policy-controller |
| image_signing | CRYSTALLIZED | Rekor records; signing opt-in |
| policy_enforcement | **ACTIVE** | Unsigned images rejected at admission |
| provenance_attestation | CRYSTALLIZED | SLSA attestation opt-in |
| sbom_attestation | CRYSTALLIZED | SBOM opt-in |
