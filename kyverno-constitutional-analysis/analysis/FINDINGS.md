# FINDINGS: Kyverno Constitutional Analysis
*Wave 2 — System 8 · EAR ceiling: CRYSTALLIZED · Highest governance: image_verification · Fingerprint: f8674e5d48aceee5*

## Executive Finding
Kyverno is the most interesting governance architecture in the Wave 2 policy engine cluster because it has differentiated governance quality across operation families. Policy evaluation and mutation are CRYSTALLIZED (PolicyReport exists, not constitutive). Image verification is the closest any Wave 2 policy engine gets to ACTIVE-EAR: the admission decision explicitly depends on attestation verification outcome.

## PolicyReport Gap
The PolicyReport CRD records Kyverno's policy evaluation results. It is CRYSTALLIZED: Kyverno generates PolicyReports, but the admission decision does not depend on the PolicyReport write succeeding. Under load or resource pressure, PolicyReports may fail to write without affecting admission decisions. The gap: the governance record is decoupled from the governance event.

## Image Verification: Highest Governance Surface
Kyverno's image verification path is structurally different from its policy evaluation path. The admission decision for a pod with an `imageVerify` rule depends on the attestation verification outcome — the container image is either admitted or denied based on whether its signature/attestation chain validates. This is the admission decision being constitutively dependent on a governance check. CRYSTALLIZED technically (formal structured receipt not separately mandatory), but the closest to ACTIVE in the policy engine cluster.

## Background Scan Completeness
Background scans check existing resources periodically. The gap: resources created in violation and then modified to compliance have their violation history erased. PolicyReport reflects current state, not historical governance record.


## Real-World Incident Mapping

**Finding: Kyverno's CVE history directly expresses the PolicyReport decoupling gap.**

Kyverno has the most precise real-world validation of any Wave 2 system. Multiple independent CVEs all share the same constitutional structure: the admission decision and the governance record are decoupled, and the decoupling is exploitable.

**CVE-2025-46342 (May 2025) — namespace selector cache miss:**
Due to a missing error propagation in `GetNamespaceSelectorsFromNamespaceLister`, policy rules using namespace selectors in their `match` statements were silently not applied during admission review processing. Kyverno handled the admission review requests as if the policy rules did not exist — no error, no violation record, no indication that governance had failed. This is the GCG three-condition conjunction as a CVE: N declared (cluster_policy + admission_webhook), k=0, no non-participation record. The absence was invisible.

**CVE-2026-22039 (CVSS 10.0, February 2026) — authorization boundary bypass:**
Authenticated users with namespaced Policy permissions could access and mutate resources in different namespaces across the entire cluster via Kyverno's apiCall feature, completely breaking Kubernetes namespace isolation. Kyverno's privileged network position (admission controller with broad cluster egress) combined with user-controlled policy logic created a structural bypass. This is the CSoftA finding expressed at maximum severity: governance technology that has no governance over its own execution surface.

**CVE-2023-34091 — deletionTimestamp bypass:**
Resources with `deletionTimestamp` set (indicating pending deletion) were excluded from policy validation for performance reasons. An attacker using a Kubernetes finalizer to set the timestamp without actually deleting the resource could bypass any Kyverno policy in enforce mode. The resource appeared to be under governance (constraint existed, no violations recorded) while the governance was structurally absent. PolicyReport showed no violations because the resource was not evaluated.

**CVE-2023-47630 — image digest control:**
An attacker could control the digest of images used by Kyverno users, undermining image verification policies. This directly maps to the CSoftA finding that image_verification is the highest-governance surface in Kyverno — and the CVE confirms that even this surface has exploitable gaps.

**CVE-2024-48921 — PolicyException namespace bypass:**
A ClusterPolicy could be overridden by creating a PolicyException in any namespace. The governance layer (ClusterPolicy) was declared applicable and appeared active, but the PolicyException mechanism provided an undeclared bypass route with gap magnitude equal to the bypassed policy's declared layers.

**The pattern across all Kyverno CVEs:** Every Kyverno CVE in this class shares the constitutional structure: the PolicyReport records outcomes but does not govern whether policies are evaluated. When evaluation is silently skipped (cache miss, timestamp bypass, namespace exception), the governance record shows no violations — correctly reflecting that no violation was recorded, incorrectly implying that no violation occurred. This is STRUCTURAL_NONLOCALITY: the governance state cannot be reconstructed from the PolicyReport alone.

## The Add-On: `kyverno-receipt-enforcer`

*T1659* — Complementary admission webhook validating Kyverno's own governance participation. Verifies PolicyReport written per admission event (CVE-2025-46342 class); validates PolicyException allowlist (CVE-2024-48921 class); enforces deletionTimestamp evaluation (CVE-2023-34091 class); monitors apiCall cross-namespace usage (CVE-2026-22039 class). Recursive governance: a second webhook governing the governance webhook.

## Summary
| Family | EAR State | Key gap |
|--------|-----------|---------|
| policy_evaluation | CRYSTALLIZED | PolicyReport non-constitutive |
| image_verification | CRYSTALLIZED (approaching ACTIVE) | Attestation constitutive; formal receipt not mandatory |
| mutation_admission | CRYSTALLIZED | No receipt of mutation applied |
| background_scan | CRYSTALLIZED | Historical gap — current state only |
