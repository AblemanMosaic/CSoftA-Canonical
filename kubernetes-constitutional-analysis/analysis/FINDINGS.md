# FINDINGS: Kubernetes Constitutional Analysis

*Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*
*Version: 1.0 — 2026-05-29*
*EAR state: CRYSTALLIZED (all families — audit opt-in, non-participation unrecorded)*
*Recoverability: COMPOSITIONAL (API server) / STRUCTURAL_NONLOCALITY (node execution)*
*GCG codex cross-validation: CONFIRMS canonical finding*

---

## Executive Finding

Kubernetes is a continuously executing governance machine that cannot
provide a unified explanation of how governance was applied to any
specific operation.

Multiple governance mechanisms exist and participate selectively.
In default configuration, only RBAC participates reliably. Admission
controllers, Pod Security Standards, and NetworkPolicy are declared
applicable but absent from most executions without record of their
non-participation.

This analysis confirms the GCG codex canonical finding (PCM-0333-191):
default cluster pod_create: N=5, k=2 (RBAC + audit), gap magnitude=3.

The GCG codex cross-validation result: **VALIDATED**.

---

## GCG Codex Cross-Validation

This analysis serves as the cross-validation of `gcg-codex-v1-0`
(PCM-0333-006, previously UNVALIDATED). Per Phase 0f (T1577).

**Canonical claim:** Default cluster pod_create: N=5, k≈1, gap magnitude≈4.

**Cross-validation result:** Gap magnitude=3 (k=2: RBAC + audit_logging).

**Variance explanation:** The codex predicts k=1 (RBAC only) assuming
audit is not enabled by default. This analysis counts audit_logging as
participating when the entry is present in the audit log. The structural
gap (admission, PSS, NetworkPolicy absent) is confirmed.

**Codex status:** UNVALIDATED → **VALIDATED** (with noted k-assessment
variance for audit_logging participation criterion).

---

## Dimension 1: Authority (F-AUTH)

**Finding: F-AUTH PRESENT — authority distributed across independent layers**

Kubernetes authority is distributed across RBAC (user/service account
permissions), admission controllers (webhook policies), PSS (namespace-level
pod restrictions), and NetworkPolicy (traffic restrictions). No single
authority surface unifies these layers.

Each layer has its own authority model:
- RBAC: Role/ClusterRole + binding to subject
- Admission: webhook policy (external system)
- PSS: namespace annotation
- NetworkPolicy: selector-based policy object

There is no mechanism that produces a unified authority record spanning
all five layers for a single operation. The resolution cascade is opaque
(SFA finding PCM-0113-012).

---

## Dimension 2: Accountability (F-LINEAGE)

**Finding: F-LINEAGE PRESENT — opt-in ledger, non-participation unrecorded**

Kubernetes audit logging is an opt-in ledger (T1573: CRYSTALLIZED).
When enabled, it records: request verb, resource, user, RBAC decision
(`authorization.k8s.io/reason`), and response code.

It does NOT record:
- Which admission webhooks were called vs. not called
- Whether PSS enforced, evaluated but passed, or was not configured
- Whether NetworkPolicy matched the pod's traffic
- Why any layer was absent

This is the diagnostic signature of GCG (DI-05): the non-participation
record is absent. An operator reviewing the audit log for a pod admission
sees only that RBAC allowed it — not that four other declared layers
did not participate.

---

## Dimension 3: Governance (F-ADMIT)

**Finding: F-ADMIT PRESENT — multi-layer fragmentation with magnitude ≥ 3**

**GCG instances identified (default cluster):**

| Operation Family    | Form             | N | k | Gap | Absent layers                             |
|---------------------|------------------|---|---|-----|-------------------------------------------|
| pod_create          | NON_ACTIVATION   | 5 | 2 | 3   | admission_controllers, PSS, network_policy |
| pod_privileged_create | NON_ACTIVATION | 5 | 2 | 3   | admission_controllers, PSS, network_policy |
| rbac_escalation     | NON_ACTIVATION   | 3 | 2 | 1   | admission_controllers                     |
| workload_create     | NON_ACTIVATION   | 4 | 2 | 2   | admission_controllers, PSS                |

**The central finding:** Kubernetes governance is RBAC-heavy at the
API layer and structurally silent on the governance behavior of the
four other declared layers. The system can explain individual RBAC
decisions; it struggles to explain the complete governance path.

**Hardened cluster:** With admission webhooks + PSS Restricted + NetworkPolicy,
gap magnitude approaches 0. Constitutional governance is achievable
in Kubernetes — it requires deliberate configuration of all five layers.

---

## Dimension 4: Configuration and Authority Binding

**Finding: INHERENT ENTANGLEMENT**

Kubernetes Pod specs define capabilities (hostNetwork, privileged,
capabilities.add) that simultaneously configure behavior and implicitly
claim authority. The RBAC layer declares whether the user can create
pods; the pod spec itself determines what authority the running pod
exercises — with no re-evaluation by a unified authority surface.

This is the canonical "inherent entanglement" case from the SFA corpus
(PCM-0113-013): specs define capabilities, not declarations authorize them.

---

## Dimension 5: Resolution Cascade Opacity

**Finding: MATERIAL opacity — the central Kubernetes finding**

A Pod admitted with hostNetwork:true in a default cluster generates
this audit record:
```
authorization.k8s.io/reason: "RBAC: allowed by ClusterRoleBinding admin"
```

The audit log does not explain:
- Absence of admission enforcement (no webhooks registered)
- Absence of PSS enforcement (no namespace annotation)
- Absence of NetworkPolicy (none deployed)

The operator cannot reconstruct which layers should have participated
but did not. This is F-INTERP + F-LINEAGE combined: the interpretation
of "this admission was governed" is false, but the record cannot
demonstrate that falsity without external knowledge of N(O).

---

## Dimension 6: Extension Surfaces (F-SCOPE)

**Finding: POWERFUL but weakly governed extension surfaces**

Kubernetes has three classes of extension with distinct governance:
- Admission webhooks: perimeter-governed (API server calls them)
  but their internal behavior is outside Kubernetes's audit scope
- Custom controllers/operators: run in cluster, watch API resources,
  may create/modify resources with broad permissions — RBAC governs
  their API access but not their internal logic
- Init containers and sidecar injection: run with pod permissions,
  fully ungoverned by Kubernetes once the pod is admitted

The webhook extension model is more governed than npm (ABSENT) but
less governed than the ideal: webhook decisions are not receipted
in the audit log in a way that supports reconstruction.

---

## Dimension 7: Authority Bypass

**Finding: Multiple scoped bypasses**

| Bypass | Form | Scope |
|--------|------|-------|
| cluster-admin binding | Layer Non-Activation (all admission) | User-scoped |
| PSS namespace=Privileged | Layer Non-Activation (PSS) | Namespace-scoped |
| `--dry-run=server` (some versions) | Layer Bypass | Request-scoped |
| Direct etcd access (cluster admin) | Layer Bypass | Unbounded |

No Kubernetes bypass matches the simplicity of Docker's `--privileged`
or Vault's root token in terms of single-flag total bypass. Kubernetes
bypasses are compositional — requiring multiple grants to achieve
comprehensive governance avoidance.

---

## Dimension 8: Projection Divergence (F-PROJ)

**Finding: F-PROJ MATERIAL**

Kubernetes presents as a multi-layer governance system with defense in
depth. The default cluster configuration provides single-layer governance
(RBAC only) with four additional layers declared but absent.

The divergence is material: practitioners who believe their cluster is
governed because it has RBAC, admission webhooks, PSS, NetworkPolicy,
and audit logging — without verifying each layer is active and producing
receipts — have a fundamentally incorrect model of their cluster's
governance posture.

---

## The Add-On: `k8s-governance-auditor`

*T1655* — Kubernetes operator producing Coverage Gap Assertions for pods below governance threshold. Computes k/N per pod via ear_adapter_kubernetes; validates audit logging policy level; enforces Pod Security Standards; monitors RBAC drift (cluster-admin grants outside declared principals); produces k8s_posture.json per namespace. Makes GCG VALIDATED continuous.

## Summary

| Dimension              | Finding                                    | Severity |
|------------------------|--------------------------------------------|----------|
| Authority              | Distributed; no unified authority record   | HIGH     |
| Accountability         | CRYSTALLIZED; non-participation unrecorded | HIGH     |
| Governance             | N=5 declared; k=2 default (gap mag 3)      | HIGH     |
| Config-Authority       | Inherent entanglement                      | HIGH     |
| Resolution Opacity     | MATERIAL — cannot reconstruct governance path | HIGH  |
| Extension Surfaces     | Perimeter-governed webhooks; ungoverned interior | MEDIUM |
| Authority Bypass       | Compositional scoped bypasses              | MEDIUM   |
| Projection Divergence  | MATERIAL                                   | HIGH     |

**Constitutional verdict: Kubernetes is governance-complete when all five
layers are active and producing receipts. In default configuration it is
single-layer RBAC governance with four absent layers and no record of
their absence. The gap is configurable; the non-participation record
absence is structural.**
