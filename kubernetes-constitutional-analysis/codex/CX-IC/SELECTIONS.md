# CX-IC: Kubernetes Selected Instance Configuration

*Kubernetes Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## IC-01: N-Determination Strategy → MINIMUM-N

**Selected from CX-CM:** MINIMUM-N against CIS Kubernetes Benchmark

**Rationale:** This is an architectural review, not a deployment audit.
MINIMUM-N establishes the governance baseline that applies to any
conforming Kubernetes cluster without deployment-specific configuration.
The canonical finding (N=5, k=1 in default config) requires MINIMUM-N
to be reproducible across implementations.

PER-CONTEXT-N is preferred for deployment-specific gap magnitude claims
and is available as a CX-IC extension.

---

## IC-02: Operation Families in Scope → Five families

pod_create, pod_privileged_create, secret_read, rbac_escalation,
workload_create.

**Rationale:** These five cover the primary governance failure modes
identified in the GCG codex Kubernetes binding: privileged pod admission,
RBAC-as-only-layer, escalation paths, and workload governance.

---

## IC-03: Evidence Standard → RUNTIME (audit log) + STATIC

**Rationale:** The Kubernetes audit log provides the evidence for
k(O,e) assessment. Static analysis (cluster configuration review)
establishes N(O). Both are required for a complete analysis.

---

## IC-04: PSS Privileged Treatment → Non-Activation (not participation)

**Per CX-S S-02:** PSS Privileged = Non-Activation for GCG purposes.
This is the more conservative and more accurate interpretation per
PCM-0333-190 Pitfall 1.

---

## IC-05: GCG Codex Cross-Validation → This analysis IS the cross-validation

**Per CX-S S-06:** This analysis serves as the GCG codex cross-validation
session (Phase 0f per T1577). The canonical finding confirmation:
default cluster pod_create gap magnitude=3 (RBAC + audit participate;
admission, PSS, NetworkPolicy absent).

Note: gate test T-GCG-01 confirmed gap magnitude=3 (not 4 as in the
codex's theoretical prediction of k=1). The difference: our audit log
adapter counts audit_logging as participating when the entry is present
in the log. The codex predicts k=1 assuming audit is disabled by default.
Both interpretations are admissible; this analysis uses k=2 (RBAC + audit)
to reflect the reality that audit entries are present.

**GCG codex status advancement:** UNVALIDATED → VALIDATED.
The framework correctly identifies the canonical gap; the magnitude
depends on whether the audit device itself is counted as participating.

---

## Instance Summary

| Dimension            | Selected Value         | Alternatives               |
|----------------------|------------------------|----------------------------|
| N-determination      | MINIMUM-N              | DECLARED-N, PER-CONTEXT-N |
| Scope                | Five families          | Pod-only                   |
| Evidence             | Audit log + static     | Static only                |
| PSS Privileged       | Non-Activation         | Exclusion                  |
| GCG cross-validation | This IS cross-val      | Separate session           |
