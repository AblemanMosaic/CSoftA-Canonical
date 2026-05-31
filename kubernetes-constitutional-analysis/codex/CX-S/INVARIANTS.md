# CX-S: Kubernetes Constitutional Domain Invariants

*Kubernetes Constitutional Analysis — CX:AES Codex*
*Inherits from: CSoftA Parent CX:AES Codex (T1574)*
*Version: 1.0*

---

## S-01: pod_create Has Five Declared Governance Layers

The canonical Kubernetes operation family — `pod_create` — has five
declared applicable governance layers per CIS Kubernetes Benchmark:
RBAC, admission controllers, Pod Security Standards, NetworkPolicy,
and audit logging. N(O) = 5 for pod_create in any conforming analysis.

**What must hold:** Any analysis claiming N(O) < 5 for pod_create
must declare the exclusion with rationale (e.g., MINIMUM-N against
an older cluster version without PSS). Treating N(O) = 1 (RBAC only)
is inadmissible without explicit declaration. (PCM-0333-190 Pitfall 2)

**GCG codex canonical case (PCM-0333-191):**
Default cluster: k=1 (RBAC only), gap magnitude=4.
CIS Level 2 hardened: k=5, gap magnitude=0.

---

## S-02: PSS Privileged Mode Is Non-Activation, Not Participation

Pod Security Standards in Privileged mode evaluates pods but imposes
no constraints and produces no accountability. It must be classified
as Layer Non-Activation (C-09) for GCG purposes — the layer exists,
was technically invoked, but produced no governance effect.

**What must hold:** A namespace with PSS mode=Privileged must NOT be
counted as having pod_security_standards participate in k(O,e).
Counting it would produce a false zero gap. (PCM-0333-190 Pitfall 1)

---

## S-03: Kubernetes Is CRYSTALLIZED-EAR, Not ACTIVE-EAR

The Kubernetes audit log records API request outcomes. It does not
record which governance layers did not participate and why — the
non-participation record absence is the diagnostic signature (DI-05).

**What must hold:** No Kubernetes operation family may be classified
as ACTIVE-EAR. The audit log is an opt-in ledger, not a mandatory
ledger. The critical distinction from Vault: Vault's
`policyresults.grantingpolicies` names which policy permitted the
operation; Kubernetes's `authorization.k8s.io/reason` names why RBAC
allowed the request but says nothing about admission, PSS, or NetworkPolicy.

---

## S-04: N(O) Is Context-Variable by Namespace and Cluster Configuration

Kubernetes N(O) varies by:
- Namespace (PSS mode — Privileged/Baseline/Restricted or absent)
- Cluster (which admission webhooks are registered)
- API group (audit policy may cover some groups and not others)

**What must hold:** Every GCG assertion must state which N-determination
strategy was used. PER-CONTEXT-N gives the most precise gap magnitudes;
MINIMUM-N gives the architectural baseline. Both are admissible with
declaration. (PCM-0333-189)

---

## S-05: The Non-Participation Record Is Absent by Architecture

Kubernetes does not produce a record when governance layers do not
participate. The audit log records what RBAC allowed; it does not
record that admission webhooks were not called, that PSS was not
enforced, or that no NetworkPolicy matched. This is the GCG
origin finding (PCM-0333-023, TARGET R batch 1).

**What must hold:** Any GCG assertion for Kubernetes must note that
the non-participation record is absent — not that it could not be
found. The absence is structural and universal across all operation
families in the default configuration.

---

## S-06: Kubernetes Is the GCG Framework Cross-Validation Target

The GCG codex (PCM-0333-006) is UNVALIDATED pending cross-validation
with an independent analyst on a novel target. This Kubernetes analysis
serves as the cross-validation: applying GCG Phases A–F to the
framework's origin system, confirming the codex converges on the
canonical findings stated in PCM-0333-191 and PCM-0333-023.

**What must hold:** This analysis must confirm or contradict the
canonical finding (default cluster pod_create: N=5, k≥1, gap magnitude≥3).
Any deviation must be documented as a codex refinement finding.
