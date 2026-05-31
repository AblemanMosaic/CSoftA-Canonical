# FINDINGS: HashiCorp Vault Constitutional Analysis

*Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*
*Version: 1.0 — 2026-05-29*
*EAR state: ACTIVE (with audit device) / CRYSTALLIZED (without)*
*Recoverability: LOCAL (Integrated Raft) / COMPOSITIONAL (Consul) / STRUCTURAL_NONLOCALITY (cloud)*

---

## Executive Finding

Vault is the strongest governance case in the 17-system SFA corpus.
It is the only analyzed system with a mandatory-ledger receipt tier —
every permitted operation produces a structured, externally queryable
record including the policy chain that authorized the operation.

The central finding is that Vault demonstrates constitutional governance
is achievable in production software, not merely theoretical.

The singular constitutional weakness is the root token: an unbounded
Layer Bypass that circumvents all governance mechanisms. Every other
Vault governance mechanism is constitutionally complete or close to it.

---

## Dimension 1: Authority (F-AUTH)

**Finding: F-AUTH ABSENT (authority is explicitly declared)**

Authority in Vault is explicit and declared. Every operation's authority
derives from a named policy path attached to the requesting token.

- Policies are named documents with explicit capability declarations
  per path (e.g., `path "secret/*" { capabilities = ["read"] }`)
- Every token carries an explicit list of attached policies
- `policyresults.grantingpolicies` in the audit log names which policy
  granted the permission for each operation

This is the Vault reference case for remediated F-AUTH: authority is
separated from execution, declared before operation, and receipted per use.

**Exception:** Root token operations. Root token authority is implicit
(it has all capabilities) and unreceipted by the policy evaluation layer.
This is classified as F-SCOPE (Bypass), not F-AUTH.

---

## Dimension 2: Accountability (F-LINEAGE)

**Finding: F-LINEAGE ABSENT when audit device enabled; F-LINEAGE PRESENT when disabled**

**With audit device (ACTIVE-EAR):**
Receipt tier: Mandatory Ledger — all operations recorded.
Each audit entry includes: request path/operation, token identity,
token policies, policy evaluation result (`policyresults.grantingpolicies`),
response outcome.

The complete authorization receipt is externally visible. The resolution
chain `request → token lookup → policy eval → storage → response` is
reconstructible from audit log alone.

**Without audit device (CRYSTALLIZED):**
The receipt mechanism exists but is not activated. Operations complete
without producing records. F-LINEAGE present for all operation families.

**Bootstrapping gap:** The first `sys/audit` enable is unreceipted.
This is a known, structural gap — not a defect. Declare explicitly in
any governance-complete claim.

---

## Dimension 3: Governance (F-ADMIT)

**Finding: F-ADMIT LOW for core operations; present for root token and unaudited deployments**

**Core authenticated operations (non-root):** Admissibility evaluation
is complete. RBAC (policy engine) evaluates every request and records
the evaluation. PSS-equivalent constraints are expressed as policy rules.

**GCG instances identified:**

| Operation Family  | Gap Form           | N(O) | k(O,e) | Absent Layer         |
|-------------------|--------------------|------|--------|----------------------|
| secret_read (no audit) | NON_ACTIVATION | 3  | 2      | audit_device         |
| root_token_operation | BYPASS         | 3    | 1      | policy_evaluation, audit partial |
| sys_audit (first enable) | NON_ACTIVATION | 3 | 2   | audit_device (self)  |

**Vault is unique in the corpus for having the smallest F-ADMIT surface
among multi-mechanism systems.**

---

## Dimension 4: Configuration and Authority Binding

**Finding: STRUCTURAL SEPARATION**

Vault separates configuration and authorization:
- `sys/mounts` configures the secrets engine topology
- `sys/policy` defines authorization rules
- Auth method configuration (`auth/*/config`) is separate from
  the policies that govern who can use the auth method

This is the cleanest configuration-authority separation in the corpus.
PostgreSQL shows similar structural separation; Kubernetes shows inherent
entanglement; npm shows accidental entanglement.

---

## Dimension 5: Resolution Cascade Opacity

**Finding: LOW opacity for ACTIVE-EAR deployments**

When audit device is enabled, the resolution chain for any Vault operation
is externally reconstructible:
1. `auth.client_token` → identifies which token
2. `auth.token_policies` → lists which policies were attached
3. `auth.policy_results.granting_policies` → names which policy permitted
4. `request.path` + `request.operation` → what was accessed

This is markedly better than Kubernetes (where the multi-layer decision
path is partially opaque) and npm (where execution is fully opaque).

**Exception:** Multi-auth method chains (e.g., OIDC → Vault token → policy)
where the external auth provider's decision is accepted without internal
re-evaluation. The external auth JD (JD-2) introduces opacity at that
boundary.

---

## Dimension 6: Extension Surfaces (F-SCOPE)

**Finding: F-SCOPE PRESENT for plugin backends (limited scope)**

Vault supports plugin-based secrets engines and auth methods.
Plugins run as separate processes with a defined API contract.

**Extension classification: Perimeter-governed**
- Plugin API is declared and typed
- Vault controls what data flows to/from plugins
- Plugins cannot directly access Vault's storage
- Plugin execution is audited at the Vault process boundary

This is better than npm (fully ungoverned) and comparable to Deno
(perimeter-governed module system). It is not fully governed (plugin
internal behavior is not receipted by Vault).

---

## Dimension 7: Authority Bypass

**Finding: UNBOUNDED bypass (root token) + scoped bypasses**

| Bypass Type     | Example                           | Scope      |
|-----------------|-----------------------------------|------------|
| Unbounded       | Root token                        | All capabilities, all paths |
| Process-scoped  | DR (Disaster Recovery) token      | DR operations only |
| Config-scoped   | `sys/raw` endpoint (when enabled) | Raw storage read/write |

Root token is the constitutional problem. It cannot be disabled without
breaking emergency recovery. It must be:
- Declared as a Layer Bypass in all governance analyses
- Excluded from production governance scope declarations
- Enumerated and audited wherever it appears in audit logs

---

## Dimension 8: Projection Divergence (F-PROJ)

**Finding: F-PROJ LOW — the lowest projection divergence in the corpus**

What Vault's interface claims and what execution produces are closely
aligned for authenticated, non-root operations.

The interface says "policy controls access" → execution confirms it
via `policyresults.grantingpolicies`.

The interface says "all operations are audited" → true only when audit
device is enabled (not the default). This is the primary projection
divergence: the documentation implies audit completeness but the default
Vault installation has no audit device enabled. First-time operators
frequently run governance-incomplete deployments believing they are complete.

**F-PROJ severity: MINOR** — the divergence is well-documented and
correctable with a single configuration operation (`vault audit enable`).

---

## The Add-On: `vault-governance-bootstrap`

*T1652* — Terraform module and CLI tool enforcing audit device presence as a prerequisite for production-readiness. Validates sys/audit for enabled devices; enables file audit device if absent; records signed bypass declarations for root token operations; produces governance_posture.json for CI/CD gating; optionally integrates with SIEM for root token alerting. Makes the audit device mandatory — the configuration gap that separates ABSENT from ACTIVE for Vault closes with one gate.

## Summary

| Dimension              | Finding                     | Severity  |
|------------------------|-----------------------------|-----------|
| Authority              | F-AUTH ABSENT (explicitly declared) | — |
| Accountability         | F-LINEAGE absent with audit; present without | MODERATE (config-dependent) |
| Governance             | F-ADMIT for root token and bootstrap | LOW |
| Configuration-Authority| Structural separation       | — |
| Resolution Opacity     | LOW with audit device       | LOW |
| Extension Surfaces     | Perimeter-governed plugins  | LOW |
| Authority Bypass       | Root token (unbounded)      | HIGH (bounded scope) |
| Projection Divergence  | Audit default miscommunication | MINOR |

**Constitutional verdict: Vault is governance-complete for authenticated
non-root operations when an audit device is enabled.**
The root token is the single constitutional weakness; its scope is bounded
and its presence is detectable.
