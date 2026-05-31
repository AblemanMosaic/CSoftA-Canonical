# CX-IC: Vault Selected Instance Configuration

*Vault Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

This layer records which choices from the CX-CM admissible variation
space were made for this specific analysis, and why. It is structurally
distinct from CX-CM (which defines the full admissible world) to prevent
selected paths from masquerading as the only valid options.

---

## IC-01: N-Determination Strategy → DECLARED-N

**Selected from CX-CM CC-01:** DECLARED-N

**Rationale:** This analysis is an architectural review, not a deployment
audit of a specific cluster. DECLARED-N against the Vault Architecture
Guide and CIS Benchmark for Vault is appropriate because it establishes
what governance layers Vault's own documentation declares as applicable.
Deployment-specific variations (which auth methods are enabled, whether
Sentinel is licensed) are noted as CX-IC extensions in individual sections.

**Consequence:** Gap assertions produced by this analysis represent
architectural gaps — what Vault's declared model fails to provide —
rather than deployment-specific gaps in a particular cluster.

---

## IC-02: Operation Families in Scope → Full Scope

**Selected from CX-CM CC-02:** Full scope

**Rationale:** This is the founding analysis in the Wave 1 series,
establishing the reference fingerprint. Full scope maximizes the
coverage of the convergence claim and provides the richest comparison
basis for subsequent system analyses.

**In scope:** secret_read, secret_write, auth_login, token_create,
policy_manage, sys_audit, root_token_operation.

**Out of scope (declared):** Vault Enterprise namespaces, HSM seal
operations, DR replication operations. These are declared scope boundaries,
not omissions.

---

## IC-03: Evidence Standard → RUNTIME (with STATIC fallback)

**Selected from CX-CM CC-03:** RUNTIME primary; STATIC for architectural claims

**Rationale:** The convergence fingerprint and gate tests use synthetic
audit log fixtures (RUNTIME semantics without a live cluster) to permit
CI/CD execution without infrastructure dependency. Architectural claims
(CX-S invariants, CX-CM options) are grounded in STATIC analysis of
Vault documentation.

**Implication:** GCG assertions produced by the Python implementation
are instance-level claims derived from actual audit log entries. The
FINDINGS.md architectural claims are grounded in documentation review.

---

## IC-04: Audit Log Format → FILE

**Selected from CX-CM CC-04:** FILE audit device

**Rationale:** The Vault file audit device produces JSON newline-delimited
records that are machine-readable without additional infrastructure.
It is the most common audit device in production deployments.

**Limitation declared:** SYSLOG and SOCKET audit devices require different
parsing; the Python implementation supports FILE only in this version.
Extending to other audit device types is a CX-IR extension point.

---

## IC-05: Vault Edition → OSS

**Selected from CX-CM CC-05:** OSS

**Rationale:** Vault OSS is the universally available edition and the
correct scope for a founding architectural analysis. Enterprise features
(Sentinel, namespaces, MFA enforcement) are noted where they would
increase N(O) or close identified gaps, but are not required for the
core constitutional profile.

---

## IC-06: Root Token Handling → ENUMERATE

**Selected from CX-CM CC-06:** ENUMERATE (root token included as bypass instances)

**Rationale:** Excluding root token operations would understate the gap
magnitude and misrepresent the constitutional completeness of the deployment.
Root token operations must be enumerated as Layer Bypass instances to
produce an accurate gap count. This is the more conservative and more
honest option.

---

## Instance Summary

| Dimension             | Selected Value      | Admissible Alternatives                  |
|-----------------------|---------------------|------------------------------------------|
| N-determination       | DECLARED-N          | MINIMUM-N, PER-CONTEXT-N                |
| Operation scope       | Full                | Minimum (secret + auth only)            |
| Evidence standard     | RUNTIME+STATIC      | STATIC only                             |
| Audit log format      | FILE                | SYSLOG, SOCKET                          |
| Vault edition         | OSS                 | ENTERPRISE                              |
| Root token handling   | ENUMERATE           | EXCLUDE (with declaration)              |
