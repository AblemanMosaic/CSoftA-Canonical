# CX-IC: npm Selected Instance Configuration

*npm Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## IC-01: N-Determination Strategy → DECLARED-N

**Selected from CX-CM CC-01:** DECLARED-N

**Rationale:** Using MINIMUM-N for npm would produce N(O) = 0 for
lifecycle_script_execution, because no lifecycle governance layer exists
in npm's architecture. This erases the finding. DECLARED-N includes
lifecycle_governance and audit_surface in N(O) because these are what
a constitutionally complete package manager must provide — their absence
is the primary finding, not a reason to exclude them from the declared set.

**This is the most important instance selection in the npm analysis.**
The choice between DECLARED-N and MINIMUM-N determines whether lifecycle
script execution is visible as a gap or invisible as a non-issue.

---

## IC-02: Analytical Scope → FULL

**Selected from CX-CM CC-02:** Full (all four operation families)

**Rationale:** Wave 1 founding analysis requires full scope for the
convergence fingerprint to cover the complete governance profile.

---

## IC-03: Evidence Standard → STATIC

**Selected from CX-CM CC-03:** STATIC

**Rationale:** npm's primary finding is structural — the lifecycle
governance layer is absent by architecture, detectable without running
npm install. Static analysis of package.json and lockfile is sufficient
to identify all major GCG instances. Runtime instrumentation would add
evidence volume but not change the structural findings.

---

## IC-04: Dependency Depth → FULL_TREE (cap 50)

**Selected from CX-CM CC-04:** FULL_TREE with cap of 50 packages

**Rationale:** Supply chain attacks enter via transitive dependencies.
The lifecycle_governance gap applies to all packages with lifecycle scripts,
not only direct dependencies. Cap at 50 for test suite performance.

---

## IC-05: Lockfile Treatment → OPTIONAL

**Selected from CX-CM CC-05:** OPTIONAL (absence recorded as gap)

**Rationale:** Lockfile absence is itself a governance finding.
The analysis must handle both cases to produce correct gap assertions
in both the locked and unlocked scenarios.

---

## Instance Summary

| Dimension          | Selected Value  | Rationale summary                              |
|--------------------|-----------------|------------------------------------------------|
| N-determination    | DECLARED-N      | MINIMUM-N erases the primary finding           |
| Scope              | Full            | Founding analysis requires full coverage       |
| Evidence           | STATIC          | Structural gap — runtime adds no new findings  |
| Dependency depth   | FULL_TREE/50    | Supply chain attacks enter via transitive deps |
| Lockfile           | OPTIONAL        | Absence is itself a governance finding         |
