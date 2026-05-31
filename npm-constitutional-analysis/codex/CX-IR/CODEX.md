# CX-IR: npm Implementation Codex

*npm Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## CODEX-1: Implementation Architecture

| Component          | File                 | Purpose                           |
|--------------------|----------------------|-----------------------------------|
| EAR Adapter        | ear_adapter_npm.py   | Phase A: topology, C-01..C-04     |
| GCG Analyzer       | gcg_analyzer.py      | Phases B–F: C-05..C-19            |
| Gap Assertions     | gap_assertions.py    | Serialization, fingerprint        |
| Gate Tests         | tests/test_gate_suite.py | Convergence verification      |

Inherits CX-S invariants from INVARIANTS.md.
Key implementation constraint from IC-01: N-determination must use
DECLARED-N — lifecycle_governance and audit_surface must appear in
N(O) for lifecycle_script_execution even though they don't exist
in npm's architecture.

---

## CODEX-2: Phase Execution

### Phase A — Foundation
Static topology: package.json scripts + lockfile packages.
Gate: lifecycle families identified with lifecycle_governance in N(O).

### Phase B — Core Constructs
N(O) from declared layers; k(O,e) from structural presence
(lockfile entry, integrity hash, provenance field).
No runtime measurement — static evidence only (IC-03).

### Phase C — GCG Assertion
Three-condition conjunction: N declared (yes, via DECLARED-N),
k < N (yes — lifecycle_governance always absent), no non-participation
record (yes — npm produces none).
All lifecycle instances with scripts → GCG assertion.

### Phase D — Form Classification
lifecycle_governance absent → GCGForm.ABSENCE (not NON_ACTIVATION).
lockfile_integrity absent (no lockfile) → GCGForm.ABSENCE.
audit_surface absent → GCGForm.ABSENCE (structural, never exists).

### Phase E — Diagnostics
Gap magnitude = |N(O)| - |k(O,e)|.
For lifecycle: magnitude = 2 (both declared layers absent).

### Phase F — Report
Complete GCGAnalysisReport with convergence fingerprint.

---

## CODEX-3: Convergence Specification

**Reference fingerprint:** `e3c8223a140ce81e`

Canonical inputs: PKG_WITH_LIFECYCLE + LOCKFILE_WITH_LIFECYCLE_DEP
(package with postinstall + lockfile with a dep that also has postinstall).

Fingerprint components: EAR states, gap forms per family, N(O),
total gap count. Instance-specific data excluded.

Conformance: all 9 gate tests pass AND fingerprint matches.
