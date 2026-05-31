# CX-I: Vault Implementation Codex

*Vault Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## CODEX-1: Implementation Architecture

### Scope
This codex specifies the Python reference implementation for
Vault constitutional analysis. It defines the component contract,
phase execution order, and gate conditions.

### Component contract

| Component          | File                  | Purpose                              |
|--------------------|-----------------------|--------------------------------------|
| EAR Adapter        | ear_adapter_vault.py  | Phase A: topology, C-01..C-04        |
| GCG Analyzer       | gcg_analyzer.py       | Phases B-F: C-05..C-19               |
| Gap Assertions     | gap_assertions.py     | Serialization, fingerprint, receipts |
| Gate Tests         | tests/test_gate_suite.py | Convergence verification           |

### Invariant inheritance
This implementation must satisfy all CX-S invariants (INVARIANTS.md).
Specifically:
- S-02: Implementation must detect absent audit device as NON_ACTIVATION
- S-04: Implementation must classify root token as BYPASS, not governed
- S-05: Implementation must declare storage backend as JD-1
- S-07: Implementation must document N-determination strategy per assertion

---

## CODEX-2: Phase Execution

### Phase A — Foundation
**Entry condition:** VaultEARAdapter initialized with audit log source.
**Output:** Operation family list + governance layer topology.
**Gate:** T-A: all operation families identified with declared layers.

### Phase B — Core Constructs
**Entry condition:** Phase A complete.
**Output:** N(O) per family, k(O,e) per instance, non-participation notes.
**Gate:** T-B: N(O) and k(O,e) correctly computed for test fixtures.

### Phase C — GCG Assertion
**Entry condition:** Phase B complete.
**Output:** List of CoverageGapAssertion objects.
**Gate:** T-C / T-GCG-01..03: assertions present for gaps, absent for clean ops.

### Phase D — Form Classification
**Entry condition:** Phase C complete.
**Output:** GCG form (NON_ACTIVATION/ABSENCE/BYPASS) per assertion.
**Gate:** T-D: root token = BYPASS, disabled audit = NON_ACTIVATION.

### Phase E — Diagnostics
**Entry condition:** Phase D complete.
**Output:** Gap magnitude, artifact overstating flag, remediation class.
**Gate:** T-E: all seven assertion fields populated.

### Phase F — Report
**Entry condition:** Phase E complete.
**Output:** GCGAnalysisReport with convergence fingerprint.
**Gate:** T-F: report contains all required sections, fingerprint stable.

---

## CODEX-3: Convergence Specification

### Reference fingerprint
`6936be4feb549511`

Canonical inputs:
1. One secret_read with full policy receipt (no gap)
2. One root_token_operation (BYPASS gap)
3. One secret_read with no policy receipt (NON_ACTIVATION gap)
Adapter: audit_device_enabled=True

### Fingerprint components
The fingerprint is computed over structural properties only:
- EAR states per operation family
- Gap forms per operation family  
- N(O) per operation family
- Total gap count and form distribution

Instance-specific data (timestamps, request IDs) is excluded.

### Conformance claim
An implementation passes conformance verification if and only if:
1. All 9 gate tests pass (test_gate_suite.py)
2. The convergence fingerprint matches `6936be4feb549511`
   for the canonical input set

---

## CODEX-4: Extension Points

### Adding Vault Enterprise layers
To add Sentinel EGP/RGP as governance layers:
1. Add entries to VAULT_GOVERNANCE_LAYERS in ear_adapter_vault.py
2. Update VAULT_OPERATION_FAMILIES declared_layers for relevant families
3. Update _assess_k to check for sentinel policy results in audit entry
4. Declare CC-05=ENTERPRISE in the analysis

### Adding auth method-specific N(O)
For PER-CONTEXT-N analyses:
1. Override collect_governance_layers per operation family
2. Inspect the audit entry's auth.display_name to determine auth method
3. Adjust N(O) based on which auth method was used
4. Document the per-context strategy in the governance declaration

### Runtime vs static analysis
Current implementation is RUNTIME (requires audit log).
For STATIC-only analysis:
1. Override collect_executions to return empty list
2. Override assess_ear_state to use structural heuristics only
3. Declare CC-03=STATIC in the analysis
4. Note that no instance-level GCG assertions can be made
