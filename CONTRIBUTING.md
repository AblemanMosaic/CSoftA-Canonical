# Contributing a System Analysis

**Ableman Constitutional Systems** — ableman.research@gmail.com

---

A conforming CSoftA analysis consists of three files. This document specifies
what each file must contain, how the convergence fingerprint is registered, and
what qualifies as a new constitutional concept.

---

## The three required files

### 1. `ear_adapter.py`

The EAR (Execution Authorization Receipt) adapter is the formal model of the system's governance architecture.
It must implement the following interface:

```python
class MySystemEARAdapter:

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="...",          # where N(O) was derived from (docs, architecture guides, CVEs)
        strategy="DECLARED-N", # DECLARED-N | MINIMUM-N | PER-CONTEXT-N
        description="...",     # prose description of the classification rationale
    )

    def collect_operation_families(self) -> list[OperationFamily]:
        """Return the operation families for this system."""

    def collect_governance_layers(self, op_family: OperationFamily) -> list[GovernanceLayer]:
        """Return N(O) — the declared governance layers for this operation family."""

    def collect_executions(self, op_family: OperationFamily) -> list[ExecutionInstance]:
        """Return execution instances. For gate tests, synthetic instances are used."""

    def assess_k(self, instance: ExecutionInstance) -> list[str]:
        """Return k(O,e) — which governance layers participated in this execution."""

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """Return ACTIVE, CRYSTALLIZED, or ABSENT for this operation family."""

    def get_governance_declaration(self) -> GovernanceDeclaration:
        """Return the governance declaration for this adapter."""
```

The adapter's `__init__` should accept parameters that control which governance
layers are active — this allows gate tests to construct the adapter in specific
configurations. For example:

```python
def __init__(self, audit_enabled: bool = False, tls_enabled: bool = True):
    self._audit = audit_enabled
    self._tls = tls_enabled
```

The `assess_ear_state` method must return ACTIVE only when the governance check
is genuinely constitutive — when the operation fails if the governance mechanism
fails. Do not return ACTIVE because good governance practices are documented;
return ACTIVE because the mechanism is fail-closed.

The `GOVERNANCE_DECLARATION.description` should document:
- Which operation families reach ACTIVE and what makes them constitutive
- The ceiling for the system and why it cannot be exceeded
- Key CVEs or incidents that illustrate the structural gaps
- Constitutional comparisons to related systems in the corpus

### 2. `FINDINGS.md`

The FINDINGS document is the human-readable analysis. Required sections:

**Executive Finding** — The single most important constitutional finding for this
system. This should be a structural finding, not a CVE summary. What is the
governance ceiling and why? What is the most significant gap?

**EAR State Table** — A table of all operation families with their EAR states and
the key property that determines each classification.

**Key CVEs or Incidents** — Real-world incidents where the gaps you identified
were exploited. Ground the structural finding in evidence.

**Constitutional Comparison** (where applicable) — How does this system compare
to related systems in the corpus? The IaC spectrum, the CI/CD comparison, the
messaging broker comparison are examples of comparisons that generate insight
beyond any individual analysis.

**Summary table** — Operation family | EAR State | Character.

The FINDINGS document should be independently readable — a reader who has not
seen the adapter should understand the finding from FINDINGS.md alone.

### 3. `tests/test_gate_suite.py`

The gate test suite must implement the T1576 standard: 9 minimum tests across
3 categories, with a `run_all_gates()` function that returns
`(passed: int, failed: int, fingerprint: str)`.

```python
def run_all_gates() -> tuple[int, int, str]:
    tests = [
        test_gcg_01, test_gcg_02, test_gcg_03,  # GCG detection
        test_nd_01, test_nd_02, test_nd_03,       # N-determination
        test_ear_01, test_ear_02, test_ear_03,    # EAR state assessment
    ]
    passed, failed, failures = 0, 0, []
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed += 1
            failures.append((t.__name__, str(e)))
    fp = compute_fingerprint()
    return passed, failed, fp
```

**GCG detection tests** must verify:
- A known-gap configuration produces a GCG assertion with the correct gap form
- A Layer Bypass configuration produces a BYPASS assertion with gap magnitude > 0
- A fully governed configuration produces zero false-positive assertions

**N-determination tests** must verify:
- `collect_governance_layers()` returns the same result on two independent calls
- The N-determination strategy is documented in `GOVERNANCE_DECLARATION`
- The source documentation for N(O) is cited

**EAR state tests** must verify the characteristic EAR properties of the system:
- The ACTIVE configuration (or highest achievable state) is correctly classified
- A degraded configuration is correctly classified as CRYSTALLIZED or ABSENT
- A system-specific property that distinguishes this analysis from others

---

## Registering the convergence fingerprint

After writing the adapter and passing all 9 gate tests:

```bash
cd systems/your-system
python3 tests/test_gate_suite.py
# ... output includes FINGERPRINT: <16-char-hex>
```

Add the fingerprint to `KNOWN_FINGERPRINTS` in `governed_pytest.py`:

```python
KNOWN_FINGERPRINTS: dict[str, str] = {
    # ... existing entries ...
    "your-system": "the16charfingerprint",
}
```

Run `python governed_pytest.py` from the repo root to verify your new system
produces PASS. The session hash will change — that is correct. Document the
new session hash in your pull request.

---

## What qualifies as a new constitutional concept

Not every new system generates a new constitutional concept. A concept earns
its name when:

1. It describes a structural property of governance that **recurs across systems**,
   not a finding specific to one system.

2. It is **not already captured** by the existing vocabulary (ACTIVE /
   CRYSTALLIZED / ABSENT, NON_ACTIVATION / ABSENCE / BYPASS, the 17 existing
   concepts).

3. It **changes how you look at governance** in systems you have already analyzed.
   A concept that causes you to re-read existing FINDINGS documents with new eyes
   is likely a genuine concept.

4. It has a **clear definition** that can be stated in two sentences without
   referring to the specific system that introduced it.

If you believe your analysis has introduced a new concept, document it in
FINDINGS.md with the claim "This analysis introduces a new constitutional
concept: [name]." Propose its addition to CONCEPTS.md. The decision to formally
add it to the corpus rests with Ableman Constitutional Systems.

---

## Licensing of contributions

Code contributions (`.py` files) are accepted under Apache License 2.0.

Analysis contributions (`.md` files) are accepted with the understanding that
they become part of the CSoftA corpus under the copyright of Ableman
Constitutional Systems, licensed CC BY-ND 4.0 International. Contributors
retain moral rights to their contributions and will be credited in the
system's FINDINGS document.

The CC BY-ND license on documentation means that derivative versions of
individual FINDINGS documents cannot be published. A contribution to the
corpus is a submission of a new analysis authored by the contributor — not
a derivative of an existing analysis — and is therefore a compatible
original work under the corpus license.

---

## Contact

Questions about contributing, methodology questions, or findings that challenge
existing classifications: ableman.research@gmail.com

---

*© Ableman Constitutional Systems — ableman.research@gmail.com*  
*Documentation: CC BY-ND 4.0 International*
