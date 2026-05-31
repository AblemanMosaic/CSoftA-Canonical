# Vault Constitutional Analysis

*A Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*

---

This analysis is part of the Constitutional Software Analysis (CSoftA)
research corpus developed by Ableman Constitutional Systems.

CSoftA applies Constitutional Systems Analysis (CSysA) and
Structural Fragmentation Analysis (SFA) to production software systems.

This repository contains the HashiCorp Vault analysis — the reference
implementation of strong constitutional governance in production software.

---

## What This Analysis Finds

Vault is governance-complete for authenticated non-root operations
when an audit device is enabled.

It is the only system in the 17-system SFA corpus with a
**mandatory-ledger receipt tier**: every permitted operation produces
a structured record including token identity, policy chain, and outcome.

The central constitutional weakness is the root token — an unbounded
Layer Bypass that circumvents all governance mechanisms. Its scope
is bounded and its presence is detectable; it is not a disqualifying
defect but a declared constitutional limitation.

---

## Constitutional Profile

| Dimension              | Finding                              |
|------------------------|--------------------------------------|
| Authority              | Explicitly declared via named policy paths |
| Accountability         | ACTIVE-EAR when audit device enabled |
| Governance             | Complete for non-root operations     |
| Configuration-Authority| Structural separation                |
| Resolution Opacity     | LOW — full decision chain in audit log |
| Extension Surfaces     | Perimeter-governed (plugin API)      |
| Authority Bypass       | Root token (unbounded, detectable)   |
| Projection Divergence  | MINOR — audit default miscommunicates |

**EAR State:**
- `secret_read`, `secret_write`, `token_create`, `policy_manage`: **ACTIVE** (with audit)
- `auth_login`: **CRYSTALLIZED** (pre-auth, no policy receipt)
- `root_token_operation`: **ABSENT** (bypasses policy evaluation)

**Recoverability Regime:**
- Integrated Raft: **LOCAL**
- Consul backend: **COMPOSITIONAL**
- Cloud storage: **STRUCTURAL_NONLOCALITY**

---

## Analytical Dimensions

This analysis evaluates Vault across the eight primary CSoftA dimensions:
authority declaration, accountability receipt surface, governance mechanisms,
configuration-authority binding, resolution cascade opacity, extension
surfaces, authority bypass scope, and projection divergence.

Findings are structured against the CSoftA fragmentation taxonomy:
F-AUTH, F-ADMIT, F-LINEAGE, F-INTERP, F-PROJ, F-SCOPE.

---

## Why Vault First

The Wave 1 CSoftA publication sequence begins with Vault because it
establishes the existence of the standard before subsequent analyses
describe systems that fail to meet it.

Vault demonstrates that constitutional governance in production software
is achievable, not theoretical.

---

## Repository Structure

```
analysis/
├── FINDINGS.md          # Structured findings against 8 SFA dimensions

codex/
├── CX-S/INVARIANTS.md   # Domain invariants — must hold in any conforming analysis
├── CX-C/MANIFOLD.md     # Configuration manifold — what may vary
├── CX-I/CODEX.md        # Implementation codex — Python spec
└── CX-IR/               # Realization guidance

impl/
├── ear_adapter_vault.py # EAR Adapter — reads Vault audit log
├── gcg_analyzer.py      # GCG Analysis Engine — Phases A–F
├── gap_assertions.py    # Coverage Gap Assertion serialization
└── tests/
    └── test_gate_suite.py  # 9-test convergence gate suite

d3/
└── CLASSIFICATION.md    # D3 compact classification artifact
```

---

## Python Reference Implementation

The implementation requires Python 3.10+. No external dependencies.

```bash
# Run gate tests (establishes convergence)
python3 impl/tests/test_gate_suite.py

# Analyze a live Vault audit log
python3 -c "
from impl.ear_adapter_vault import VaultEARAdapter
from impl.gcg_analyzer import GCGAnalyzer
from impl.gap_assertions import write_receipt, convergence_fingerprint

adapter = VaultEARAdapter(
    audit_log_path='/path/to/vault/audit.log',
    audit_device_enabled=True,
)
analyzer = GCGAnalyzer()
report = analyzer.analyze(adapter, target_version='1.16.x')
fp = write_receipt(report, 'vault_gcg_report.json')
print(f'Analysis complete. Fingerprint: {fp}')
print(f'Total gaps: {report.total_gaps_found}')
print(f'Gap forms: {report.gap_by_form}')
"
```

**Convergence fingerprint:** `6936be4feb549511`

Two independent implementations that produce this fingerprint for
the canonical inputs are convergent — they agree on the structural
governance profile of Vault.

---

## CX:AES Codex

The `codex/` directory contains the CX:AES specification for this analysis.

The CX:AES codex is portable: load `codex/CX-S/INVARIANTS.md` and
`codex/CX-I/CODEX.md` into any LLM or implement them in any language
to produce a conforming constitutional analysis of Vault.

The Python implementation in `impl/` is the reference realization
proving the codex converges.

---

## Related CSoftA Analyses

Wave 1 publication sequence:
1. **Vault** ← *this repository* (strong governance reference case)
2. npm (absent governance contrast case)
3. Docker (boundary governance)
4. Kubernetes (multi-layer governance fragmentation, GCG generative site)
5. Keycloak (identity governance)

---

## About CSoftA

Constitutional Software Analysis (CSoftA) is part of the C\*A family
developed by Ableman Constitutional Systems.

| Domain | Framework |
|--------|-----------|
| Software Systems | CSoftA |
| Civilizational & Sociotechnical Systems | CSysA |
| Physical Systems | CPhysA |
| Scientific Knowledge Systems | CSciA |

The objective is not to determine whether a system is secure or efficient.
The objective is to determine whether a system can explain how governance
was applied to every operation it executes.

---

## Citation

*[DOI to be assigned — Corpus DOI: Constitutional Software Analysis Corpus v1.0]*

## License

Documentation and research artifacts: CC BY-ND 4.0 International
Code and implementations: Apache License 2.0
