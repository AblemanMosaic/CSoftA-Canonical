# npm Constitutional Analysis

*A Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*

---

This analysis is part of the Constitutional Software Analysis (CSoftA)
research corpus developed by Ableman Constitutional Systems.

This repository contains the npm analysis — the reference case for
absent constitutional governance in a universally-deployed developer tool.

---

## What This Analysis Finds

npm lifecycle scripts execute arbitrary code with the installing user's
full privileges. There is no governance layer for this execution.
No record is produced of what ran.

This is not a vulnerability. It is a structural property of npm's design.

The analysis finds that every npm package with a `postinstall`,
`preinstall`, or other lifecycle script represents a pre-governance
capability exercise: code that runs because it exists, not because it
was authorized.

---

## Constitutional Profile

| Dimension              | Finding                                      |
|------------------------|----------------------------------------------|
| Authority              | Execution-derived — presence = authority     |
| Accountability         | ABSENT for lifecycle; CRYSTALLIZED for install with lockfile |
| Governance             | lifecycle_governance layer does not exist    |
| Configuration-Authority| Accidental entanglement                      |
| Resolution Opacity     | TOTAL for lifecycle; LOW for resolution      |
| Extension Surfaces     | UNGOVERNED — only in SFA corpus              |
| Authority Bypass       | No governance baseline to bypass             |
| Projection Divergence  | HIGH — "install dependencies" conceals scope |

**EAR State:**
- `lifecycle_script_execution`: **ABSENT**
- `dependency_install` (with lockfile): **CRYSTALLIZED**
- `dependency_install` (no lockfile): **ABSENT**
- `package_publish` (--provenance): **CRYSTALLIZED**

**Recoverability Regime: STRUCTURAL_NONLOCALITY**

---

## Why npm Second

The Wave 1 publication sequence places npm immediately after Vault
to establish the maximum contrast in the governance spectrum.

After reading Vault (every operation receipted, authority explicit),
reading npm makes the governance gap concrete and universal: this
runs on nearly every JavaScript developer's machine, today.

---

## Repository Structure

```
analysis/FINDINGS.md          # 8-dimension SFA findings
codex/CX-S/INVARIANTS.md      # Domain invariants
codex/CX-C/MANIFOLD.md        # Configuration manifold
codex/CX-I/CODEX.md           # Implementation codex
d3/CLASSIFICATION.md           # D3 compact classification
impl/
├── ear_adapter_npm.py         # Static analyzer (package.json + lockfile)
├── gcg_analyzer.py            # GCG Phases A–F
├── gap_assertions.py          # Receipt serialization
└── tests/test_gate_suite.py   # 9-test gate suite
```

---

## Python Reference Implementation

No live cluster required — the implementation is a static analyzer.

```bash
python3 impl/tests/test_gate_suite.py

# Analyze a project
python3 -c "
from impl.ear_adapter_npm import NpmEARAdapter
from impl.gcg_analyzer import GCGAnalyzer
from impl.gap_assertions import write_receipt

adapter = NpmEARAdapter(
    package_json_path='path/to/package.json',
    lockfile_path='path/to/package-lock.json',
)
report = GCGAnalyzer().analyze(adapter, target_system='npm')
fp = write_receipt(report, 'npm_gcg_report.json')
print(f'Gaps: {report.total_gaps_found}, Fingerprint: {fp}')
"
```

**Convergence fingerprint:** `e3c8223a140ce81e`

---

## CX:AES Codex

The `codex/CX-S/INVARIANTS.md` specifies what a constitutionally governed
package manager would require. It is not a description of npm as it exists —
it is a portable specification for what must be built.

---

## Related CSoftA Analyses

Wave 1: Vault → **npm** → Docker → Kubernetes → Keycloak

---

## License

Documentation: CC BY-ND 4.0 International · Code: Apache License 2.0
