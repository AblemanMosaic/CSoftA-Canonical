# CSoftA — Constitutional Software Analysis

**Ableman Constitutional Systems** — ableman.research@gmail.com

---

## What this repository contains

80 constitutional analyses of production software systems. A constitutional
analysis asks whether governance mechanisms are constitutive of operations
completing — meaning the operation fails if the check fails — or merely
parallel to them, or absent entirely.

Each analysis is a reproducible package: a formal governance model, a
findings document, and a gate test suite with a stable convergence
fingerprint.

| | |
|---|---:|
| Systems with at least one ACTIVE operation family | 35 |
| Systems whose highest state is CRYSTALLIZED | 45 |
| Total systems analyzed | 80 |
| Verification gates | 722 |

---

## Closing the Gap

**[CLOSING_THE_GAP.md](CLOSING_THE_GAP.md)** — For security teams,
platform engineers, and software maintainers: exactly where each analyzed
system falls short of full governance, what form the gap takes, and what
closes it. Covers 15 systems in this release including Vault, Kubernetes,
PostgreSQL, MongoDB, MySQL, OPA, GitHub Actions, Kafka, Elasticsearch,
CloudTrail, Active Directory, Docker, npm, Entra ID, and Jenkins.

Three gap forms, one document, no ambiguity about what needs to change.

---

## Verify it

```bash
git clone https://github.com/ableman-constitutional-systems/csofta
cd csofta
python governed_pytest.py
```

Expected output:

```
80/80 PASS  0 MISMATCH  0 ERROR
722/722 tests passed
Session hash: c2e4a49a6a18be8f5fb91b34430438a7
```

The session hash covers all 80 convergence fingerprints. If it matches,
every analysis is identical to its authored state.

`pytest` also works and collects 720 tests from the repo root (79 × 9 + npm's
9 base tests). The npm suite has 2 additional extended tests visible when run
in isolation: `pytest npm-constitutional-analysis/`. Both pass completely.

This repository is intended as a research corpus and reference implementation,
not a security rating system. ACTIVE does not mean secure. CRYSTALLIZED does
not mean inadequate. ABSENT does not mean unusable. The classifications
describe governance architecture, not fitness for any particular purpose.

---

## Why this exists

Most software audits examine code for vulnerabilities. This corpus examines
the governance architecture of production systems — whether the checks that
are supposed to run actually run, whether their outputs are constitutive of
operations completing or merely parallel to them, and where the structural
gaps are regardless of whether they have been exploited yet.

The goal is to make those assumptions observable, testable, and reproducible.

---

## What the three states mean

**ACTIVE** — the governance check is constitutive of the operation. If the
check fails, the operation fails. The receipt is load-bearing.
*Vault `secret_read` with audit device enabled: the audit device is
fail-closed. The operation cannot complete without producing a receipt.*

**CRYSTALLIZED** — governance mechanisms exist and are evaluated, but the
operation proceeds regardless. The receipt is parallel, not constitutive.
*Kubernetes audit log: present, configurable, not mandatory. Execution
proceeds whether or not the audit device is active.*

**ABSENT** — no governance mechanism exists for this operation family.
The operation completes and leaves no structured record.
*Default Elasticsearch: no authentication, no audit log. Any
network-reachable client has full access.*

EAR (Execution-Authority Receipt Contract) state is per operation family, not per
system. Vault is ACTIVE for `secret_read` and ABSENT for
`root_token_operation`. Both are true.

`†` marks systems where ACTIVE requires a commercial license.
See [CONCEPTS.md](CONCEPTS.md#commercial-governance-paywalling-t1784).

---

## What each analysis contains

```
vault-constitutional-analysis/
├── impl/
│   ├── ear_adapter_vault.py   # Formal model: operation families, governance
│   │                          # layers, EAR state logic, N-determination
│   ├── gcg_analyzer.py        # GCG (Governance Coverage Gap) analysis engine
│   ├── gap_assertions.py      # Assertion serialization and fingerprinting
│   └── tests/
│       └── test_gate_suite.py # 9 gate tests per T1576 standard
└── analysis/
    └── FINDINGS.md            # Findings: executive summary, EAR state table,
                               # key CVEs, constitutional comparisons
```

The **adapter** is the formal model. It declares what governance layers exist
for each operation family and what EAR state results. It can run against real
system data where the system exposes an API or audit log.

The **FINDINGS document** is the human-readable analysis. It explains the
constitutional finding, cites real incidents where identified gaps were
exploited, and positions the system relative to others in the corpus.

The **gate tests** verify the adapter: known-bad configurations produce the
correct gap assertions, fully governed configurations produce no false
positives, and N-determination is stable and documented. The convergence
fingerprint is a content-addressed hash of the analysis's structural
properties — EAR states, governance layers, gap forms. Two independent
implementations that reach the same classifications produce the same
fingerprint.

Some Wave 1–2 directories also contain a `codex/` directory with CX:AES
specification artifacts and a `d3/CLASSIFICATION.md` compact profile.

---

## Selected systems

A sample across the classification space. Full index of all 80 systems in
[CATALOG.md](CATALOG.md).

| System | Category | EAR Ceiling | Key Finding |
|--------|----------|-------------|-------------|
| vault | Secrets | ACTIVE | `secret_read` ACTIVE — audit device failure causes the operation to fail |
| stripe | Payments | ACTIVE | Charge event is mandatory, immutable, and independent of the caller |
| cilium | Network/Security | ACTIVE | eBPF LSM hooks enforce policy in-kernel before system calls complete |
| linkerd | Service Mesh | ACTIVE | mTLS mandatory for meshed pods without admission webhook dependency |
| aws-codepipeline | CI/CD | ACTIVE | Only CI/CD system in corpus where deployment requires explicit human approval |
| kubernetes | K8s | CRYSTALLIZED | Multi-layer governance cascade; default cluster is effectively ungoverned |
| elasticsearch | Observability | CRYSTALLIZED | Default ABSENT; a gap here exposes all stored governance evidence from other systems |
| active-directory | Identity | CRYSTALLIZED | Kerberoasting exploits correct protocol behavior — cannot be configured away |
| jenkins | CI/CD | CRYSTALLIZED | Governance degrades continuously over operational lifetime without active maintenance |
| npm | Supply Chain | CRYSTALLIZED | Two structurally independent ABSENT surfaces: lifecycle scripts and module-load-time |

---

## Interpretive framework

The classification methodology — what ACTIVE means, how N(O) is determined,
what gap forms exist, how convergence fingerprints are derived — is in
[METHODOLOGY.md](METHODOLOGY.md). A glossary of key terms (EAR, GCG, N(O),
operation family, convergence fingerprint) is at the top of that document.

The 17 named constitutional concepts that emerged from the corpus are in
[CONCEPTS.md](CONCEPTS.md). These include things like kernel-time
enforcement, split-path governance, commercial governance paywalling, and
protocol-inherent bypass — structural properties that recurred across the
corpus and motivated a new vocabulary for describing them.

The system index and gate tests are fact. The methodology and concepts are
interpretation. The gate tests are the connection: they verify that the
interpretive classifications are internally consistent and produce the same
fingerprint on every run.

---

## Contributing

To add system #81: write an EAR adapter, a FINDINGS document, and 9 gate
tests meeting the T1576 standard. Run `governed_pytest.py` to get the
convergence fingerprint, add it to `KNOWN_FINGERPRINTS`, and confirm
80+1 systems pass. Full specification in [CONTRIBUTING.md](CONTRIBUTING.md).

---

## The paper

The methodology is described in full in [PAPER.md](PAPER.md):

> Mazurk, A. A. *Constitutional Software Analysis (CSoftA): A
> Governance-Based Classification Method for Software Systems.* 2026.
> https://doi.org/10.5281/zenodo.20472195

## Cite this work

```bibtex
@article{mazurk2026csofta,
  title   = {Constitutional Software Analysis (CSoftA): A Governance-Based
             Classification Method for Software Systems},
  author  = {Mazurk, Adam Ableman},
  year    = {2026},
  doi     = {10.5281/zenodo.20472195},
  url     = {https://doi.org/10.5281/zenodo.20472195},
  publisher = {Zenodo}
}
```

## About

Ableman Constitutional Systems conducts constitutional analysis of
production software governance infrastructure.

Contact: ableman.research@gmail.com

---

## License

**Code** (`.py` files): Apache License 2.0  
**Documentation and analyses** (`.md` files): CC BY-ND 4.0 International

© Ableman Constitutional Systems — ableman.research@gmail.com
