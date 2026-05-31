# Docker Constitutional Analysis

*A Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*

---

This repository contains the Docker constitutional analysis — the reference
case for boundary governance in container infrastructure.

---

## What This Analysis Finds

Docker applies meaningful governance at the container boundary:
seccomp syscall filtering, AppArmor MAC profiles, Linux capability
restrictions, and namespace isolation. For standard containers with
default settings, all five declared governance layers participate.

The `--privileged` flag is a Layer Bypass that simultaneously disables
three of five governance layers (seccomp, AppArmor, capabilities)
with no record of the bypass. Gap magnitude = 3.

The interior of a running container — process execution, filesystem
access after namespace establishment — has no governance and no receipt.

---

## Constitutional Profile

| Dimension              | Finding                                      |
|------------------------|----------------------------------------------|
| Authority              | Flag-derived — no prior declaration          |
| Accountability         | CRYSTALLIZED boundary; ABSENT interior       |
| Governance             | Real at boundary; BYPASS for --privileged    |
| Configuration-Authority| Accidental entanglement                      |
| Resolution Opacity     | LOW via inspect; TOTAL for --privileged      |
| Extension Surfaces     | Build and interior ungoverned                |
| Authority Bypass       | --privileged (process-scoped, magnitude 3)   |
| Projection Divergence  | MODERATE                                     |

**EAR State:**
- `container_run_standard`: **CRYSTALLIZED**
- `container_run_privileged`: **ABSENT**
- `container_interior_execution`: **ABSENT**
- `image_build`: **ABSENT**

**Recoverability:** COMPOSITIONAL (daemon) / STRUCTURAL_NONLOCALITY (interior)

---

## Why Docker Third

Wave 1: Vault (governance complete) → npm (governance absent) → **Docker**

Docker demonstrates that governance can be real at a defined boundary
without extending inside. Readers who have seen Vault and npm arrive
at Docker understanding both the vocabulary and the spectrum.
Docker occupies the middle — genuine boundary governance, absent interior.

---

## Python Reference Implementation

```bash
python3 impl/tests/test_gate_suite.py

# Analyze running containers
python3 -c "
import json, subprocess
from impl.ear_adapter_docker import DockerEARAdapter
from impl.gcg_analyzer import GCGAnalyzer
from impl.gap_assertions import write_receipt

# Get inspect data for all running containers
result = subprocess.run(['docker', 'inspect', '\$(docker ps -q)'],
                       capture_output=True, text=True, shell=False)
data = json.loads(result.stdout) if result.stdout else []

adapter = DockerEARAdapter(inspect_data=data)
report = GCGAnalyzer().analyze(adapter, target_system='Docker')
fp = write_receipt(report, 'docker_gcg_report.json')
print(f'Gaps: {report.total_gaps_found}, By form: {report.gap_by_form}')
print(f'Fingerprint: {fp}')
"
```

**Convergence fingerprint:** `1b0fde1ac25d1170`

---

## Open Question: Build-Run Authority Disconnect

The Dockerfile `USER` directive declares intended runtime user.
`docker run --user <override>` supersedes it at runtime.

Whether this constitutes Layer Bypass (Dockerfile USER as governance
declaration) or a distinct structure is declared as an open question
(GCG codex OQ-03, PCM-0333-208, unresolved in RC v1.6).

---

## Related CSoftA Analyses

Wave 1: Vault → npm → **Docker** → Kubernetes → Keycloak

---

## License

Documentation: CC BY-ND 4.0 International · Code: Apache License 2.0
