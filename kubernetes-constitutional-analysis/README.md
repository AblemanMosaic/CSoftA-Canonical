# Kubernetes Constitutional Analysis

*A Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*

---

This repository contains the Kubernetes constitutional analysis — the
analysis that generated the Governance Coverage Gap (GCG) construct,
and the cross-validation target for the GCG codex.

---

## What This Analysis Finds

Kubernetes has five declared governance layers for pod creation:
RBAC, admission controllers, Pod Security Standards, NetworkPolicy,
and audit logging. In a default cluster, only RBAC and audit logging
participate. Gap magnitude = 3.

The system can explain individual RBAC decisions.
It cannot explain the complete governance path that produced an outcome.

This analysis confirms and formalizes the GCG construct's origin:
**GCG codex status advances from UNVALIDATED to VALIDATED.**

---

## Constitutional Profile

| Dimension              | Finding                                      |
|------------------------|----------------------------------------------|
| Authority              | Distributed across 5 independent layers      |
| Accountability         | CRYSTALLIZED — opt-in audit, no non-participation record |
| Governance             | N=5 declared; k=2 default (gap magnitude=3)  |
| Config-Authority       | Inherent entanglement (pod spec = capability claim) |
| Resolution Opacity     | MATERIAL — cannot reconstruct governance path |
| Extension Surfaces     | Webhooks perimeter-governed; interior ungoverned |
| Authority Bypass       | Compositional scoped bypasses                |
| Projection Divergence  | MATERIAL                                     |

**EAR State:** All families → **CRYSTALLIZED** (no operation family reaches ACTIVE)

**Recoverability:** COMPOSITIONAL (API server) / STRUCTURAL_NONLOCALITY (node)

---

## GCG Codex Cross-Validation

This analysis serves as the Phase 0f cross-validation of `gcg-codex-v1-0`.

| Metric | Codex prediction | This analysis |
|--------|-----------------|---------------|
| N(O) for pod_create | 5 | 5 ✓ |
| k in default cluster | ~1 | 2 (RBAC + audit) |
| Gap magnitude (default) | ~4 | 3 |
| Gap form | NON_ACTIVATION | NON_ACTIVATION ✓ |
| Non-participation record | absent | absent ✓ |

**Variance note:** k=2 vs k=1 — the adapter counts audit_logging as
participating when audit entries are present. Both interpretations are
admissible; this is a CX-IC selection, not a codex error.

**GCG codex verdict: VALIDATED.**

---

## Why Kubernetes Fourth

Wave 1: Vault → npm → Docker → **Kubernetes**

Readers arrive having seen the full governance spectrum: ACTIVE-EAR
(Vault), ABSENT (npm), boundary CRYSTALLIZED (Docker). Kubernetes
demonstrates the most complex case: multiple real governance mechanisms
that interact in ways that cannot be explained from the record.

Kubernetes is also where GCG was born. Publishing it fourth means
readers understand the construct before seeing its origin system.

---

## Python Reference Implementation

```bash
python3 impl/tests/test_gate_suite.py

# Analyze a cluster (requires kubeconfig and audit log access)
python3 -c "
from impl.ear_adapter_kubernetes import KubernetesEARAdapter
from impl.gcg_analyzer import GCGAnalyzer
from impl.gap_assertions import write_receipt

adapter = KubernetesEARAdapter(
    audit_log_path='/var/log/kube-audit/audit.log',
    audit_policy_enabled=True,
    # Add deployment-specific config:
    # admission_webhooks=['gatekeeper', 'kyverno'],
    # namespace_pss_modes={'prod': 'Restricted', 'dev': 'Baseline'},
    # has_network_policies=True,
)
report = GCGAnalyzer().analyze(adapter, target_system='Kubernetes')
fp = write_receipt(report, 'k8s_gcg_report.json')
print(f'Gap magnitude (pod_create): '
      f'{max((a.gap_magnitude for a in report.assertions if a.operation_family==\"pod_create\"), default=0)}')
print(f'Fingerprint: {fp}')
"
```

**Convergence fingerprint:** `6c832e715c13bd1d`
(Default cluster, N=5, k=2, gap magnitude=3)

---

## Related CSoftA Analyses

Wave 1: Vault → npm → Docker → **Kubernetes** → Keycloak

---

## License

Documentation: CC BY-ND 4.0 International · Code: Apache License 2.0
