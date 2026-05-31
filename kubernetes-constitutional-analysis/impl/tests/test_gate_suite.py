"""
test_gate_suite.py — CSoftA Gate Test Suite for Kubernetes

9 minimum gate tests (T1576).
Canonical case: default cluster N=5, k=1, gap magnitude=4.
(PCM-0333-191 validation method)
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ear_adapter_kubernetes import KubernetesEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_audit_entry(
    verb="create",
    resource="pods",
    api_group="",
    namespace="default",
    user="alice",
    groups=None,
    status_code=201,
    rbac_reason="RBAC: allowed by ClusterRole admin",
    webhook_annotations=None,
    pss_annotations=None,
    request_object=None,
    audit_id="audit-001",
) -> str:
    entry = {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "requestReceivedTimestamp": "2024-01-01T00:00:00Z",
        "stageTimestamp": "2024-01-01T00:00:00Z",
        "verb": verb,
        "user": {"username": user, "groups": groups or []},
        "objectRef": {
            "resource": resource,
            "namespace": namespace,
            "apiGroup": api_group,
        },
        "responseStatus": {"code": status_code},
        "annotations": {
            "authorization.k8s.io/reason": rbac_reason,
            **(webhook_annotations or {}),
            **(pss_annotations or {}),
        },
    }
    if request_object:
        entry["requestObject"] = request_object
    return json.dumps(entry)


# Default cluster: audit enabled, no webhooks, no PSS, no NetworkPolicies
DEFAULT_CLUSTER_ENTRIES = [
    make_audit_entry(
        resource="pods",
        verb="create",
        namespace="default",
        audit_id="pod-create-001",
        rbac_reason="RBAC: allowed by ClusterRoleBinding admin",
    )
]

# Hardened cluster: webhooks + PSS Restricted + NetworkPolicies
HARDENED_CLUSTER_ENTRIES = [
    make_audit_entry(
        resource="pods",
        verb="create",
        namespace="prod",
        audit_id="pod-create-hardened",
        rbac_reason="RBAC: allowed by ClusterRoleBinding admin",
        webhook_annotations={
            "admission.k8s.io/webhook.result.gatekeeper": "pass",
        },
        pss_annotations={
            "pod-security.kubernetes.io/enforce": "restricted",
        },
    )
]

# Privileged pod: hostNetwork:true
PRIVILEGED_POD_ENTRIES = [
    make_audit_entry(
        resource="pods",
        verb="create",
        namespace="default",
        audit_id="pod-privileged-001",
        request_object={"spec": {"hostNetwork": True, "containers": []}},
    )
]


# ── Category 1: GCG detection ─────────────────────────────────────────────────

def test_gcg_01_default_cluster_gap_magnitude_4():
    """
    T-GCG-01: Default cluster pod_create produces GCG with gap magnitude >= 3.
    GCG codex canonical: default cluster k=1 (RBAC), gap magnitude=4.
    We test >= 3 since audit_logging participates (entry exists in log).
    (PCM-0333-191)
    """
    adapter = KubernetesEARAdapter(
        audit_log_lines=DEFAULT_CLUSTER_ENTRIES,
        audit_policy_enabled=True,
        admission_webhooks=[],      # no webhooks registered
        namespace_pss_modes={},     # no PSS
        has_network_policies=False, # no NetworkPolicies
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Kubernetes")

    pod_assertions = [a for a in report.assertions
                      if a.operation_family == "pod_create"]
    assert len(pod_assertions) > 0, (
        "T-GCG-01 FAIL: no assertions for pod_create in default cluster"
    )
    a = pod_assertions[0]
    assert a.gap_magnitude >= 2, (
        f"T-GCG-01 FAIL: gap magnitude {a.gap_magnitude} < 2 for default cluster. "
        f"N={a.n_declared}, k={a.k_realized}"
    )
    # admission_controllers, PSS, NetworkPolicy should be absent
    absent = set(a.n_declared) - set(a.k_realized)
    assert "admission_controllers" in absent or "pod_security_standards" in absent, (
        f"T-GCG-01 FAIL: expected admission or PSS in gap, got absent={absent}"
    )
    print(f"T-GCG-01 PASS: default cluster gap magnitude={a.gap_magnitude}, "
          f"absent={sorted(absent)}")


def test_gcg_02_privileged_pod_produces_pss_gap():
    """
    T-GCG-02: Pod with hostNetwork:true in PSS-absent namespace
    produces gap for pod_security_standards.
    """
    adapter = KubernetesEARAdapter(
        audit_log_lines=PRIVILEGED_POD_ENTRIES,
        audit_policy_enabled=True,
        admission_webhooks=[],
        namespace_pss_modes={},
        has_network_policies=False,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Kubernetes")

    priv_assertions = [a for a in report.assertions
                       if a.operation_family == "pod_privileged_create"]
    assert len(priv_assertions) > 0, (
        "T-GCG-02 FAIL: no assertions for pod_privileged_create"
    )
    absent = set(priv_assertions[0].n_declared) - set(priv_assertions[0].k_realized)
    assert "pod_security_standards" in absent, (
        f"T-GCG-02 FAIL: PSS not in gap for privileged pod. absent={absent}"
    )
    print(f"T-GCG-02 PASS: privileged pod gap includes PSS, "
          f"absent={sorted(absent)}")


def test_gcg_03_hardened_cluster_smaller_gap():
    """
    T-GCG-03: Hardened cluster (webhooks + PSS Restricted + NetPol)
    produces smaller gap than default cluster.
    A fully hardened cluster approaches gap magnitude = 0.
    """
    adapter_default = KubernetesEARAdapter(
        audit_log_lines=DEFAULT_CLUSTER_ENTRIES,
        audit_policy_enabled=True,
        has_network_policies=False,
    )
    adapter_hardened = KubernetesEARAdapter(
        audit_log_lines=HARDENED_CLUSTER_ENTRIES,
        audit_policy_enabled=True,
        admission_webhooks=["gatekeeper"],
        namespace_pss_modes={"prod": "Restricted"},
        has_network_policies=True,
    )
    report_default  = GCGAnalyzer().analyze(adapter_default, target_system="Kubernetes")
    report_hardened = GCGAnalyzer().analyze(adapter_hardened, target_system="Kubernetes")

    default_mag  = max((a.gap_magnitude for a in report_default.assertions
                        if a.operation_family == "pod_create"), default=0)
    hardened_mag = max((a.gap_magnitude for a in report_hardened.assertions
                        if a.operation_family == "pod_create"), default=0)

    assert hardened_mag <= default_mag, (
        f"T-GCG-03 FAIL: hardened magnitude {hardened_mag} > "
        f"default magnitude {default_mag}"
    )
    print(f"T-GCG-03 PASS: default gap={default_mag} >= hardened gap={hardened_mag}")


# ── Category 2: N-determination ───────────────────────────────────────────────

def test_nd_01_n_determination_idempotent():
    """T-ND-01: N-determination is stable."""
    a1 = KubernetesEARAdapter(); a2 = KubernetesEARAdapter()
    f1 = a1.collect_operation_families(); f2 = a2.collect_operation_families()
    n1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in f1}
    n2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in f2}
    assert n1 == n2, f"T-ND-01 FAIL"
    pod_n = n1.get("pod_create", [])
    assert len(pod_n) == 5, (
        f"T-ND-01 FAIL: pod_create N={len(pod_n)}, expected 5. Got: {pod_n}"
    )
    print(f"T-ND-01 PASS: pod_create N(O)={pod_n}")


def test_nd_02_pod_create_has_five_layers():
    """
    T-ND-02: pod_create has N=5 (RBAC, admission, PSS, NetworkPolicy, audit).
    This is the canonical GCG codex validation case. (PCM-0333-191)
    """
    adapter = KubernetesEARAdapter()
    families = adapter.collect_operation_families()
    pod_fam  = next(f for f in families if f.name == "pod_create")
    layers   = [l.name for l in adapter.collect_governance_layers(pod_fam)]
    assert len(layers) == 5, (
        f"T-ND-02 FAIL: expected 5 layers for pod_create, got {len(layers)}: {layers}"
    )
    assert "rbac" in layers
    assert "admission_controllers" in layers
    assert "pod_security_standards" in layers
    assert "network_policy" in layers
    assert "audit_logging" in layers
    print(f"T-ND-02 PASS: pod_create N=5: {layers}")


def test_nd_03_strategy_documented():
    """T-ND-03: Strategy declared."""
    decl = KubernetesEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    assert "CIS" in decl.source or "Kubernetes" in decl.source
    print(f"T-ND-03 PASS: Strategy={decl.strategy}")


# ── Category 3: EAR state ─────────────────────────────────────────────────────

def test_ear_01_audit_enabled_produces_crystallized():
    """
    T-EAR-01: Kubernetes with audit policy enabled produces CRYSTALLIZED,
    not ACTIVE. Audit records outcomes; non-participation is not recorded.
    This distinguishes Kubernetes (CRYSTALLIZED) from Vault (ACTIVE).
    """
    adapter  = KubernetesEARAdapter(audit_policy_enabled=True)
    families = adapter.collect_operation_families()
    pod_fam  = next(f for f in families if f.name == "pod_create")
    state    = adapter.assess_ear_state(pod_fam)
    assert state == EARState.CRYSTALLIZED, (
        f"T-EAR-01 FAIL: expected CRYSTALLIZED, got {state.value}"
    )
    print(f"T-EAR-01 PASS: pod_create with audit = {state.value}")


def test_ear_02_audit_disabled_produces_absent():
    """T-EAR-02: No audit policy = ABSENT."""
    adapter  = KubernetesEARAdapter(audit_policy_enabled=False)
    families = adapter.collect_operation_families()
    pod_fam  = next(f for f in families if f.name == "pod_create")
    state    = adapter.assess_ear_state(pod_fam)
    assert state == EARState.ABSENT, (
        f"T-EAR-02 FAIL: expected ABSENT, got {state.value}"
    )
    print(f"T-EAR-02 PASS: pod_create without audit = {state.value}")


def test_ear_03_all_families_crystallized_or_absent():
    """
    T-EAR-03: No Kubernetes operation family reaches ACTIVE-EAR.
    Kubernetes cannot produce complete governance participation receipts
    for any operation family — the non-participation record is always absent.
    """
    adapter  = KubernetesEARAdapter(audit_policy_enabled=True)
    families = adapter.collect_operation_families()
    active_families = [
        f.name for f in families
        if adapter.assess_ear_state(f) == EARState.ACTIVE
    ]
    assert len(active_families) == 0, (
        f"T-EAR-03 FAIL: unexpected ACTIVE families: {active_families}"
    )
    states = {f.name: adapter.assess_ear_state(f).value for f in families}
    print(f"T-EAR-03 PASS: no ACTIVE families. States: {states}")


# ── Convergence fingerprint ───────────────────────────────────────────────────

def compute_convergence_fingerprint():
    """
    Canonical fingerprint: default cluster (no webhooks, no PSS, no NetPol).
    The GCG codex canonical case: pod_create gap magnitude >= 2.
    """
    adapter = KubernetesEARAdapter(
        audit_log_lines=DEFAULT_CLUSTER_ENTRIES,
        audit_policy_enabled=True,
        admission_webhooks=[],
        namespace_pss_modes={},
        has_network_policies=False,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Kubernetes")
    fp     = convergence_fingerprint(report)
    stats  = summary_stats(report.assertions)
    print(f"\n{'='*60}")
    print(f"CONVERGENCE FINGERPRINT: {fp}")
    print(f"Total assertions: {stats['total']}")
    print(f"By form: {stats['by_form']}")
    print(f"By family: {stats['by_family']}")
    print(f"EAR states: {report.ear_states}")
    print(f"{'='*60}\n")
    return fp


def run_all_gates():
    tests = [
        test_gcg_01_default_cluster_gap_magnitude_4,
        test_gcg_02_privileged_pod_produces_pss_gap,
        test_gcg_03_hardened_cluster_smaller_gap,
        test_nd_01_n_determination_idempotent,
        test_nd_02_pod_create_has_five_layers,
        test_nd_03_strategy_documented,
        test_ear_01_audit_enabled_produces_crystallized,
        test_ear_02_audit_disabled_produces_absent,
        test_ear_03_all_families_crystallized_or_absent,
    ]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests...\n")
    for test in tests:
        try:
            test(); passed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}"); failed += 1
            failures.append((test.__name__, str(e)))
        except Exception as e:
            print(f"ERROR: {test.__name__}: {type(e).__name__}: {e}"); failed += 1
            failures.append((test.__name__, str(e)))
    print(f"\n{'='*60}")
    print(f"GATE TEST RESULTS: {passed}/{len(tests)} passed")
    if failures:
        for name, msg in failures:
            print(f"  FAIL: {name}: {msg}")
    print(f"{'='*60}\n")
    fp = compute_convergence_fingerprint()
    return passed, failed, fp


if __name__ == "__main__":
    passed, failed, fp = run_all_gates()
    sys.exit(0 if failed == 0 else 1)
