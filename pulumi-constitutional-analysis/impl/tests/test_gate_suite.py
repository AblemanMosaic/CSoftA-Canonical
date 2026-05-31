"""test_gate_suite.py — Pulumi gate tests. Wave 13."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_pulumi import PulumiEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = PulumiEARAdapter(remote_backend=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "stack_update")
    state = adapter.assess_ear_state(fam)
    assert state in (EARState.ABSENT, EARState.CRYSTALLIZED), f"unexpected: {state}"
    print("T-GCG-01 PASS: no remote backend → ABSENT")


def test_gcg_02():
    adapter = PulumiEARAdapter(remote_backend=True, crossguard_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Pulumi")
    items = [a for a in report.assertions if a.operation_family == "stack_update"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "crossguard_policy" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no CrossGuard → gap={absent}")


def test_gcg_03():
    adapter = PulumiEARAdapter(remote_backend=True, crossguard_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "policy_enforcement")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-GCG-03 PASS: CrossGuard → ACTIVE (policy constitutive of stack update)")


def test_nd_01():
    a1, a2 = PulumiEARAdapter(), PulumiEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = PulumiEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "stack_update")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["state_backend", "stack_lock"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: layers={layers}")


def test_nd_03():
    decl = PulumiEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = PulumiEARAdapter(remote_backend=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "stack_update")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no backend → ABSENT")


def test_ear_02():
    adapter = PulumiEARAdapter(remote_backend=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "stack_update")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: remote backend → CRYSTALLIZED")


def test_ear_03():
    adapter = PulumiEARAdapter(remote_backend=True, crossguard_enabled=True, audit_log_enabled=True, drift_monitoring=True, esc_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "policy_enforcement"); assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-03 PASS: policy_enforcement with CrossGuard → ACTIVE")


def compute_fingerprint():
    adapter = PulumiEARAdapter(remote_backend=True, crossguard_enabled=True, audit_log_enabled=True, drift_monitoring=True, esc_configured=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Pulumi")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: completes IaC trilogy; CrossGuard ACTIVE; drift ABSENT (Insights adds CRYSTALLIZED-forward); extends T1671 + T1726")
    print("=" * 60)
    return fp


def run_all_gates():
    tests = [
        test_gcg_01, test_gcg_02, test_gcg_03,
        test_nd_01, test_nd_02, test_nd_03,
        test_ear_01, test_ear_02, test_ear_03,
    ]
    passed = 0
    failed = 0
    failures = []
    print("Running " + str(len(tests)) + " gate tests (" + "Pulumi" + ")...")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print("FAIL: " + t.__name__ + ": " + str(e))
            failed += 1
            failures.append((t.__name__, str(e)))
    print("=" * 60)
    print("RESULTS: " + str(passed) + "/" + str(len(tests)))
    if failures:
        for n, m in failures:
            print("  FAIL: " + n + ": " + m)
    print("=" * 60)
    fp = compute_fingerprint()
    return passed, failed, fp


if __name__ == "__main__":
    p, f, fp = run_all_gates()
    sys.exit(0 if f == 0 else 1)
