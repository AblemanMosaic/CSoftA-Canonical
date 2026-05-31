"""test_gate_suite.py — Jenkins gate tests."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_jenkins import JenkinsEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = JenkinsEARAdapter(matrix_auth=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "build_execution")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-GCG-01 PASS: no RBAC → ABSENT")


def test_gcg_02():
    adapter = JenkinsEARAdapter(matrix_auth=True, credential_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Jenkins")
    items = [a for a in report.assertions if a.operation_family == "credential_access"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "credential_scope" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no credential scope → gap={absent}")


def test_gcg_03():
    adapter = JenkinsEARAdapter(matrix_auth=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "build_execution")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: with RBAC → CRYSTALLIZED ceiling")


def test_nd_01():
    a1, a2 = JenkinsEARAdapter(), JenkinsEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = JenkinsEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "build_execution")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["rbac_check", "credential_scope"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: build layers={layers}")


def test_nd_03():
    decl = JenkinsEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = JenkinsEARAdapter(matrix_auth=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "build_execution")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no RBAC → ABSENT")


def test_ear_02():
    adapter = JenkinsEARAdapter(matrix_auth=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "build_execution")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: with RBAC → CRYSTALLIZED")


def test_ear_03():
    adapter = JenkinsEARAdapter(matrix_auth=True, audit_trail=True, credential_scoped=True, plugins_current=True)
    active = [f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f) == EARState.ACTIVE]; assert len(active) == 0, f"unexpected ACTIVE: {active}"
    print("T-EAR-03 PASS: no Jenkins family reaches ACTIVE")


def compute_fingerprint():
    adapter = JenkinsEARAdapter(matrix_auth=True, audit_trail=True, credential_scoped=True, plugins_current=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Jenkins")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: config drift gap; credential scope; Codecov breach class; CRYSTALLIZED ceiling only")
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
    print("Running " + str(len(tests)) + " gate tests (" + "Jenkins" + ")...")
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
