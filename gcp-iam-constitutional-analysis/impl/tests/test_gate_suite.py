"""test_gate_suite.py — GCP-IAM gate tests. Wave 13."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_gcp_iam import GCPIAMEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = GCPIAMEARAdapter(data_access_logs=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "data_access")
    state = adapter.assess_ear_state(fam)
    assert state in (EARState.ABSENT, EARState.CRYSTALLIZED), f"unexpected: {state}"
    print("T-GCG-01 PASS: no data access logs → ABSENT (like CloudTrail data events gap)")


def test_gcg_02():
    adapter = GCPIAMEARAdapter(data_access_logs=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GCP-IAM")
    items = [a for a in report.assertions if a.operation_family == "data_access"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "data_access_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: data_access with no data logs → gap={absent}")


def test_gcg_03():
    adapter = GCPIAMEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "api_authorization")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: api_authorization → CRYSTALLIZED (admin log always on)")


def test_nd_01():
    a1, a2 = GCPIAMEARAdapter(), GCPIAMEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = GCPIAMEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "api_authorization")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["iam_policy", "admin_activity_log"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: layers={layers}")


def test_nd_03():
    decl = GCPIAMEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = GCPIAMEARAdapter(data_access_logs=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "data_access")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no data logs → ABSENT")


def test_ear_02():
    adapter = GCPIAMEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "api_authorization")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: api_auth → CRYSTALLIZED")


def test_ear_03():
    adapter = GCPIAMEARAdapter(data_access_logs=True, org_policy_applied=True, workload_identity=True, least_privilege=True)
    active = [f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f) == EARState.ACTIVE]; assert len(active) == 0, f"unexpected: {active}"
    print("T-EAR-03 PASS: no GCP IAM family reaches ACTIVE")


def compute_fingerprint():
    adapter = GCPIAMEARAdapter(data_access_logs=True, org_policy_applied=True, workload_identity=True, least_privilege=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GCP-IAM")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: ImageRunner NON_ACTIVATION; tag-based escalation; data access logs ABSENT by default like CloudTrail T1727")
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
    print("Running " + str(len(tests)) + " gate tests (" + "GCP-IAM" + ")...")
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
