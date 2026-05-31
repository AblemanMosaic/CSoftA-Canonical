"""test_gate_suite.py — MongoDB gate tests."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_mongodb import MongoDBEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = MongoDBEARAdapter(auth_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "document_write")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-GCG-01 PASS: no auth → ABSENT (MongoBleed class: 87k+ vulnerable)")


def test_gcg_02():
    adapter = MongoDBEARAdapter(auth_enabled=True, rbac_configured=True, enterprise_audit=False)
    report = GCGAnalyzer().analyze(adapter, target_system="MongoDB")
    items = [a for a in report.assertions if a.operation_family == "document_write"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "enterprise_audit" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no enterprise audit → gap={absent}")


def test_gcg_03():
    adapter = MongoDBEARAdapter(auth_enabled=True, tls_enabled=True, enterprise_audit=True, rbac_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "document_write")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-GCG-03 PASS: Enterprise Audit → ACTIVE (commercial paywall)")


def test_nd_01():
    a1, a2 = MongoDBEARAdapter(), MongoDBEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = MongoDBEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "document_write")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["auth_required", "enterprise_audit"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: write layers={layers}")


def test_nd_03():
    decl = MongoDBEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = MongoDBEARAdapter(auth_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "document_write")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no auth → ABSENT")


def test_ear_02():
    adapter = MongoDBEARAdapter(auth_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "document_write")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: auth, no enterprise → CRYSTALLIZED")


def test_ear_03():
    adapter = MongoDBEARAdapter(auth_enabled=True, enterprise_audit=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "document_write"); assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-03 PASS: Enterprise Audit → ACTIVE")


def compute_fingerprint():
    adapter = MongoDBEARAdapter(auth_enabled=True, tls_enabled=True, enterprise_audit=True, rbac_configured=True)
    report = GCGAnalyzer().analyze(adapter, target_system="MongoDB")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: MongoBleed CVE-2025-14847; enterprise audit paywall; extends T1670 PostgreSQL")
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
    print("Running " + str(len(tests)) + " gate tests (" + "MongoDB" + ")...")
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
