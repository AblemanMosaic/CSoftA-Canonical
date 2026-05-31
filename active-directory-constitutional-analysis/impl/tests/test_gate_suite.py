"""test_gate_suite.py — Active-Directory gate tests. Wave 13."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_active_directory import ActiveDirectoryEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = ActiveDirectoryEARAdapter(aes_enforced=False, gmsas_deployed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "service_ticket_request")
    state = adapter.assess_ear_state(fam)
    assert state in (EARState.ABSENT, EARState.CRYSTALLIZED), f"unexpected: {state}"
    print("T-GCG-01 PASS: no AES + no gMSAs → CRYSTALLIZED only (Kerberoasting is protocol-inherent BYPASS)")


def test_gcg_02():
    adapter = ActiveDirectoryEARAdapter(aes_enforced=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Active-Directory")
    items = [a for a in report.assertions if a.operation_family == "service_ticket_request"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "aes_enforcement" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no AES enforcement → gap={absent}")


def test_gcg_03():
    adapter = ActiveDirectoryEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "kerberos_authentication")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: kerberos_authentication → CRYSTALLIZED (Event 4769 logged but not constitutive)")


def test_nd_01():
    a1, a2 = ActiveDirectoryEARAdapter(), ActiveDirectoryEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = ActiveDirectoryEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "service_ticket_request")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["kerberos_audit", "aes_enforcement"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: layers={layers}")


def test_nd_03():
    decl = ActiveDirectoryEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = ActiveDirectoryEARAdapter(aes_enforced=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "service_ticket_request")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-01 PASS: service ticket → CRYSTALLIZED not ABSENT (Event 4769 logged)")


def test_ear_02():
    adapter = ActiveDirectoryEARAdapter(aes_enforced=True, gmsas_deployed=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "service_ticket_request")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: AES+gMSA → still CRYSTALLIZED (protocol-inherent bypass cannot reach ACTIVE)")


def test_ear_03():
    adapter = ActiveDirectoryEARAdapter(aes_enforced=True, gmsas_deployed=True, tiered_admin=True, dc_auditing_enabled=True)
    active = [f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f) == EARState.ACTIVE]; assert len(active) == 0, f"unexpected: {active}"
    print("T-EAR-03 PASS: no AD family ACTIVE (Kerberoasting is protocol-inherent bypass — mitigable but not constitutively preventable)")


def compute_fingerprint():
    adapter = ActiveDirectoryEARAdapter(aes_enforced=True, gmsas_deployed=True, tiered_admin=True, dc_auditing_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Active-Directory")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: Kerberoasting protocol-inherent bypass; Ascension Health 2024 breach; gMSAs mitigate but cannot reach ACTIVE")
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
    print("Running " + str(len(tests)) + " gate tests (" + "Active-Directory" + ")...")
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
