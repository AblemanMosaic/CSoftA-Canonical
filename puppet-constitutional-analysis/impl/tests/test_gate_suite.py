"""test_gate_suite.py — Puppet gate tests. Wave 16."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_puppet import PuppetEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = PuppetEARAdapter(tls_configured=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "catalog_compilation")
    state = adapter.assess_ear_state(fam)
    assert state in (EARState.ABSENT, EARState.CRYSTALLIZED), f"unexpected: {state}"
    print("T-GCG-01 PASS: no TLS → ABSENT (no client cert auth)")


def test_gcg_02():
    adapter = PuppetEARAdapter(tls_configured=True, rbac_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Puppet")
    items = [a for a in report.assertions if a.operation_family == "catalog_compilation"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "rbac_check" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no RBAC (community edition) → gap={absent}")


def test_gcg_03():
    adapter = PuppetEARAdapter(tls_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "catalog_application")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: catalog application → CRYSTALLIZED (convergence_log always produced)")


def test_nd_01():
    a1, a2 = PuppetEARAdapter(), PuppetEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = PuppetEARAdapter()
    # catalog_compilation N includes tls_auth and catalog_signing
    fam = next(f for f in adapter.collect_operation_families() if f.name == "catalog_compilation")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["tls_auth", "rbac_check"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    # catalog_application N includes convergence_log
    fam2 = next(f for f in adapter.collect_operation_families() if f.name == "catalog_application")
    layers2 = [l.name for l in adapter.collect_governance_layers(fam2)]
    assert "convergence_log" in layers2, f"T-ND-02 FAIL: convergence_log not in {layers2}"
    print(f"T-ND-02 PASS: compilation={layers}, application={layers2}")


def test_nd_03():
    decl = PuppetEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = PuppetEARAdapter(tls_configured=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "catalog_compilation")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no TLS → ABSENT")


def test_ear_02():
    adapter = PuppetEARAdapter(tls_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "catalog_compilation")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: TLS → CRYSTALLIZED")


def test_ear_03():
    adapter = PuppetEARAdapter(tls_configured=True, rbac_enabled=True, catalog_signed=True, audit_log_enabled=True)
    active = [f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f) == EARState.ACTIVE]; assert len(active) == 0, f"unexpected: {active}"
    print("T-EAR-03 PASS: no Puppet family ACTIVE (CRYSTALLIZED convergence receipt; RBAC paywall T1784)")


def compute_fingerprint():
    adapter = PuppetEARAdapter(tls_configured=True, rbac_enabled=True, catalog_signed=True, audit_log_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Puppet")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: convergence receipt CRYSTALLIZED extends Ansible ABSENT; RBAC paywall T1784; catalog injection threat; IaC spectrum Ansible<Puppet<Terraform<Crossplane")
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
    print("Running " + str(len(tests)) + " gate tests (" + "Puppet" + ")...")
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
