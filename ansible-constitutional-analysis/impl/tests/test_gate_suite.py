"""test_gate_suite.py — Ansible gate tests."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_ansible import AnsibleEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = AnsibleEARAdapter(awx_managed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "playbook_execution")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-GCG-01 PASS: CLI → ABSENT (stateless IaC: no state model by architecture)")


def test_gcg_02():
    adapter = AnsibleEARAdapter(awx_managed=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Ansible")
    items = [a for a in report.assertions if a.operation_family == "playbook_execution"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "awx_audit" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no AWX → gap={absent}")


def test_gcg_03():
    adapter = AnsibleEARAdapter(awx_managed=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "playbook_execution")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: AWX managed → CRYSTALLIZED ceiling")


def test_nd_01():
    a1, a2 = AnsibleEARAdapter(), AnsibleEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = AnsibleEARAdapter()
    # playbook_execution N includes awx_audit and rbac_gate
    fam = next(f for f in adapter.collect_operation_families() if f.name == "playbook_execution")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["awx_audit", "rbac_gate"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    # secret_access N includes vault_encryption
    fam2 = next(f for f in adapter.collect_operation_families() if f.name == "secret_access")
    layers2 = [l.name for l in adapter.collect_governance_layers(fam2)]
    assert "vault_encryption" in layers2, f"T-ND-02 FAIL: vault_encryption not in {layers2}"
    print(f"T-ND-02 PASS: playbook layers={layers}, secret layers={layers2}")


def test_nd_03():
    decl = AnsibleEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = AnsibleEARAdapter(awx_managed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "playbook_execution")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: CLI → ABSENT")


def test_ear_02():
    adapter = AnsibleEARAdapter(awx_managed=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "playbook_execution")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: AWX → CRYSTALLIZED")


def test_ear_03():
    adapter = AnsibleEARAdapter(awx_managed=True, vault_encrypted=True, rbac_configured=True)
    active = [f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f) == EARState.ACTIVE]; assert len(active) == 0, f"unexpected ACTIVE: {active}"
    print("T-EAR-03 PASS: no Ansible family reaches ACTIVE (stateless IaC — ABSENT is architectural)")


def compute_fingerprint():
    adapter = AnsibleEARAdapter(awx_managed=True, vault_encrypted=True, rbac_configured=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Ansible")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: stateless IaC — ABSENT receipt is architectural; extends T1684; no ACTIVE path")
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
    print("Running " + str(len(tests)) + " gate tests (" + "Ansible" + ")...")
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
