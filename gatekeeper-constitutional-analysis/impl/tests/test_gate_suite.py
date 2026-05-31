"""test_gate_suite.py — Gatekeeper gate tests. Wave 2 System 7."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_gatekeeper import GatekeeperEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def make_violation(uid="v001", kind="Pod", namespace="default"):
    return {"uid": uid, "kind": kind, "namespace": namespace,
            "message": "constraint violation", "timestamp": "2026-05-29T00:00:00Z"}

def test_gcg_01_no_audit_produces_gap():
    adapter = GatekeeperEARAdapter(audit_enabled=False, webhook_active=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Gatekeeper")
    admission = [a for a in report.assertions if a.operation_family == "admission_evaluation"]
    assert len(admission) > 0, "T-GCG-01 FAIL: no assertions"
    absent = set(admission[0].n_declared) - set(admission[0].k_realized)
    assert "audit_log" in absent or "violation_record" in absent,         f"T-GCG-01 FAIL: gap not found. absent={absent}"
    print(f"T-GCG-01 PASS: no audit → gap={absent}")

def test_gcg_02_no_webhook_produces_absent():
    adapter = GatekeeperEARAdapter(webhook_active=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Gatekeeper")
    states = report.ear_states
    assert all(v == "ABSENT" for v in states.values()),         f"T-GCG-02 FAIL: expected all ABSENT, got {states}"
    print(f"T-GCG-02 PASS: no webhook → all ABSENT")

def test_gcg_03_violation_logged_minimal_gap():
    adapter = GatekeeperEARAdapter(
        violation_records=[make_violation()], audit_enabled=True, webhook_active=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Gatekeeper")
    admission = [a for a in report.assertions if a.operation_family == "admission_evaluation"]
    assert len(admission) == 0,         f"T-GCG-03 FAIL: {len(admission)} unexpected gaps: {[(a.gap_form, sorted(set(a.n_declared)-set(a.k_realized))) for a in admission]}"
    print("T-GCG-03 PASS: violation recorded + audit → zero admission gaps")

def test_nd_01_n_idempotent():
    a1, a2 = GatekeeperEARAdapter(), GatekeeperEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print(f"T-ND-01 PASS: N idempotent")

def test_nd_02_admission_n_declared():
    adapter = GatekeeperEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "admission_evaluation")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "constraint_template" in layers and "admission_webhook" in layers
    print(f"T-ND-02 PASS: admission_evaluation layers={layers}")

def test_nd_03_strategy_documented():
    decl = GatekeeperEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print(f"T-ND-03 PASS: strategy={decl.strategy}")

def test_ear_01_no_webhook_absent():
    adapter = GatekeeperEARAdapter(webhook_active=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "admission_evaluation")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no webhook → ABSENT")

def test_ear_02_webhook_crystallized():
    adapter = GatekeeperEARAdapter(webhook_active=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "admission_evaluation")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: webhook active → CRYSTALLIZED (not ACTIVE — violation not constitutive)")

def test_ear_03_no_active_any_family():
    adapter = GatekeeperEARAdapter(webhook_active=True, audit_enabled=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f) == EARState.ACTIVE]
    assert len(active) == 0, f"T-EAR-03 FAIL: unexpected ACTIVE: {active}"
    print("T-EAR-03 PASS: no Gatekeeper family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = GatekeeperEARAdapter(
        violation_records=[make_violation()], audit_enabled=True, webhook_active=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Gatekeeper")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nCONVERGENCE FINGERPRINT: {fp}")
    print(f"Assertions: {stats['total']} | Forms: {stats['by_form']} | EAR: {report.ear_states}")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests = [test_gcg_01_no_audit_produces_gap, test_gcg_02_no_webhook_produces_absent,
             test_gcg_03_violation_logged_minimal_gap, test_nd_01_n_idempotent,
             test_nd_02_admission_n_declared, test_nd_03_strategy_documented,
             test_ear_01_no_webhook_absent, test_ear_02_webhook_crystallized,
             test_ear_03_no_active_any_family]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests (Gatekeeper)...\n")
    for t in tests:
        try: t(); passed += 1
        except AssertionError as e: print(f"FAIL: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
        except Exception as e: print(f"ERROR: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
    print(f"\n{'='*60}\nGATE RESULTS: {passed}/{len(tests)} passed")
    if failures: [print(f"  FAIL: {n}: {m}") for n, m in failures]
    print(f"{'='*60}\n"); fp = compute_convergence_fingerprint(); return passed, failed, fp

if __name__ == "__main__":
    passed, failed, fp = run_all_gates()
    sys.exit(0 if failed == 0 else 1)
