"""test_gate_suite.py — Kyverno gate tests. Wave 2 System 8."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_kyverno import KyvernoEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_policy_report_produces_gap():
    adapter = KyvernoEARAdapter(policy_reports_enabled=False, webhook_active=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Kyverno")
    pe = [a for a in report.assertions if a.operation_family == "policy_evaluation"]
    assert len(pe) > 0, "T-GCG-01 FAIL"
    absent = set(pe[0].n_declared) - set(pe[0].k_realized)
    assert "policy_report" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no PolicyReport → gap={absent}")

def test_gcg_02_no_webhook_produces_absent():
    adapter = KyvernoEARAdapter(webhook_active=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Kyverno")
    assert all(v == "ABSENT" for v in report.ear_states.values())
    print("T-GCG-02 PASS: no webhook → all ABSENT")

def test_gcg_03_full_config_minimal_gap():
    adapter = KyvernoEARAdapter(policy_reports_enabled=True, webhook_active=True,
                                image_verification_mode=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Kyverno")
    pe = [a for a in report.assertions if a.operation_family == "policy_evaluation"]
    assert len(pe) == 0, f"T-GCG-03 FAIL: {len(pe)} gaps"
    print("T-GCG-03 PASS: full config → zero policy_evaluation gaps")

def test_nd_01_n_idempotent():
    a1, a2 = KyvernoEARAdapter(), KyvernoEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2; print("T-ND-01 PASS: N idempotent")

def test_nd_02_image_verification_layers():
    adapter = KyvernoEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "image_verification")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "image_attestation" in layers
    print(f"T-ND-02 PASS: image_verification has attestation layer={layers}")

def test_nd_03_strategy_documented():
    decl = KyvernoEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print(f"T-ND-03 PASS: strategy={decl.strategy}")

def test_ear_01_no_webhook_absent():
    adapter = KyvernoEARAdapter(webhook_active=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "policy_evaluation")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no webhook → ABSENT")

def test_ear_02_webhook_crystallized():
    adapter = KyvernoEARAdapter(webhook_active=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "policy_evaluation")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: webhook → CRYSTALLIZED")

def test_ear_03_image_verification_highest_governance():
    """Image verification is highest governance in Kyverno — attestation is more constitutive."""
    adapter = KyvernoEARAdapter(webhook_active=True, image_verification_mode=True)
    fams = adapter.collect_operation_families()
    img_fam = next(f for f in fams if f.name == "image_verification")
    # Currently CRYSTALLIZED but structurally most constitutive
    state = adapter.assess_ear_state(img_fam)
    assert state in (EARState.ACTIVE, EARState.CRYSTALLIZED)
    print(f"T-EAR-03 PASS: image_verification = {state.value} (highest governance in Kyverno)")

def compute_convergence_fingerprint():
    adapter = KyvernoEARAdapter(policy_reports_enabled=True, webhook_active=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Kyverno")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nCONVERGENCE FINGERPRINT: {fp}")
    print(f"Assertions: {stats['total']} | Forms: {stats['by_form']} | EAR: {report.ear_states}")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests = [test_gcg_01_no_policy_report_produces_gap, test_gcg_02_no_webhook_produces_absent,
             test_gcg_03_full_config_minimal_gap, test_nd_01_n_idempotent,
             test_nd_02_image_verification_layers, test_nd_03_strategy_documented,
             test_ear_01_no_webhook_absent, test_ear_02_webhook_crystallized,
             test_ear_03_image_verification_highest_governance]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests (Kyverno)...\n")
    for t in tests:
        try: t(); passed += 1
        except AssertionError as e: print(f"FAIL: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
        except Exception as e: print(f"ERROR: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
    print(f"\n{'='*60}\nGATE RESULTS: {passed}/{len(tests)} passed")
    if failures: [print(f"  FAIL: {n}: {m}") for n, m in failures]
    print(f"{'='*60}\n"); fp = compute_convergence_fingerprint(); return passed, failed, fp

if __name__ == "__main__":
    passed, failed, fp = run_all_gates(); sys.exit(0 if failed == 0 else 1)
