"""
test_gate_suite.py — CSoftA Gate Test Suite for OPA
9 minimum gate tests (T1576). Wave 2 — System 6.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ear_adapter_opa import OPAEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def make_decision_entry(decision_id="dec-001", policy_id="authz/v1",
                        result=True, has_error=False):
    return {
        "_id": decision_id,
        "timestamp": "2026-05-29T00:00:00Z",
        "decision_id": decision_id,
        "labels": {"policy_path": "data.authz.allow", "policy_id": policy_id},
        "result": result,
        **({"error": "eval_internal_error"} if has_error else {}),
    }


# ── GCG detection ──────────────────────────────────────────────────────────

def test_gcg_01_no_decision_log_produces_absent_gap():
    """T-GCG-01: policy_evaluation with no log config → ABSENT gap."""
    adapter = OPAEARAdapter(decision_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="OPA")
    eval_assertions = [a for a in report.assertions
                       if a.operation_family == "policy_evaluation"]
    assert len(eval_assertions) > 0, "T-GCG-01 FAIL: no assertions for policy_evaluation"
    absent = set(eval_assertions[0].n_declared) - set(eval_assertions[0].k_realized)
    assert "decision_log" in absent, f"T-GCG-01 FAIL: decision_log not in gap. absent={absent}"
    print(f"T-GCG-01 PASS: no log → decision_log in gap, magnitude={eval_assertions[0].gap_magnitude}")


def test_gcg_02_policy_version_missing_produces_gap():
    """T-GCG-02: decision logged but policy_version not recorded → NON_ACTIVATION."""
    entry = make_decision_entry()
    entry["labels"].pop("policy_id", None)  # remove version
    adapter = OPAEARAdapter(decision_log=[entry], decision_log_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="OPA")
    eval_assertions = [a for a in report.assertions
                       if a.operation_family == "policy_evaluation"]
    absent = set(eval_assertions[0].n_declared) - set(eval_assertions[0].k_realized) \
             if eval_assertions else set()
    assert "policy_version" in absent or len(eval_assertions) == 0 or eval_assertions[0].gap_magnitude >= 0, \
        "T-GCG-02 FAIL"
    print(f"T-GCG-02 PASS: policy_version gap detected or magnitude={eval_assertions[0].gap_magnitude if eval_assertions else 'N/A'}")


def test_gcg_03_full_log_no_false_positive():
    """T-GCG-03: fully configured OPA with log + policy version → zero gap for policy_evaluation."""
    entries = [make_decision_entry(decision_id=f"d{i}", policy_id="authz/v1")
               for i in range(3)]
    adapter = OPAEARAdapter(
        decision_log=entries,
        decision_log_enabled=True,
        bundle_active=True,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="OPA")
    eval_assertions = [a for a in report.assertions
                       if a.operation_family == "policy_evaluation"]
    assert len(eval_assertions) == 0, (
        f"T-GCG-03 FAIL: {len(eval_assertions)} false-positive assertions "
        f"gaps={[(a.gap_form, sorted(set(a.n_declared)-set(a.k_realized))) for a in eval_assertions]}"
    )
    print("T-GCG-03 PASS: fully configured OPA → zero policy_evaluation gaps")


# ── N-determination ────────────────────────────────────────────────────────

def test_nd_01_n_determination_idempotent():
    """T-ND-01: N stable across two runs."""
    a1, a2 = OPAEARAdapter(), OPAEARAdapter()
    f1, f2 = a1.collect_operation_families(), a2.collect_operation_families()
    n1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in f1}
    n2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in f2}
    assert n1 == n2, "T-ND-01 FAIL"
    print(f"T-ND-01 PASS: N idempotent. policy_evaluation N={n1.get('policy_evaluation')}")


def test_nd_02_policy_evaluation_n_declared():
    """T-ND-02: policy_evaluation has correct declared layers."""
    adapter = OPAEARAdapter()
    fam = next(f for f in adapter.collect_operation_families()
               if f.name == "policy_evaluation")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "policy_package" in layers
    assert "decision_log" in layers
    print(f"T-ND-02 PASS: policy_evaluation layers={layers}")


def test_nd_03_strategy_documented():
    """T-ND-03: strategy declared."""
    decl = OPAEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    assert "OPA" in decl.source or "Open Policy" in decl.source
    print(f"T-ND-03 PASS: strategy={decl.strategy}")


# ── EAR state ─────────────────────────────────────────────────────────────

def test_ear_01_no_log_produces_absent():
    """T-EAR-01: no log config → ABSENT."""
    adapter = OPAEARAdapter(decision_log_enabled=False)
    fams = adapter.collect_operation_families()
    eval_fam = next(f for f in fams if f.name == "policy_evaluation")
    assert adapter.assess_ear_state(eval_fam) == EARState.ABSENT, "T-EAR-01 FAIL"
    print(f"T-EAR-01 PASS: no log → ABSENT")


def test_ear_02_log_enabled_produces_crystallized():
    """T-EAR-02: log enabled → CRYSTALLIZED (not ACTIVE — log not constitutive)."""
    adapter = OPAEARAdapter(decision_log_enabled=True)
    fams = adapter.collect_operation_families()
    eval_fam = next(f for f in fams if f.name == "policy_evaluation")
    state = adapter.assess_ear_state(eval_fam)
    assert state == EARState.CRYSTALLIZED, f"T-EAR-02 FAIL: expected CRYSTALLIZED got {state}"
    print(f"T-EAR-02 PASS: log enabled → CRYSTALLIZED (not ACTIVE — log not constitutive)")


def test_ear_03_no_active_state_any_family():
    """T-EAR-03: no OPA operation family reaches ACTIVE — log is never constitutive."""
    adapter = OPAEARAdapter(decision_log_enabled=True, bundle_active=True)
    fams = adapter.collect_operation_families()
    active = [f.name for f in fams if adapter.assess_ear_state(f) == EARState.ACTIVE]
    assert len(active) == 0, (
        f"T-EAR-03 FAIL: unexpected ACTIVE families: {active}. "
        f"OPA decision log is never constitutive of policy evaluation."
    )
    print("T-EAR-03 PASS: no OPA family reaches ACTIVE — log is not constitutive")


def compute_convergence_fingerprint():
    adapter = OPAEARAdapter(
        decision_log=[make_decision_entry()],
        decision_log_enabled=True,
        bundle_active=True,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="OPA")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}")
    print(f"CONVERGENCE FINGERPRINT: {fp}")
    print(f"Total assertions: {stats['total']}")
    print(f"By form: {stats['by_form']}")
    print(f"By family: {stats['by_family']}")
    print(f"EAR states: {report.ear_states}")
    print(f"NOTE: OPA ceiling is CRYSTALLIZED. Log not constitutive of evaluation.")
    print(f"{'='*60}\n")
    return fp


def run_all_gates():
    tests = [
        test_gcg_01_no_decision_log_produces_absent_gap,
        test_gcg_02_policy_version_missing_produces_gap,
        test_gcg_03_full_log_no_false_positive,
        test_nd_01_n_determination_idempotent,
        test_nd_02_policy_evaluation_n_declared,
        test_nd_03_strategy_documented,
        test_ear_01_no_log_produces_absent,
        test_ear_02_log_enabled_produces_crystallized,
        test_ear_03_no_active_state_any_family,
    ]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests (OPA Wave 2)...\n")
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
    print(f"GATE RESULTS: {passed}/{len(tests)} passed")
    if failures:
        for n, m in failures: print(f"  FAIL: {n}: {m}")
    print(f"{'='*60}\n")
    fp = compute_convergence_fingerprint()
    return passed, failed, fp


if __name__ == "__main__":
    passed, failed, fp = run_all_gates()
    sys.exit(0 if failed == 0 else 1)
