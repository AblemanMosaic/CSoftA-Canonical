"""test_gate_suite.py — OPA Engine gate tests. Wave 10 System 46."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_opa_engine import OPAEngineEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_log_gap():
    adapter = OPAEngineEARAdapter(decision_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="OPA-Engine")
    eval_gaps = [a for a in report.assertions if a.operation_family=="policy_evaluation"]
    assert len(eval_gaps)>0, "T-GCG-01 FAIL"
    absent = set(eval_gaps[0].n_declared)-set(eval_gaps[0].k_realized)
    assert "decision_log" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no decision log → gap={absent}")

def test_gcg_02_no_policy_test_gap():
    adapter = OPAEngineEARAdapter(decision_log_enabled=True, policy_tested=False)
    report = GCGAnalyzer().analyze(adapter, target_system="OPA-Engine")
    eval_gaps = [a for a in report.assertions if a.operation_family=="policy_evaluation"]
    assert len(eval_gaps)>0, "T-GCG-02 FAIL"
    absent = set(eval_gaps[0].n_declared)-set(eval_gaps[0].k_realized)
    assert "policy_test" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no policy tests → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = OPAEngineEARAdapter(decision_log_enabled=True, policy_tested=True,
                                   policy_versioned=True, bundle_signed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="OPA-Engine")
    eval_gaps = [a for a in report.assertions if a.operation_family=="policy_evaluation"]
    assert len(eval_gaps)==0, f"T-GCG-03 FAIL: {len(eval_gaps)} gaps"
    print("T-GCG-03 PASS: full config → zero policy_evaluation gaps")

def test_nd_01_n_idempotent():
    a1,a2=OPAEngineEARAdapter(),OPAEngineEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_policy_test_in_eval_n():
    adapter = OPAEngineEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="policy_evaluation")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "policy_test" in layers and "rego_policy" in layers
    print(f"T-ND-02 PASS: eval layers={layers}")

def test_nd_03_strategy_documented():
    decl = OPAEngineEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_policy_evaluation_active():
    adapter = OPAEngineEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="policy_evaluation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: policy_evaluation = ACTIVE (decision constitutive of allowed action)")

def test_ear_02_api_authorization_active():
    adapter = OPAEngineEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="api_authorization")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: api_authorization = ACTIVE")

def test_ear_03_bundle_management_crystallized():
    adapter = OPAEngineEARAdapter(bundle_signed=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="bundle_management")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: bundle_management = CRYSTALLIZED")

def compute_convergence_fingerprint():
    adapter = OPAEngineEARAdapter(decision_log_enabled=True, policy_tested=True,
                                   policy_versioned=True, bundle_signed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="OPA-Engine")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: ACTIVE policy evaluation; policy content correctness gap (wrong Rego = wrong decisions)")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_log_gap,test_gcg_02_no_policy_test_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_policy_test_in_eval_n,test_nd_03_strategy_documented,
           test_ear_01_policy_evaluation_active,test_ear_02_api_authorization_active,
           test_ear_03_bundle_management_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (OPA Engine)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
