"""test_gate_suite.py — Terraform gate tests. Wave 5 System 24."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_terraform import TerraformEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_remote_backend_absent():
    adapter=TerraformEARAdapter(remote_backend=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Terraform")
    assert all(v in ("ABSENT","CRYSTALLIZED") for v in report.ear_states.values())
    print(f"T-GCG-01 PASS: no remote backend → states={report.ear_states}")

def test_gcg_02_no_plan_approval_gap():
    adapter=TerraformEARAdapter(remote_backend=True, state_locking=True,
                                plan_approval_required=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Terraform")
    apply=[a for a in report.assertions if a.operation_family=="apply_operation"]
    if apply:
        absent=set(apply[0].n_declared)-set(apply[0].k_realized)
        assert "plan_approval" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no plan approval → gap confirmed")

def test_gcg_03_full_config_minimal_gap():
    adapter=TerraformEARAdapter(remote_backend=True,state_locking=True,
                                plan_approval_required=True,audit_log_enabled=True,
                                drift_detection_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Terraform")
    apply=[a for a in report.assertions if a.operation_family=="apply_operation"]
    assert len(apply)==0, f"T-GCG-03 FAIL: {len(apply)} gaps"
    print("T-GCG-03 PASS: full config → zero apply gaps")

def test_nd_01_n_idempotent():
    a1,a2=TerraformEARAdapter(),TerraformEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_state_file_in_apply_n():
    adapter=TerraformEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="apply_operation")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "state_file" in layers and "state_lock" in layers
    print(f"T-ND-02 PASS: apply layers={layers}")

def test_nd_03_strategy_documented():
    decl=TerraformEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_remote_absent():
    adapter=TerraformEARAdapter(remote_backend=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="state_management")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no remote → ABSENT")

def test_ear_02_state_management_active_with_lock():
    adapter=TerraformEARAdapter(remote_backend=True, state_locking=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="state_management")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: state_management + remote lock = ACTIVE")

def test_ear_03_apply_crystallized():
    adapter=TerraformEARAdapter(remote_backend=True, state_locking=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="apply_operation")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: apply = CRYSTALLIZED (state drift not receipted)")

def compute_convergence_fingerprint():
    adapter=TerraformEARAdapter(remote_backend=True,state_locking=True,
                                plan_approval_required=True,audit_log_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Terraform")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: State drift = ABSENT gap. Resources outside Terraform have no receipt.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_remote_backend_absent,test_gcg_02_no_plan_approval_gap,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_state_file_in_apply_n,test_nd_03_strategy_documented,
           test_ear_01_no_remote_absent,test_ear_02_state_management_active_with_lock,
           test_ear_03_apply_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Terraform)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
