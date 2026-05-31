"""test_gate_suite.py — AWS Config gate tests. Wave 10 System 49."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_aws_config import AWSConfigEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_recorder_absent():
    adapter = AWSConfigEARAdapter(recorder_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-Config")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no recorder → all ABSENT")

def test_gcg_02_no_remediation_gap():
    adapter = AWSConfigEARAdapter(recorder_enabled=True, auto_remediation=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-Config")
    rule = [a for a in report.assertions if a.operation_family=="rule_evaluation"]
    assert len(rule)>0, "T-GCG-02 FAIL"
    absent = set(rule[0].n_declared)-set(rule[0].k_realized)
    assert "auto_remediation" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no auto-remediation → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = AWSConfigEARAdapter(recorder_enabled=True, auto_remediation=True,
                                   encryption=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-Config")
    record = [a for a in report.assertions if a.operation_family=="configuration_recording"]
    assert len(record)==0, f"T-GCG-03 FAIL: {len(record)} gaps"
    print("T-GCG-03 PASS: full config → zero recording gaps")

def test_nd_01_n_idempotent():
    a1,a2=AWSConfigEARAdapter(),AWSConfigEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_rule_in_eval_n():
    adapter = AWSConfigEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="rule_evaluation")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "config_rule" in layers and "config_recorder" in layers
    print(f"T-ND-02 PASS: rule_eval layers={layers}")

def test_nd_03_strategy_documented():
    decl = AWSConfigEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_recorder_absent():
    adapter = AWSConfigEARAdapter(recorder_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="configuration_recording")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no recorder → ABSENT")

def test_ear_02_with_recorder_crystallized():
    adapter = AWSConfigEARAdapter(recorder_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="configuration_recording")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: recording = CRYSTALLIZED (drift detected after it occurs)")

def test_ear_03_no_active_family():
    adapter = AWSConfigEARAdapter(recorder_enabled=True, auto_remediation=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no AWS Config family reaches ACTIVE (drift detected post-hoc)")

def compute_convergence_fingerprint():
    adapter = AWSConfigEARAdapter(recorder_enabled=True, auto_remediation=True,
                                   encryption=True, aggregator_enabled=True, multi_account=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-Config")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: CRYSTALLIZED complement to CloudTrail. Experian: 2-5min detection-to-remediation.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_recorder_absent,test_gcg_02_no_remediation_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_rule_in_eval_n,test_nd_03_strategy_documented,
           test_ear_01_no_recorder_absent,test_ear_02_with_recorder_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (AWS Config)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
