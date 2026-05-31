"""test_gate_suite.py — CloudTrail gate tests. Wave 8 System 36."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_cloudtrail import CloudTrailEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_trail_absent():
    adapter = CloudTrailEARAdapter(trail_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="CloudTrail")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no trail → all ABSENT (governance-of-governance gap)")

def test_gcg_02_no_data_events_absent():
    adapter = CloudTrailEARAdapter(trail_enabled=True, data_events=False)
    state = CloudTrailEARAdapter(trail_enabled=True,data_events=False)
    fam_data = next(f for f in state.collect_operation_families() if f.name=="data_event_logging")
    assert state.assess_ear_state(fam_data)==EARState.ABSENT
    print("T-GCG-02 PASS: no data events → data_event_logging=ABSENT (S3 object access ungoverned)")

def test_gcg_03_no_log_validation_gap():
    adapter = CloudTrailEARAdapter(trail_enabled=True, log_validation=False)
    report = GCGAnalyzer().analyze(adapter, target_system="CloudTrail")
    mgmt = [a for a in report.assertions if a.operation_family=="management_event_logging"]
    assert len(mgmt)>0, "T-GCG-03 FAIL"
    absent = set(mgmt[0].n_declared)-set(mgmt[0].k_realized)
    assert "log_validation" in absent, f"T-GCG-03 FAIL: {absent}"
    print(f"T-GCG-03 PASS: no log validation → gap={absent}")

def test_nd_01_n_idempotent():
    a1,a2=CloudTrailEARAdapter(),CloudTrailEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_log_validation_in_mgmt_n():
    adapter = CloudTrailEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="management_event_logging")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "trail_enabled" in layers and "log_validation" in layers
    print(f"T-ND-02 PASS: mgmt layers={layers}")

def test_nd_03_strategy_documented():
    decl = CloudTrailEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_trail_absent():
    adapter = CloudTrailEARAdapter(trail_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="management_event_logging")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no trail → ABSENT")

def test_ear_02_with_trail_crystallized():
    adapter = CloudTrailEARAdapter(trail_enabled=True, log_validation=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="management_event_logging")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: mgmt event logging = CRYSTALLIZED (trail can be disabled)")

def test_ear_03_no_active_family():
    adapter = CloudTrailEARAdapter(trail_enabled=True, multi_region=True,
                                   log_validation=True, data_events=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no CloudTrail family reaches ACTIVE (StopLogging is always possible)")

def compute_convergence_fingerprint():
    adapter = CloudTrailEARAdapter(trail_enabled=True, multi_region=True,
                                   log_validation=True, data_events=True,
                                   stop_logging_alert=True)
    report = GCGAnalyzer().analyze(adapter, target_system="CloudTrail")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Governance-of-governance case — all AWS audit receipts depend on CloudTrail")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_trail_absent,test_gcg_02_no_data_events_absent,
           test_gcg_03_no_log_validation_gap,test_nd_01_n_idempotent,
           test_nd_02_log_validation_in_mgmt_n,test_nd_03_strategy_documented,
           test_ear_01_no_trail_absent,test_ear_02_with_trail_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (CloudTrail)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
