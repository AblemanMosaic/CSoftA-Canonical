"""test_gate_suite.py — GuardDuty gate tests. Wave 9 System 42."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_aws_guardduty import AWSGuardDutyEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_detector_absent():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GuardDuty")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no detector → all ABSENT")

def test_gcg_02_no_multi_region_gap():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=True, multi_region=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GuardDuty")
    detect = [a for a in report.assertions if a.operation_family=="threat_detection"]
    assert len(detect)>0, "T-GCG-02 FAIL"
    absent = set(detect[0].n_declared)-set(detect[0].k_realized)
    assert "multi_region_coverage" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no multi-region → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=True, multi_region=True,
                                      etd_enabled=True, s3_protection=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GuardDuty")
    detect = [a for a in report.assertions if a.operation_family=="threat_detection"]
    assert len(detect)==0, f"T-GCG-03 FAIL: {len(detect)} gaps"
    print("T-GCG-03 PASS: full config → zero threat_detection gaps")

def test_nd_01_n_idempotent():
    a1,a2=AWSGuardDutyEARAdapter(),AWSGuardDutyEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_multi_region_in_detect_n():
    adapter = AWSGuardDutyEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="threat_detection")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "multi_region_coverage" in layers and "detector_enabled" in layers
    print(f"T-ND-02 PASS: detect layers={layers}")

def test_nd_03_strategy_documented():
    decl = AWSGuardDutyEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_detector_absent():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="threat_detection")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no detector → ABSENT")

def test_ear_02_with_detector_crystallized():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="threat_detection")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: threat_detection = CRYSTALLIZED (findings post-hoc; detector can be disabled)")

def test_ear_03_no_active_family():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=True, multi_region=True,
                                      etd_enabled=True, s3_protection=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no GuardDuty family reaches ACTIVE (meta-governance case 4)")

def compute_convergence_fingerprint():
    adapter = AWSGuardDutyEARAdapter(detector_enabled=True, multi_region=True,
                                      etd_enabled=True, s3_protection=True,
                                      auto_remediation=True, disable_alert=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GuardDuty")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Meta-governance case 4 — AWS security triad complete (CloudTrail+KMS+GuardDuty)")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_detector_absent,test_gcg_02_no_multi_region_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_multi_region_in_detect_n,test_nd_03_strategy_documented,
           test_ear_01_no_detector_absent,test_ear_02_with_detector_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (GuardDuty)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
