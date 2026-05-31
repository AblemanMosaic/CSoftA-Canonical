"""test_gate_suite.py — AWS IAM gate tests. Wave 4 System 16."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_aws_iam import AWSIAMEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_cloudtrail_absent():
    adapter = AWSIAMEARAdapter(cloudtrail_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-IAM")
    assert all(v in ("ABSENT","CRYSTALLIZED") for v in report.ear_states.values())
    print(f"T-GCG-01 PASS: no CloudTrail → states={report.ear_states}")

def test_gcg_02_full_cloudtrail_no_gap():
    adapter = AWSIAMEARAdapter(cloudtrail_enabled=True, cloudtrail_log_validation=True,
                               all_regions_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-IAM")
    api = [a for a in report.assertions if a.operation_family=="api_call_authorization"]
    assert len(api)==0, f"T-GCG-02 FAIL: {len(api)} gaps"
    print("T-GCG-02 PASS: full CloudTrail → zero api_call_authorization gaps")

def test_gcg_03_root_operation_crystallized():
    adapter = AWSIAMEARAdapter(cloudtrail_enabled=True, cloudtrail_log_validation=True,
                               all_regions_enabled=True, is_root=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="root_operation")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: root_operation = CRYSTALLIZED (root can delete logs — structural bypass)")

def test_nd_01_n_idempotent():
    a1,a2=AWSIAMEARAdapter(),AWSIAMEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_cloudtrail_in_n():
    adapter=AWSIAMEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="api_call_authorization")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "cloudtrail_event" in layers; print(f"T-ND-02 PASS: api_call layers={layers}")

def test_nd_03_strategy_documented():
    decl=AWSIAMEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_cloudtrail_absent():
    adapter=AWSIAMEARAdapter(cloudtrail_enabled=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="api_call_authorization")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no CT → ABSENT")

def test_ear_02_full_cloudtrail_active():
    adapter=AWSIAMEARAdapter(cloudtrail_enabled=True,cloudtrail_log_validation=True,all_regions_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="api_call_authorization")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE; print("T-EAR-02 PASS: full CT → ACTIVE")

def test_ear_03_credential_issuance_active():
    adapter=AWSIAMEARAdapter(cloudtrail_enabled=True,cloudtrail_log_validation=True,all_regions_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="credential_issuance")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-03 PASS: credential_issuance = ACTIVE (STS token is credential-as-receipt)")

def compute_convergence_fingerprint():
    adapter=AWSIAMEARAdapter(cloudtrail_enabled=True,cloudtrail_log_validation=True,all_regions_enabled=True,mfa_required=True)
    report=GCGAnalyzer().analyze(adapter,target_system="AWS-IAM")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}\n{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_cloudtrail_absent,test_gcg_02_full_cloudtrail_no_gap,
           test_gcg_03_root_operation_crystallized,test_nd_01_n_idempotent,
           test_nd_02_cloudtrail_in_n,test_nd_03_strategy_documented,
           test_ear_01_no_cloudtrail_absent,test_ear_02_full_cloudtrail_active,
           test_ear_03_credential_issuance_active]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (AWS IAM)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
