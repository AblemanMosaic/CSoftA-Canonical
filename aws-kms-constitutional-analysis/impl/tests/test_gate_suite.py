"""test_gate_suite.py — AWS KMS gate tests. Wave 8 System 37."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_aws_kms import AWSKMSEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_cloudtrail_absent():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-KMS")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no CloudTrail → all ABSENT (KMS governance depends on CloudTrail)")

def test_gcg_02_no_rotation_gap():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=True, key_rotation_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-KMS")
    crypt = [a for a in report.assertions if a.operation_family=="encrypt_decrypt"]
    assert len(crypt)>0, "T-GCG-02 FAIL"
    absent = set(crypt[0].n_declared)-set(crypt[0].k_realized)
    assert "key_rotation" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no rotation → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=True, key_rotation_enabled=True,
                               deletion_protected=True, cross_account_restricted=True,
                               grants_reviewed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-KMS")
    crypt = [a for a in report.assertions if a.operation_family=="encrypt_decrypt"]
    assert len(crypt)==0, f"T-GCG-03 FAIL: {len(crypt)} gaps"
    print("T-GCG-03 PASS: full config → zero encrypt_decrypt gaps")

def test_nd_01_n_idempotent():
    a1,a2=AWSKMSEARAdapter(),AWSKMSEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_key_policy_in_crypt_n():
    adapter = AWSKMSEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="encrypt_decrypt")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "key_policy" in layers and "cloudtrail_event" in layers
    print(f"T-ND-02 PASS: encrypt_decrypt layers={layers}")

def test_nd_03_strategy_documented():
    decl = AWSKMSEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_ct_absent():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="encrypt_decrypt")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no CT → ABSENT")

def test_ear_02_with_ct_crystallized():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="encrypt_decrypt")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: encrypt_decrypt = CRYSTALLIZED (key policy evaluated + CloudTrail)")

def test_ear_03_all_crystallized_with_ct():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=True, key_rotation_enabled=True)
    states = {f.name: adapter.assess_ear_state(f) for f in adapter.collect_operation_families()}
    assert all(v==EARState.CRYSTALLIZED for v in states.values())
    print("T-EAR-03 PASS: all KMS families CRYSTALLIZED with CloudTrail enabled")

def compute_convergence_fingerprint():
    adapter = AWSKMSEARAdapter(cloudtrail_enabled=True, key_rotation_enabled=True,
                               deletion_protected=True, cross_account_restricted=True,
                               grants_reviewed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-KMS")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Codefinger BYOK ransomware (Jan 2025) exploited SSE-C key governance gap")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_cloudtrail_absent,test_gcg_02_no_rotation_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_key_policy_in_crypt_n,test_nd_03_strategy_documented,
           test_ear_01_no_ct_absent,test_ear_02_with_ct_crystallized,
           test_ear_03_all_crystallized_with_ct]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (AWS KMS)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
