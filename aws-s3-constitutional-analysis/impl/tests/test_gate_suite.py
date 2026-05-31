"""test_gate_suite.py — AWS S3 gate tests. Wave 6 System 29."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_aws_s3 import AWSS3EARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_logging_absent():
    adapter = AWSS3EARAdapter(server_logging=False, cloudtrail_data_events=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-S3")
    read = [a for a in report.assertions if a.operation_family=="object_read"]
    state = report.ear_states.get("object_read","UNKNOWN")
    assert state == "ABSENT" or len(read)>0
    print(f"T-GCG-01 PASS: no logging → object_read={state}")

def test_gcg_02_no_encryption_gap():
    adapter = AWSS3EARAdapter(server_logging=True, cloudtrail_data_events=True,
                              encryption=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-S3")
    read = [a for a in report.assertions if a.operation_family=="object_read"]
    assert len(read)>0, "T-GCG-02 FAIL"
    absent = set(read[0].n_declared)-set(read[0].k_realized)
    assert "encryption_at_rest" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no encryption → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = AWSS3EARAdapter(server_logging=True, cloudtrail_data_events=True,
                              encryption=True, versioning=True, block_public_access=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-S3")
    read = [a for a in report.assertions if a.operation_family=="object_read"]
    assert len(read)==0, f"T-GCG-03 FAIL: {len(read)} gaps"
    print("T-GCG-03 PASS: full config → zero object_read gaps")

def test_nd_01_n_idempotent():
    a1,a2=AWSS3EARAdapter(),AWSS3EARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_cloudtrail_in_read_n():
    adapter = AWSS3EARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="object_read")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "cloudtrail_event" in layers and "encryption_at_rest" in layers
    print(f"T-ND-02 PASS: object_read layers={layers}")

def test_nd_03_strategy_documented():
    decl = AWSS3EARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_object_lock_active():
    adapter = AWSS3EARAdapter(object_lock=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="object_lock")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: object_lock COMPLIANCE = ACTIVE (constitutive immutability)")

def test_ear_02_no_bpa_public_absent():
    adapter = AWSS3EARAdapter(block_public_access=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="public_access")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-02 PASS: no BPA → public_access=ABSENT (bucket potentially public)")

def test_ear_03_no_logging_absent():
    adapter = AWSS3EARAdapter(server_logging=False, cloudtrail_data_events=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="object_read")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-03 PASS: no logging → object_read=ABSENT (default S3 deployment)")

def compute_convergence_fingerprint():
    adapter = AWSS3EARAdapter(server_logging=True,cloudtrail_data_events=True,
                              encryption=True,versioning=True,block_public_access=True,object_lock=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-S3")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: S3 is single most common source of large-scale data breaches in corpus")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_logging_absent,test_gcg_02_no_encryption_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_cloudtrail_in_read_n,test_nd_03_strategy_documented,
           test_ear_01_object_lock_active,test_ear_02_no_bpa_public_absent,
           test_ear_03_no_logging_absent]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (AWS S3)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
