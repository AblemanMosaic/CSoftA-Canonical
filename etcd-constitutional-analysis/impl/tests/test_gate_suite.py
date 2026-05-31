"""test_gate_suite.py — etcd gate tests. Wave 6 System 27."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_etcd import EtcdEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_mtls_absent():
    adapter = EtcdEARAdapter(mtls_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="etcd")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print(f"T-GCG-01 PASS: no mTLS → all ABSENT")

def test_gcg_02_no_encryption_at_rest_gap():
    adapter = EtcdEARAdapter(mtls_enabled=True, encryption_at_rest=False)
    report = GCGAnalyzer().analyze(adapter, target_system="etcd")
    read = [a for a in report.assertions if a.operation_family=="key_read"]
    assert len(read)>0, "T-GCG-02 FAIL"
    absent = set(read[0].n_declared)-set(read[0].k_realized)
    assert "encryption_at_rest" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no encryption at rest → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = EtcdEARAdapter(mtls_enabled=True, encryption_at_rest=True,
                             audit_log_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="etcd")
    read = [a for a in report.assertions if a.operation_family=="key_read"]
    assert len(read)==0, f"T-GCG-03 FAIL: {len(read)} gaps"
    print("T-GCG-03 PASS: full config → zero key_read gaps")

def test_nd_01_n_idempotent():
    a1,a2=EtcdEARAdapter(),EtcdEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_encryption_in_read_n():
    adapter = EtcdEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="key_read")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "encryption_at_rest" in layers and "peer_mtls" in layers
    print(f"T-ND-02 PASS: key_read layers={layers}")

def test_nd_03_strategy_documented():
    decl = EtcdEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_mtls_absent():
    adapter = EtcdEARAdapter(mtls_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="key_read")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no mTLS → ABSENT")

def test_ear_02_peer_auth_active():
    adapter = EtcdEARAdapter(mtls_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="peer_authentication")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: peer_authentication with mTLS = ACTIVE")

def test_ear_03_key_read_crystallized_with_mtls():
    adapter = EtcdEARAdapter(mtls_enabled=True, encryption_at_rest=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="key_read")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: key_read = CRYSTALLIZED (no native audit log)")

def compute_convergence_fingerprint():
    adapter = EtcdEARAdapter(mtls_enabled=True,encryption_at_rest=True,
                             audit_log_enabled=True,backup_encrypted=True)
    report = GCGAnalyzer().analyze(adapter, target_system="etcd")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Direct etcd access bypasses all Kubernetes RBAC — substrate-of-substrate gap")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_mtls_absent,test_gcg_02_no_encryption_at_rest_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_encryption_in_read_n,test_nd_03_strategy_documented,
           test_ear_01_no_mtls_absent,test_ear_02_peer_auth_active,
           test_ear_03_key_read_crystallized_with_mtls]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (etcd)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
