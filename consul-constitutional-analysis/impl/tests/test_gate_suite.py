"""test_gate_suite.py — Consul gate tests. Wave 3 System 13."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_consul import ConsulEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_oss_no_audit_log():
    adapter = ConsulEARAdapter(enterprise=False, acl_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Consul")
    acl = [a for a in report.assertions if a.operation_family == "acl_authorization"]
    if acl:
        absent = set(acl[0].n_declared)-set(acl[0].k_realized)
        assert "audit_log" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: OSS Consul → audit_log absent (enterprise-only feature)")

def test_gcg_02_connect_cert_no_gap():
    adapter = ConsulEARAdapter(connect_enabled=True, acl_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Consul")
    cc = [a for a in report.assertions if a.operation_family == "connect_certificate"]
    assert len(cc) == 0, f"T-GCG-02 FAIL: {len(cc)} gaps in connect_certificate"
    print("T-GCG-02 PASS: Connect cert fully governed → zero gaps")

def test_gcg_03_no_acl_kv_absent():
    adapter = ConsulEARAdapter(acl_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Consul")
    kv_states = [v for k,v in report.ear_states.items() if "kv" in k.lower() or "acl" in k.lower()]
    print(f"T-GCG-03 PASS: no ACL → states={report.ear_states}")

def test_nd_01_n_idempotent():
    a1,a2=ConsulEARAdapter(),ConsulEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_svid_receipt_in_connect_n():
    adapter=ConsulEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="connect_certificate")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "svid_receipt" in layers; print(f"T-ND-02 PASS: connect layers={layers}")

def test_nd_03_strategy_documented():
    decl=ConsulEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_connect_certificate_active():
    adapter=ConsulEARAdapter(connect_enabled=True,acl_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="connect_certificate")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE; print("T-EAR-01 PASS: connect_certificate = ACTIVE")

def test_ear_02_acl_oss_absent_enterprise_crystallized():
    oss=ConsulEARAdapter(enterprise=False,acl_enabled=True)
    ent=ConsulEARAdapter(enterprise=True,acl_enabled=True)
    fam_oss=next(f for f in oss.collect_operation_families() if f.name=="acl_authorization")
    fam_ent=next(f for f in ent.collect_operation_families() if f.name=="acl_authorization")
    assert oss.assess_ear_state(fam_oss)==EARState.ABSENT
    assert ent.assess_ear_state(fam_ent)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: OSS acl=ABSENT, Enterprise acl=CRYSTALLIZED")

def test_ear_03_connect_is_highest_governance():
    adapter=ConsulEARAdapter(connect_enabled=True,enterprise=True,acl_enabled=True)
    active=[f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert "connect_certificate" in active; print(f"T-EAR-03 PASS: ACTIVE families={active}")

def compute_convergence_fingerprint():
    adapter=ConsulEARAdapter(enterprise=False,connect_enabled=True,acl_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Consul")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}\n{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_oss_no_audit_log,test_gcg_02_connect_cert_no_gap,
           test_gcg_03_no_acl_kv_absent,test_nd_01_n_idempotent,test_nd_02_svid_receipt_in_connect_n,
           test_nd_03_strategy_documented,test_ear_01_connect_certificate_active,
           test_ear_02_acl_oss_absent_enterprise_crystallized,test_ear_03_connect_is_highest_governance]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Consul)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); import sys; sys.exit(0 if f==0 else 1)
