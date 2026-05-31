"""test_gate_suite.py — Redis gate tests. Wave 7 System 34."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_redis import RedisEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_auth_absent():
    adapter = RedisEARAdapter(auth_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Redis")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no auth → all ABSENT (60,000+ internet-exposed unauthenticated instances)")

def test_gcg_02_no_tls_gap():
    adapter = RedisEARAdapter(auth_enabled=True, tls_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Redis")
    read = [a for a in report.assertions if a.operation_family=="data_read"]
    assert len(read)>0, "T-GCG-02 FAIL"
    absent = set(read[0].n_declared)-set(read[0].k_realized)
    assert "tls_transport" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no TLS → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = RedisEARAdapter(auth_enabled=True, acl_enabled=True,
                              tls_enabled=True, audit_log_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Redis")
    read = [a for a in report.assertions if a.operation_family=="data_read"]
    assert len(read)==0, f"T-GCG-03 FAIL: {len(read)} gaps"
    print("T-GCG-03 PASS: full config → zero data_read gaps")

def test_nd_01_n_idempotent():
    a1,a2=RedisEARAdapter(),RedisEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_auth_in_read_n():
    adapter = RedisEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="data_read")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "auth_control" in layers and "acl_policy" in layers
    print(f"T-ND-02 PASS: data_read layers={layers}")

def test_nd_03_strategy_documented():
    decl = RedisEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_auth_absent():
    adapter = RedisEARAdapter(auth_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="data_read")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no auth → ABSENT (two CVSS 10.0 vulns in default Lua engine)")

def test_ear_02_with_auth_crystallized():
    adapter = RedisEARAdapter(auth_enabled=True, acl_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="data_read")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: with auth → CRYSTALLIZED (no audit log)")

def test_ear_03_no_active_family():
    adapter = RedisEARAdapter(auth_enabled=True, acl_enabled=True, tls_enabled=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Redis family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = RedisEARAdapter(auth_enabled=True, acl_enabled=True,
                              tls_enabled=True, lua_restricted=True, audit_log_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Redis")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: CVE-2025-49844 CVSS 10.0 (RediShell) + CVE-2022-0543 CVSS 10.0 in default Lua engine")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_auth_absent,test_gcg_02_no_tls_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_auth_in_read_n,test_nd_03_strategy_documented,
           test_ear_01_no_auth_absent,test_ear_02_with_auth_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Redis)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
