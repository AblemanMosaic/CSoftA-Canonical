"""test_gate_suite.py — external-secrets gate tests. Wave 3 System 12."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_external_secrets import ExternalSecretsEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_store_auth_produces_absent():
    adapter = ExternalSecretsEARAdapter(store_auth_configured=False)
    report = GCGAnalyzer().analyze(adapter, target_system="external-secrets")
    assert all(v == "ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no store auth → ABSENT")

def test_gcg_02_no_sync_status_produces_gap():
    adapter = ExternalSecretsEARAdapter(sync_status_enabled=False, store_auth_configured=True)
    report = GCGAnalyzer().analyze(adapter, target_system="external-secrets")
    ss = [a for a in report.assertions if a.operation_family == "secret_sync"]
    assert len(ss) > 0, "T-GCG-02 FAIL"
    absent = set(ss[0].n_declared)-set(ss[0].k_realized)
    assert "sync_status" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no sync_status → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = ExternalSecretsEARAdapter(sync_status_enabled=True, store_auth_configured=True)
    report = GCGAnalyzer().analyze(adapter, target_system="external-secrets")
    ss = [a for a in report.assertions if a.operation_family == "secret_sync"]
    assert len(ss) == 0, f"T-GCG-03 FAIL: {len(ss)} gaps"
    print("T-GCG-03 PASS: full config → zero secret_sync gaps")

def test_nd_01_n_idempotent():
    a1,a2=ExternalSecretsEARAdapter(),ExternalSecretsEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_store_auth_in_n():
    adapter=ExternalSecretsEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="secret_sync")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "store_auth" in layers; print(f"T-ND-02 PASS: layers={layers}")

def test_nd_03_strategy_documented():
    decl=ExternalSecretsEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print(f"T-ND-03 PASS")

def test_ear_01_no_auth_absent():
    adapter=ExternalSecretsEARAdapter(store_auth_configured=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="secret_sync")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no auth → ABSENT")

def test_ear_02_with_auth_crystallized():
    adapter=ExternalSecretsEARAdapter(store_auth_configured=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="secret_sync")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED; print("T-EAR-02 PASS: auth → CRYSTALLIZED")

def test_ear_03_no_active_any_family():
    adapter=ExternalSecretsEARAdapter(store_auth_configured=True,sync_status_enabled=True)
    active=[f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no ESO family reaches ACTIVE (upstream store governs)")

def compute_convergence_fingerprint():
    adapter=ExternalSecretsEARAdapter(store_type="vault",sync_status_enabled=True,store_auth_configured=True)
    report=GCGAnalyzer().analyze(adapter,target_system="external-secrets")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}\n{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_store_auth_produces_absent,test_gcg_02_no_sync_status_produces_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,test_nd_02_store_auth_in_n,
           test_nd_03_strategy_documented,test_ear_01_no_auth_absent,
           test_ear_02_with_auth_crystallized,test_ear_03_no_active_any_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (external-secrets)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); import sys; sys.exit(0 if f==0 else 1)
