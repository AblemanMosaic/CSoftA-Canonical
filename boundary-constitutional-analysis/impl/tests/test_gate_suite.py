"""test_gate_suite.py — Boundary gate tests. Wave 3 System 15."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_boundary import BoundaryEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_audit_log_absent():
    adapter=BoundaryEARAdapter(audit_log_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Boundary")
    assert all(v=="ABSENT" for v in report.ear_states.values()); print("T-GCG-01 PASS: no audit → ABSENT")

def test_gcg_02_full_config_no_gap():
    adapter=BoundaryEARAdapter(vault_integrated=True,audit_log_enabled=True,oidc_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Boundary")
    sa=[a for a in report.assertions if a.operation_family=="session_authorization"]
    assert len(sa)==0, f"T-GCG-02 FAIL: {len(sa)} gaps"
    print("T-GCG-02 PASS: full config → zero session_authorization gaps")

def test_gcg_03_no_vault_credential_gap():
    adapter=BoundaryEARAdapter(vault_integrated=False,audit_log_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Boundary")
    cb=[a for a in report.assertions if a.operation_family=="credential_brokering"]
    if cb:
        absent=set(cb[0].n_declared)-set(cb[0].k_realized)
        assert "vault_credential" in absent, f"T-GCG-03 FAIL: {absent}"
    print(f"T-GCG-03 PASS: no vault → credential_brokering gap or {'vault_credential absent' if cb else 'no assertion'}")

def test_nd_01_n_idempotent():
    a1,a2=BoundaryEARAdapter(),BoundaryEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_vault_credential_in_brokering_n():
    adapter=BoundaryEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="credential_brokering")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "vault_credential" in layers; print(f"T-ND-02 PASS: credential_brokering layers={layers}")

def test_nd_03_strategy_documented():
    decl=BoundaryEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_audit_absent():
    adapter=BoundaryEARAdapter(audit_log_enabled=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="session_authorization")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no audit → ABSENT")

def test_ear_02_with_audit_crystallized():
    adapter=BoundaryEARAdapter(audit_log_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="session_authorization")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED; print("T-EAR-02 PASS: audit → CRYSTALLIZED")

def test_ear_03_no_active_any_family():
    adapter=BoundaryEARAdapter(vault_integrated=True,audit_log_enabled=True,oidc_enabled=True)
    active=[f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Boundary family reaches ACTIVE (Vault upstream governs credentials)")

def compute_convergence_fingerprint():
    adapter=BoundaryEARAdapter(vault_integrated=True,audit_log_enabled=True,oidc_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Boundary")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}\n{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_audit_log_absent,test_gcg_02_full_config_no_gap,
           test_gcg_03_no_vault_credential_gap,test_nd_01_n_idempotent,test_nd_02_vault_credential_in_brokering_n,
           test_nd_03_strategy_documented,test_ear_01_no_audit_absent,
           test_ear_02_with_audit_crystallized,test_ear_03_no_active_any_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Boundary)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); import sys; sys.exit(0 if f==0 else 1)
