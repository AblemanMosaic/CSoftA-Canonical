"""test_gate_suite.py — Argo CD gate tests. Wave 5 System 22."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_argocd import ArgoCDEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_audit_log_produces_gap():
    adapter=ArgoCDEARAdapter(rbac_enabled=True, audit_log_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="ArgoCD")
    sync=[a for a in report.assertions if a.operation_family=="git_sync"]
    assert len(sync)>0, "T-GCG-01 FAIL"
    absent=set(sync[0].n_declared)-set(sync[0].k_realized)
    assert "audit_log" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no audit log → gap={absent}")

def test_gcg_02_no_rbac_absent():
    adapter=ArgoCDEARAdapter(rbac_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="ArgoCD")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-02 PASS: no RBAC → all ABSENT")

def test_gcg_03_full_config_minimal_gap():
    adapter=ArgoCDEARAdapter(rbac_enabled=True, audit_log_enabled=True,
                             credential_scope_enforced=True)
    report=GCGAnalyzer().analyze(adapter,target_system="ArgoCD")
    sync=[a for a in report.assertions if a.operation_family=="git_sync"]
    assert len(sync)==0, f"T-GCG-03 FAIL: {len(sync)} gaps"
    print("T-GCG-03 PASS: full config → zero git_sync gaps")

def test_nd_01_n_idempotent():
    a1,a2=ArgoCDEARAdapter(),ArgoCDEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_git_commit_in_sync_n():
    adapter=ArgoCDEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="git_sync")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "git_commit" in layers and "rbac_policy" in layers
    print(f"T-ND-02 PASS: git_sync layers={layers}")

def test_nd_03_strategy_documented():
    decl=ArgoCDEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_rbac_absent():
    adapter=ArgoCDEARAdapter(rbac_enabled=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="git_sync")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no RBAC → ABSENT")

def test_ear_02_rbac_crystallized():
    adapter=ArgoCDEARAdapter(rbac_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="git_sync")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: git_sync = CRYSTALLIZED (sync_status not constitutive)")

def test_ear_03_no_active_family():
    adapter=ArgoCDEARAdapter(rbac_enabled=True, audit_log_enabled=True)
    active=[f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Argo CD family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter=ArgoCDEARAdapter(rbac_enabled=True,audit_log_enabled=True,credential_scope_enforced=True)
    report=GCGAnalyzer().analyze(adapter,target_system="ArgoCD")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Git commit IS governance declaration. Sync receipt is CRYSTALLIZED.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_audit_log_produces_gap,test_gcg_02_no_rbac_absent,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_git_commit_in_sync_n,test_nd_03_strategy_documented,
           test_ear_01_no_rbac_absent,test_ear_02_rbac_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Argo CD)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
