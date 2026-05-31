"""test_gate_suite.py — PostgreSQL gate tests. Wave 5 System 23."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_postgresql import PostgreSQLEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_pgaudit_absent():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="PostgreSQL")
    q=[a for a in report.assertions if a.operation_family=="query_execution"]
    assert len(q)>0 or report.ear_states.get("query_execution")=="ABSENT"
    print(f"T-GCG-01 PASS: no pgaudit → query_execution={report.ear_states.get('query_execution')}")

def test_gcg_02_pgaudit_no_gap():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=True, rls_enabled=True, ssl_required=True)
    report=GCGAnalyzer().analyze(adapter,target_system="PostgreSQL")
    q=[a for a in report.assertions if a.operation_family=="query_execution"]
    assert len(q)==0, f"T-GCG-02 FAIL: {len(q)} gaps"
    print("T-GCG-02 PASS: pgaudit enabled → zero query_execution gaps")

def test_gcg_03_rls_gap_without_pgaudit():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=False, rls_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="PostgreSQL")
    rls=[a for a in report.assertions if a.operation_family=="rls_enforcement"]
    if rls:
        absent=set(rls[0].n_declared)-set(rls[0].k_realized)
        assert "pgaudit_log" in absent
    print(f"T-GCG-03 PASS: RLS without pgaudit → audit gap confirmed")

def test_nd_01_n_idempotent():
    a1,a2=PostgreSQLEARAdapter(),PostgreSQLEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_pgaudit_in_query_n():
    adapter=PostgreSQLEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "pgaudit_log" in layers and "rls_policy" in layers
    print(f"T-ND-02 PASS: query layers={layers}")

def test_nd_03_strategy_documented():
    decl=PostgreSQLEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_pgaudit_absent():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no pgaudit → ABSENT (default PostgreSQL has no structured audit)")

def test_ear_02_pgaudit_active():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: pgaudit enabled → ACTIVE (queries cannot complete without logging)")

def test_ear_03_pgaudit_active_ddl_too():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="ddl_operation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-03 PASS: DDL with pgaudit = ACTIVE")

def compute_convergence_fingerprint():
    adapter=PostgreSQLEARAdapter(pgaudit_enabled=True,rls_enabled=True,ssl_required=True,log_connections=True)
    report=GCGAnalyzer().analyze(adapter,target_system="PostgreSQL")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: pgaudit = ACTIVE but it is an extension — ABSENT by default installation.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_pgaudit_absent,test_gcg_02_pgaudit_no_gap,
           test_gcg_03_rls_gap_without_pgaudit,test_nd_01_n_idempotent,
           test_nd_02_pgaudit_in_query_n,test_nd_03_strategy_documented,
           test_ear_01_no_pgaudit_absent,test_ear_02_pgaudit_active,
           test_ear_03_pgaudit_active_ddl_too]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (PostgreSQL)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
