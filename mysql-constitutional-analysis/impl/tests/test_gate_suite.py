"""test_gate_suite.py — MySQL gate tests. Wave 11 System 55."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_mysql import MySQLEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_audit_absent():
    adapter = MySQLEARAdapter(enterprise_audit=False, general_log=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-GCG-01 PASS: no audit → query_execution=ABSENT (OSS default)")

def test_gcg_02_general_log_crystallized():
    adapter = MySQLEARAdapter(enterprise_audit=False, general_log=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-GCG-02 PASS: general_log → CRYSTALLIZED (not default, high perf impact)")

def test_gcg_03_enterprise_audit_active():
    adapter = MySQLEARAdapter(enterprise_audit=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-GCG-03 PASS: Enterprise Audit → query_execution = ACTIVE (commercial only)")

def test_nd_01_n_idempotent():
    a1,a2=MySQLEARAdapter(),MySQLEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_enterprise_audit_in_query_n():
    adapter = MySQLEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "enterprise_audit" in layers and "general_log" in layers
    print(f"T-ND-02 PASS: query layers={layers}")

def test_nd_03_strategy_documented():
    decl = MySQLEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_audit_absent():
    adapter = MySQLEARAdapter(enterprise_audit=False, general_log=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no audit → ABSENT (OSS default)")

def test_ear_02_enterprise_active():
    adapter = MySQLEARAdapter(enterprise_audit=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: Enterprise Audit → ACTIVE (commercial paywall governance)")

def test_ear_03_general_log_crystallized():
    adapter = MySQLEARAdapter(general_log=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="query_execution")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: general_log → CRYSTALLIZED")

def compute_convergence_fingerprint():
    adapter = MySQLEARAdapter(enterprise_audit=False, general_log=True,
                               tls_required=True, auth_configured=True)
    report = GCGAnalyzer().analyze(adapter, target_system="MySQL")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: ACTIVE audit paywalled; CVE-2026-3494 comment bypass; extends T1670 PostgreSQL")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_audit_absent,test_gcg_02_general_log_crystallized,
           test_gcg_03_enterprise_audit_active,test_nd_01_n_idempotent,
           test_nd_02_enterprise_audit_in_query_n,test_nd_03_strategy_documented,
           test_ear_01_no_audit_absent,test_ear_02_enterprise_active,
           test_ear_03_general_log_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (MySQL)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
