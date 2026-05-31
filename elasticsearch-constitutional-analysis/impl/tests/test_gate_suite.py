"""test_gate_suite.py — Elasticsearch gate tests. Wave 11 System 51."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_elasticsearch import ElasticsearchEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_auth_absent():
    adapter = ElasticsearchEARAdapter(auth_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Elasticsearch")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no auth → all ABSENT (governance evidence layer unprotected)")

def test_gcg_02_no_audit_gap():
    adapter = ElasticsearchEARAdapter(auth_enabled=True, rbac_configured=True, audit_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Elasticsearch")
    search = [a for a in report.assertions if a.operation_family=="document_search"]
    assert len(search)>0, "T-GCG-02 FAIL"
    absent = set(search[0].n_declared)-set(search[0].k_realized)
    assert "audit_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no audit log → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = ElasticsearchEARAdapter(auth_enabled=True, tls_enabled=True,
                                       audit_log_enabled=True, rbac_configured=True,
                                       field_security=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Elasticsearch")
    search = [a for a in report.assertions if a.operation_family=="document_search"]
    assert len(search)==0, f"T-GCG-03 FAIL: {len(search)} gaps"
    print("T-GCG-03 PASS: full config (with field security) → zero document_search gaps")

def test_nd_01_n_idempotent():
    a1,a2=ElasticsearchEARAdapter(),ElasticsearchEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_auth_in_search_n():
    adapter = ElasticsearchEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="document_search")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "auth_required" in layers and "audit_log" in layers
    print(f"T-ND-02 PASS: search layers={layers}")

def test_nd_03_strategy_documented():
    decl = ElasticsearchEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_auth_absent():
    adapter = ElasticsearchEARAdapter(auth_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="document_search")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no auth → ABSENT (governance evidence layer open)")

def test_ear_02_with_auth_crystallized():
    adapter = ElasticsearchEARAdapter(auth_enabled=True, audit_log_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="document_search")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: document_search = CRYSTALLIZED (no ACTIVE path in standard deployment)")

def test_ear_03_no_active_family():
    adapter = ElasticsearchEARAdapter(auth_enabled=True, tls_enabled=True,
                                       audit_log_enabled=True, rbac_configured=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no ES family reaches ACTIVE (governance evidence storage layer)")

def compute_convergence_fingerprint():
    adapter = ElasticsearchEARAdapter(auth_enabled=True, tls_enabled=True,
                                       audit_log_enabled=True, rbac_configured=True,
                                       field_security=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Elasticsearch")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Governance evidence layer — ABSENT ES means all stored audit logs exposed")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_auth_absent,test_gcg_02_no_audit_gap,test_gcg_03_full_config_no_gap,
           test_nd_01_n_idempotent,test_nd_02_auth_in_search_n,test_nd_03_strategy_documented,
           test_ear_01_no_auth_absent,test_ear_02_with_auth_crystallized,test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Elasticsearch)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
