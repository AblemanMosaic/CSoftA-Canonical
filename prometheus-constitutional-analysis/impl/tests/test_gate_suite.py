"""test_gate_suite.py — Prometheus gate tests. Wave 6 System 30."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_prometheus import PrometheusEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_auth_absent():
    adapter = PrometheusEARAdapter(auth_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Prometheus")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print(f"T-GCG-01 PASS: no auth → all ABSENT (default Prometheus has no authentication)")

def test_gcg_02_no_rule_version_gap():
    adapter = PrometheusEARAdapter(auth_enabled=True, rule_version_tracked=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Prometheus")
    alert = [a for a in report.assertions if a.operation_family=="alert_evaluation"]
    assert len(alert)>0, "T-GCG-02 FAIL"
    absent = set(alert[0].n_declared)-set(alert[0].k_realized)
    assert "rule_version" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no rule version → gap={absent}")

def test_gcg_03_full_config_minimal_gap():
    adapter = PrometheusEARAdapter(auth_enabled=True, tls_enabled=True,
                                   rule_version_tracked=True, delivery_receipt=True,
                                   config_hash_tracked=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Prometheus")
    scrape = [a for a in report.assertions if a.operation_family=="metric_scrape"]
    assert len(scrape)==0, f"T-GCG-03 FAIL: {len(scrape)} gaps"
    print("T-GCG-03 PASS: full config → zero scrape gaps")

def test_nd_01_n_idempotent():
    a1,a2=PrometheusEARAdapter(),PrometheusEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_auth_in_scrape_n():
    adapter = PrometheusEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="metric_scrape")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "auth_config" in layers and "scrape_log" in layers
    print(f"T-ND-02 PASS: scrape layers={layers}")

def test_nd_03_strategy_documented():
    decl = PrometheusEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_auth_absent():
    adapter = PrometheusEARAdapter(auth_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="metric_scrape")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no auth → ABSENT (Prometheus has no default authentication)")

def test_ear_02_with_auth_crystallized():
    adapter = PrometheusEARAdapter(auth_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="metric_scrape")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: with auth → CRYSTALLIZED (missed scrape has no receipt)")

def test_ear_03_no_active_family():
    adapter = PrometheusEARAdapter(auth_enabled=True, tls_enabled=True, rule_version_tracked=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Prometheus family reaches ACTIVE — meta-governance case 3")

def compute_convergence_fingerprint():
    adapter = PrometheusEARAdapter(auth_enabled=True,tls_enabled=True,
                                   rule_version_tracked=True,delivery_receipt=True,
                                   config_hash_tracked=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Prometheus")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Meta-governance case 3 — Prometheus governs governance data but has governance gaps")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_auth_absent,test_gcg_02_no_rule_version_gap,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_auth_in_scrape_n,test_nd_03_strategy_documented,
           test_ear_01_no_auth_absent,test_ear_02_with_auth_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Prometheus)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
