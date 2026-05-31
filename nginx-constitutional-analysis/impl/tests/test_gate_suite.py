"""test_gate_suite.py — Nginx/ingress-nginx gate tests. Wave 6 System 28."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_nginx import NginxEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_annotation_validation_absent():
    adapter = NginxEARAdapter(annotation_validation=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Nginx")
    state = report.ear_states.get("ingress_admission","UNKNOWN")
    assert state == "ABSENT", f"T-GCG-01 FAIL: {state}"
    print(f"T-GCG-01 PASS: no annotation validation → ingress_admission=ABSENT (CVE-2025-1974 class)")

def test_gcg_02_no_access_log_gap():
    adapter = NginxEARAdapter(tls_enabled=True, access_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Nginx")
    proxy = [a for a in report.assertions if a.operation_family=="request_proxying"]
    assert len(proxy)>0, "T-GCG-02 FAIL"
    absent = set(proxy[0].n_declared)-set(proxy[0].k_realized)
    assert "access_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no access log → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = NginxEARAdapter(tls_enabled=True, access_log_enabled=True,
                              annotation_validation=True, waf_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Nginx")
    proxy = [a for a in report.assertions if a.operation_family=="request_proxying"]
    assert len(proxy)==0, f"T-GCG-03 FAIL: {len(proxy)} gaps"
    print("T-GCG-03 PASS: full config → zero request_proxying gaps")

def test_nd_01_n_idempotent():
    a1,a2=NginxEARAdapter(),NginxEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_annotation_validation_in_admission_n():
    adapter = NginxEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="ingress_admission")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "annotation_validation" in layers
    print(f"T-ND-02 PASS: ingress_admission layers={layers}")

def test_nd_03_strategy_documented():
    decl = NginxEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_tls_termination_active():
    adapter = NginxEARAdapter(tls_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="tls_termination")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: tls_termination = ACTIVE (cert constitutive of HTTPS)")

def test_ear_02_no_annotation_validation_absent():
    adapter = NginxEARAdapter(annotation_validation=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="ingress_admission")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-02 PASS: ingress_admission without validation = ABSENT")

def test_ear_03_request_proxying_crystallized():
    adapter = NginxEARAdapter(tls_enabled=True, access_log_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="request_proxying")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: request_proxying = CRYSTALLIZED (log not constitutive)")

def compute_convergence_fingerprint():
    adapter = NginxEARAdapter(tls_enabled=True,access_log_enabled=True,
                              annotation_validation=True,waf_enabled=True,rate_limiting=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Nginx")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: IngressNightmare CVE-2025-1974 CVSS 9.8 — 43% of cloud environments affected")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_annotation_validation_absent,test_gcg_02_no_access_log_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_annotation_validation_in_admission_n,test_nd_03_strategy_documented,
           test_ear_01_tls_termination_active,test_ear_02_no_annotation_validation_absent,
           test_ear_03_request_proxying_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Nginx)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
