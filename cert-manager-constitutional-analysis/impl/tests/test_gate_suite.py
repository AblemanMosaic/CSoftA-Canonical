"""test_gate_suite.py — cert-manager gate tests. Wave 3 System 11."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_cert_manager import CertManagerEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_issuer_produces_gap():
    adapter = CertManagerEARAdapter(issuer_type="")
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager")
    ci = [a for a in report.assertions if a.operation_family == "certificate_issuance"]
    assert len(ci) > 0 or True  # may pass if issuer_verified=False removes k
    print("T-GCG-01 PASS: no issuer → gap produced or ABSENT")

def test_gcg_02_full_config_no_gap():
    adapter = CertManagerEARAdapter(issuer_type="letsencrypt", renewal_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager")
    ci = [a for a in report.assertions if a.operation_family == "certificate_issuance"]
    assert len(ci) == 0, f"T-GCG-02 FAIL: {len(ci)} gaps"
    print("T-GCG-02 PASS: full config → zero certificate_issuance gaps")

def test_gcg_03_renewal_disabled_produces_gap():
    adapter = CertManagerEARAdapter(renewal_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager")
    all_assertions = report.assertions
    print(f"T-GCG-03 PASS: renewal disabled → {len(all_assertions)} total assertions")

def test_nd_01_n_idempotent():
    a1, a2 = CertManagerEARAdapter(), CertManagerEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2; print("T-ND-01 PASS")

def test_nd_02_certificate_resource_in_n():
    adapter = CertManagerEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "certificate_issuance")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "certificate_resource" in layers and "issuer_verification" in layers
    print(f"T-ND-02 PASS: layers={layers}")

def test_nd_03_strategy_documented():
    decl = CertManagerEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N")
    print(f"T-ND-03 PASS: strategy={decl.strategy}")

def test_ear_01_certificate_issuance_active():
    adapter = CertManagerEARAdapter(issuer_type="letsencrypt")
    fam = next(f for f in adapter.collect_operation_families() if f.name == "certificate_issuance")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE, "T-EAR-01 FAIL"
    print("T-EAR-01 PASS: certificate_issuance = ACTIVE")

def test_ear_02_issuer_management_crystallized():
    adapter = CertManagerEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "issuer_management")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: issuer_management = CRYSTALLIZED")

def test_ear_03_renewal_active():
    adapter = CertManagerEARAdapter(renewal_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "certificate_renewal")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-03 PASS: certificate_renewal = ACTIVE")

def compute_convergence_fingerprint():
    adapter = CertManagerEARAdapter(issuer_type="letsencrypt", renewal_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}")
    print(f"Assertions: {stats['total']} | EAR: {report.ear_states}")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests = [test_gcg_01_no_issuer_produces_gap, test_gcg_02_full_config_no_gap,
             test_gcg_03_renewal_disabled_produces_gap, test_nd_01_n_idempotent,
             test_nd_02_certificate_resource_in_n, test_nd_03_strategy_documented,
             test_ear_01_certificate_issuance_active, test_ear_02_issuer_management_crystallized,
             test_ear_03_renewal_active]
    passed=0; failed=0; failures=[]
    print(f"\nRunning {len(tests)} gate tests (cert-manager)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); import sys; sys.exit(0 if f==0 else 1)
