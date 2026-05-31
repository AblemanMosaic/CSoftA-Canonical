"""test_gate_suite.py — cert-manager ACME gate tests. Wave 10 System 47."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_cert_manager_acme import CertManagerACMEEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_solver_scope_gap():
    adapter = CertManagerACMEEARAdapter(solver_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager-ACME")
    # solver_rbac is in challenge_completion N
    challenge = [a for a in report.assertions if a.operation_family=="challenge_completion"]
    assert len(challenge)>0, "T-GCG-01 FAIL"
    absent = set(challenge[0].n_declared)-set(challenge[0].k_realized)
    assert "solver_rbac" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no solver scope → challenge_completion gap={absent}")

def test_gcg_02_full_config_no_gap():
    adapter = CertManagerACMEEARAdapter(ct_monitored=True, renewal_automated=True,
                                         solver_scoped=True, account_key_encrypted=True)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager-ACME")
    issue = [a for a in report.assertions if a.operation_family=="cert_issuance"]
    assert len(issue)==0, f"T-GCG-02 FAIL: {len(issue)} gaps"
    print("T-GCG-02 PASS: full config → zero cert_issuance gaps")

def test_gcg_03_renewal_gap():
    adapter = CertManagerACMEEARAdapter(renewal_automated=False)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager-ACME")
    renew = [a for a in report.assertions if a.operation_family=="cert_renewal"]
    assert len(renew)>0 or "renewal_automation" not in [l.name for f in adapter.collect_operation_families()
        if f.name=="cert_renewal" for l in adapter.collect_governance_layers(f)]
    print(f"T-GCG-03 PASS: renewal governance checked")

def test_nd_01_n_idempotent():
    a1,a2=CertManagerACMEEARAdapter(),CertManagerACMEEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_ct_in_issuance_n():
    adapter = CertManagerACMEEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="cert_issuance")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "cert_transparency" in layers and "acme_challenge" in layers
    print(f"T-ND-02 PASS: issuance layers={layers}")

def test_nd_03_strategy_documented():
    decl = CertManagerACMEEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_cert_issuance_active():
    adapter = CertManagerACMEEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="cert_issuance")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: cert_issuance = ACTIVE (cert constitutive of TLS)")

def test_ear_02_cert_renewal_active():
    adapter = CertManagerACMEEARAdapter(renewal_automated=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="cert_renewal")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: cert_renewal = ACTIVE (automated renewal)")

def test_ear_03_ct_crystallized():
    adapter = CertManagerACMEEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="cert_revocation")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: cert_revocation = CRYSTALLIZED")

def compute_convergence_fingerprint():
    adapter = CertManagerACMEEARAdapter(ct_monitored=True, renewal_automated=True,
                                         solver_scoped=True, account_key_encrypted=True)
    report = GCGAnalyzer().analyze(adapter, target_system="cert-manager-ACME")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: cert_issuance ACTIVE; CT log = public misissuance record; DNS-01 solver RBAC gap")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_solver_scope_gap,test_gcg_02_full_config_no_gap,
           test_gcg_03_renewal_gap,test_nd_01_n_idempotent,
           test_nd_02_ct_in_issuance_n,test_nd_03_strategy_documented,
           test_ear_01_cert_issuance_active,test_ear_02_cert_renewal_active,
           test_ear_03_ct_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (cert-manager ACME)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
