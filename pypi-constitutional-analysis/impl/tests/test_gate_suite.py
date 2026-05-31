"""test_gate_suite.py — PyPI gate tests. Wave 11 System 52."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_pypi import PyPIEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_verification_absent():
    adapter = PyPIEARAdapter(attestation_verification=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="package_install")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-GCG-01 PASS: no verification → package_install=ABSENT (supply chain ungoverned)")

def test_gcg_02_no_mfa_gap():
    adapter = PyPIEARAdapter(trusted_publishing=True, mfa_enforced=False)
    report = GCGAnalyzer().analyze(adapter, target_system="PyPI")
    publish = [a for a in report.assertions if a.operation_family=="maintainer_authentication"]
    assert len(publish)>0, "T-GCG-02 FAIL"
    absent = set(publish[0].n_declared)-set(publish[0].k_realized)
    assert "mfa_maintainer" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no MFA → maintainer_auth gap={absent}")

def test_gcg_03_full_config_minimal_gap():
    adapter = PyPIEARAdapter(attestation_verification=True, trusted_publishing=True,
                              mfa_enforced=True, dependency_locked=True)
    report = GCGAnalyzer().analyze(adapter, target_system="PyPI")
    install = [a for a in report.assertions if a.operation_family=="package_install"]
    assert len(install)==0, f"T-GCG-03 FAIL: {len(install)} gaps"
    print("T-GCG-03 PASS: full config → zero package_install gaps")

def test_nd_01_n_idempotent():
    a1,a2=PyPIEARAdapter(),PyPIEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_attestation_in_install_n():
    adapter = PyPIEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="package_install")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "attestation_verification" in layers and "trusted_publishing" in layers
    print(f"T-ND-02 PASS: install layers={layers}")

def test_nd_03_strategy_documented():
    decl = PyPIEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_install_absent_without_verification():
    adapter = PyPIEARAdapter(attestation_verification=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="package_install")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no verification → package_install ABSENT")

def test_ear_02_install_crystallized_with_verification():
    adapter = PyPIEARAdapter(attestation_verification=True, trusted_publishing=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="package_install")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: with verification → CRYSTALLIZED (Sigstore records, not constitutive)")

def test_ear_03_no_active_family_pip_default():
    adapter = PyPIEARAdapter()
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no PyPI family reaches ACTIVE (pip does not verify attestations)")

def compute_convergence_fingerprint():
    adapter = PyPIEARAdapter(attestation_verification=True, trusted_publishing=True,
                              mfa_enforced=True, dependency_locked=True)
    report = GCGAnalyzer().analyze(adapter, target_system="PyPI")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Mini Shai-Hulud — SLSA L3 packages compromised; T1777 at supply chain layer")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_verification_absent,test_gcg_02_no_mfa_gap,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_attestation_in_install_n,test_nd_03_strategy_documented,
           test_ear_01_install_absent_without_verification,
           test_ear_02_install_crystallized_with_verification,
           test_ear_03_no_active_family_pip_default]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (PyPI)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
