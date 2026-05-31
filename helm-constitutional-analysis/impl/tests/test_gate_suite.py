"""test_gate_suite.py — Helm gate tests. Wave 7 System 35."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_helm import HelmEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_provenance_gap():
    adapter = HelmEARAdapter(chart_provenance_verified=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Helm")
    install = [a for a in report.assertions if a.operation_family=="chart_install"]
    assert len(install)>0, "T-GCG-01 FAIL"
    absent = set(install[0].n_declared)-set(install[0].k_realized)
    assert "chart_provenance" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no provenance → gap={absent}")

def test_gcg_02_chart_pull_absent_without_provenance():
    adapter = HelmEARAdapter(chart_provenance_verified=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="chart_pull")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-GCG-02 PASS: chart_pull without provenance = ABSENT (supply chain gap)")

def test_gcg_03_full_config_no_gap():
    adapter = HelmEARAdapter(chart_provenance_verified=True, rbac_scoped=True,
                             values_encrypted=True, registry_auth=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Helm")
    install = [a for a in report.assertions if a.operation_family=="chart_install"]
    assert len(install)==0, f"T-GCG-03 FAIL: {len(install)} gaps"
    print("T-GCG-03 PASS: full config → zero chart_install gaps")

def test_nd_01_n_idempotent():
    a1,a2=HelmEARAdapter(),HelmEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_provenance_in_install_n():
    adapter = HelmEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="chart_install")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "chart_provenance" in layers and "release_record" in layers
    print(f"T-ND-02 PASS: chart_install layers={layers}")

def test_nd_03_strategy_documented():
    decl = HelmEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_chart_pull_absent_no_provenance():
    adapter = HelmEARAdapter(chart_provenance_verified=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="chart_pull")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: chart_pull without provenance = ABSENT")

def test_ear_02_chart_install_crystallized():
    adapter = HelmEARAdapter(chart_provenance_verified=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="chart_install")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: chart_install = CRYSTALLIZED (release record exists; not constitutive)")

def test_ear_03_no_active_family():
    adapter = HelmEARAdapter(chart_provenance_verified=True, rbac_scoped=True,
                             values_encrypted=True, registry_auth=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Helm family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = HelmEARAdapter(chart_provenance_verified=True, rbac_scoped=True,
                             values_encrypted=True, registry_auth=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Helm")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Chart provenance verification rarely used in practice — supply chain gap at deploy layer")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_provenance_gap,test_gcg_02_chart_pull_absent_without_provenance,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_provenance_in_install_n,test_nd_03_strategy_documented,
           test_ear_01_chart_pull_absent_no_provenance,test_ear_02_chart_install_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Helm)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
