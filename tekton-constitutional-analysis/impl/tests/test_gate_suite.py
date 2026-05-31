"""test_gate_suite.py — Tekton gate tests. Wave 9 System 43."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_tekton import TektonEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_chains_gap():
    adapter = TektonEARAdapter(chains_enabled=False, rbac_scoped=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Tekton")
    pipeline = [a for a in report.assertions if a.operation_family=="pipeline_execution"]
    assert len(pipeline)>0, "T-GCG-01 FAIL"
    absent = set(pipeline[0].n_declared)-set(pipeline[0].k_realized)
    assert "chains_signing" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no Chains → gap={absent}")

def test_gcg_02_no_rbac_absent():
    adapter = TektonEARAdapter(rbac_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Tekton")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-02 PASS: no RBAC → all ABSENT")

def test_gcg_03_full_config_no_gap():
    adapter = TektonEARAdapter(chains_enabled=True, sa_scoped=True,
                                audit_log_enabled=True, rbac_scoped=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Tekton")
    pipeline = [a for a in report.assertions if a.operation_family=="pipeline_execution"]
    assert len(pipeline)==0, f"T-GCG-03 FAIL: {len(pipeline)} gaps"
    print("T-GCG-03 PASS: full config → zero pipeline_execution gaps")

def test_nd_01_n_idempotent():
    a1,a2=TektonEARAdapter(),TektonEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_chains_in_pipeline_n():
    adapter = TektonEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pipeline_execution")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "chains_signing" in layers and "rbac_check" in layers
    print(f"T-ND-02 PASS: pipeline layers={layers}")

def test_nd_03_strategy_documented():
    decl = TektonEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_rbac_absent():
    adapter = TektonEARAdapter(rbac_scoped=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pipeline_execution")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no RBAC → ABSENT")

def test_ear_02_result_attestation_active_with_chains():
    adapter = TektonEARAdapter(chains_enabled=True, rbac_scoped=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="result_attestation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: result_attestation with Chains = ACTIVE")

def test_ear_03_pipeline_crystallized():
    adapter = TektonEARAdapter(rbac_scoped=True, chains_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pipeline_execution")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: pipeline_execution = CRYSTALLIZED")

def compute_convergence_fingerprint():
    adapter = TektonEARAdapter(chains_enabled=True, sa_scoped=True,
                                audit_log_enabled=True, rbac_scoped=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Tekton")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Tekton Chains closes pipeline-level supply chain gap — K8s-native SLSA provenance")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_chains_gap,test_gcg_02_no_rbac_absent,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_chains_in_pipeline_n,test_nd_03_strategy_documented,
           test_ear_01_no_rbac_absent,test_ear_02_result_attestation_active_with_chains,
           test_ear_03_pipeline_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Tekton)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
