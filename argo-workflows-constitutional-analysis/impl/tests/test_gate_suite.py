"""test_gate_suite.py — Argo Workflows gate tests. Wave 8 System 38."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_argo_workflows import ArgoWorkflowsEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_sa_scope_gap():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=True, service_account_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Argo-Workflows")
    submit = [a for a in report.assertions if a.operation_family=="workflow_submission"]
    assert len(submit)>0, "T-GCG-01 FAIL"
    absent = set(submit[0].n_declared)-set(submit[0].k_realized)
    assert "service_account_scope" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no SA scope → gap={absent}")

def test_gcg_02_no_rbac_absent():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Argo-Workflows")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-02 PASS: no RBAC → all ABSENT")

def test_gcg_03_full_config_minimal_gap():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=True, service_account_scoped=True,
                                       audit_log_enabled=True, template_verified=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Argo-Workflows")
    submit = [a for a in report.assertions if a.operation_family=="workflow_submission"]
    assert len(submit)==0, f"T-GCG-03 FAIL: {len(submit)} gaps"
    print("T-GCG-03 PASS: full config → zero workflow_submission gaps")

def test_nd_01_n_idempotent():
    a1,a2=ArgoWorkflowsEARAdapter(),ArgoWorkflowsEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_sa_scope_in_submit_n():
    adapter = ArgoWorkflowsEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="workflow_submission")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "service_account_scope" in layers and "rbac_check" in layers
    print(f"T-ND-02 PASS: submission layers={layers}")

def test_nd_03_strategy_documented():
    decl = ArgoWorkflowsEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_rbac_absent():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="workflow_submission")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no RBAC → ABSENT")

def test_ear_02_with_rbac_crystallized():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="workflow_submission")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: workflow_submission = CRYSTALLIZED (SA scope not constitutive)")

def test_ear_03_no_active_family():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=True, service_account_scoped=True,
                                       audit_log_enabled=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Argo Workflows family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = ArgoWorkflowsEARAdapter(rbac_scoped=True, service_account_scoped=True,
                                       audit_log_enabled=True, template_verified=True,
                                       artifact_signed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Argo-Workflows")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: CVE-2023-22736 namespace bypass; SA scope gap; templateRef supply chain")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_sa_scope_gap,test_gcg_02_no_rbac_absent,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_sa_scope_in_submit_n,test_nd_03_strategy_documented,
           test_ear_01_no_rbac_absent,test_ear_02_with_rbac_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Argo Workflows)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
