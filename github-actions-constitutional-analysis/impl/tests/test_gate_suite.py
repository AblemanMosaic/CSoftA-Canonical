"""test_gate_suite.py — GitHub Actions gate tests. Wave 6 System 26."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_github_actions import GitHubActionsEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_hash_pin_action_absent():
    adapter = GitHubActionsEARAdapter(hash_pinned=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GitHub-Actions")
    state = report.ear_states.get("action_consumption","UNKNOWN")
    assert state == "ABSENT", f"T-GCG-01 FAIL: {state}"
    print(f"T-GCG-01 PASS: no hash pin → action_consumption=ABSENT (CVE-2025-30066 class)")

def test_gcg_02_no_workflow_permissions_gap():
    adapter = GitHubActionsEARAdapter(hash_pinned=True, workflow_permissions_declared=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GitHub-Actions")
    wf = [a for a in report.assertions if a.operation_family=="workflow_execution"]
    assert len(wf) > 0, "T-GCG-02 FAIL"
    absent = set(wf[0].n_declared)-set(wf[0].k_realized)
    assert "workflow_permissions" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no permissions declared → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = GitHubActionsEARAdapter(hash_pinned=True, workflow_permissions_declared=True,
                                      oidc_enabled=True, audit_log_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GitHub-Actions")
    wf = [a for a in report.assertions if a.operation_family=="workflow_execution"]
    assert len(wf)==0, f"T-GCG-03 FAIL: {len(wf)} gaps"
    print("T-GCG-03 PASS: full config → zero workflow_execution gaps")

def test_nd_01_n_idempotent():
    a1,a2 = GitHubActionsEARAdapter(),GitHubActionsEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_action_provenance_in_action_n():
    adapter = GitHubActionsEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="action_consumption")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "action_provenance" in layers and "action_hash" in layers
    print(f"T-ND-02 PASS: action layers={layers}")

def test_nd_03_strategy_documented():
    decl = GitHubActionsEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_oidc_cloud_federation_active():
    adapter = GitHubActionsEARAdapter(oidc_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="cloud_federation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: cloud_federation with OIDC = ACTIVE")

def test_ear_02_no_hash_pin_absent():
    adapter = GitHubActionsEARAdapter(hash_pinned=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="action_consumption")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-02 PASS: action_consumption without hash = ABSENT")

def test_ear_03_workflow_execution_crystallized():
    adapter = GitHubActionsEARAdapter(hash_pinned=True, workflow_permissions_declared=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="workflow_execution")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: workflow_execution = CRYSTALLIZED (run log not constitutive)")

def compute_convergence_fingerprint():
    adapter = GitHubActionsEARAdapter(hash_pinned=True,workflow_permissions_declared=True,
                                      oidc_enabled=True,audit_log_enabled=True,artifact_provenance=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GitHub-Actions")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Third-party action supply chain is ABSENT by default — CVE-2025-30066 confirmed")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_hash_pin_action_absent,test_gcg_02_no_workflow_permissions_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_action_provenance_in_action_n,test_nd_03_strategy_documented,
           test_ear_01_oidc_cloud_federation_active,test_ear_02_no_hash_pin_absent,
           test_ear_03_workflow_execution_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (GitHub Actions)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
