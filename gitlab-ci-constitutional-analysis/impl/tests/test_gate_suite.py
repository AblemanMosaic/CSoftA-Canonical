"""test_gate_suite.py — GitLab CI gate tests. Wave 11 System 54."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_gitlab_ci import GitLabCIEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_job_token_scope_gap():
    adapter = GitLabCIEARAdapter(job_token_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GitLab-CI")
    token = [a for a in report.assertions if a.operation_family=="job_token_access"]
    assert len(token)>0, "T-GCG-01 FAIL"
    absent = set(token[0].n_declared)-set(token[0].k_realized)
    assert "job_token_scope" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no job token scope → gap={absent}")

def test_gcg_02_shared_runner_gap():
    adapter = GitLabCIEARAdapter(runner_isolated=False)
    report = GCGAnalyzer().analyze(adapter, target_system="GitLab-CI")
    pipeline = [a for a in report.assertions if a.operation_family=="pipeline_execution"]
    assert len(pipeline)>0, "T-GCG-02 FAIL"
    absent = set(pipeline[0].n_declared)-set(pipeline[0].k_realized)
    assert "runner_isolation" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: shared runner → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = GitLabCIEARAdapter(rbac_configured=True, audit_log_enabled=True,
                                  oidc_enabled=True, job_token_scoped=True,
                                  runner_isolated=True, protected_branches=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GitLab-CI")
    pipeline = [a for a in report.assertions if a.operation_family=="pipeline_execution"]
    assert len(pipeline)==0, f"T-GCG-03 FAIL: {len(pipeline)} gaps"
    print("T-GCG-03 PASS: full config → zero pipeline_execution gaps")

def test_nd_01_n_idempotent():
    a1,a2=GitLabCIEARAdapter(),GitLabCIEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_runner_isolation_in_pipeline_n():
    adapter = GitLabCIEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pipeline_execution")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "runner_isolation" in layers and "rbac_check" in layers
    print(f"T-ND-02 PASS: pipeline layers={layers}")

def test_nd_03_strategy_documented():
    decl = GitLabCIEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_rbac_absent():
    adapter = GitLabCIEARAdapter(rbac_configured=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pipeline_execution")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no RBAC → ABSENT")

def test_ear_02_with_rbac_crystallized():
    adapter = GitLabCIEARAdapter(rbac_configured=True, audit_log_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pipeline_execution")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: pipeline_execution = CRYSTALLIZED")

def test_ear_03_no_active_family():
    adapter = GitLabCIEARAdapter(rbac_configured=True, oidc_enabled=True,
                                  runner_isolated=True, job_token_scoped=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no GitLab CI family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = GitLabCIEARAdapter(rbac_configured=True, audit_log_enabled=True,
                                  oidc_enabled=True, job_token_scoped=True,
                                  runner_isolated=True, protected_branches=True)
    report = GCGAnalyzer().analyze(adapter, target_system="GitLab-CI")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: CVE-2024-6678 CVSS 9.9; job token scope; self-hosted runner isolation")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_job_token_scope_gap,test_gcg_02_shared_runner_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_runner_isolation_in_pipeline_n,test_nd_03_strategy_documented,
           test_ear_01_no_rbac_absent,test_ear_02_with_rbac_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (GitLab CI)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
