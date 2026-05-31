"""test_gate_suite.py — K8s RBAC gate tests. Wave 9 System 41."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_k8s_rbac import K8sRBACSEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_audit_gap():
    adapter = K8sRBACSEARAdapter(audit_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-RBAC")
    authz = [a for a in report.assertions if a.operation_family=="api_authorization"]
    assert len(authz)>0, "T-GCG-01 FAIL"
    absent = set(authz[0].n_declared)-set(authz[0].k_realized)
    assert "audit_log" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no audit log → gap={absent}")

def test_gcg_02_no_escalation_control_gap():
    adapter = K8sRBACSEARAdapter(audit_log_enabled=True, escalation_verbs_restricted=False)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-RBAC")
    authz = [a for a in report.assertions if a.operation_family=="api_authorization"]
    assert len(authz)>0, "T-GCG-02 FAIL"
    absent = set(authz[0].n_declared)-set(authz[0].k_realized)
    assert "escalation_control" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no escalation control → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = K8sRBACSEARAdapter(audit_log_enabled=True, least_privilege_enforced=True,
                                  escalation_verbs_restricted=True, wildcards_prohibited=True,
                                  stale_bindings_reviewed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-RBAC")
    authz = [a for a in report.assertions if a.operation_family=="api_authorization"]
    assert len(authz)==0, f"T-GCG-03 FAIL: {len(authz)} gaps"
    print("T-GCG-03 PASS: full config → zero api_authorization gaps")

def test_nd_01_n_idempotent():
    a1,a2=K8sRBACSEARAdapter(),K8sRBACSEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_escalation_control_in_authz_n():
    adapter = K8sRBACSEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="api_authorization")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "escalation_control" in layers and "rbac_policy" in layers
    print(f"T-ND-02 PASS: authz layers={layers}")

def test_nd_03_strategy_documented():
    decl = K8sRBACSEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_api_authorization_active():
    adapter = K8sRBACSEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="api_authorization")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: api_authorization = ACTIVE (RBAC constitutive of every API request)")

def test_ear_02_role_management_crystallized():
    adapter = K8sRBACSEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="role_management")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: role_management = CRYSTALLIZED (policy content not constitutively governed)")

def test_ear_03_all_others_crystallized():
    adapter = K8sRBACSEARAdapter(audit_log_enabled=True)
    non_active = [f.name for f in adapter.collect_operation_families()
                  if f.name != "api_authorization" and adapter.assess_ear_state(f) != EARState.CRYSTALLIZED]
    assert len(non_active)==0, f"T-EAR-03 FAIL: {non_active}"
    print("T-EAR-03 PASS: all non-authz families = CRYSTALLIZED")

def compute_convergence_fingerprint():
    adapter = K8sRBACSEARAdapter(audit_log_enabled=True, least_privilege_enforced=True,
                                  escalation_verbs_restricted=True, wildcards_prohibited=True,
                                  stale_bindings_reviewed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-RBAC")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: api_authorization ACTIVE — RBAC constitutive of all K8s API requests")
    print("NOTE: 58% of clusters have RBAC misconfigs enabling cluster-admin escalation")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_audit_gap,test_gcg_02_no_escalation_control_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_escalation_control_in_authz_n,test_nd_03_strategy_documented,
           test_ear_01_api_authorization_active,test_ear_02_role_management_crystallized,
           test_ear_03_all_others_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (K8s RBAC)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
