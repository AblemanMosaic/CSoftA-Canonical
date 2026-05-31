"""test_gate_suite.py — K8s Admission Controllers gate tests. Wave 10 System 48."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_k8s_admission import K8sAdmissionEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_fail_open_absent():
    adapter = K8sAdmissionEARAdapter(fail_closed=False)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-Admission")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: failurePolicy:Ignore → all ABSENT (webhook failure = bypass)")

def test_gcg_02_no_audit_gap():
    adapter = K8sAdmissionEARAdapter(fail_closed=True, audit_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-Admission")
    validate = [a for a in report.assertions if a.operation_family=="validating_admission"]
    assert len(validate)>0, "T-GCG-02 FAIL"
    absent = set(validate[0].n_declared)-set(validate[0].k_realized)
    assert "audit_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no audit log → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = K8sAdmissionEARAdapter(fail_closed=True, audit_log_enabled=True,
                                      tls_verified=True, webhook_healthy=True)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-Admission")
    validate = [a for a in report.assertions if a.operation_family=="validating_admission"]
    assert len(validate)==0, f"T-GCG-03 FAIL: {len(validate)} gaps"
    print("T-GCG-03 PASS: full config → zero validating_admission gaps")

def test_nd_01_n_idempotent():
    a1,a2=K8sAdmissionEARAdapter(),K8sAdmissionEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_fail_policy_in_validate_n():
    adapter = K8sAdmissionEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="validating_admission")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "fail_policy" in layers and "webhook_config" in layers
    print(f"T-ND-02 PASS: validate layers={layers}")

def test_nd_03_strategy_documented():
    decl = K8sAdmissionEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_fail_closed_active():
    adapter = K8sAdmissionEARAdapter(fail_closed=True, webhook_healthy=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="validating_admission")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: failurePolicy:Fail = ACTIVE (violations cannot be created)")

def test_ear_02_fail_open_absent():
    adapter = K8sAdmissionEARAdapter(fail_closed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="validating_admission")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-02 PASS: failurePolicy:Ignore = ABSENT (webhook failure = bypass)")

def test_ear_03_unhealthy_webhook_absent():
    adapter = K8sAdmissionEARAdapter(fail_closed=True, webhook_healthy=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="validating_admission")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-03 PASS: unhealthy webhook = ABSENT (no enforcement)")

def compute_convergence_fingerprint():
    adapter = K8sAdmissionEARAdapter(fail_closed=True, audit_log_enabled=True,
                                      tls_verified=True, webhook_healthy=True)
    report = GCGAnalyzer().analyze(adapter, target_system="K8s-Admission")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: failurePolicy:Fail = ACTIVE; failurePolicy:Ignore = ABSENT (bypass route)")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_fail_open_absent,test_gcg_02_no_audit_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_fail_policy_in_validate_n,test_nd_03_strategy_documented,
           test_ear_01_fail_closed_active,test_ear_02_fail_open_absent,
           test_ear_03_unhealthy_webhook_absent]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (K8s Admission)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
