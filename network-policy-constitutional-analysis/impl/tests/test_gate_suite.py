"""test_gate_suite.py — NetworkPolicy gate tests. Wave 7 System 32."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_network_policy import NetworkPolicyEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_policy_absent():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=False)
    report = GCGAnalyzer().analyze(adapter, target_system="NetworkPolicy")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no NetworkPolicy → all ABSENT (Kubernetes default)")

def test_gcg_02_no_flow_log_gap():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=True, cni_enforcing=True,
                                       flow_logging=False)
    report = GCGAnalyzer().analyze(adapter, target_system="NetworkPolicy")
    ingress = [a for a in report.assertions if a.operation_family=="ingress_control"]
    assert len(ingress)>0, "T-GCG-02 FAIL"
    absent = set(ingress[0].n_declared)-set(ingress[0].k_realized)
    assert "flow_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no flow log → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=True, cni_enforcing=True,
                                       flow_logging=True, default_deny=True)
    report = GCGAnalyzer().analyze(adapter, target_system="NetworkPolicy")
    ingress = [a for a in report.assertions if a.operation_family=="ingress_control"]
    assert len(ingress)==0, f"T-GCG-03 FAIL: {len(ingress)} gaps"
    print("T-GCG-03 PASS: full config → zero ingress_control gaps")

def test_nd_01_n_idempotent():
    a1,a2=NetworkPolicyEARAdapter(),NetworkPolicyEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_cni_in_ingress_n():
    adapter = NetworkPolicyEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="ingress_control")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "cni_enforcement" in layers and "network_policy" in layers
    print(f"T-ND-02 PASS: ingress layers={layers}")

def test_nd_03_strategy_documented():
    decl = NetworkPolicyEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_cni_absent():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=True, cni_enforcing=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="ingress_control")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no CNI enforcement → ABSENT (policy declared but unenforced)")

def test_ear_02_with_cni_crystallized():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=True, cni_enforcing=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="ingress_control")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: with CNI → CRYSTALLIZED (traffic controlled, not receipted per flow)")

def test_ear_03_no_active_family():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=True, cni_enforcing=True,
                                      flow_logging=True, default_deny=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no NetworkPolicy family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = NetworkPolicyEARAdapter(network_policy_declared=True, cni_enforcing=True,
                                      flow_logging=True, default_deny=True)
    report = GCGAnalyzer().analyze(adapter, target_system="NetworkPolicy")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Default K8s = all-allow. Policy+CNI required for any segmentation governance.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_policy_absent,test_gcg_02_no_flow_log_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_cni_in_ingress_n,test_nd_03_strategy_documented,
           test_ear_01_no_cni_absent,test_ear_02_with_cni_crystallized,
           test_ear_03_no_active_family]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (NetworkPolicy)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
