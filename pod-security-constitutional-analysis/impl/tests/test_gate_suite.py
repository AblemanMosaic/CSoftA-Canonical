"""test_gate_suite.py — Pod Security Admission gate tests. Wave 10 System 50."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_pod_security import PodSecurityEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_namespace_label_absent():
    adapter = PodSecurityEARAdapter(enforce_mode=True, all_namespaces_labeled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Pod-Security")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no namespace labels → all ABSENT (default K8s = all pods admitted)")

def test_gcg_02_audit_only_crystallized():
    adapter = PodSecurityEARAdapter(enforce_mode=False, audit_mode=True,
                                     all_namespaces_labeled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Pod-Security")
    admit = [a for a in report.assertions if a.operation_family=="pod_admission"]
    state = report.ear_states.get("pod_admission","UNKNOWN")
    assert state == "CRYSTALLIZED", f"T-GCG-02 FAIL: {state}"
    print("T-GCG-02 PASS: audit-only → CRYSTALLIZED (violations logged, pods admitted)")

def test_gcg_03_enforce_no_gap():
    adapter = PodSecurityEARAdapter(enforce_mode=True, audit_mode=True,
                                     warn_mode=True, all_namespaces_labeled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Pod-Security")
    admit = [a for a in report.assertions if a.operation_family=="pod_admission"]
    assert len(admit)==0, f"T-GCG-03 FAIL: {len(admit)} gaps"
    print("T-GCG-03 PASS: enforce mode → zero pod_admission gaps")

def test_nd_01_n_idempotent():
    a1,a2=PodSecurityEARAdapter(),PodSecurityEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_psa_enforce_in_admit_n():
    adapter = PodSecurityEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pod_admission")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "psa_enforce" in layers and "namespace_label" in layers
    print(f"T-ND-02 PASS: admission layers={layers}")

def test_nd_03_strategy_documented():
    decl = PodSecurityEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_enforce_mode_active():
    adapter = PodSecurityEARAdapter(enforce_mode=True, all_namespaces_labeled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pod_admission")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: enforce mode = ACTIVE (violating pods cannot be created)")

def test_ear_02_no_labels_absent():
    adapter = PodSecurityEARAdapter(all_namespaces_labeled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pod_admission")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-02 PASS: no namespace labels → ABSENT (default K8s)")

def test_ear_03_audit_only_crystallized():
    adapter = PodSecurityEARAdapter(enforce_mode=False, audit_mode=True,
                                     all_namespaces_labeled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="pod_admission")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: audit-only → CRYSTALLIZED")

def compute_convergence_fingerprint():
    adapter = PodSecurityEARAdapter(enforce_mode=True, audit_mode=True,
                                     warn_mode=True, all_namespaces_labeled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Pod-Security")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: PSA enforce ACTIVE prevents container escape vectors (privileged/hostPath/hostNetwork)")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_namespace_label_absent,test_gcg_02_audit_only_crystallized,
           test_gcg_03_enforce_no_gap,test_nd_01_n_idempotent,
           test_nd_02_psa_enforce_in_admit_n,test_nd_03_strategy_documented,
           test_ear_01_enforce_mode_active,test_ear_02_no_labels_absent,
           test_ear_03_audit_only_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Pod Security)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
