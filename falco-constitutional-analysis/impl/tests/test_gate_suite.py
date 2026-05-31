"""test_gate_suite.py — Falco gate tests. Wave 5 System 25."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_falco import FalcoEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_rule_version_produces_gap():
    adapter=FalcoEARAdapter(kernel_module_loaded=True, rule_version_tracked=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Falco")
    det=[a for a in report.assertions if a.operation_family=="syscall_detection"]
    assert len(det)>0, "T-GCG-01 FAIL"
    absent=set(det[0].n_declared)-set(det[0].k_realized)
    assert "rule_version" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no rule version → gap={absent}")

def test_gcg_02_full_config_minimal_gap():
    adapter=FalcoEARAdapter(kernel_module_loaded=True,rule_version_tracked=True,
                            alert_delivery_verified=True,rule_hash_monitored=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Falco")
    det=[a for a in report.assertions if a.operation_family=="syscall_detection"]
    assert len(det)==0, f"T-GCG-02 FAIL: {len(det)} gaps"
    print("T-GCG-02 PASS: full config → zero detection gaps")

def test_gcg_03_meta_governance_finding():
    """Alert generation is not constitutive of the detected event — CRYSTALLIZED."""
    adapter=FalcoEARAdapter(kernel_module_loaded=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="syscall_detection")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-GCG-03 PASS: syscall_detection = CRYSTALLIZED — alert follows event, does not govern it")

def test_nd_01_n_idempotent():
    a1,a2=FalcoEARAdapter(),FalcoEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_syscall_capture_in_detection_n():
    adapter=FalcoEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="syscall_detection")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "syscall_capture" in layers and "rule_match" in layers
    print(f"T-ND-02 PASS: detection layers={layers}")

def test_nd_03_strategy_documented():
    decl=FalcoEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_kernel_module_absent():
    adapter=FalcoEARAdapter(kernel_module_loaded=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="syscall_detection")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no kernel → ABSENT")

def test_ear_02_kernel_load_active():
    adapter=FalcoEARAdapter(kernel_module_loaded=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="kernel_module_load")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: kernel_module_load = ACTIVE (constitutive of monitoring availability)")

def test_ear_03_detection_crystallized():
    adapter=FalcoEARAdapter(kernel_module_loaded=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="syscall_detection")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: detection = CRYSTALLIZED (event occurs before alert)")

def compute_convergence_fingerprint():
    adapter=FalcoEARAdapter(kernel_module_loaded=True,rule_version_tracked=True,
                            alert_delivery_verified=True,rule_hash_monitored=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Falco")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Falco is meta-governance case 2 — governance tech with CRYSTALLIZED own governance.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_rule_version_produces_gap,test_gcg_02_full_config_minimal_gap,
           test_gcg_03_meta_governance_finding,test_nd_01_n_idempotent,
           test_nd_02_syscall_capture_in_detection_n,test_nd_03_strategy_documented,
           test_ear_01_no_kernel_module_absent,test_ear_02_kernel_load_active,
           test_ear_03_detection_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Falco)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
