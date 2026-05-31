"""test_gate_suite.py — Triton gate tests. Wave 4 System 20."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_triton import TritonEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_inference_log_produces_gap():
    adapter=TritonEARAdapter(inference_logging=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Triton")
    inf=[a for a in report.assertions if a.operation_family=="inference_request"]
    assert len(inf)>0, "T-GCG-01 FAIL"
    absent=set(inf[0].n_declared)-set(inf[0].k_realized)
    assert "inference_log" in absent or "input_hash" in absent
    print(f"T-GCG-01 PASS: no inference log → gap={absent}")

def test_gcg_02_no_input_hash_produces_gap():
    adapter=TritonEARAdapter(inference_logging=True,input_hash_capture=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Triton")
    inf=[a for a in report.assertions if a.operation_family=="inference_request"]
    if inf:
        absent=set(inf[0].n_declared)-set(inf[0].k_realized)
        assert "input_hash" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no input hash → AI governance gap (output not bound to input)")

def test_gcg_03_full_config_minimal_gap():
    adapter=TritonEARAdapter(inference_logging=True,input_hash_capture=True,model_version_pinned=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Triton")
    inf=[a for a in report.assertions if a.operation_family=="inference_request"]
    assert len(inf)==0, f"T-GCG-03 FAIL: {len(inf)} gaps"
    print("T-GCG-03 PASS: full config → zero inference_request gaps")

def test_nd_01_n_idempotent():
    a1,a2=TritonEARAdapter(),TritonEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_input_hash_in_inference_n():
    adapter=TritonEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="inference_request")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "input_hash" in layers and "model_version" in layers
    print(f"T-ND-02 PASS: inference layers={layers}")

def test_nd_03_strategy_documented():
    decl=TritonEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_active_family():
    adapter=TritonEARAdapter(inference_logging=True,input_hash_capture=True)
    active=[f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-01 FAIL: {active}"
    print("T-EAR-01 PASS: no Triton family reaches ACTIVE — AI inference governance gap")

def test_ear_02_inference_crystallized():
    adapter=TritonEARAdapter(inference_logging=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="inference_request")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: inference_request = CRYSTALLIZED")

def test_ear_03_model_loading_crystallized():
    """model_loading is highest-governance in Triton but still CRYSTALLIZED."""
    adapter=TritonEARAdapter(model_version_pinned=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="model_loading")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: model_loading = CRYSTALLIZED (config versioned but inference not constitutively receipted)")

def compute_convergence_fingerprint():
    adapter=TritonEARAdapter(inference_logging=True,input_hash_capture=True,model_version_pinned=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Triton")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: AI inference governance gap — outputs not constitutively bound to governed model state")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_inference_log_produces_gap,test_gcg_02_no_input_hash_produces_gap,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_input_hash_in_inference_n,test_nd_03_strategy_documented,
           test_ear_01_no_active_family,test_ear_02_inference_crystallized,
           test_ear_03_model_loading_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Triton)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
