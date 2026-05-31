"""test_gate_suite.py — OpenTelemetry gate tests. Wave 4 System 18."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_opentelemetry import OpenTelemetryEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_drop_log_produces_gap():
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="OpenTelemetry")
    proc=[a for a in report.assertions if a.operation_family=="telemetry_processing"]
    assert len(proc)>0, "T-GCG-01 FAIL"
    absent=set(proc[0].n_declared)-set(proc[0].k_realized)
    assert "drop_log" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no drop log → gap={absent}")

def test_gcg_02_full_config_minimal_gap():
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=True,exporter_acks_enabled=True,config_hash_tracking=True)
    report=GCGAnalyzer().analyze(adapter,target_system="OpenTelemetry")
    proc=[a for a in report.assertions if a.operation_family=="telemetry_processing"]
    assert len(proc)==0, f"T-GCG-02 FAIL: {len(proc)} gaps"
    print("T-GCG-02 PASS: full config → zero processing gaps")

def test_gcg_03_meta_governance_finding():
    """The system governing governance data has governance gaps in its own operation."""
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=False,exporter_acks_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="OpenTelemetry")
    total_gaps=len(report.assertions)
    assert total_gaps>0, "T-GCG-03 FAIL: expected governance gaps in governance pipeline"
    print(f"T-GCG-03 PASS: meta-governance finding confirmed — {total_gaps} gaps in observability pipeline")

def test_nd_01_n_idempotent():
    a1,a2=OpenTelemetryEARAdapter(),OpenTelemetryEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_pipeline_config_in_all_n():
    adapter=OpenTelemetryEARAdapter()
    for fam in adapter.collect_operation_families():
        layers=[l.name for l in adapter.collect_governance_layers(fam)]
        assert "pipeline_config" in layers, f"T-ND-02 FAIL: {fam.name} missing pipeline_config"
    print("T-ND-02 PASS: pipeline_config in N for all families")

def test_nd_03_strategy_documented():
    decl=OpenTelemetryEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_active_family():
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=True,exporter_acks_enabled=True)
    active=[f.name for f in adapter.collect_operation_families() if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-01 FAIL: {active}"
    print("T-EAR-01 PASS: no OTel family reaches ACTIVE — meta-governance gap confirmed")

def test_ear_02_all_families_crystallized():
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=True,exporter_acks_enabled=True)
    states={f.name: adapter.assess_ear_state(f) for f in adapter.collect_operation_families()}
    assert all(v==EARState.CRYSTALLIZED for v in states.values()), f"T-EAR-02 FAIL: {states}"
    print("T-EAR-02 PASS: all OTel families CRYSTALLIZED")

def test_ear_03_drop_constitutes_governance_gap():
    """Silent span drops = governance absence with no record — STRUCTURAL_NONLOCALITY."""
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="OpenTelemetry")
    drop_gaps=[a for a in report.assertions if "drop_log" in set(a.n_declared)-set(a.k_realized)]
    assert len(drop_gaps)>0, "T-EAR-03 FAIL"
    print(f"T-EAR-03 PASS: {len(drop_gaps)} families with drop_log gap — STRUCTURAL_NONLOCALITY")

def compute_convergence_fingerprint():
    adapter=OpenTelemetryEARAdapter(drop_logging_enabled=True,exporter_acks_enabled=True,config_hash_tracking=True)
    report=GCGAnalyzer().analyze(adapter,target_system="OpenTelemetry")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: OTel is meta-governance case — governance data pipeline has governance gaps")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_drop_log_produces_gap,test_gcg_02_full_config_minimal_gap,
           test_gcg_03_meta_governance_finding,test_nd_01_n_idempotent,
           test_nd_02_pipeline_config_in_all_n,test_nd_03_strategy_documented,
           test_ear_01_no_active_family,test_ear_02_all_families_crystallized,
           test_ear_03_drop_constitutes_governance_gap]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (OpenTelemetry)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
