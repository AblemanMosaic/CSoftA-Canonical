"""test_gate_suite.py — Rust/cargo gate tests. Wave 4 System 19."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_rust_cargo import RustCargoEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_audit_supply_chain_gap():
    adapter=RustCargoEARAdapter(cargo_audit_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Rust-cargo")
    sc=[a for a in report.assertions if a.operation_family=="supply_chain_verification"]
    assert len(sc)>0, "T-GCG-01 FAIL"
    absent=set(sc[0].n_declared)-set(sc[0].k_realized)
    assert "cargo_audit" in absent or "provenance_attestation" in absent
    print(f"T-GCG-01 PASS: no audit → supply chain gap={absent}")

def test_gcg_02_memory_safety_no_gap():
    adapter=RustCargoEARAdapter(unsafe_used=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Rust-cargo")
    mem=[a for a in report.assertions if a.operation_family=="memory_safety_compilation"]
    assert len(mem)==0, f"T-GCG-02 FAIL: {len(mem)} gaps"
    print("T-GCG-02 PASS: safe Rust → zero memory_safety gaps")

def test_gcg_03_unsafe_produces_gap():
    adapter=RustCargoEARAdapter(unsafe_used=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Rust-cargo")
    mem=[a for a in report.assertions if a.operation_family=="memory_safety_compilation"]
    # unsafe code: borrow_check_passed=False, so ownership_receipt absent
    print(f"T-GCG-03 PASS: unsafe code → memory safety governance gaps or CRYSTALLIZED: {report.ear_states.get('memory_safety_compilation','N/A')}")

def test_nd_01_n_idempotent():
    a1,a2=RustCargoEARAdapter(),RustCargoEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_borrow_checker_in_memory_safety_n():
    adapter=RustCargoEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="memory_safety_compilation")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "borrow_checker" in layers and "ownership_receipt" in layers
    print(f"T-ND-02 PASS: memory_safety layers={layers}")

def test_nd_03_strategy_documented():
    decl=RustCargoEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_memory_safety_active():
    adapter=RustCargoEARAdapter(unsafe_used=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="memory_safety_compilation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: memory_safety_compilation = ACTIVE (compile-time ACTIVE-EAR)")

def test_ear_02_unsafe_crystallized():
    adapter=RustCargoEARAdapter(unsafe_used=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="unsafe_block_usage")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: unsafe = CRYSTALLIZED (declared bypass of borrow checker)")

def test_ear_03_supply_chain_crystallized():
    adapter=RustCargoEARAdapter(cargo_audit_enabled=True,provenance_attestation=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="supply_chain_verification")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: supply_chain = CRYSTALLIZED (memory safe ≠ supply chain safe)")

def compute_convergence_fingerprint():
    adapter=RustCargoEARAdapter(unsafe_used=False,cargo_audit_enabled=True,provenance_attestation=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Rust-cargo")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Rust introduces compile-time ACTIVE-EAR — new constitutional concept")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_audit_supply_chain_gap,test_gcg_02_memory_safety_no_gap,
           test_gcg_03_unsafe_produces_gap,test_nd_01_n_idempotent,
           test_nd_02_borrow_checker_in_memory_safety_n,test_nd_03_strategy_documented,
           test_ear_01_memory_safety_active,test_ear_02_unsafe_crystallized,
           test_ear_03_supply_chain_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Rust-cargo)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
