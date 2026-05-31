"""test_gate_suite.py — Packer gate tests. Wave 7 System 31."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_packer import PackerEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_provenance_gap():
    adapter = PackerEARAdapter(provenance_attested=False, image_signed=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Packer")
    build = [a for a in report.assertions if a.operation_family=="image_build"]
    assert len(build)>0, "T-GCG-01 FAIL"
    absent = set(build[0].n_declared)-set(build[0].k_realized)
    assert "provenance_attestation" in absent or "image_signing" in absent
    print(f"T-GCG-01 PASS: no provenance/signing → gap={absent}")

def test_gcg_02_full_config_no_gap():
    adapter = PackerEARAdapter(image_signed=True, provenance_attested=True,
                               sbom_generated=True, registry_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Packer")
    build = [a for a in report.assertions if a.operation_family=="image_build"]
    assert len(build)==0, f"T-GCG-02 FAIL: {len(build)} gaps"
    print("T-GCG-02 PASS: full config → zero image_build gaps")

def test_gcg_03_sbom_gap_without_generation():
    adapter = PackerEARAdapter(sbom_generated=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Packer")
    sbom = [a for a in report.assertions if a.operation_family=="sbom_generation"]
    assert len(sbom)>0, "T-GCG-03 FAIL"
    print(f"T-GCG-03 PASS: no SBOM → sbom_generation gap")

def test_nd_01_n_idempotent():
    a1,a2=PackerEARAdapter(),PackerEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_provenance_in_build_n():
    adapter = PackerEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="image_build")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "provenance_attestation" in layers and "image_signing" in layers
    print(f"T-ND-02 PASS: image_build layers={layers}")

def test_nd_03_strategy_documented():
    decl = PackerEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_active_family():
    adapter = PackerEARAdapter(image_signed=True, provenance_attested=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f)==EARState.ACTIVE]
    assert len(active)==0, f"T-EAR-01 FAIL: {active}"
    print("T-EAR-01 PASS: no Packer family reaches ACTIVE (provenance opt-in)")

def test_ear_02_all_crystallized():
    adapter = PackerEARAdapter(image_signed=True, provenance_attested=True)
    states = {f.name: adapter.assess_ear_state(f) for f in adapter.collect_operation_families()}
    assert all(v==EARState.CRYSTALLIZED for v in states.values())
    print(f"T-EAR-02 PASS: all Packer families CRYSTALLIZED")

def test_ear_03_no_signing_still_crystallized():
    adapter = PackerEARAdapter(image_signed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="image_build")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: unsigned build = CRYSTALLIZED (log exists; provenance absent)")

def compute_convergence_fingerprint():
    adapter = PackerEARAdapter(image_signed=True, provenance_attested=True,
                               sbom_generated=True, registry_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Packer")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Image build provenance is ABSENT by default — supply chain gap at artifact level")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_provenance_gap,test_gcg_02_full_config_no_gap,
           test_gcg_03_sbom_gap_without_generation,test_nd_01_n_idempotent,
           test_nd_02_provenance_in_build_n,test_nd_03_strategy_documented,
           test_ear_01_no_active_family,test_ear_02_all_crystallized,
           test_ear_03_no_signing_still_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Packer)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
