"""test_gate_suite.py — Cosign gate tests. Wave 8 System 39."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_cosign import CosignEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_verify_absent():
    adapter = CosignEARAdapter(signature_verified=False, policy_enforced=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="image_verification")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-GCG-01 PASS: no verification → image_verification=ABSENT (supply chain gap open)")

def test_gcg_02_no_rekor_gap():
    adapter = CosignEARAdapter(signature_verified=True, rekor_logged=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Cosign")
    verify = [a for a in report.assertions if a.operation_family=="image_verification"]
    assert len(verify)>0, "T-GCG-02 FAIL"
    absent = set(verify[0].n_declared)-set(verify[0].k_realized)
    assert "rekor_transparency" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no Rekor → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = CosignEARAdapter(signature_verified=True, policy_enforced=True,
                               rekor_logged=True, oidc_signing=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Cosign")
    verify = [a for a in report.assertions if a.operation_family=="image_verification"]
    assert len(verify)==0, f"T-GCG-03 FAIL: {len(verify)} gaps"
    print("T-GCG-03 PASS: full config → zero image_verification gaps")

def test_nd_01_n_idempotent():
    a1,a2=CosignEARAdapter(),CosignEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_rekor_in_verify_n():
    adapter = CosignEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="image_verification")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "rekor_transparency" in layers and "signature_verification" in layers
    print(f"T-ND-02 PASS: verify layers={layers}")

def test_nd_03_strategy_documented():
    decl = CosignEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_policy_enforcement_active():
    adapter = CosignEARAdapter(signature_verified=True, policy_enforced=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="policy_enforcement")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: policy_enforcement = ACTIVE (unsigned images rejected at admission)")

def test_ear_02_signing_only_crystallized():
    adapter = CosignEARAdapter(signature_verified=True, policy_enforced=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="image_signing")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: image_signing without enforcement = CRYSTALLIZED")

def test_ear_03_no_verify_absent():
    adapter = CosignEARAdapter(signature_verified=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="image_verification")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-03 PASS: without verification = ABSENT (unsigned images admitted)")

def compute_convergence_fingerprint():
    adapter = CosignEARAdapter(signature_verified=True, policy_enforced=True,
                               rekor_logged=True, oidc_signing=True,
                               sbom_attested=True, provenance_attested=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Cosign")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: policy_enforcement is ACTIVE — closes Packer/Helm/GHA supply chain gaps")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_verify_absent,test_gcg_02_no_rekor_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_rekor_in_verify_n,test_nd_03_strategy_documented,
           test_ear_01_policy_enforcement_active,test_ear_02_signing_only_crystallized,
           test_ear_03_no_verify_absent]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Cosign)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
