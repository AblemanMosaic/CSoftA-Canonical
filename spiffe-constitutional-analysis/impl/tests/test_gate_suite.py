"""test_gate_suite.py — SPIFFE/SPIRE gate tests. Wave 2 System 10."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_spiffe import SPIFFEEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_attestation_plugin_produces_gap():
    adapter = SPIFFEEARAdapter(attestation_plugin="")
    report = GCGAnalyzer().analyze(adapter, target_system="SPIFFE")
    svid = [a for a in report.assertions if a.operation_family == "svid_issuance"]
    assert len(svid) > 0, "T-GCG-01 FAIL: no assertions"
    absent = set(svid[0].n_declared) - set(svid[0].k_realized)
    assert "workload_attestation" in absent or "svid_receipt" in absent,         f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no attestation → gap={absent}")

def test_gcg_02_full_attestation_no_gap():
    adapter = SPIFFEEARAdapter(attestation_plugin="k8s_psat")
    report = GCGAnalyzer().analyze(adapter, target_system="SPIFFE")
    svid = [a for a in report.assertions if a.operation_family == "svid_issuance"]
    assert len(svid) == 0, f"T-GCG-02 FAIL: {len(svid)} gaps"
    print("T-GCG-02 PASS: full attestation → zero svid_issuance gaps")

def test_gcg_03_short_ttl_enforcement():
    """Short TTL SVIDs force re-attestation — a governance property."""
    adapter = SPIFFEEARAdapter(attestation_plugin="k8s_psat", svid_ttl_seconds=3600)
    report = GCGAnalyzer().analyze(adapter, target_system="SPIFFE")
    svid_fam = next(f for f in adapter.collect_operation_families() if f.name == "svid_issuance")
    state = adapter.assess_ear_state(svid_fam)
    assert state == EARState.ACTIVE, f"T-GCG-03 FAIL: expected ACTIVE got {state}"
    print(f"T-GCG-03 PASS: svid_issuance with attestation = {state.value} (Wave 2 ACTIVE-EAR case)")

def test_nd_01_n_idempotent():
    a1, a2 = SPIFFEEARAdapter(), SPIFFEEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2; print("T-ND-01 PASS: N idempotent")

def test_nd_02_svid_issuance_n_correct():
    adapter = SPIFFEEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "svid_issuance")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "workload_attestation" in layers
    assert "svid_receipt" in layers
    print(f"T-ND-02 PASS: svid_issuance layers={layers}")

def test_nd_03_strategy_documented():
    decl = SPIFFEEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    assert "SPIFFE" in decl.source or "SPIRE" in decl.source
    print(f"T-ND-03 PASS: strategy={decl.strategy}")

def test_ear_01_svid_issuance_active():
    """SPIFFE svid_issuance is ACTIVE-EAR — Wave 2 analog of Vault."""
    adapter = SPIFFEEARAdapter(attestation_plugin="k8s_psat")
    fam = next(f for f in adapter.collect_operation_families() if f.name == "svid_issuance")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE,         "T-EAR-01 FAIL: svid_issuance must be ACTIVE"
    print("T-EAR-01 PASS: svid_issuance = ACTIVE (workload attestation is constitutive)")

def test_ear_02_svid_rotation_active():
    """SVID rotation also ACTIVE — re-attestation is constitutive."""
    adapter = SPIFFEEARAdapter(attestation_plugin="k8s_psat")
    fam = next(f for f in adapter.collect_operation_families() if f.name == "svid_rotation")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-02 PASS: svid_rotation = ACTIVE")

def test_ear_03_admin_ops_crystallized():
    """Administrative operations are CRYSTALLIZED — audit log is opt-in."""
    adapter = SPIFFEEARAdapter(attestation_plugin="k8s_psat")
    fam = next(f for f in adapter.collect_operation_families() if f.name == "workload_registration")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: workload_registration = CRYSTALLIZED (audit log opt-in)")

def compute_convergence_fingerprint():
    adapter = SPIFFEEARAdapter(attestation_plugin="k8s_psat", svid_ttl_seconds=3600)
    report = GCGAnalyzer().analyze(adapter, target_system="SPIFFE")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nCONVERGENCE FINGERPRINT: {fp}")
    print(f"Assertions: {stats['total']} | Forms: {stats['by_form']} | EAR: {report.ear_states}")
    print(f"NOTE: svid_issuance ACTIVE — Wave 2 strongest governance, analog of Vault.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests = [test_gcg_01_no_attestation_plugin_produces_gap, test_gcg_02_full_attestation_no_gap,
             test_gcg_03_short_ttl_enforcement, test_nd_01_n_idempotent,
             test_nd_02_svid_issuance_n_correct, test_nd_03_strategy_documented,
             test_ear_01_svid_issuance_active, test_ear_02_svid_rotation_active,
             test_ear_03_admin_ops_crystallized]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests (SPIFFE/SPIRE)...\n")
    for t in tests:
        try: t(); passed += 1
        except AssertionError as e: print(f"FAIL: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
        except Exception as e: print(f"ERROR: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
    print(f"\n{'='*60}\nGATE RESULTS: {passed}/{len(tests)} passed")
    if failures: [print(f"  FAIL: {n}: {m}") for n, m in failures]
    print(f"{'='*60}\n"); fp = compute_convergence_fingerprint(); return passed, failed, fp

if __name__ == "__main__":
    passed, failed, fp = run_all_gates(); sys.exit(0 if failed == 0 else 1)
