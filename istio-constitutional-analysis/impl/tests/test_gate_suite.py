"""test_gate_suite.py — Istio gate tests. Wave 2 System 9."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_istio import IstioEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_sidecar_bypass():
    adapter = IstioEARAdapter(sidecar_injection_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Istio")
    assert all(v == "ABSENT" for v in report.ear_states.values()),         f"T-GCG-01 FAIL: {report.ear_states}"
    print("T-GCG-01 PASS: no sidecar → all ABSENT (BYPASS — Istio governance fully absent)")

def test_gcg_02_no_access_log_produces_gap():
    adapter = IstioEARAdapter(access_log_enabled=False, sidecar_injection_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Istio")
    authz = [a for a in report.assertions if a.operation_family == "request_authorization"]
    assert len(authz) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(authz[0].n_declared) - set(authz[0].k_realized)
    assert "envoy_access_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no access log → gap={absent}")

def test_gcg_03_full_config_minimal_gap():
    adapter = IstioEARAdapter(access_log_enabled=True, mtls_strict=True,
                              sidecar_injection_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Istio")
    authz = [a for a in report.assertions if a.operation_family == "request_authorization"]
    assert len(authz) == 0, f"T-GCG-03 FAIL: {len(authz)} gaps"
    print("T-GCG-03 PASS: full config → zero request_authorization gaps")

def test_nd_01_n_idempotent():
    a1, a2 = IstioEARAdapter(), IstioEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2; print("T-ND-01 PASS: N idempotent")

def test_nd_02_substrate_dependency_in_sidecar_family():
    adapter = IstioEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "sidecar_injection")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "injection_webhook" in layers
    print(f"T-ND-02 PASS: sidecar_injection has webhook layer={layers}")

def test_nd_03_strategy_documented():
    decl = IstioEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print(f"T-ND-03 PASS: strategy={decl.strategy}")

def test_ear_01_no_sidecar_absent():
    adapter = IstioEARAdapter(sidecar_injection_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "request_authorization")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no sidecar → ABSENT")

def test_ear_02_sidecar_crystallized():
    adapter = IstioEARAdapter(sidecar_injection_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "request_authorization")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: sidecar present → CRYSTALLIZED")

def test_ear_03_no_active_any_family():
    adapter = IstioEARAdapter(access_log_enabled=True, mtls_strict=True, sidecar_injection_enabled=True)
    active = [f.name for f in adapter.collect_operation_families()
              if adapter.assess_ear_state(f) == EARState.ACTIVE]
    assert len(active) == 0, f"T-EAR-03 FAIL: {active}"
    print("T-EAR-03 PASS: no Istio family reaches ACTIVE")

def compute_convergence_fingerprint():
    adapter = IstioEARAdapter(access_log_enabled=True, mtls_strict=True, sidecar_injection_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Istio")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nCONVERGENCE FINGERPRINT: {fp}")
    print(f"Assertions: {stats['total']} | Forms: {stats['by_form']} | EAR: {report.ear_states}")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests = [test_gcg_01_no_sidecar_bypass, test_gcg_02_no_access_log_produces_gap,
             test_gcg_03_full_config_minimal_gap, test_nd_01_n_idempotent,
             test_nd_02_substrate_dependency_in_sidecar_family, test_nd_03_strategy_documented,
             test_ear_01_no_sidecar_absent, test_ear_02_sidecar_crystallized,
             test_ear_03_no_active_any_family]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests (Istio)...\n")
    for t in tests:
        try: t(); passed += 1
        except AssertionError as e: print(f"FAIL: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
        except Exception as e: print(f"ERROR: {t.__name__}: {e}"); failed += 1; failures.append((t.__name__, str(e)))
    print(f"\n{'='*60}\nGATE RESULTS: {passed}/{len(tests)} passed")
    if failures: [print(f"  FAIL: {n}: {m}") for n, m in failures]
    print(f"{'='*60}\n"); fp = compute_convergence_fingerprint(); return passed, failed, fp

if __name__ == "__main__":
    passed, failed, fp = run_all_gates(); sys.exit(0 if failed == 0 else 1)
