"""test_gate_suite.py — Entra ID gate tests. Wave 11 System 53."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_entra_id import EntraIDEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_legacy_auth_absent():
    adapter = EntraIDEARAdapter(legacy_auth_blocked=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="legacy_authentication")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-GCG-01 PASS: legacy auth not blocked → ABSENT (CAP bypass route open)")

def test_gcg_02_modern_auth_active_with_cap_mfa():
    adapter = EntraIDEARAdapter(mfa_enforced=True, cap_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="modern_authentication")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-GCG-02 PASS: CAP + MFA → modern_authentication = ACTIVE")

def test_gcg_03_split_path_gap():
    adapter = EntraIDEARAdapter(mfa_enforced=True, cap_configured=True, legacy_auth_blocked=False)
    modern_state = adapter.assess_ear_state(
        next(f for f in adapter.collect_operation_families() if f.name=="modern_authentication"))
    legacy_state = adapter.assess_ear_state(
        next(f for f in adapter.collect_operation_families() if f.name=="legacy_authentication"))
    assert modern_state==EARState.ACTIVE and legacy_state==EARState.ABSENT
    print("T-GCG-03 PASS: split-path governance — modern=ACTIVE, legacy=ABSENT (new concept)")

def test_nd_01_n_idempotent():
    a1,a2=EntraIDEARAdapter(),EntraIDEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_cap_in_modern_auth_n():
    adapter = EntraIDEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="modern_authentication")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "conditional_access" in layers and "mfa_enforcement" in layers
    print(f"T-ND-02 PASS: modern auth layers={layers}")

def test_nd_03_strategy_documented():
    decl = EntraIDEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_modern_auth_active_with_cap():
    adapter = EntraIDEARAdapter(mfa_enforced=True, cap_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="modern_authentication")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: modern auth with CAP+MFA = ACTIVE")

def test_ear_02_legacy_auth_absent():
    adapter = EntraIDEARAdapter(legacy_auth_blocked=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="legacy_authentication")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-02 PASS: legacy auth unblocked = ABSENT (CAP bypass)")

def test_ear_03_legacy_blocked_crystallized():
    adapter = EntraIDEARAdapter(legacy_auth_blocked=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="legacy_authentication")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: legacy auth blocked = CRYSTALLIZED (bypass closed)")

def compute_convergence_fingerprint():
    adapter = EntraIDEARAdapter(mfa_enforced=True, legacy_auth_blocked=True,
                                 cap_configured=True, pim_enabled=True,
                                 sign_in_logs_exported=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Entra-ID")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: modern_auth ACTIVE; CVE-2025-55241 Actor token bypass ABSENT+no logs — worst case in corpus")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_legacy_auth_absent,test_gcg_02_modern_auth_active_with_cap_mfa,
           test_gcg_03_split_path_gap,test_nd_01_n_idempotent,
           test_nd_02_cap_in_modern_auth_n,test_nd_03_strategy_documented,
           test_ear_01_modern_auth_active_with_cap,test_ear_02_legacy_auth_absent,
           test_ear_03_legacy_blocked_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Entra ID)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
