"""test_gate_suite.py — Teleport gate tests. Wave 3 System 14."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_teleport import TeleportEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_recording_no_audit_absent():
    adapter=TeleportEARAdapter(recording_mode="off",audit_log_enabled=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Teleport")
    # All families should be ABSENT or all gap assertions should exist
    states = report.ear_states
    all_absent = all(v=="ABSENT" for v in states.values())
    has_gaps = len(report.assertions) > 0
    assert all_absent or has_gaps, f"T-GCG-01 FAIL: expected ABSENT or gaps, got states={states}"
    print(f"T-GCG-01 PASS: no recording/audit → states={states} assertions={len(report.assertions)}")

def test_gcg_02_strict_recording_no_gap():
    adapter=TeleportEARAdapter(recording_mode="strict",audit_log_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Teleport")
    se=[a for a in report.assertions if a.operation_family=="session_establishment"]
    assert len(se)==0, f"T-GCG-02 FAIL: {len(se)} gaps"
    print("T-GCG-02 PASS: strict recording → zero session_establishment gaps")

def test_gcg_03_cert_issuance_no_gap():
    adapter=TeleportEARAdapter(audit_log_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Teleport")
    ci=[a for a in report.assertions if a.operation_family=="certificate_issuance"]
    assert len(ci)==0, f"T-GCG-03 FAIL: {len(ci)} gaps"
    print("T-GCG-03 PASS: cert_issuance fully governed → zero gaps")

def test_nd_01_n_idempotent():
    a1,a2=TeleportEARAdapter(),TeleportEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_session_recording_in_n():
    adapter=TeleportEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="session_establishment")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "session_recording" in layers; print(f"T-ND-02 PASS: session layers={layers}")

def test_nd_03_strategy_documented():
    decl=TeleportEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_strict_session_active():
    adapter=TeleportEARAdapter(recording_mode="strict",audit_log_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="session_establishment")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE; print("T-EAR-01 PASS: strict session = ACTIVE")

def test_ear_02_cert_issuance_active():
    adapter=TeleportEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="certificate_issuance")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE; print("T-EAR-02 PASS: cert_issuance = ACTIVE")

def test_ear_03_best_effort_crystallized():
    adapter=TeleportEARAdapter(recording_mode="best_effort",audit_log_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="session_establishment")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: best_effort recording = CRYSTALLIZED (not ACTIVE)")

def compute_convergence_fingerprint():
    adapter=TeleportEARAdapter(recording_mode="strict",audit_log_enabled=True,mfa_required=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Teleport")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Teleport is Wave 3 strongest governance — two ACTIVE families")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_recording_no_audit_absent,test_gcg_02_strict_recording_no_gap,
           test_gcg_03_cert_issuance_no_gap,test_nd_01_n_idempotent,test_nd_02_session_recording_in_n,
           test_nd_03_strategy_documented,test_ear_01_strict_session_active,
           test_ear_02_cert_issuance_active,test_ear_03_best_effort_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Teleport)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); import sys; sys.exit(0 if f==0 else 1)
