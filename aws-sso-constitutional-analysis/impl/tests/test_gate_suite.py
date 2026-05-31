"""test_gate_suite.py — AWS SSO gate tests. Wave 7 System 33."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_aws_sso import AWSSSOEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_cloudtrail_absent():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-SSO")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no CloudTrail → all ABSENT")

def test_gcg_02_no_mfa_gap():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=True, mfa_required=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-SSO")
    login = [a for a in report.assertions if a.operation_family=="federated_login"]
    assert len(login)>0, "T-GCG-02 FAIL"
    absent = set(login[0].n_declared)-set(login[0].k_realized)
    assert "mfa_context" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no MFA → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=True, mfa_required=True,
                               permission_set_reviewed=True, idp_synced=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-SSO")
    login = [a for a in report.assertions if a.operation_family=="federated_login"]
    assert len(login)==0, f"T-GCG-03 FAIL: {len(login)} gaps"
    print("T-GCG-03 PASS: full config → zero federated_login gaps")

def test_nd_01_n_idempotent():
    a1,a2=AWSSSOEARAdapter(),AWSSSOEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_permission_set_in_login_n():
    adapter = AWSSSOEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="federated_login")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "permission_set" in layers and "cloudtrail_event" in layers
    print(f"T-ND-02 PASS: federated_login layers={layers}")

def test_nd_03_strategy_documented():
    decl = AWSSSOEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_cloudtrail_absent():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="federated_login")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no CT → ABSENT")

def test_ear_02_session_credential_active():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="session_credential_issuance")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: session_credential_issuance = ACTIVE (temp creds + CloudTrail)")

def test_ear_03_federated_login_crystallized():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="federated_login")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: federated_login = CRYSTALLIZED (IdP compromise propagates)")

def compute_convergence_fingerprint():
    adapter = AWSSSOEARAdapter(cloudtrail_enabled=True, mfa_required=True,
                               permission_set_reviewed=True, idp_synced=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-SSO")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: IdP compromise propagates to all federated accounts — upstream governance T1613")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_cloudtrail_absent,test_gcg_02_no_mfa_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_permission_set_in_login_n,test_nd_03_strategy_documented,
           test_ear_01_no_cloudtrail_absent,test_ear_02_session_credential_active,
           test_ear_03_federated_login_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (AWS SSO)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
