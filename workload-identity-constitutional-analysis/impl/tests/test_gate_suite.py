"""test_gate_suite.py — Workload Identity gate tests. Wave 9 System 44."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_workload_identity import WorkloadIdentityEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_oidc_absent():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Workload-Identity")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no OIDC → all ABSENT (long-lived credentials required)")

def test_gcg_02_no_trust_scope_gap():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=True, trust_policy_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Workload-Identity")
    trust = [a for a in report.assertions if a.operation_family=="trust_policy_governance"]
    assert len(trust)>0, "T-GCG-02 FAIL: no trust_policy_governance assertions"
    absent = set(trust[0].n_declared)-set(trust[0].k_realized)
    assert "iam_trust_policy" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no trust scope → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=True, token_expiry_short=True,
                                          trust_policy_scoped=True, cloudtrail_enabled=True,
                                          audience_restricted=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Workload-Identity")
    exchange = [a for a in report.assertions if a.operation_family=="credential_exchange"]
    assert len(exchange)==0, f"T-GCG-03 FAIL: {len(exchange)} gaps"
    print("T-GCG-03 PASS: full config → zero credential_exchange gaps")

def test_nd_01_n_idempotent():
    a1,a2=WorkloadIdentityEARAdapter(),WorkloadIdentityEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_oidc_token_in_exchange_n():
    adapter = WorkloadIdentityEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="credential_exchange")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "oidc_token" in layers and "cloudtrail_event" in layers
    print(f"T-ND-02 PASS: exchange layers={layers}")

def test_nd_03_strategy_documented():
    decl = WorkloadIdentityEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_credential_exchange_active():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="credential_exchange")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: credential_exchange = ACTIVE (OIDC token constitutive of cloud creds)")

def test_ear_02_role_assumption_active():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="role_assumption")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: role_assumption = ACTIVE (AssumeRoleWithWebIdentity constitutive)")

def test_ear_03_no_oidc_absent():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="credential_exchange")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-03 PASS: no OIDC → ABSENT (must use long-lived credentials)")

def compute_convergence_fingerprint():
    adapter = WorkloadIdentityEARAdapter(oidc_configured=True, token_expiry_short=True,
                                          trust_policy_scoped=True, cloudtrail_enabled=True,
                                          audience_restricted=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Workload-Identity")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: ACTIVE credential_exchange closes T1731 (Crossplane), T1724 (Argo WF), T1671 (TF)")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_oidc_absent,test_gcg_02_no_trust_scope_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_oidc_token_in_exchange_n,test_nd_03_strategy_documented,
           test_ear_01_credential_exchange_active,test_ear_02_role_assumption_active,
           test_ear_03_no_oidc_absent]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Workload Identity)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
