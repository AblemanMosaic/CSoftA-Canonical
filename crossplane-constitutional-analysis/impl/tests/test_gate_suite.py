"""test_gate_suite.py — Crossplane gate tests. Wave 8 System 40."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_crossplane import CrossplaneEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_rbac_absent():
    adapter = CrossplaneEARAdapter(rbac_scoped=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Crossplane")
    assert all(v=="ABSENT" for v in report.ear_states.values())
    print("T-GCG-01 PASS: no RBAC → all ABSENT")

def test_gcg_02_no_audit_gap():
    adapter = CrossplaneEARAdapter(rbac_scoped=True, audit_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Crossplane")
    prov = [a for a in report.assertions if a.operation_family=="resource_provisioning"]
    assert len(prov)>0, "T-GCG-02 FAIL"
    absent = set(prov[0].n_declared)-set(prov[0].k_realized)
    assert "audit_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no audit log → gap={absent}")

def test_gcg_03_full_config_no_gap():
    adapter = CrossplaneEARAdapter(rbac_scoped=True, audit_log_enabled=True,
                                   credentials_scoped=True, drift_reconciliation=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Crossplane")
    prov = [a for a in report.assertions if a.operation_family=="resource_provisioning"]
    assert len(prov)==0, f"T-GCG-03 FAIL: {len(prov)} gaps"
    print("T-GCG-03 PASS: full config → zero resource_provisioning gaps")

def test_nd_01_n_idempotent():
    a1,a2=CrossplaneEARAdapter(),CrossplaneEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_drift_reconciliation_in_provision_n():
    adapter = CrossplaneEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name=="resource_provisioning")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    assert "drift_reconciliation" in layers and "rbac_check" in layers
    print(f"T-ND-02 PASS: provision layers={layers}")

def test_nd_03_strategy_documented():
    decl = CrossplaneEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_rbac_absent():
    adapter = CrossplaneEARAdapter(rbac_scoped=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="resource_provisioning")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT; print("T-EAR-01 PASS: no RBAC → ABSENT")

def test_ear_02_drift_reconciliation_active():
    adapter = CrossplaneEARAdapter(rbac_scoped=True, drift_reconciliation=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="drift_reconciliation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: drift_reconciliation = ACTIVE (closes Terraform T1684 state drift gap)")

def test_ear_03_resource_provisioning_crystallized():
    adapter = CrossplaneEARAdapter(rbac_scoped=True, drift_reconciliation=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name=="resource_provisioning")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: resource_provisioning = CRYSTALLIZED (provider creds gap remains)")

def compute_convergence_fingerprint():
    adapter = CrossplaneEARAdapter(rbac_scoped=True, audit_log_enabled=True,
                                   credentials_scoped=True, drift_reconciliation=True,
                                   composition_governed=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Crossplane")
    fp = convergence_fingerprint(report); stats = summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: drift_reconciliation ACTIVE closes Terraform T1684 state drift ABSENT gap")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_rbac_absent,test_gcg_02_no_audit_gap,
           test_gcg_03_full_config_no_gap,test_nd_01_n_idempotent,
           test_nd_02_drift_reconciliation_in_provision_n,test_nd_03_strategy_documented,
           test_ear_01_no_rbac_absent,test_ear_02_drift_reconciliation_active,
           test_ear_03_resource_provisioning_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Crossplane)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
