"""test_gate_suite.py — Kafka gate tests. Wave 5 System 21."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_kafka import KafkaEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_acl_absent():
    adapter = KafkaEARAdapter(acl_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Kafka")
    prod = [a for a in report.assertions if a.operation_family=="produce"]
    assert len(prod)>0 or report.ear_states.get("produce")=="ABSENT"
    print(f"T-GCG-01 PASS: no ACL → produce={report.ear_states.get('produce')}")

def test_gcg_02_no_audit_log_gap():
    adapter = KafkaEARAdapter(acl_enabled=True, audit_log_enabled=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Kafka")
    prod = [a for a in report.assertions if a.operation_family=="produce"]
    assert len(prod)>0, "T-GCG-02 FAIL: no produce assertions"
    absent = set(prod[0].n_declared)-set(prod[0].k_realized)
    assert "audit_log" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no audit log → gap={absent}")

def test_gcg_03_full_config_minimal_gap():
    adapter = KafkaEARAdapter(acl_enabled=True, tls_required=True,
                              audit_log_enabled=True, sasl_enabled=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Kafka")
    prod = [a for a in report.assertions if a.operation_family=="produce"]
    assert len(prod)==0, f"T-GCG-03 FAIL: {len(prod)} gaps"
    print("T-GCG-03 PASS: full config → zero produce gaps")

def test_nd_01_n_idempotent():
    a1,a2=KafkaEARAdapter(),KafkaEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_acl_in_produce_n():
    adapter=KafkaEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="produce")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "acl_authorization" in layers and "audit_log" in layers
    print(f"T-ND-02 PASS: produce layers={layers}")

def test_nd_03_strategy_documented():
    decl=KafkaEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_no_acl_absent():
    adapter=KafkaEARAdapter(acl_enabled=False)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="produce")
    assert adapter.assess_ear_state(fam)==EARState.ABSENT
    print("T-EAR-01 PASS: no ACL → ABSENT (largest default governance gap in corpus)")

def test_ear_02_broker_auth_tls_active():
    adapter=KafkaEARAdapter(tls_required=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="broker_auth")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-02 PASS: broker_auth with mTLS = ACTIVE")

def test_ear_03_produce_crystallized_with_acl():
    adapter=KafkaEARAdapter(acl_enabled=True, audit_log_enabled=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="produce")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: produce with ACL+audit = CRYSTALLIZED (audit not constitutive)")

def compute_convergence_fingerprint():
    adapter=KafkaEARAdapter(acl_enabled=True, tls_required=True, audit_log_enabled=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Kafka")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Default Kafka = ABSENT for all data operations. Largest default gap in corpus.")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_acl_absent,test_gcg_02_no_audit_log_gap,
           test_gcg_03_full_config_minimal_gap,test_nd_01_n_idempotent,
           test_nd_02_acl_in_produce_n,test_nd_03_strategy_documented,
           test_ear_01_no_acl_absent,test_ear_02_broker_auth_tls_active,
           test_ear_03_produce_crystallized_with_acl]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Kafka)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
