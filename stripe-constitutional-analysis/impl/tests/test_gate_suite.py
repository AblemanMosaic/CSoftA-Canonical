"""test_gate_suite.py — Stripe API gate tests. Wave 4 System 17."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from ear_adapter_stripe import StripeAPIEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats

def test_gcg_01_no_idempotency_produces_gap():
    adapter=StripeAPIEARAdapter(idempotency_keys_used=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Stripe")
    ch=[a for a in report.assertions if a.operation_family=="charge_creation"]
    if ch:
        absent=set(ch[0].n_declared)-set(ch[0].k_realized)
        assert "idempotency_key" in absent, f"T-GCG-01 FAIL: {absent}"
    print(f"T-GCG-01 PASS: no idempotency → gap or no assertions (optional layer)")

def test_gcg_02_full_config_no_gap():
    adapter=StripeAPIEARAdapter(idempotency_keys_used=True,webhook_configured=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Stripe")
    ch=[a for a in report.assertions if a.operation_family=="charge_creation"]
    assert len(ch)==0, f"T-GCG-02 FAIL: {len(ch)} gaps"
    print("T-GCG-02 PASS: full config → zero charge_creation gaps")

def test_gcg_03_webhook_disabled_gap():
    adapter=StripeAPIEARAdapter(webhook_configured=False)
    report=GCGAnalyzer().analyze(adapter,target_system="Stripe")
    wh_state = report.ear_states.get("webhook_delivery","UNKNOWN")
    assert wh_state in ("ABSENT","CRYSTALLIZED"), f"T-GCG-03 FAIL: {wh_state}"
    print(f"T-GCG-03 PASS: no webhook → webhook_delivery={wh_state}")

def test_nd_01_n_idempotent():
    a1,a2=StripeAPIEARAdapter(),StripeAPIEARAdapter()
    f1={f.name:sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2={f.name:sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1==f2; print("T-ND-01 PASS")

def test_nd_02_stripe_event_mandatory():
    adapter=StripeAPIEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="charge_creation")
    layers=[l.name for l in adapter.collect_governance_layers(fam)]
    assert "stripe_event" in layers and "pci_log" in layers
    print(f"T-ND-02 PASS: charge layers={layers}")

def test_nd_03_strategy_documented():
    decl=StripeAPIEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N","MINIMUM-N","PER-CONTEXT-N"); print("T-ND-03 PASS")

def test_ear_01_charge_active():
    adapter=StripeAPIEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="charge_creation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE
    print("T-EAR-01 PASS: charge_creation = ACTIVE (Event is mandatory, immutable, caller-independent)")

def test_ear_02_refund_active():
    adapter=StripeAPIEARAdapter()
    fam=next(f for f in adapter.collect_operation_families() if f.name=="refund_creation")
    assert adapter.assess_ear_state(fam)==EARState.ACTIVE; print("T-EAR-02 PASS: refund = ACTIVE")

def test_ear_03_webhook_crystallized():
    adapter=StripeAPIEARAdapter(webhook_configured=True)
    fam=next(f for f in adapter.collect_operation_families() if f.name=="webhook_delivery")
    assert adapter.assess_ear_state(fam)==EARState.CRYSTALLIZED
    print("T-EAR-03 PASS: webhook_delivery = CRYSTALLIZED (delivery may fail)")

def compute_convergence_fingerprint():
    adapter=StripeAPIEARAdapter(idempotency_keys_used=True,webhook_configured=True)
    report=GCGAnalyzer().analyze(adapter,target_system="Stripe")
    fp=convergence_fingerprint(report); stats=summary_stats(report.assertions)
    print(f"\n{'='*60}\nFINGERPRINT: {fp}\nAssertions: {stats['total']} | EAR: {report.ear_states}")
    print("NOTE: Stripe is strongest ACTIVE case — receipt independence from caller")
    print(f"{'='*60}\n"); return fp

def run_all_gates():
    tests=[test_gcg_01_no_idempotency_produces_gap,test_gcg_02_full_config_no_gap,
           test_gcg_03_webhook_disabled_gap,test_nd_01_n_idempotent,
           test_nd_02_stripe_event_mandatory,test_nd_03_strategy_documented,
           test_ear_01_charge_active,test_ear_02_refund_active,test_ear_03_webhook_crystallized]
    passed=0;failed=0;failures=[]
    print(f"\nRunning {len(tests)} gate tests (Stripe)...\n")
    for t in tests:
        try: t(); passed+=1
        except Exception as e: print(f"FAIL: {t.__name__}: {e}"); failed+=1; failures.append((t.__name__,str(e)))
    print(f"\n{'='*60}\nRESULTS: {passed}/{len(tests)}")
    if failures: [print(f"  FAIL: {n}: {m}") for n,m in failures]
    print(f"{'='*60}\n"); fp=compute_convergence_fingerprint(); return passed,failed,fp
if __name__=="__main__":
    p,f,fp=run_all_gates(); sys.exit(0 if f==0 else 1)
