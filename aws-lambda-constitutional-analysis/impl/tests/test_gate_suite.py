"""test_gate_suite.py — AWS-Lambda gate tests. Wave 15."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_aws_lambda import AWSLambdaEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = AWSLambdaEARAdapter(least_privilege_role=False, layer_pinned=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "layer_consumption")
    state = adapter.assess_ear_state(fam)
    assert state in (EARState.ABSENT, EARState.CRYSTALLIZED), f"unexpected: {state}"
    print("T-GCG-01 PASS: unpinned layer → layer_consumption CRYSTALLIZED (ABSENT provenance)")


def test_gcg_02():
    adapter = AWSLambdaEARAdapter(least_privilege_role=False, layer_pinned=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-Lambda")
    items = [a for a in report.assertions if a.operation_family == "layer_consumption"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "layer_governance" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no layer governance → gap={absent}")


def test_gcg_03():
    adapter = AWSLambdaEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "aws_api_call")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-GCG-03 PASS: aws_api_call → ACTIVE (IAM always evaluated, T1629 carries)")


def test_nd_01():
    a1, a2 = AWSLambdaEARAdapter(), AWSLambdaEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = AWSLambdaEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "function_invocation")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["iam_invoke_policy", "least_privilege_role"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: layers={layers}")


def test_nd_03():
    decl = AWSLambdaEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = AWSLambdaEARAdapter(layer_pinned=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "layer_consumption")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-01 PASS: layer consumption → CRYSTALLIZED (IAM evaluated even without pin)")


def test_ear_02():
    adapter = AWSLambdaEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "aws_api_call")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-02 PASS: aws_api_call → ACTIVE (IAM execution role governs all API calls)")


def test_ear_03():
    adapter = AWSLambdaEARAdapter(least_privilege_role=True, cloudwatch_enabled=True, layer_pinned=True, secrets_manager=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "aws_api_call"); assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-03 PASS: aws_api_call ACTIVE confirms IAM T1629 carries to Lambda")


def compute_fingerprint():
    adapter = AWSLambdaEARAdapter(least_privilege_role=True, cloudwatch_enabled=True, layer_pinned=True, secrets_manager=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-Lambda")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: serverless execution model; layer supply chain ABSENT provenance; internal execution ABSENT; T1629 IAM ACTIVE carries; CVE-2025-55182 SSJI")
    print("=" * 60)
    return fp


def run_all_gates():
    tests = [
        test_gcg_01, test_gcg_02, test_gcg_03,
        test_nd_01, test_nd_02, test_nd_03,
        test_ear_01, test_ear_02, test_ear_03,
    ]
    passed = 0
    failed = 0
    failures = []
    print("Running " + str(len(tests)) + " gate tests (" + "AWS-Lambda" + ")...")
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print("FAIL: " + t.__name__ + ": " + str(e))
            failed += 1
            failures.append((t.__name__, str(e)))
    print("=" * 60)
    print("RESULTS: " + str(passed) + "/" + str(len(tests)))
    if failures:
        for n, m in failures:
            print("  FAIL: " + n + ": " + m)
    print("=" * 60)
    fp = compute_fingerprint()
    return passed, failed, fp


if __name__ == "__main__":
    p, f, fp = run_all_gates()
    sys.exit(0 if f == 0 else 1)
