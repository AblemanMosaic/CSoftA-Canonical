"""test_gate_suite.py — AWS-CodePipeline gate tests. Wave 16."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_aws_codepipeline import AWSCodePipelineEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = AWSCodePipelineEARAdapter(approval_gate=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "approval_gate")
    state = adapter.assess_ear_state(fam)
    assert state in (EARState.ABSENT, EARState.CRYSTALLIZED), f"unexpected: {state}"
    print("T-GCG-01 PASS: no approval gate → approval_gate not ACTIVE")


def test_gcg_02():
    adapter = AWSCodePipelineEARAdapter(artifact_encrypted=False)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-CodePipeline")
    items = [a for a in report.assertions if a.operation_family == "artifact_management"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "artifact_encryption" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: no KMS encryption → gap={absent}")


def test_gcg_03():
    adapter = AWSCodePipelineEARAdapter(approval_gate=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "approval_gate")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-GCG-03 PASS: approval gate configured → ACTIVE (deployment cannot proceed without human approval)")


def test_nd_01():
    a1, a2 = AWSCodePipelineEARAdapter(), AWSCodePipelineEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = AWSCodePipelineEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "pipeline_execution")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["iam_policy", "cloudtrail_log"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: layers={layers}")


def test_nd_03():
    decl = AWSCodePipelineEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = AWSCodePipelineEARAdapter(approval_gate=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "pipeline_execution")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-01 PASS: pipeline always CRYSTALLIZED (CloudTrail+IAM always present)")


def test_ear_02():
    adapter = AWSCodePipelineEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "pipeline_execution")
    assert adapter.assess_ear_state(fam) == EARState.CRYSTALLIZED
    print("T-EAR-02 PASS: CloudTrail + IAM → CRYSTALLIZED baseline")


def test_ear_03():
    adapter = AWSCodePipelineEARAdapter(approval_gate=True, artifact_encrypted=True, cross_account=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "approval_gate"); assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-03 PASS: approval_gate with configured gate → ACTIVE (most governed CI/CD in corpus)")


def compute_fingerprint():
    adapter = AWSCodePipelineEARAdapter(approval_gate=True, artifact_encrypted=True, cross_account=True)
    report = GCGAnalyzer().analyze(adapter, target_system="AWS-CodePipeline")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: completes CI/CD quintuple; CloudTrail T1737 + IAM T1629 carry; approval_gate ACTIVE; most governed CI/CD in corpus")
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
    print("Running " + str(len(tests)) + " gate tests (" + "AWS-CodePipeline" + ")...")
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
