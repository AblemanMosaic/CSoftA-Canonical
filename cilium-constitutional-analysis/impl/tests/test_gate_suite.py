"""test_gate_suite.py — Cilium gate tests."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ear_adapter_cilium import CiliumEARAdapter, EARState
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


def test_gcg_01():
    adapter = CiliumEARAdapter(tetragon_deployed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "syscall_enforcement")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-GCG-01 PASS: no Tetragon → syscall_enforcement ABSENT")


def test_gcg_02():
    adapter = CiliumEARAdapter(tetragon_deployed=True, enforcement_mode=False)
    report = GCGAnalyzer().analyze(adapter, target_system="Cilium")
    items = [a for a in report.assertions if a.operation_family == "syscall_enforcement"]
    assert len(items) > 0, "T-GCG-02 FAIL: no assertions"
    absent = set(items[0].n_declared) - set(items[0].k_realized)
    assert "lsm_hook" in absent, f"T-GCG-02 FAIL: {absent}"
    print(f"T-GCG-02 PASS: observe-only (no enforcement) → gap={absent}")


def test_gcg_03():
    adapter = CiliumEARAdapter(tetragon_deployed=True, enforcement_mode=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "syscall_enforcement")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-GCG-03 PASS: enforcement mode → ACTIVE (kernel-time enforcement)")


def test_nd_01():
    a1, a2 = CiliumEARAdapter(), CiliumEARAdapter()
    f1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in a1.collect_operation_families()}
    f2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in a2.collect_operation_families()}
    assert f1 == f2
    print("T-ND-01 PASS: N-determination idempotent")


def test_nd_02():
    adapter = CiliumEARAdapter()
    fam = next(f for f in adapter.collect_operation_families() if f.name == "syscall_enforcement")
    layers = [l.name for l in adapter.collect_governance_layers(fam)]
    for required in ["ebpf_enforcement", "lsm_hook"]:
        assert required in layers, f"T-ND-02 FAIL: {required} not in {layers}"
    print(f"T-ND-02 PASS: syscall layers={layers}")


def test_nd_03():
    decl = CiliumEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    print("T-ND-03 PASS: strategy documented")


def test_ear_01():
    adapter = CiliumEARAdapter(tetragon_deployed=False)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "syscall_enforcement")
    assert adapter.assess_ear_state(fam) == EARState.ABSENT
    print("T-EAR-01 PASS: no Tetragon → ABSENT")


def test_ear_02():
    adapter = CiliumEARAdapter(tetragon_deployed=True, enforcement_mode=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "syscall_enforcement")
    assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-02 PASS: enforcement → ACTIVE (new kernel-time concept)")


def test_ear_03():
    adapter = CiliumEARAdapter(tetragon_deployed=True, network_policy_enforced=True)
    fam = next(f for f in adapter.collect_operation_families() if f.name == "network_enforcement"); assert adapter.assess_ear_state(fam) == EARState.ACTIVE
    print("T-EAR-03 PASS: network_enforcement → ACTIVE via eBPF dataplane")


def compute_fingerprint():
    adapter = CiliumEARAdapter(tetragon_deployed=True, enforcement_mode=True, hubble_enabled=True, network_policy_enforced=True)
    report = GCGAnalyzer().analyze(adapter, target_system="Cilium")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print("=" * 60)
    print("FINGERPRINT: " + fp)
    print("Assertions: " + str(stats["total"]) + " | EAR: " + str(report.ear_states))
    print("NOTE: kernel-time enforcement ACTIVE — below container runtime; eliminates TOCTOU; extends T1640")
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
    print("Running " + str(len(tests)) + " gate tests (" + "Cilium" + ")...")
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
