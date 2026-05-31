"""
test_gate_suite.py — CSoftA Gate Test Suite for Docker

9 minimum gate tests (T1576):
Category 1: GCG detection
Category 2: N-determination
Category 3: EAR state assessment
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ear_adapter_docker import DockerEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_container(
    cid="abc123456789",
    name="test-container",
    image="ubuntu:22.04",
    privileged=False,
    seccomp=None,        # None = use default logic
    apparmor=None,       # None = use default logic
    caps_drop=None,
    caps_add=None,
    network="bridge",
    pid_mode="",
):
    """Build a minimal docker inspect object."""
    sec_opts = []
    if seccomp == "unconfined":
        sec_opts.append("seccomp=unconfined")
    elif seccomp and seccomp != "default":
        sec_opts.append(f"seccomp={seccomp}")
    if apparmor == "unconfined":
        sec_opts.append("apparmor=unconfined")
    elif apparmor and apparmor != "docker-default":
        sec_opts.append(f"apparmor={apparmor}")

    return [{
        "Id": cid,
        "Name": f"/{name}",
        "State": {"Running": True},
        "Config": {"Image": image, "User": ""},
        "HostConfig": {
            "Privileged": privileged,
            "SecurityOpt": sec_opts if sec_opts else None,
            "CapDrop": caps_drop or ["NET_RAW", "SYS_CHROOT"],
            "CapAdd": caps_add or [],
            "NetworkMode": network,
            "PidMode": pid_mode,
            "IpcMode": "private",
            "ReadonlyRootfs": False,
            "Resources": {},
        },
    }]


PRIVILEGED_CONTAINER = make_container(
    cid="priv111111111", name="privileged-test",
    privileged=True,
)

STANDARD_CONTAINER = make_container(
    cid="std222222222", name="standard-test",
    privileged=False,
)

HOST_NETWORK_CONTAINER = make_container(
    cid="hostnet333333", name="hostnet-test",
    privileged=False,
    network="host",
)

UNCONFINED_SECCOMP = make_container(
    cid="unconf444444", name="unconfined-seccomp",
    privileged=False,
    seccomp="unconfined",
)


# ── Category 1: GCG detection ─────────────────────────────────────────────────

def test_gcg_01_privileged_produces_bypass_assertion():
    """
    T-GCG-01: --privileged container produces BYPASS assertion.
    GCG codex canonical case (PCM-0333-136 T-D.1).
    """
    adapter = DockerEARAdapter(inspect_data=PRIVILEGED_CONTAINER)
    report  = GCGAnalyzer().analyze(adapter, target_system="Docker")

    bypass_assertions = [
        a for a in report.assertions
        if a.gap_form == GCGForm.BYPASS.value
        and a.operation_family == "container_run_privileged"
    ]
    assert len(bypass_assertions) > 0, (
        "T-GCG-01 FAIL: no BYPASS assertion for --privileged container"
    )
    # seccomp, apparmor, capabilities should be in the gap
    gap_layers = set(bypass_assertions[0].n_declared) - set(bypass_assertions[0].k_realized)
    assert "seccomp" in gap_layers or "apparmor" in gap_layers, (
        f"T-GCG-01 FAIL: seccomp/apparmor not in gap for --privileged. "
        f"Gap: {gap_layers}"
    )
    assert bypass_assertions[0].gap_magnitude >= 2, (
        f"T-GCG-01 FAIL: gap magnitude {bypass_assertions[0].gap_magnitude} < 2"
    )
    print(f"T-GCG-01 PASS: --privileged produces BYPASS, "
          f"magnitude={bypass_assertions[0].gap_magnitude}, "
          f"absent={sorted(gap_layers)}")


def test_gcg_02_unconfined_seccomp_produces_assertion():
    """
    T-GCG-02: Container with seccomp=unconfined produces GCG assertion.
    seccomp layer is declared applicable but explicitly disabled.
    """
    adapter = DockerEARAdapter(inspect_data=UNCONFINED_SECCOMP)
    report  = GCGAnalyzer().analyze(adapter, target_system="Docker")

    seccomp_gaps = [
        a for a in report.assertions
        if "seccomp" in (set(a.n_declared) - set(a.k_realized))
        and a.operation_family == "container_run_standard"
    ]
    assert len(seccomp_gaps) > 0, (
        "T-GCG-02 FAIL: no assertion for seccomp=unconfined container"
    )
    print(f"T-GCG-02 PASS: seccomp=unconfined produces assertion, "
          f"form={seccomp_gaps[0].gap_form}")


def test_gcg_03_standard_container_no_false_positive():
    """
    T-GCG-03: Standard container with all default layers active
    produces no GCG assertions for the standard family.
    """
    adapter = DockerEARAdapter(inspect_data=STANDARD_CONTAINER)
    report  = GCGAnalyzer().analyze(adapter, target_system="Docker")

    standard_assertions = [
        a for a in report.assertions
        if a.operation_family == "container_run_standard"
    ]
    assert len(standard_assertions) == 0, (
        f"T-GCG-03 FAIL: {len(standard_assertions)} false-positive assertions "
        f"for standard container with all layers active. "
        f"Gaps: {[(a.gap_form, sorted(set(a.n_declared)-set(a.k_realized))) for a in standard_assertions]}"
    )
    print("T-GCG-03 PASS: standard container with defaults = zero assertions")


# ── Category 2: N-determination ───────────────────────────────────────────────

def test_nd_01_n_determination_idempotent():
    """T-ND-01: N-determination is stable."""
    a1 = DockerEARAdapter(); a2 = DockerEARAdapter()
    f1 = a1.collect_operation_families()
    f2 = a2.collect_operation_families()
    n1 = {f.name: [l.name for l in a1.collect_governance_layers(f)] for f in f1}
    n2 = {f.name: [l.name for l in a2.collect_governance_layers(f)] for f in f2}
    assert n1 == n2, f"T-ND-01 FAIL: {n1} != {n2}"
    print(f"T-ND-01 PASS: N idempotent. standard N={n1.get('container_run_standard')}")


def test_nd_02_privileged_n_same_as_standard():
    """
    T-ND-02: N(O) for container_run_privileged equals N(O) for standard.
    The GCG claim is that --privileged bypasses layers that ARE declared.
    N must be the same; k differs.
    """
    adapter = DockerEARAdapter()
    families = adapter.collect_operation_families()
    std  = next(f for f in families if f.name == "container_run_standard")
    priv = next(f for f in families if f.name == "container_run_privileged")
    n_std  = sorted([l.name for l in adapter.collect_governance_layers(std)])
    n_priv = sorted([l.name for l in adapter.collect_governance_layers(priv)])
    assert n_std == n_priv, (
        f"T-ND-02 FAIL: standard N={n_std} != privileged N={n_priv}. "
        "The bypass claim requires same declared N."
    )
    print(f"T-ND-02 PASS: standard and privileged share N={n_std}")


def test_nd_03_strategy_documented():
    """T-ND-03: N-determination strategy declared."""
    decl = DockerEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    assert decl.source
    assert "CIS" in decl.source or "Docker" in decl.source
    print(f"T-ND-03 PASS: Strategy={decl.strategy}")


# ── Category 3: EAR state assessment ─────────────────────────────────────────

def test_ear_01_standard_container_crystallized():
    """
    T-EAR-01: standard container run produces CRYSTALLIZED EAR state.
    Boundary governance exists (seccomp etc.) but no per-operation receipt.
    """
    adapter  = DockerEARAdapter()
    families = adapter.collect_operation_families()
    std      = next(f for f in families if f.name == "container_run_standard")
    state    = adapter.assess_ear_state(std)
    assert state == EARState.CRYSTALLIZED, (
        f"T-EAR-01 FAIL: expected CRYSTALLIZED for standard container, got {state.value}"
    )
    print(f"T-EAR-01 PASS: container_run_standard = {state.value}")


def test_ear_02_privileged_container_absent():
    """T-EAR-02: --privileged produces ABSENT (bypasses governance layers)."""
    adapter  = DockerEARAdapter()
    families = adapter.collect_operation_families()
    priv     = next(f for f in families if f.name == "container_run_privileged")
    state    = adapter.assess_ear_state(priv)
    assert state == EARState.ABSENT, (
        f"T-EAR-02 FAIL: expected ABSENT for --privileged, got {state.value}"
    )
    print(f"T-EAR-02 PASS: container_run_privileged = {state.value}")


def test_ear_03_interior_execution_absent():
    """T-EAR-03: container interior execution produces ABSENT."""
    adapter  = DockerEARAdapter()
    families = adapter.collect_operation_families()
    interior = next(f for f in families if f.name == "container_interior_execution")
    state    = adapter.assess_ear_state(interior)
    assert state == EARState.ABSENT, (
        f"T-EAR-03 FAIL: expected ABSENT for interior execution, got {state.value}"
    )
    print(f"T-EAR-03 PASS: container_interior_execution = {state.value}")


# ── Convergence fingerprint ───────────────────────────────────────────────────

def compute_convergence_fingerprint():
    # Canonical: one standard + one privileged + one unconfined-seccomp
    canonical_data = (
        STANDARD_CONTAINER +
        PRIVILEGED_CONTAINER +
        UNCONFINED_SECCOMP
    )
    adapter = DockerEARAdapter(inspect_data=canonical_data, audit_log_enabled=False)
    report  = GCGAnalyzer().analyze(adapter, target_system="Docker")
    fp      = convergence_fingerprint(report)
    stats   = summary_stats(report.assertions)
    print(f"\n{'='*60}")
    print(f"CONVERGENCE FINGERPRINT: {fp}")
    print(f"Total assertions: {stats['total']}")
    print(f"By form: {stats['by_form']}")
    print(f"By family: {stats['by_family']}")
    print(f"EAR states: {report.ear_states}")
    print(f"{'='*60}\n")
    return fp


def run_all_gates():
    tests = [
        test_gcg_01_privileged_produces_bypass_assertion,
        test_gcg_02_unconfined_seccomp_produces_assertion,
        test_gcg_03_standard_container_no_false_positive,
        test_nd_01_n_determination_idempotent,
        test_nd_02_privileged_n_same_as_standard,
        test_nd_03_strategy_documented,
        test_ear_01_standard_container_crystallized,
        test_ear_02_privileged_container_absent,
        test_ear_03_interior_execution_absent,
    ]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests...\n")
    for test in tests:
        try:
            test(); passed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}"); failed += 1
            failures.append((test.__name__, str(e)))
        except Exception as e:
            print(f"ERROR: {test.__name__}: {type(e).__name__}: {e}"); failed += 1
            failures.append((test.__name__, str(e)))

    print(f"\n{'='*60}")
    print(f"GATE TEST RESULTS: {passed}/{len(tests)} passed")
    if failures:
        for name, msg in failures:
            print(f"  FAIL: {name}: {msg}")
    print(f"{'='*60}\n")
    fp = compute_convergence_fingerprint()
    return passed, failed, fp


if __name__ == "__main__":
    passed, failed, fp = run_all_gates()
    sys.exit(0 if failed == 0 else 1)
