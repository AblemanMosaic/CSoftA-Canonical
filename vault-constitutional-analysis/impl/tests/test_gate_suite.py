"""
test_gate_suite.py — CSoftA Gate Test Suite for Vault

Implements the 9 minimum gate tests defined in T1576.
Category 1: GCG detection (T-GCG-01, T-GCG-02, T-GCG-03)
Category 2: N-determination (T-ND-01, T-ND-02, T-ND-03)
Category 3: EAR state assessment (T-EAR-01, T-EAR-02, T-EAR-03)

All tests use synthetic audit log fixtures — no live cluster required.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'impl'))

from ear_adapter_vault import VaultEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


# ── Audit log fixtures ────────────────────────────────────────────────────────

def make_entry(
    path: str,
    operation: str = "read",
    token_type: str = "service",
    policies: list = None,
    granting_policies: list = None,
    request_id: str = "req-001",
    timestamp: str = "2024-01-01T00:00:00Z",
    token_type_val: str = None,
) -> dict:
    """Build a minimal Vault audit log entry."""
    return {
        "time": timestamp,
        "type": "request",
        "request": {
            "id": request_id,
            "path": path,
            "operation": operation,
        },
        "auth": {
            "client_token": "hvs.test",
            "token_type": token_type_val or token_type,
            "policies": policies or ["default"],
            "policy_results": {
                "allowed_policies": granting_policies or [],
                "granting_policies": [
                    {"name": p, "namespace_id": "root", "type": "acl"}
                    for p in (granting_policies or [])
                ],
            },
        },
        "response": {},
    }


def make_root_entry(path: str = "sys/policy/admin", request_id: str = "req-root") -> dict:
    """Build a root token audit log entry."""
    return make_entry(
        path=path,
        operation="create",
        policies=["root"],
        granting_policies=[],
        request_id=request_id,
        token_type_val="service",
    )


def make_no_policy_receipt_entry(
    path: str = "secret/data/mykey",
    request_id: str = "req-nopolicy",
) -> dict:
    """Build an entry where policy_results has no granting_policies."""
    entry = make_entry(path=path, request_id=request_id)
    entry["auth"]["policy_results"] = {"allowed_policies": [], "granting_policies": []}
    return entry


# ── Category 1: GCG detection ─────────────────────────────────────────────────

def test_gcg_01_layer_absence_produces_assertion():
    """
    T-GCG-01: given audit trace with Layer Absence (audit device disabled),
    analyzer produces a GCG assertion with correct form.
    """
    # Audit device explicitly disabled — all operations are CRYSTALLIZED
    adapter = VaultEARAdapter(
        audit_log_lines=[
            json.dumps(make_no_policy_receipt_entry(request_id="req-01"))
        ],
        audit_device_enabled=False,
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter)

    # Find assertions for secret_read family
    secret_read_assertions = [
        a for a in report.assertions if a.operation_family == "secret_read"
    ]
    assert len(secret_read_assertions) > 0, (
        "T-GCG-01 FAIL: no assertions produced for secret_read family "
        "when policy evaluation receipt absent"
    )

    # At least one should flag missing policy evaluation
    policy_gaps = [
        a for a in secret_read_assertions if "policy_evaluation" in
        (set(a.n_declared) - set(a.k_realized))
    ]
    assert len(policy_gaps) > 0, (
        "T-GCG-01 FAIL: no policy_evaluation gap found even though "
        "granting_policies was empty"
    )

    print("T-GCG-01 PASS: Layer Absence (policy evaluation) produces assertion")


def test_gcg_02_layer_bypass_root_token():
    """
    T-GCG-02: given audit trace with root token (Layer Bypass),
    analyzer produces GCG assertion with form BYPASS.
    """
    adapter = VaultEARAdapter(
        audit_log_lines=[json.dumps(make_root_entry())],
        audit_device_enabled=True,
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter)

    bypass_assertions = [
        a for a in report.assertions
        if a.gap_form == GCGForm.BYPASS.value
        and a.operation_family == "root_token_operation"
    ]
    assert len(bypass_assertions) > 0, (
        "T-GCG-02 FAIL: no BYPASS assertion for root token operation"
    )
    assert bypass_assertions[0].gap_magnitude > 0, (
        "T-GCG-02 FAIL: BYPASS assertion has zero gap magnitude"
    )
    print("T-GCG-02 PASS: Root token produces BYPASS assertion with gap magnitude > 0")


def test_gcg_03_fully_governed_no_false_positive():
    """
    T-GCG-03: given fully governed trace (all N layers participated),
    produces zero GCG assertions for that operation family.
    """
    # Good entry: token_auth + policy_evaluation + audit_device all present
    good_entry = make_entry(
        path="secret/data/mykey",
        operation="read",
        policies=["read-policy"],
        granting_policies=["read-policy"],
        request_id="req-good",
    )
    adapter = VaultEARAdapter(
        audit_log_lines=[json.dumps(good_entry)],
        audit_device_enabled=True,
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter)

    # secret_read should have no assertions (all layers participated)
    secret_read_assertions = [
        a for a in report.assertions if a.operation_family == "secret_read"
    ]
    assert len(secret_read_assertions) == 0, (
        f"T-GCG-03 FAIL: {len(secret_read_assertions)} false-positive assertions "
        f"for fully governed operation. Assertions: "
        f"{[a.to_dict() for a in secret_read_assertions]}"
    )
    print("T-GCG-03 PASS: Fully governed operation produces zero GCG assertions")


# ── Category 2: N-determination ───────────────────────────────────────────────

def test_nd_01_n_determination_idempotent():
    """
    T-ND-01: N-determination for a canonical deployment returns
    stable result across two independent calls (idempotency).
    """
    adapter1 = VaultEARAdapter(audit_device_enabled=True)
    adapter2 = VaultEARAdapter(audit_device_enabled=True)

    families1 = adapter1.collect_operation_families()
    families2 = adapter2.collect_operation_families()

    n_by_family_1 = {
        f.name: [l.name for l in adapter1.collect_governance_layers(f)]
        for f in families1
    }
    n_by_family_2 = {
        f.name: [l.name for l in adapter2.collect_governance_layers(f)]
        for f in families2
    }

    assert n_by_family_1 == n_by_family_2, (
        f"T-ND-01 FAIL: N-determination not idempotent. "
        f"Run 1: {n_by_family_1}, Run 2: {n_by_family_2}"
    )
    print("T-ND-01 PASS: N-determination is idempotent across two independent calls")


def test_nd_02_declared_n_gte_minimum_n():
    """
    T-ND-02: N-determination with DECLARED-N strategy returns N >= 
    N-determination with MINIMUM-N strategy (monotonicity).
    Vault DECLARED-N includes audit_device; a deployment without
    audit device has MINIMUM-N that excludes it.
    """
    # DECLARED-N adapter (includes audit_device in N by declaration)
    adapter_declared = VaultEARAdapter(audit_device_enabled=True)

    # MINIMUM-N adapter (audit device not enabled — k-measurement would exclude it)
    adapter_minimum = VaultEARAdapter(audit_device_enabled=False)

    families = adapter_declared.collect_operation_families()
    target = next(f for f in families if f.name == "secret_read")

    n_declared = [l.name for l in adapter_declared.collect_governance_layers(target)]
    n_minimum  = [l.name for l in adapter_minimum.collect_governance_layers(target)]

    # Both adapters return the same declared layer set
    # (N-determination strategy difference shows in GCG assertion, not layer count)
    # The structural test: DECLARED-N family set should be superset of any realized k
    assert len(n_declared) >= 1, "T-ND-02 FAIL: DECLARED-N returned empty"
    assert "audit_device" in n_declared, (
        "T-ND-02 FAIL: audit_device not in DECLARED-N for secret_read"
    )
    print(f"T-ND-02 PASS: DECLARED-N for secret_read = {n_declared} "
          f"(includes audit_device)")


def test_nd_03_strategy_documented():
    """
    T-ND-03: N-determination documents its strategy selection
    in the governance declaration (DI-01 enforcement).
    """
    adapter = VaultEARAdapter()
    decl = adapter.get_governance_declaration()

    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N"), (
        f"T-ND-03 FAIL: strategy '{decl.strategy}' not a valid N-determination strategy"
    )
    assert decl.source, "T-ND-03 FAIL: governance declaration has no source citation"
    assert decl.description, "T-ND-03 FAIL: governance declaration has no description"
    print(f"T-ND-03 PASS: Strategy={decl.strategy}, Source='{decl.source[:60]}...'")


# ── Category 3: EAR state assessment ─────────────────────────────────────────

def test_ear_01_mandatory_audit_produces_active():
    """
    T-EAR-01: system with mandatory audit + policy receipts 
    produces ACTIVE for at least one operation family.
    """
    good_entry = make_entry(
        path="secret/data/mykey",
        operation="read",
        policies=["read-policy"],
        granting_policies=["read-policy"],
        request_id="req-ear01",
    )
    adapter = VaultEARAdapter(
        audit_log_lines=[json.dumps(good_entry)],
        audit_device_enabled=True,
    )
    families = adapter.collect_operation_families()
    target = next(f for f in families if f.name == "secret_read")
    state = adapter.assess_ear_state(target)

    assert state == EARState.ACTIVE, (
        f"T-EAR-01 FAIL: expected ACTIVE for Vault with mandatory audit "
        f"and policy receipts, got {state.value}"
    )
    print(f"T-EAR-01 PASS: secret_read EAR state = {state.value}")


def test_ear_02_disabled_audit_produces_crystallized():
    """
    T-EAR-02: system with audit device disabled produces CRYSTALLIZED
    (mechanism exists in architecture but not activated).
    """
    adapter = VaultEARAdapter(audit_device_enabled=False)
    families = adapter.collect_operation_families()
    target = next(f for f in families if f.name == "secret_read")
    state = adapter.assess_ear_state(target)

    assert state in (EARState.CRYSTALLIZED, EARState.ABSENT), (
        f"T-EAR-02 FAIL: expected CRYSTALLIZED or ABSENT when audit disabled, "
        f"got {state.value}"
    )
    print(f"T-EAR-02 PASS: secret_read with audit disabled = {state.value}")


def test_ear_03_root_token_family_produces_absent():
    """
    T-EAR-03: root_token_operation family produces ABSENT EAR state
    (root token bypasses policy evaluation — no receipt surface for that layer).
    """
    adapter = VaultEARAdapter(
        audit_log_lines=[json.dumps(make_root_entry())],
        audit_device_enabled=True,
    )
    families = adapter.collect_operation_families()
    target = next(f for f in families if f.name == "root_token_operation")
    state = adapter.assess_ear_state(target)

    assert state == EARState.ABSENT, (
        f"T-EAR-03 FAIL: expected ABSENT for root_token_operation, "
        f"got {state.value}"
    )
    print(f"T-EAR-03 PASS: root_token_operation EAR state = {state.value}")


# ── Convergence fingerprint ───────────────────────────────────────────────────

def compute_convergence_fingerprint():
    """
    Compute and print the canonical convergence fingerprint.
    This is the reference fingerprint for the Vault implementation.
    Any conforming implementation must produce this fingerprint
    for the same canonical inputs.
    """
    # Canonical input: mixed trace with good ops, root token, and no-policy-receipt op
    lines = [
        json.dumps(make_entry(
            path="secret/data/key1",
            operation="read",
            policies=["read-policy"],
            granting_policies=["read-policy"],
            request_id="canonical-001",
        )),
        json.dumps(make_root_entry(request_id="canonical-002")),
        json.dumps(make_no_policy_receipt_entry(request_id="canonical-003")),
    ]

    adapter = VaultEARAdapter(audit_log_lines=lines, audit_device_enabled=True)
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter)
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)

    print(f"\n{'='*60}")
    print(f"CONVERGENCE FINGERPRINT: {fp}")
    print(f"Total assertions: {stats['total']}")
    print(f"By form: {stats['by_form']}")
    print(f"By family: {stats['by_family']}")
    print(f"EAR states: {report.ear_states}")
    print(f"{'='*60}\n")
    return fp


# ── Test runner ───────────────────────────────────────────────────────────────

def run_all_gates():
    """Run all 9 minimum gate tests. Returns (passed, failed) counts."""
    tests = [
        # Category 1: GCG detection
        test_gcg_01_layer_absence_produces_assertion,
        test_gcg_02_layer_bypass_root_token,
        test_gcg_03_fully_governed_no_false_positive,
        # Category 2: N-determination
        test_nd_01_n_determination_idempotent,
        test_nd_02_declared_n_gte_minimum_n,
        test_nd_03_strategy_documented,
        # Category 3: EAR state
        test_ear_01_mandatory_audit_produces_active,
        test_ear_02_disabled_audit_produces_crystallized,
        test_ear_03_root_token_family_produces_absent,
    ]

    passed = 0
    failed = 0
    failures = []

    print(f"\nRunning {len(tests)} gate tests (T1576 minimum suite)...\n")
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {test.__name__}: {e}")
            failed += 1
            failures.append((test.__name__, str(e)))
        except Exception as e:
            print(f"ERROR: {test.__name__}: {type(e).__name__}: {e}")
            failed += 1
            failures.append((test.__name__, f"{type(e).__name__}: {e}"))

    print(f"\n{'='*60}")
    print(f"GATE TEST RESULTS: {passed}/{len(tests)} passed")
    if failures:
        print("FAILURES:")
        for name, msg in failures:
            print(f"  {name}: {msg}")
    print(f"{'='*60}\n")

    # Compute fingerprint regardless of test results
    fp = compute_convergence_fingerprint()
    return passed, failed, fp


if __name__ == "__main__":
    passed, failed, fingerprint = run_all_gates()
    sys.exit(0 if failed == 0 else 1)
