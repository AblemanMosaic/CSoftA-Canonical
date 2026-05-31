"""
test_gate_suite.py — CSoftA Gate Test Suite for Keycloak
9 minimum gate tests (T1576).
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ear_adapter_keycloak import KeycloakEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_login_event(
    user_id="user-001", client_id="myclient",
    session_id="sess-001", error=None, event_id="ev-001"
) -> dict:
    return {
        "id": event_id, "time": 1700000000000,
        "type": "LOGIN" if not error else "LOGIN_ERROR",
        "realmId": "master", "clientId": client_id,
        "userId": user_id, "sessionId": session_id,
        "ipAddress": "127.0.0.1",
        "details": {"username": "alice"},
        **({"error": error} if error else {}),
    }


def make_token_event(
    event_type="CODE_TO_TOKEN", token_type="Bearer",
    session_id="sess-001", event_id="ev-token"
) -> dict:
    return {
        "id": event_id, "time": 1700000001000,
        "type": event_type,
        "realmId": "master", "clientId": "myclient",
        "userId": "user-001", "sessionId": session_id,
        "details": {"token_type": token_type},
    }


def make_introspect_event(event_id="ev-intro") -> dict:
    return {
        "id": event_id, "time": 1700000002000,
        "type": "TOKEN_INTROSPECT",
        "realmId": "master", "clientId": "myclient",
        "userId": "user-001", "sessionId": "sess-001",
        "details": {"token_type": "Bearer"},
    }


def make_admin_event(
    op_type="CREATE", resource="USER", event_id="adm-001"
) -> dict:
    return {
        "id": event_id, "time": 1700000003000,
        "operationType": op_type, "resourceType": resource,
        "realmId": "master",
        "authDetails": {"userId": "admin-001", "decision": "PERMIT"},
    }


# ── Category 1: GCG detection ─────────────────────────────────────────────────

def test_gcg_01_authz_services_absent_produces_gap():
    """
    T-GCG-01: authorization_decision with authz_services disabled
    produces GCG (authorization_services layer ABSENT).
    """
    adapter = KeycloakEARAdapter(
        authz_services_enabled=False,
        user_events_enabled=True,
        admin_events_enabled=True,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Keycloak")

    authz_assertions = [a for a in report.assertions
                        if a.operation_family == "authorization_decision"]
    assert len(authz_assertions) > 0, (
        "T-GCG-01 FAIL: no assertions for authorization_decision when authz disabled"
    )
    absent = set(authz_assertions[0].n_declared) - set(authz_assertions[0].k_realized)
    assert "authorization_services" in absent, (
        f"T-GCG-01 FAIL: authorization_services not in gap. absent={absent}"
    )
    print(f"T-GCG-01 PASS: authz disabled → gap includes authorization_services, "
          f"magnitude={authz_assertions[0].gap_magnitude}")


def test_gcg_02_user_events_disabled_produces_gap():
    """
    T-GCG-02: user_authentication with user events disabled
    produces gap for user_event_audit layer (Non-Activation).
    """
    adapter = KeycloakEARAdapter(
        user_events_enabled=False,
        admin_events_enabled=True,
        user_events=[make_login_event()],
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Keycloak")

    auth_assertions = [a for a in report.assertions
                       if a.operation_family == "user_authentication"]
    assert len(auth_assertions) > 0, (
        "T-GCG-02 FAIL: no assertions for user_authentication when events disabled"
    )
    absent = set(auth_assertions[0].n_declared) - set(auth_assertions[0].k_realized)
    assert "user_event_audit" in absent, (
        f"T-GCG-02 FAIL: user_event_audit not in gap. absent={absent}"
    )
    print(f"T-GCG-02 PASS: user events disabled → user_event_audit in gap")


def test_gcg_03_token_introspection_no_false_positive():
    """
    T-GCG-03: token_introspection with events enabled produces no GCG.
    token_introspection is Keycloak's ACTIVE-EAR operation — both
    declared layers participate.
    """
    adapter = KeycloakEARAdapter(
        user_events=[make_introspect_event()],
        user_events_enabled=True,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Keycloak")

    intro_assertions = [a for a in report.assertions
                        if a.operation_family == "token_introspection"]
    assert len(intro_assertions) == 0, (
        f"T-GCG-03 FAIL: {len(intro_assertions)} false-positive assertions "
        f"for token_introspection. "
        f"Gaps: {[(a.gap_form, sorted(set(a.n_declared)-set(a.k_realized))) for a in intro_assertions]}"
    )
    print("T-GCG-03 PASS: token_introspection with events → zero GCG assertions")


# ── Category 2: N-determination ───────────────────────────────────────────────

def test_nd_01_n_determination_idempotent():
    """T-ND-01: N-determination is stable."""
    a1 = KeycloakEARAdapter(); a2 = KeycloakEARAdapter()
    f1 = a1.collect_operation_families(); f2 = a2.collect_operation_families()
    n1 = {f.name: sorted([l.name for l in a1.collect_governance_layers(f)]) for f in f1}
    n2 = {f.name: sorted([l.name for l in a2.collect_governance_layers(f)]) for f in f2}
    assert n1 == n2, f"T-ND-01 FAIL"
    print(f"T-ND-01 PASS: N idempotent. "
          f"token_introspection N={n1.get('token_introspection')}")


def test_nd_02_token_introspection_n_equals_2():
    """
    T-ND-02: token_introspection has N=2 (token_validation + user_event_audit).
    This is the ACTIVE-EAR operation — smallest N, highest governance quality.
    """
    adapter = KeycloakEARAdapter()
    families = adapter.collect_operation_families()
    intro_fam = next(f for f in families if f.name == "token_introspection")
    layers = [l.name for l in adapter.collect_governance_layers(intro_fam)]
    assert len(layers) == 2, (
        f"T-ND-02 FAIL: expected N=2 for token_introspection, got {len(layers)}: {layers}"
    )
    assert "token_validation" in layers
    assert "user_event_audit" in layers
    print(f"T-ND-02 PASS: token_introspection N=2: {layers}")


def test_nd_03_strategy_documented():
    """T-ND-03: Strategy declared."""
    decl = KeycloakEARAdapter().get_governance_declaration()
    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N")
    assert "Keycloak" in decl.source or "OAuth" in decl.source
    print(f"T-ND-03 PASS: Strategy={decl.strategy}")


# ── Category 3: EAR state ─────────────────────────────────────────────────────

def test_ear_01_token_introspection_active():
    """
    T-EAR-01: token_introspection produces ACTIVE EAR state.
    This is Keycloak's unique contribution: the only Wave 1 operation
    family (besides Vault) that reaches ACTIVE-EAR.
    """
    adapter  = KeycloakEARAdapter(user_events_enabled=True)
    families = adapter.collect_operation_families()
    intro_fam = next(f for f in families if f.name == "token_introspection")
    state = adapter.assess_ear_state(intro_fam)
    assert state == EARState.ACTIVE, (
        f"T-EAR-01 FAIL: expected ACTIVE for token_introspection, got {state.value}"
    )
    print(f"T-EAR-01 PASS: token_introspection = {state.value}")


def test_ear_02_authz_disabled_produces_absent():
    """T-EAR-02: authorization_decision with authz disabled = ABSENT."""
    adapter  = KeycloakEARAdapter(authz_services_enabled=False)
    families = adapter.collect_operation_families()
    authz_fam = next(f for f in families if f.name == "authorization_decision")
    state = adapter.assess_ear_state(authz_fam)
    assert state == EARState.ABSENT, (
        f"T-EAR-02 FAIL: expected ABSENT for disabled authz, got {state.value}"
    )
    print(f"T-EAR-02 PASS: authorization_decision (disabled) = {state.value}")


def test_ear_03_authentication_crystallized():
    """T-EAR-03: user_authentication with events enabled = CRYSTALLIZED."""
    adapter  = KeycloakEARAdapter(user_events_enabled=True)
    families = adapter.collect_operation_families()
    auth_fam = next(f for f in families if f.name == "user_authentication")
    state = adapter.assess_ear_state(auth_fam)
    assert state == EARState.CRYSTALLIZED, (
        f"T-EAR-03 FAIL: expected CRYSTALLIZED for auth, got {state.value}"
    )
    print(f"T-EAR-03 PASS: user_authentication = {state.value}")


# ── Convergence fingerprint ───────────────────────────────────────────────────

def compute_convergence_fingerprint():
    """Canonical: default Keycloak (no authz services, events enabled)."""
    adapter = KeycloakEARAdapter(
        user_events=[make_login_event(), make_token_event(), make_introspect_event()],
        admin_events=[make_admin_event()],
        authz_services_enabled=False,
        user_events_enabled=True,
        admin_events_enabled=True,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="Keycloak")
    fp     = convergence_fingerprint(report)
    stats  = summary_stats(report.assertions)
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
        test_gcg_01_authz_services_absent_produces_gap,
        test_gcg_02_user_events_disabled_produces_gap,
        test_gcg_03_token_introspection_no_false_positive,
        test_nd_01_n_determination_idempotent,
        test_nd_02_token_introspection_n_equals_2,
        test_nd_03_strategy_documented,
        test_ear_01_token_introspection_active,
        test_ear_02_authz_disabled_produces_absent,
        test_ear_03_authentication_crystallized,
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
