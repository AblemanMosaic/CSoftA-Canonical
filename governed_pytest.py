#!/usr/bin/env python3
"""
governed_pytest.py
==================
A minimal governance wrapper for the CSoftA gate test suite.

WHAT THIS SCRIPT DOES
---------------------
Runs all 80 EAR adapter gate test suites, verifies each system's convergence
fingerprint against the known reference values recorded when the analysis was
authored, and emits a JSON receipt to .csofta_receipts/ documenting the session
outcome.

WHY THIS EXISTS (the governance rationale)
------------------------------------------
CSoftA analyses a core question: is governance constitutive of an operation
completing, or merely parallel to it? A system that logs what happened
after the fact is CRYSTALLIZED. A system where the operation cannot succeed
without producing a verifiable receipt is ACTIVE.

This script applies that same question to the test suite itself.

Running `pytest` tells you that tests passed. That is useful but CRYSTALLIZED:
the test outcome is recorded in terminal output that may not be preserved, is
not tied to a specific analysis version, and cannot be independently verified
without re-running the suite.

This script produces an ACTIVE-adjacent outcome: a structured receipt file
that ties each system's test result to its convergence fingerprint — a
content-addressed hash of the adapter's full analysis output. The fingerprint
is deterministic: two independent runs of the same adapter on the same code
produce the same fingerprint. If an analysis changes (intentionally or not),
the fingerprint changes, the receipt records a MISMATCH, and the deviation is
visible in version control.

This is not a full governance framework. It is the minimum useful receipt
infrastructure for a corpus whose subject matter is governance receipts.

CONVERGENCE FINGERPRINTS (what they are and why they matter)
-------------------------------------------------------------
Each EAR adapter analysis produces a convergence fingerprint via
`gap_assertions.convergence_fingerprint(report)`. The fingerprint is a
SHA-256 hash of the analysis's structural properties:

    - EAR states per operation family (ACTIVE / CRYSTALLIZED / ABSENT)
    - N(O) declared governance layers per family
    - Gap forms and gap patterns per family
    - Total gap count and form distribution

The fingerprint deliberately EXCLUDES timestamps, request IDs, and
instance-specific evidence text. Two conforming implementations that
classify the same system identically will produce the same fingerprint.
A changed classification — even a single family shifting from CRYSTALLIZED
to ABSENT — produces a different fingerprint. This property is defined in
the corpus as T1576 (convergence fingerprint invariant).

The KNOWN_FINGERPRINTS table below is the reference. These values were
recorded from the gate record log when each analysis was authored and
verified. They are the ground truth against which this script checks.

HOW TO READ THE RECEIPT
-----------------------
The receipt is written to .csofta_receipts/receipt_<timestamp>.json.
Each entry has:

    system      — system name (matches the systems/ directory)
    tests_run   — number of gate tests executed
    tests_passed — number that passed
    fingerprint  — fingerprint computed in this session
    expected     — known reference fingerprint
    status       — PASS, MISMATCH, or ERROR

PASS: tests passed and fingerprint matches reference.
     This is the expected outcome for an unchanged analysis.

MISMATCH: tests passed but fingerprint differs from reference.
     This means the analysis classification changed. Inspect the diff.
     This is not necessarily wrong — it may be an intentional update —
     but it requires a conscious decision to update the reference table.

ERROR: test suite failed to load or tests failed.
     The system's analysis needs investigation.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import hashlib
import datetime
import pathlib
from typing import NamedTuple

# ── SECTION 1: REFERENCE FINGERPRINTS ────────────────────────────────────────
#
# These are the canonical convergence fingerprints for all 80 systems.
# Each was recorded from the ACIS gate log at the time of analysis authorship
# and verified against the corpus CMB spine (hash bd6425e80c31c6b1, T1830).
#
# A fingerprint change indicates a classification change. Whether that change
# is correct is a governance decision — not an automatic failure. This table
# is the stable reference; update it deliberately and with a commit message
# that explains what changed and why.
#
# Format: { system_name: expected_16char_hex_fingerprint }
#
KNOWN_FINGERPRINTS: dict[str, str] = {
    "active-directory":   "3f4ad40fd8dc2c3c",
    "ansible":            "2dc25cf8769ed24e",
    "argo-workflows":     "be7bcbdaf7a6d88f",
    "argocd":             "536bf22a3c9f3584",
    "aws-codepipeline":   "f89beb732eabf502",
    "aws-config":         "acc5093ee712f6ce",
    "aws-guardduty":      "bee971f5d3e100ea",
    "aws-iam":            "aa255556e281d862",
    "aws-kms":            "72d83d52216d1425",
    "aws-lambda":         "f95380dbab83348d",
    "aws-s3":             "ea5f14a05d5c0d4d",
    "aws-secrets-manager":"df58ce790f76cb8f",
    "aws-sso":            "0dd4a41ce52c82a7",
    "boundary":           "fbb184dfbf411e82",
    "ceph":               "7d76157cf208e7a8",
    "cert-manager":       "164cdec1a94bb5a6",
    "cert-manager-acme":  "be6105890fe8f56f",
    "cilium":             "1c3d880d7a780cb0",
    "circleci":           "940a7eb305c2b1de",
    "cloudtrail":         "656fb3fca68867ae",
    "consul":             "64b81b25e1b19c94",
    "cosign":             "926a43d9730065f4",
    "crossplane":         "2993063160dcf1a2",
    "docker":             "1b0fde1ac25d1170",
    "docker-hub":         "ec55c46d91bffa7d",
    "elasticsearch":      "7a9fd670c4aa40df",
    "entra-id":           "a99ccf679a8fd267",
    "etcd":               "ae087f82bc081d32",
    "external-secrets":   "470814a27d6395e5",
    "falco":              "eeb233194100c6ab",
    "gatekeeper":         "dc5e6d6a0bd7fb41",
    "gcp-iam":            "46bafa757de69558",
    "github-actions":     "4b595e5b832d0a05",
    "gitlab-ci":          "93b2408c4b3fccdf",
    "grafana":            "3f83fd761056a3f0",
    "helm":               "77e8b9f8025abca0",
    "istio":              "5696f45f889bba1d",
    "jaeger":             "370a8c817aae5a17",
    "jenkins":            "a54d8a0510e96c75",
    "k8s-admission":      "0a4619eb593054b4",
    "k8s-rbac":           "1c0f339a0fe10190",
    "kafka":              "7ef198eee84b42bc",
    "keycloak":           "85c7340ecd34f3ed",
    "kubeflow":           "aa3f56b4be222b83",
    "kubernetes":         "6c832e715c13bd1d",
    "kyverno":            "f8674e5d48aceee5",
    "linkerd":            "6d015915549c11ae",
    "minio":              "04cbd4a7645172b7",
    "mlflow":             "6e312765ed4a19ce",
    "mongodb":            "5640fc726ccdeb0b",
    "mysql":              "469d8705994d8200",
    "nats":               "0ecc36c4791e3bdb",
    "network-policy":     "2d0a562f1421f8df",
    "nginx":              "0f57a566e45289e5",
    "nomad":              "e8c3666122b4a1dc",
    "npm":                "d8bc7dccc605ef31",
    "opa":                "03d6372bc582c267",
    "opa-engine":         "4aef14d173b8db1c",
    "openfga":            "489ef9f8b9fb468b",
    "opentelemetry":      "da4498de15bec79b",
    "packer":             "27c3c185a592e465",
    "pod-security":       "1ba5f066ed462e1e",
    "postgresql":         "b46ea1c6353462f1",
    "prometheus":         "4350ffbb45eacbba",
    "pulumi":             "3a4ba5c5dc5b8205",
    "puppet":             "87094f8d62dce447",
    "pypi":               "242663985440d6b5",
    "rabbitmq":           "380c0c3e76db24e5",
    "redis":              "8cee438b696c3e4e",
    "rust-cargo":         "c86c6d145f7be4ae",
    "spiffe":             "1f7ef578746a90db",
    "splunk":             "d0498d59f114d814",
    "stripe":             "96b1e45d66e84c35",
    "tekton":             "cf5ab4f02ed87f0a",
    "teleport":           "8e2bdb197bdfab08",
    "terraform":          "37eb7ab8ad539c35",
    "triton":             "f23704ae199b7af1",
    "vault":              "6936be4feb549511",
    "wandb":              "2ac122a96584c313",
    "workload-identity":  "0e853df656846ad6",
}


# ── SECTION 2: RESULT TYPE ────────────────────────────────────────────────────
#
# A SystemResult captures everything we know about one system's test session.
# The status field maps to the three receipt states described in the module
# docstring: PASS, MISMATCH, or ERROR.

class SystemResult(NamedTuple):
    system:       str    # system name, e.g. "vault"
    tests_run:    int    # total tests executed (9 for most, 11 for npm)
    tests_passed: int    # tests that passed
    fingerprint:  str    # fingerprint computed this session
    expected:     str    # reference fingerprint from KNOWN_FINGERPRINTS
    status:       str    # PASS | MISMATCH | ERROR
    error:        str    # error message if status == ERROR, else ""


# ── SECTION 3: TEST LOADER ────────────────────────────────────────────────────
#
# Each test suite is a standalone Python file. They all share the same filename
# (test_gate_suite.py) because they live in separate system directories.
# Standard pytest discovers them by directory, but loading 80 files with the
# same module name into a single Python process requires importlib with per-file
# module naming to avoid module cache collisions.
#
# The sys.path insertion for each system's impl/ directory is what allows each
# test file's `from ear_adapter_X import ...` to resolve correctly. Each impl/
# directory contains its own copy of gcg_analyzer.py and gap_assertions.py
# alongside the adapter — they are co-located so each test is self-contained
# and does not require a shared installation step.
#
# This design decision (co-located framework files vs a single shared framework)
# is discussed in METHODOLOGY.md. The short version: co-location was chosen for
# the development corpus to ensure each system analysis is independently
# verifiable without the rest of the repo. The publishing plan calls for
# refactoring to a single framework/ directory; when that refactor is done,
# the sys.path.insert logic here will simplify to a single path entry.

def load_and_run_suite(system_dir: pathlib.Path) -> SystemResult:
    """
    Load a single system's test suite via importlib and call run_all_gates().

    Returns a SystemResult with tests_run, tests_passed, and the computed
    fingerprint for comparison against KNOWN_FINGERPRINTS.

    The try/except boundary here is intentional: one failing system should
    not abort the receipt for the remaining 79. Each ERROR is recorded in the
    receipt and reported in the summary.
    """
    system_name = system_dir.name.replace("-constitutional-analysis", "")
    expected_fp = KNOWN_FINGERPRINTS.get(system_name, "UNKNOWN")

    impl_path = str(system_dir / "impl")
    test_path = system_dir / "impl" / "tests" / "test_gate_suite.py"

    # Add the impl/ directory so the adapter's local imports resolve
    if impl_path not in sys.path:
        sys.path.insert(0, impl_path)

    try:
        # Load the module with a unique name derived from the system directory.
        # Without a unique name, Python's module cache would return the first
        # loaded test_gate_suite.py for all subsequent loads.
        module_name = f"csofta_test_{system_dir.name}"
        spec = importlib.util.spec_from_file_location(
            module_name,
            test_path,
            submodule_search_locations=[],
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        # run_all_gates() is the standard interface across all 80 test suites.
        # It returns (passed: int, failed: int, fingerprint: str).
        # The fingerprint is computed inside the suite by calling
        # convergence_fingerprint(report) from gap_assertions.py —
        # the same function whose output populates KNOWN_FINGERPRINTS above.
        passed, failed, fp = module.run_all_gates()
        total = passed + failed

        if passed == total and fp == expected_fp:
            status = "PASS"
        elif passed == total and fp != expected_fp:
            status = "MISMATCH"
        else:
            status = "ERROR"

        return SystemResult(
            system=system_name, tests_run=total, tests_passed=passed,
            fingerprint=fp, expected=expected_fp, status=status, error="",
        )

    except Exception as exc:
        return SystemResult(
            system=system_name, tests_run=0, tests_passed=0,
            fingerprint="", expected=expected_fp, status="ERROR",
            error=str(exc)[:200],
        )


# ── SECTION 4: RECEIPT WRITER ─────────────────────────────────────────────────
#
# The receipt is the governance artifact. It is a JSON file that records:
#
#   - when this session ran (ISO 8601 timestamp)
#   - what commit was current (git HEAD, if available)
#   - session-level outcome: PASS, PARTIAL, or FAIL
#   - per-system results: tests_run, tests_passed, fingerprint, expected, status
#   - a session hash: SHA-256 of all 80 fingerprints concatenated in sort order
#
# The session hash is a single value that changes if ANY system's analysis
# changes. It is the most compact form of "all 80 analyses are as authored".
# You can check it in one glance against a known reference.
#
# The receipt is written to .csofta_receipts/ which should be in .gitignore.
# Session receipts are evidence artifacts, not source artifacts. They document
# that a specific person ran the suite at a specific time and got a specific
# outcome. They are NOT meant to be committed to the repo on every run —
# only when producing a release or audit artifact.

RECEIPTS_DIR = pathlib.Path(".csofta_receipts")


def _get_git_commit() -> str:
    """Return the current git HEAD commit hash, or 'unknown' if not in a repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def _session_hash(results: list[SystemResult]) -> str:
    """
    Compute a single hash over all system fingerprints in sort order.

    This is a content-addressed summary of the full corpus classification:
    if any single system's analysis changes, this hash changes.
    The sort ensures determinism regardless of run order.
    """
    sorted_fps = sorted(f"{r.system}:{r.fingerprint}" for r in results)
    combined = "\n".join(sorted_fps)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]


def write_receipt(results: list[SystemResult]) -> pathlib.Path:
    """
    Write a governance receipt to .csofta_receipts/ and return its path.

    The receipt captures the full session state in a format that can be:
      - diffed between runs to see what changed
      - committed as a release artifact
      - referenced in audit trails
      - verified by a third party by re-running this script on the same commit
    """
    RECEIPTS_DIR.mkdir(exist_ok=True)

    ts = datetime.datetime.now(datetime.timezone.utc)
    ts_str = ts.strftime("%Y%m%dT%H%M%SZ")
    receipt_path = RECEIPTS_DIR / f"receipt_{ts_str}.json"

    # Determine session-level outcome:
    #   PASS    — all systems PASS (all tests passing, all fingerprints match)
    #   PARTIAL — all tests passing but ≥1 fingerprint MISMATCH
    #   FAIL    — ≥1 system ERROR (tests failed or suite would not load)
    errors    = [r for r in results if r.status == "ERROR"]
    mismatches = [r for r in results if r.status == "MISMATCH"]

    if errors:
        session_outcome = "FAIL"
    elif mismatches:
        session_outcome = "PARTIAL"
    else:
        session_outcome = "PASS"

    total_tests   = sum(r.tests_run for r in results)
    total_passed  = sum(r.tests_passed for r in results)

    receipt = {
        # ── Session metadata ─────────────────────────────────────────────────
        "session": {
            "timestamp":       ts.isoformat(),
            "git_commit":      _get_git_commit(),
            "python_version":  sys.version.split()[0],
            "outcome":         session_outcome,
            "systems_total":   len(results),
            "systems_pass":    sum(1 for r in results if r.status == "PASS"),
            "systems_mismatch":len(mismatches),
            "systems_error":   len(errors),
            "tests_total":     total_tests,
            "tests_passed":    total_passed,
            # session_hash: a single value representing the full corpus state.
            # If this matches a known-good reference, the full analysis corpus
            # is unmodified. This is the receipt's highest-level integrity check.
            "session_hash":    _session_hash(results),
        },
        # ── Per-system results ───────────────────────────────────────────────
        # Each entry records what happened for one system's adapter analysis.
        # See SystemResult and the module docstring for field definitions.
        "systems": [
            {
                "system":       r.system,
                "tests_run":    r.tests_run,
                "tests_passed": r.tests_passed,
                "fingerprint":  r.fingerprint,
                "expected":     r.expected,
                "status":       r.status,
                **({"error": r.error} if r.error else {}),
            }
            for r in sorted(results, key=lambda r: r.system)
        ],
        # ── What to do with this receipt ─────────────────────────────────────
        # This section is documentation embedded in the receipt itself.
        # It explains what each status means and what action to take.
        "_guidance": {
            "PASS":     "Tests passed and fingerprint matches reference. No action needed.",
            "MISMATCH": ("Tests passed but fingerprint differs from reference. "
                         "The analysis classification changed. Inspect the diff, "
                         "decide if the change is intentional, and update "
                         "KNOWN_FINGERPRINTS in governed_pytest.py if so."),
            "ERROR":    ("Test suite failed to load or tests failed. "
                         "See the 'error' field for details. "
                         "The system's EAR adapter needs investigation."),
            "session_hash_note": (
                "The session_hash covers all 80 system fingerprints. "
                "A stable session_hash across runs means the full corpus "
                "classification is unchanged. This is the most compact "
                "integrity check for the corpus as a whole."
            ),
        },
    }

    receipt_path.write_text(
        json.dumps(receipt, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return receipt_path


# ── SECTION 5: CONSOLE REPORTER ──────────────────────────────────────────────
#
# The console output is designed to be readable at a glance.
# - Green dots and PASS lines for the common case
# - Prominent MISMATCH / ERROR lines that are hard to miss
# - A session summary that mirrors the receipt's session block

def report_results(results: list[SystemResult], receipt_path: pathlib.Path) -> int:
    """
    Print a human-readable summary and return an exit code.

    Exit codes follow Unix convention and are compatible with CI systems:
      0 — all PASS (clean session)
      1 — any MISMATCH or ERROR
    """
    passes    = [r for r in results if r.status == "PASS"]
    mismatches = [r for r in results if r.status == "MISMATCH"]
    errors    = [r for r in results if r.status == "ERROR"]

    total_tests  = sum(r.tests_run for r in results)
    total_passed = sum(r.tests_passed for r in results)

    print()
    print("=" * 68)
    print("CSoftA Governance Receipt")
    print("=" * 68)

    # ── Per-system lines ─────────────────────────────────────────────────────
    # PASS lines are compact; MISMATCH and ERROR lines are verbose.
    # In a clean session, this section is 80 identical PASS lines.
    for r in sorted(results, key=lambda r: r.system):
        if r.status == "PASS":
            print(f"  PASS       {r.system:<28s}  fp={r.fingerprint}  {r.tests_passed}/{r.tests_run}")
        elif r.status == "MISMATCH":
            print(f"  MISMATCH   {r.system:<28s}  "
                  f"computed={r.fingerprint}  expected={r.expected}  "
                  f"{r.tests_passed}/{r.tests_run}")
            print(f"             └─ Classification changed — inspect diff, "
                  f"update KNOWN_FINGERPRINTS if intentional")
        else:
            print(f"  ERROR      {r.system:<28s}  {r.error or 'unknown error'}")

    # ── Session summary ──────────────────────────────────────────────────────
    print()
    print("-" * 68)
    print(f"  Systems:  {len(passes)}/{len(results)} PASS  "
          f"{len(mismatches)} MISMATCH  {len(errors)} ERROR")
    print(f"  Tests:    {total_passed}/{total_tests} passed")
    print(f"  Receipt:  {receipt_path}")

    # The session hash is the single-value integrity check for the full corpus.
    # Record it prominently so it can be compared against a known reference.
    sh = _session_hash(results)
    print(f"  Session hash:  {sh}")
    print("-" * 68)

    # ── Guidance for non-PASS states ─────────────────────────────────────────
    if mismatches:
        print()
        print("  MISMATCH NOTE: One or more fingerprints differ from reference.")
        print("  This means a system's governance classification changed.")
        print("  If the change is intentional: update KNOWN_FINGERPRINTS.")
        print("  If the change is unexpected: a regression may have occurred.")

    if errors:
        print()
        print("  ERROR NOTE: One or more test suites failed to run.")
        print("  Check the error messages above and inspect the adapter.")

    if not mismatches and not errors:
        print()
        print("  All 80 analyses are unchanged from their authored state.")

    print()

    return 0 if (not mismatches and not errors) else 1


# ── SECTION 6: MAIN ENTRY POINT ──────────────────────────────────────────────
#
# The entry point resolves the systems/ directory, runs all suites,
# writes the receipt, and prints the summary.
#
# Suppressing stdout during suite execution keeps console output clean:
# each suite prints its own verbose test output, which is useful when
# running a single suite directly but is noise at the full-corpus level.
# The receipt captures everything; the console shows the summary.

def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parent

    # Locate all system directories — any directory containing the
    # expected test suite path. Alphabetical order for determinism.
    system_dirs = sorted([
        d for d in repo_root.iterdir()
        if d.is_dir()
        and (d / "impl" / "tests" / "test_gate_suite.py").exists()
        and d.name != ".csofta_receipts"
    ])

    if not system_dirs:
        print("ERROR: no system directories found.", file=sys.stderr)
        print("Run this script from the repo root.", file=sys.stderr)
        return 1

    print(f"Running {len(system_dirs)} system analyses...", end="", flush=True)

    # Suppress suite stdout so it doesn't flood the terminal.
    # Each suite prints verbose test output; useful for debugging
    # individual systems, noise at full-corpus scale.
    import io
    results: list[SystemResult] = []
    for sdir in system_dirs:
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = load_and_run_suite(sdir)
        finally:
            sys.stdout = old_stdout

        results.append(result)

        # Print a progress indicator: dot for PASS, F for failure/mismatch
        indicator = "." if result.status == "PASS" else "F"
        print(indicator, end="", flush=True)

    print()  # newline after progress dots

    receipt_path = write_receipt(results)
    return report_results(results, receipt_path)


if __name__ == "__main__":
    sys.exit(main())
