"""
gap_assertions.py — Coverage Gap Assertion Producer

Serializes CoverageGapAssertion objects to JSON receipts.
Provides assertion filtering, summary statistics, and fingerprint.

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
GCG Codex C-13: well-formed Coverage Gap Assertion (PCM-0333-143)
"""
from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gcg_analyzer import CoverageGapAssertion, GCGAnalysisReport


def serialize_assertion(assertion: "CoverageGapAssertion") -> str:
    """Serialize a single CoverageGapAssertion to canonical JSON."""
    return json.dumps(assertion.to_dict(), sort_keys=True, indent=2)


def serialize_report(report: "GCGAnalysisReport") -> str:
    """Serialize a complete GCGAnalysisReport to canonical JSON."""
    return json.dumps(report.to_dict(), sort_keys=True, indent=2)


def filter_by_form(
    assertions: "list[CoverageGapAssertion]",
    form: str,
) -> "list[CoverageGapAssertion]":
    """Filter assertions by gap form (NON_ACTIVATION / ABSENCE / BYPASS)."""
    return [a for a in assertions if a.gap_form == form]


def filter_by_family(
    assertions: "list[CoverageGapAssertion]",
    family: str,
) -> "list[CoverageGapAssertion]":
    """Filter assertions by operation family."""
    return [a for a in assertions if a.operation_family == family]


def summary_stats(assertions: "list[CoverageGapAssertion]") -> dict:
    """Compute summary statistics over a list of assertions."""
    if not assertions:
        return {
            "total":      0,
            "by_form":    {},
            "by_family":  {},
            "avg_magnitude": 0.0,
            "max_magnitude": 0,
        }

    by_form:   dict[str, int] = {}
    by_family: dict[str, int] = {}
    for a in assertions:
        by_form[a.gap_form]              = by_form.get(a.gap_form, 0) + 1
        by_family[a.operation_family]    = by_family.get(a.operation_family, 0) + 1

    magnitudes = [a.gap_magnitude for a in assertions]
    return {
        "total":           len(assertions),
        "by_form":         by_form,
        "by_family":       by_family,
        "avg_magnitude":   round(sum(magnitudes) / len(magnitudes), 2),
        "max_magnitude":   max(magnitudes),
    }


def convergence_fingerprint(report: "GCGAnalysisReport") -> str:
    """
    Produce a convergence fingerprint for a GCGAnalysisReport.
    Two conforming implementations that produce the same fingerprint
    for canonical inputs are convergent. T1576.

    The fingerprint is derived from:
    - EAR states per operation family (structural, not instance-dependent)
    - Gap forms by operation family (structural)
    - N(O) by operation family (structural)
    - Total gap count and form distribution (summary)

    Deliberately excludes: timestamps, request IDs, evidence text
    (these are instance-specific and vary across runs).
    """
    canonical = {
        "ear_states":                sorted(report.ear_states.items()),
        "n_by_family":               sorted((k, sorted(v)) for k, v in report.n_by_family.items()),
        "gap_by_form":               sorted(report.gap_by_form.items()),
        "governance_depth_declared": sorted(report.governance_depth_declared.items()),
        "total_gaps_found":          report.total_gaps_found,
        # Structural gap pattern per family (not per instance)
        "gap_families":              sorted({a.operation_family for a in report.assertions}),
        "gap_forms_per_family":      sorted(
            (fam, sorted({a.gap_form for a in report.assertions if a.operation_family == fam}))
            for fam in {a.operation_family for a in report.assertions}
        ),
    }
    canonical_json = json.dumps(canonical, sort_keys=True)
    return hashlib.sha256(canonical_json.encode()).hexdigest()[:16]


def write_receipt(report: "GCGAnalysisReport", output_path: str) -> str:
    """
    Write a GCGAnalysisReport to a JSON receipt file.
    Returns the convergence fingerprint.
    """
    data = report.to_dict()
    fingerprint = convergence_fingerprint(report)
    data["convergence_fingerprint"] = fingerprint

    with open(output_path, "w") as f:
        json.dump(data, f, sort_keys=True, indent=2)

    return fingerprint
