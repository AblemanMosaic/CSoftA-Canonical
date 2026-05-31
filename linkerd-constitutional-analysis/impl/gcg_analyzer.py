"""
gcg_analyzer.py — GCG Analysis Engine

Implements GCG Codex Phases A–F (C-01 through C-19).
System-agnostic: operates on any EARAdapter implementation.

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
GCG Codex: PCM-0333-081 through PCM-0333-159
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ear_adapter_linkerd import EARState, GCGForm
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ear_adapter_vault import (
        OperationFamily, GovernanceLayer,
        ExecutionInstance, VaultEARAdapter,
    )


# ── C-13: Coverage Gap Assertion ─────────────────────────────────────────────

@dataclass
class CoverageGapAssertion:
    """
    GCG Codex C-13: well-formed Coverage Gap Assertion.
    All seven required elements (PCM-0333-143).
    """
    # Element 1: operation family
    operation_family:          str

    # Element 2: N declaration
    n_declared:                list[str]          # N(O) layer names
    n_determination_strategy:  str                # DECLARED-N / MINIMUM-N / PER-CONTEXT-N
    n_source_citation:         str                # where N(O) was derived from

    # Element 3: k assessment
    k_realized:                list[str]          # k(O,e) layer names that participated
    k_evidence:                str                # how k was assessed

    # Element 4: gap evidence
    gap_evidence:              str                # why k < N for this instance

    # Element 5: non-participation record
    non_participation_record_present: bool        # C-07 — is there a record of absence?
    non_participation_record_note:    str         # what record exists or why absent

    # Element 6: gap form classification
    gap_form:                  str                # NON_ACTIVATION / ABSENCE / BYPASS

    # Element 7: gap magnitude
    gap_magnitude:             int                # |N(O)| - |k(O,e)|

    # Additional context
    execution_instance_id:     str = ""           # request_id from audit log
    timestamp:                 str = ""
    artifact_governance_overstating: bool = False # C-15
    remediation_class:         str = ""           # C-18

    def to_dict(self) -> dict:
        return {
            "operation_family":               self.operation_family,
            "n_declared":                     self.n_declared,
            "n_determination_strategy":       self.n_determination_strategy,
            "n_source_citation":              self.n_source_citation,
            "k_realized":                     self.k_realized,
            "k_evidence":                     self.k_evidence,
            "gap_evidence":                   self.gap_evidence,
            "non_participation_record_present": self.non_participation_record_present,
            "non_participation_record_note":  self.non_participation_record_note,
            "gap_form":                       self.gap_form,
            "gap_magnitude":                  self.gap_magnitude,
            "execution_instance_id":          self.execution_instance_id,
            "timestamp":                      self.timestamp,
            "artifact_governance_overstating": self.artifact_governance_overstating,
            "remediation_class":              self.remediation_class,
        }


@dataclass
class GCGAnalysisReport:
    """GCG Codex C-17: complete GCG Analysis Report."""
    # Section 1: system identification
    target_system:        str
    target_version:       str
    governance_sources:   list[str]

    # Section 2: N-determination
    n_determination_strategy: str
    n_by_family:          dict[str, list[str]]   # op_family -> N(O)
    n_determination_note: str

    # Section 3: EAR states
    ear_states:           dict[str, str]          # op_family -> EARState value

    # Section 4: GCG assertions
    assertions:           list[CoverageGapAssertion]

    # Section 5: remediation
    remediation_summary:  dict[str, list[str]]    # form -> remediation steps

    # Section 6: summary metrics
    total_instances_analyzed:  int = 0
    total_gaps_found:          int = 0
    gap_by_form:               dict[str, int] = field(default_factory=dict)
    governance_depth_declared: dict[str, int] = field(default_factory=dict)
    governance_depth_realized: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "target_system":              self.target_system,
            "target_version":             self.target_version,
            "governance_sources":         self.governance_sources,
            "n_determination_strategy":   self.n_determination_strategy,
            "n_by_family":                self.n_by_family,
            "n_determination_note":       self.n_determination_note,
            "ear_states":                 self.ear_states,
            "assertions":                 [a.to_dict() for a in self.assertions],
            "remediation_summary":        self.remediation_summary,
            "total_instances_analyzed":   self.total_instances_analyzed,
            "total_gaps_found":           self.total_gaps_found,
            "gap_by_form":                self.gap_by_form,
            "governance_depth_declared":  self.governance_depth_declared,
            "governance_depth_realized":  self.governance_depth_realized,
        }


# ── GCG Analyzer ─────────────────────────────────────────────────────────────

class GCGAnalyzer:
    """
    Stateless GCG analysis engine.
    Implements GCG Codex Phases A–F for any EARAdapter.
    """

    # ── Phase A: Foundation ───────────────────────────────────────────────

    def phase_a_topology(self, adapter) -> tuple[
        list["OperationFamily"], dict[str, list["GovernanceLayer"]]
    ]:
        """
        Phase A (PCM-0333-081): Build operation family + governance layer topology.
        Implements C-01 through C-04.
        Returns (operation_families, layers_by_family).
        Gate: T-A.1..T-A.4 — families and layers correctly identified.
        """
        families = adapter.collect_operation_families()
        layers_by_family = {
            f.name: adapter.collect_governance_layers(f)
            for f in families
        }
        return families, layers_by_family

    # ── Phase B: Core constructs ──────────────────────────────────────────

    def phase_b_participation(
        self,
        adapter,
        op_family: "OperationFamily",
        layers_by_family: dict[str, list["GovernanceLayer"]],
    ) -> tuple[list[str], dict[str, list[str]], dict[str, str]]:
        """
        Phase B (PCM-0333-082): Compute N(O) and k(O,e) for each execution.
        Implements C-05, C-06, C-07.
        Returns (N_O, k_by_instance, non_participation_by_instance).
        Gate: T-B.1..T-B.4
        """
        # C-05: N(O)
        n_o = [layer.name for layer in layers_by_family.get(op_family.name, [])]

        # C-06: k(O,e) — realized participation per execution instance
        instances = adapter.collect_executions(op_family)
        k_by_instance: dict[str, list[str]] = {}
        non_participation: dict[str, str] = {}

        for inst in instances:
            k = self._assess_k(inst, n_o, op_family, adapter=adapter)
            k_by_instance[inst.request_id] = k

            # C-07: non-participation record
            absent = set(n_o) - set(k)
            if absent:
                non_participation[inst.request_id] = self._assess_non_participation_record(
                    inst, list(absent), adapter
                )

        return n_o, k_by_instance, non_participation

    def _assess_k(
        self,
        inst,
        n_o: list[str],
        op_family,
        adapter=None,
    ) -> list[str]:
        """
        Assess which layers actually participated. Adapter-agnostic.
        If adapter provides assess_k(), delegate to it.
        """
        # Delegate to adapter if it provides its own k-assessment
        if adapter is not None and hasattr(adapter, 'assess_k'):
            return adapter.assess_k(inst)

        k = []
        # token_auth: participated if token was validated
        if "token_auth" in n_o and getattr(inst, 'token_type', None):
            k.append("token_auth")
        # policy_evaluation: participated if granting_policies is populated
        if "policy_evaluation" in n_o and getattr(inst, 'granting_policies', None):
            k.append("policy_evaluation")
        # audit_device: structural participation (entry exists = participated)
        if "audit_device" in n_o:
            k.append("audit_device")
        # mfa
        if "mfa" in n_o:
            mfa = inst.raw.get("auth", {}).get("mfa_requirement") if hasattr(inst, 'raw') else None
            if mfa:
                k.append("mfa")
        # lockfile_integrity (npm)
        if "lockfile_integrity" in n_o and getattr(inst, 'has_integrity_hash', False):
            k.append("lockfile_integrity")
        # namespace_isolation, cgroups (Docker standard)
        if "namespace_isolation" in n_o:
            net = getattr(inst, 'network_mode', '')
            if net not in ('host',):
                k.append("namespace_isolation")
        if "cgroups" in n_o:
            k.append("cgroups")
        # seccomp (Docker standard)
        if "seccomp" in n_o:
            sp = getattr(inst, 'seccomp_profile', None)
            if sp and sp not in ('unconfined', ''):
                k.append("seccomp")
        # apparmor (Docker standard)
        if "apparmor" in n_o:
            ap = getattr(inst, 'apparmor_profile', None)
            if ap and ap not in ('unconfined', ''):
                k.append("apparmor")
        # capabilities (Docker standard)
        if "capabilities" in n_o:
            caps_drop = getattr(inst, 'capabilities_dropped', []) or []
            caps_add  = getattr(inst, 'capabilities_added', []) or []
            if caps_drop or "ALL" not in caps_add:
                k.append("capabilities")
        return k

    def _assess_non_participation_record(
        self,
        inst: "ExecutionInstance",
        absent_layers: list[str],
        adapter,
    ) -> str:
        """
        Assess whether a non-participation record exists for absent layers.
        GCG Codex C-07.
        Returns description of record (or its absence).
        """
        notes = []
        for layer in absent_layers:
            if layer == "policy_evaluation":
                # Check if granting_policies is absent vs empty
                pr = inst.raw.get("auth", {}).get("policy_results")
                if pr is None:
                    notes.append(
                        f"{layer}: no policy_results field in audit entry — "
                        "no non-participation record"
                    )
                elif not (pr.get("granting_policies") or pr.get("allowed_policies")):
                    notes.append(
                        f"{layer}: policy_results present but granting_policies empty — "
                        "silent permit, no attribution"
                    )
            elif layer == "audit_device":
                notes.append(
                    f"{layer}: structural absence — if this entry exists in log, "
                    "audit device participated; absence means no log at all"
                )
            else:
                notes.append(
                    f"{layer}: no field in audit entry indicating participation or non-participation"
                )
        return "; ".join(notes) if notes else "no non-participation record found"

    # ── Phase C: GCG construct ────────────────────────────────────────────

    def phase_c_assert_gcg(
        self,
        op_family: "OperationFamily",
        n_o: list[str],
        k_by_instance: dict[str, list[str]],
        non_participation: dict[str, str],
        instances: list["ExecutionInstance"],
        adapter,
    ) -> list[CoverageGapAssertion]:
        """
        Phase C (PCM-0333-083): Assert GCG where three-condition conjunction holds.
        GCG Codex C-08: N declared AND k < N AND no non-participation record.
        Gate: T-C.1..T-C.5
        """
        assertions = []
        decl = adapter.get_governance_declaration()

        for inst in instances:
            k = k_by_instance.get(inst.request_id, [])
            non_part_note = non_participation.get(inst.request_id, "")

            # Condition 1: N(O) declared
            if not n_o:
                continue

            # Condition 2: k < N
            if set(k) >= set(n_o):
                continue  # all declared layers participated — no GCG

            # Condition 3: no non-participation record
            # If there IS a non-participation record, this is Intentional Partial
            # Governance (C-16), not GCG
            has_non_part_record = bool(non_part_note and
                "no non-participation record" not in non_part_note.lower())

            absent = sorted(set(n_o) - set(k))

            # Classify the gap form (Phase D preview — used in assertion)
            gap_form = self._classify_form_preliminary(inst, absent, op_family)

            assertion = CoverageGapAssertion(
                operation_family=op_family.name,
                n_declared=n_o,
                n_determination_strategy=decl.strategy,
                n_source_citation=decl.source,
                k_realized=k,
                k_evidence=(
                    "Derived from Vault audit log: token_auth presence, "
                    "policy_results.granting_policies, audit device structural presence"
                ),
                gap_evidence=(
                    f"Layers declared N(O)={n_o}; "
                    f"layers realized k(O,e)={k}; "
                    f"absent: {absent}"
                ),
                non_participation_record_present=has_non_part_record,
                non_participation_record_note=non_part_note or
                    "no record of non-participation in audit entry",
                gap_form=gap_form,
                gap_magnitude=len(n_o) - len(k),
                execution_instance_id=inst.request_id,
                timestamp=inst.timestamp,
                artifact_governance_overstating=(len(n_o) - len(k)) > 0,
                remediation_class="",  # filled in Phase E/F
            )
            assertions.append(assertion)

        return assertions

    # ── Phase D: Form classification ──────────────────────────────────────

    def phase_d_classify_forms(
        self,
        assertions: list[CoverageGapAssertion],
        adapter,
        instances_by_family: dict[str, list["ExecutionInstance"]],
    ) -> list[CoverageGapAssertion]:
        """
        Phase D (PCM-0333-084): Classify each GCG as NON_ACTIVATION/ABSENCE/BYPASS.
        Implements C-09, C-10, C-11, C-12.
        Gate: T-D.1..T-D.5
        """
        # Build instance lookup for Docker-style bypass detection
        inst_lookup: dict = {}
        for fam_insts in instances_by_family.values():
            for inst in fam_insts:
                inst_lookup[inst.request_id] = inst

        for assertion in assertions:
            absent_layers = set(assertion.n_declared) - set(assertion.k_realized)
            inst = inst_lookup.get(assertion.execution_instance_id)
            assertion.gap_form = self._classify_form_full(
                assertion.operation_family,
                list(absent_layers),
                adapter,
                inst=inst,
            )
        return assertions

    def _classify_form_preliminary(
        self,
        inst,
        absent_layers: list[str],
        op_family,
    ) -> str:
        """Preliminary form classification. Adapter-agnostic."""
        # Adapter-level bypass signal
        if hasattr(inst, 'privileged') and inst.privileged:
            return GCGForm.BYPASS.value
        if hasattr(op_family, 'name') and 'bypass' in op_family.name.lower():
            return GCGForm.BYPASS.value
        token_policies = getattr(inst, 'token_policies', []) or []
        if 'root' in token_policies:
            return GCGForm.BYPASS.value
        # host network mode bypasses namespace isolation
        if (hasattr(inst, 'network_mode') and inst.network_mode == 'host'
                and 'namespace_isolation' in absent_layers):
            return GCGForm.BYPASS.value
        # Structurally absent layers (never exist in this system's architecture)
        structurally_absent = {'lifecycle_governance', 'audit_surface',
                               'interior_execution'}
        if any(layer in structurally_absent for layer in absent_layers):
            return GCGForm.ABSENCE.value
        # seccomp=unconfined = Non-Activation (layer exists, explicitly disabled)
        if ('seccomp' in absent_layers and hasattr(inst, 'seccomp_profile')
                and inst.seccomp_profile == 'unconfined'):
            return GCGForm.NON_ACTIVATION.value
        return GCGForm.NON_ACTIVATION.value

    def _classify_form_full(
        self,
        op_family_name: str,
        absent_layers: list[str],
        adapter,
        inst=None,
    ) -> str:
        """Full form classification with adapter context. GCG C-09/C-10/C-11."""
        # Root token bypass
        if op_family_name == "root_token_operation":
            return GCGForm.BYPASS.value
        # Docker --privileged bypass
        if inst is not None and getattr(inst, 'privileged', False):
            return GCGForm.BYPASS.value
        # Host network mode bypasses namespace isolation
        if (inst is not None and getattr(inst, 'network_mode', '') == 'host'
                and 'namespace_isolation' in absent_layers):
            return GCGForm.BYPASS.value
        # Structurally absent layers
        structurally_absent = {'lifecycle_governance', 'audit_surface',
                               'interior_execution'}
        if any(layer in structurally_absent for layer in absent_layers):
            return GCGForm.ABSENCE.value
        # Audit device: check adapter
        if "audit_device" in absent_layers:
            audit_enabled = getattr(adapter, '_audit_device_enabled', None)
            if audit_enabled is False:
                return GCGForm.NON_ACTIVATION.value
            if audit_enabled is None:
                return GCGForm.ABSENCE.value
        if "policy_evaluation" in absent_layers:
            return GCGForm.NON_ACTIVATION.value
        if "lockfile_integrity" in absent_layers:
            lock = getattr(adapter, '_lock_data', None)
            if lock is None:
                return GCGForm.ABSENCE.value
        # seccomp=unconfined = Non-Activation
        if ('seccomp' in absent_layers and inst is not None
                and getattr(inst, 'seccomp_profile', None) == 'unconfined'):
            return GCGForm.NON_ACTIVATION.value
        return GCGForm.NON_ACTIVATION.value

    # ── Phase E: Diagnostic and consequence constructs ────────────────────

    def phase_e_diagnostics(
        self,
        assertions: list[CoverageGapAssertion],
        n_by_family: dict[str, list[str]],
    ) -> list[CoverageGapAssertion]:
        """
        Phase E (PCM-0333-085): Compute governance depth, artifact overstating,
        intentional partial governance. Implements C-13 through C-16.
        Gate: T-E.1..T-E.4
        """
        for a in assertions:
            n = len(a.n_declared)
            k = len(a.k_realized)

            # C-14: Governance Depth
            a.gap_magnitude = n - k

            # C-15: Artifact Governance Overstating
            a.artifact_governance_overstating = (n - k) > 0

            # C-18: Remediation classification
            a.remediation_class = self._classify_remediation(a.gap_form)

        return assertions

    def _classify_remediation(self, gap_form: str) -> str:
        """GCG Codex C-18: form-specific remediation classification."""
        if gap_form == GCGForm.NON_ACTIVATION.value:
            return (
                "Configuration change to activate layer for relevant contexts. "
                "Document activation state per-context in durable governance log."
            )
        elif gap_form == GCGForm.ABSENCE.value:
            return (
                "Deploy missing governance layer. "
                "If intentionally absent, produce architectural decision record."
            )
        elif gap_form == GCGForm.BYPASS.value:
            return (
                "Constrain bypass scope. Replace global bypass with scoped capability. "
                "Produce explicit bypass receipt for every bypass invocation."
            )
        return "Unknown form — manual remediation analysis required."

    # ── Phase F: Application and reporting ───────────────────────────────

    def phase_f_report(
        self,
        adapter,
        target_system: str,
        target_version: str,
        assertions: list[CoverageGapAssertion],
        n_by_family: dict[str, list[str]],
        ear_states: dict[str, str],
        instances_by_family: dict[str, list],
    ) -> GCGAnalysisReport:
        """
        Phase F (PCM-0333-086): Produce complete GCG Analysis Report.
        Implements C-17 through C-19.
        Gate: T-F.1..T-F.4
        """
        decl = adapter.get_governance_declaration()

        gap_by_form: dict[str, int] = {}
        for a in assertions:
            gap_by_form[a.gap_form] = gap_by_form.get(a.gap_form, 0) + 1

        # Governance depth by family
        declared_depth = {
            fam: len(layers) for fam, layers in n_by_family.items()
        }
        realized_depth: dict[str, float] = {}
        for fam, instances in instances_by_family.items():
            if not instances:
                realized_depth[fam] = 0.0
                continue
            fam_assertions = [a for a in assertions if a.operation_family == fam]
            if fam_assertions:
                avg_k = sum(len(a.k_realized) for a in fam_assertions) / len(fam_assertions)
                realized_depth[fam] = round(avg_k, 2)
            else:
                # No gaps found for this family = full realization
                realized_depth[fam] = float(declared_depth.get(fam, 0))

        # Remediation summary
        remediation_summary: dict[str, list[str]] = {
            GCGForm.NON_ACTIVATION.value: [],
            GCGForm.ABSENCE.value: [],
            GCGForm.BYPASS.value: [],
        }
        for a in assertions:
            form_list = remediation_summary.get(a.gap_form)
            if form_list is not None:
                entry = f"{a.operation_family} (magnitude {a.gap_magnitude})"
                if entry not in form_list:
                    form_list.append(entry)

        return GCGAnalysisReport(
            target_system=target_system,
            target_version=target_version,
            governance_sources=[decl.source],
            n_determination_strategy=decl.strategy,
            n_by_family=n_by_family,
            n_determination_note=decl.description,
            ear_states=ear_states,
            assertions=assertions,
            remediation_summary=remediation_summary,
            total_instances_analyzed=sum(len(v) for v in instances_by_family.values()),
            total_gaps_found=len(assertions),
            gap_by_form=gap_by_form,
            governance_depth_declared=declared_depth,
            governance_depth_realized=realized_depth,
        )

    # ── Full analysis pipeline ────────────────────────────────────────────

    def analyze(
        self,
        adapter,
        target_system: str = "HashiCorp Vault",
        target_version: str = "OSS",
    ) -> GCGAnalysisReport:
        """
        Run all six GCG phases against the provided adapter.
        Returns a complete GCGAnalysisReport.
        """
        # Phase A
        families, layers_by_family = self.phase_a_topology(adapter)

        n_by_family    = {f.name: [l.name for l in layers_by_family[f.name]] for f in families}
        ear_states     = {f.name: adapter.assess_ear_state(f).value for f in families}
        all_assertions = []
        instances_by_family: dict[str, list] = {}

        for family in families:
            # Phase B
            n_o, k_by_instance, non_participation = self.phase_b_participation(
                adapter, family, layers_by_family
            )
            instances = adapter.collect_executions(family)
            instances_by_family[family.name] = instances

            # Phase C
            assertions = self.phase_c_assert_gcg(
                family, n_o, k_by_instance, non_participation, instances, adapter
            )

            # Phase D
            assertions = self.phase_d_classify_forms(assertions, adapter, instances_by_family)

            # Phase E
            assertions = self.phase_e_diagnostics(assertions, n_by_family)

            all_assertions.extend(assertions)

        # Phase F
        report = self.phase_f_report(
            adapter=adapter,
            target_system=target_system,
            target_version=target_version,
            assertions=all_assertions,
            n_by_family=n_by_family,
            ear_states=ear_states,
            instances_by_family=instances_by_family,
        )
        return report
