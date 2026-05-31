"""
ear_adapter_opa.py — OPA EAR Adapter

Open Policy Agent: general-purpose policy engine.
Decision log (--decision-log-path or management API) is the primary
evidence surface.

OPA's constitutional profile:
- Policy evaluation: CRYSTALLIZED — decision log exists, opt-in, not
  constitutive (OPA evaluates policies whether or not logging is enabled)
- Bundle activation: CRYSTALLIZED — bundle status API records activation
- Authorization decision: CRYSTALLIZED — decision recorded in log if enabled
- Policy management: CRYSTALLIZED — management API receipts changes

Key finding: decision logging is structurally CRYSTALLIZED across all
three policy engine systems (OPA/Gatekeeper/Kyverno). The log records
the decision outcome but is not constitutive — OPA allows/denies the
request regardless of whether the log write succeeds. When --decision-log-path
is not configured, decisions are ABSENT from any record.

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
Wave 2 — System 6
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class EARState(Enum):
    ACTIVE       = "ACTIVE"
    CRYSTALLIZED = "CRYSTALLIZED"
    ABSENT       = "ABSENT"


class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"
    ABSENCE        = "ABSENCE"
    BYPASS         = "BYPASS"


@dataclass
class OperationFamily:
    name:            str
    description:     str
    declared_layers: list[str]
    opa_scope:       str


@dataclass
class GovernanceLayer:
    name:         str
    description:  str
    evidence_field: str | None = None
    is_optional:  bool = False


@dataclass
class ExecutionInstance:
    operation_family:        str
    request_id:              str
    timestamp:               str
    decision_id:             str | None
    input_path:              str
    policy_package:          str
    decision:                str | None      # "allow" / "deny" / result value
    decision_logged:         bool
    bundle_active:           bool
    policy_version_recorded: bool
    error:                   str | None
    raw:                     dict = field(default_factory=dict)


@dataclass
class GovernanceDeclaration:
    source:      str
    strategy:    str
    description: str


OPA_OPERATION_FAMILIES = [
    OperationFamily(
        name="policy_evaluation",
        description="Evaluate a policy query — the primary OPA operation",
        declared_layers=["policy_package", "decision_log"],
        opa_scope="query",
    ),
    OperationFamily(
        name="bundle_activation",
        description="Activate a policy bundle from remote or local source",
        declared_layers=["bundle_status", "policy_version", "activation_receipt"],
        opa_scope="bundle",
    ),
    OperationFamily(
        name="policy_management",
        description="PUT/DELETE policy via management API",
        declared_layers=["management_auth", "policy_version", "decision_log"],
        opa_scope="management",
    ),
    OperationFamily(
        name="data_write",
        description="Write data document via management API",
        declared_layers=["management_auth", "data_version", "decision_log"],
        opa_scope="data",
    ),
]

OPA_GOVERNANCE_LAYERS = {
    "policy_package": GovernanceLayer(
        name="policy_package",
        description="Named policy package evaluated — determines which rules apply",
        evidence_field="labels.policy_path",
    ),
    "decision_log": GovernanceLayer(
        name="decision_log",
        description="Decision log entry recording input, output, policy version",
        evidence_field="decision_id",
        is_optional=False,  # declared applicable; opt-in in practice
    ),
    "input_schema": GovernanceLayer(
        name="input_schema",
        description="Input schema validation before policy evaluation",
        evidence_field=None,
        is_optional=True,
    ),
    "bundle_status": GovernanceLayer(
        name="bundle_status",
        description="Bundle activation status — confirms which policy version is active",
        evidence_field="bundle.active",
    ),
    "policy_version": GovernanceLayer(
        name="policy_version",
        description="Policy version recorded in decision — links decision to policy content",
        evidence_field="labels.policy_id",
        is_optional=False,
    ),
    "activation_receipt": GovernanceLayer(
        name="activation_receipt",
        description="Explicit receipt that a bundle was activated and is now governing",
        evidence_field=None,
        is_optional=False,
    ),
    "management_auth": GovernanceLayer(
        name="management_auth",
        description="Authentication for management API operations",
        evidence_field="bearer_token",
        is_optional=True,
    ),
    "data_version": GovernanceLayer(
        name="data_version",
        description="Version tracking for data documents",
        evidence_field=None,
        is_optional=True,
    ),
}


class OPAEARAdapter:
    """
    EAR Adapter for Open Policy Agent.
    Primary: decision log (JSON, one entry per decision).
    Secondary: bundle status API, management API.
    """

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "OPA Documentation + OPA Decision Log specification + "
            "OPA Management API spec + OPA Bundle specification"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) derived from OPA's documented governance architecture. "
            "policy_evaluation N=3 (policy_package + decision_log + input_schema). "
            "Decision log is CRYSTALLIZED: exists as mechanism, not constitutive. "
            "OPA evaluates and returns a decision whether or not the log write succeeds. "
            "Without --decision-log-path or management API configuration: ABSENT."
        ),
    )

    def __init__(
        self,
        decision_log:             list[dict] | None = None,
        decision_log_path:        str | None = None,
        decision_log_enabled:     bool | None = None,
        management_auth_enabled:  bool = False,
        bundle_active:            bool = True,
    ):
        self._log               = decision_log or []
        self._log_path          = decision_log_path
        self._log_enabled       = decision_log_enabled
        self._mgmt_auth         = management_auth_enabled
        self._bundle_active     = bundle_active
        self._loaded            = False

    def load(self) -> None:
        if self._loaded: return
        if self._log_path and not self._log:
            try:
                p = Path(self._log_path)
                if p.suffix == '.json':
                    self._log = json.loads(p.read_text())
                else:
                    self._log = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
            except Exception:
                pass
        self._loaded = True

    def collect_operation_families(self) -> list[OperationFamily]:
        return OPA_OPERATION_FAMILIES

    def collect_governance_layers(self, op_family: OperationFamily) -> list[GovernanceLayer]:
        return [OPA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in OPA_GOVERNANCE_LAYERS]

    def collect_executions(self, op_family: OperationFamily) -> list[ExecutionInstance]:
        self.load()
        if op_family.name == "policy_evaluation":
            instances = [self._parse_decision(e) for e in self._log]
            if not instances:
                instances = [ExecutionInstance(
                    operation_family="policy_evaluation",
                    request_id="synthetic:policy_eval",
                    timestamp="", decision_id=None,
                    input_path="(structural)", policy_package="(structural)",
                    decision=None,
                    decision_logged=(self._log_enabled is not False and bool(self._log)),
                    bundle_active=self._bundle_active,
                    policy_version_recorded=False,
                    error=None, raw={},
                )]
        elif op_family.name == "bundle_activation":
            instances = [ExecutionInstance(
                operation_family="bundle_activation",
                request_id="synthetic:bundle",
                timestamp="", decision_id=None,
                input_path="bundle://", policy_package="(bundle root)",
                decision="activated" if self._bundle_active else "inactive",
                decision_logged=False,
                bundle_active=self._bundle_active,
                policy_version_recorded=False,
                error=None, raw={},
            )]
        else:
            instances = [ExecutionInstance(
                operation_family=op_family.name,
                request_id=f"synthetic:{op_family.name}",
                timestamp="", decision_id=None,
                input_path="(structural)", policy_package="(structural)",
                decision=None,
                decision_logged=(self._log_enabled is not False),
                bundle_active=self._bundle_active,
                policy_version_recorded=False,
                error=None, raw={},
            )]
        return instances

    def _parse_decision(self, entry: dict) -> ExecutionInstance:
        return ExecutionInstance(
            operation_family="policy_evaluation",
            request_id=entry.get("request_id", entry.get("_id", "")),
            timestamp=str(entry.get("timestamp", entry.get("ts", ""))),
            decision_id=entry.get("decision_id"),
            input_path=entry.get("labels", {}).get("policy_path", ""),
            policy_package=entry.get("labels", {}).get("policy_id", ""),
            decision=str(entry.get("result", entry.get("decision", ""))),
            decision_logged=True,
            bundle_active=self._bundle_active,
            policy_version_recorded=bool(
                entry.get("labels", {}).get("policy_id") or
                entry.get("metrics", {}).get("timer_rego_query_eval_ns")
            ),
            error=entry.get("error"),
            raw=entry,
        )

    def assess_k(self, inst: ExecutionInstance) -> list[str]:
        k = []
        fam = next((f for f in OPA_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        declared = fam.declared_layers

        if "policy_package" in declared and inst.policy_package:
            k.append("policy_package")
        if "decision_log" in declared:
            if inst.decision_logged and self._log_enabled is not False:
                k.append("decision_log")
        if "bundle_status" in declared and inst.bundle_active:
            k.append("bundle_status")
        if "policy_version" in declared and inst.policy_version_recorded:
            k.append("policy_version")
        if "management_auth" in declared and self._mgmt_auth:
            k.append("management_auth")
        return k

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """
        OPA EAR state:
        All families: CRYSTALLIZED when log is configured, ABSENT when not.
        No family reaches ACTIVE — log write is not constitutive of evaluation.
        """
        if self._log_enabled is False:
            return EARState.ABSENT
        if self._log_enabled is True or self._log:
            return EARState.CRYSTALLIZED
        # Default OPA deployment: decision log not configured
        return EARState.ABSENT

    def get_governance_declaration(self) -> GovernanceDeclaration:
        return self.GOVERNANCE_DECLARATION

    def summary(self) -> dict:
        families = self.collect_operation_families()
        return {
            "decision_log_enabled": self._log_enabled,
            "management_auth_enabled": self._mgmt_auth,
            "bundle_active": self._bundle_active,
            "ear_states": {f.name: self.assess_ear_state(f).value for f in families},
        }
