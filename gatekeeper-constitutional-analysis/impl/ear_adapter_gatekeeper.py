"""
ear_adapter_gatekeeper.py — OPA Gatekeeper EAR Adapter
Wave 2 — System 7. Kubernetes-embedded OPA via admission webhook.

Key finding: CRYSTALLIZED ceiling with substrate dependency on Kubernetes (T019).
Violation records on constraint objects exist but are not constitutive of admission decision.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

class EARState(Enum):
    ACTIVE = "ACTIVE"; CRYSTALLIZED = "CRYSTALLIZED"; ABSENT = "ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"; ABSENCE = "ABSENCE"; BYPASS = "BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; gk_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    constraint_matched: bool; webhook_invoked: bool
    violation_recorded: bool; audit_log_present: bool
    resource_kind: str; namespace: str; decision: str | None
    error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

GK_OPERATION_FAMILIES = [
    OperationFamily("admission_evaluation",
        "Admission webhook evaluation of a Kubernetes resource",
        ["constraint_template", "admission_webhook", "audit_log", "violation_record"], "admission"),
    OperationFamily("audit_scan",
        "Periodic audit scan of existing resources against constraints",
        ["constraint_template", "audit_log", "violation_record"], "audit"),
    OperationFamily("constraint_management",
        "Create/update/delete ConstraintTemplate or Constraint",
        ["constraint_template", "admission_webhook"], "management"),
    OperationFamily("mutation",
        "Mutating admission webhook application",
        ["mutation_policy", "admission_webhook"], "mutation"),
]

GK_GOVERNANCE_LAYERS = {
    "constraint_template": GovernanceLayer("constraint_template",
        "ConstraintTemplate/Constraint CRD declaration defining policy", "spec.crd.spec"),
    "admission_webhook": GovernanceLayer("admission_webhook",
        "Admission webhook invocation — Gatekeeper receives AdmissionReview", "webhookConfiguration"),
    "audit_log": GovernanceLayer("audit_log",
        "Audit results on constraint .status.violations and external log", None),
    "violation_record": GovernanceLayer("violation_record",
        "Violation status recorded on constraint object (.status.violations)", "status.violations"),
    "mutation_policy": GovernanceLayer("mutation_policy",
        "Assign/AssignMetadata mutation policy declaration", "spec.applyTo"),
}

class GatekeeperEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Gatekeeper Documentation + OPA Gatekeeper GitHub + Kubernetes Admission Webhook spec",
        strategy="DECLARED-N",
        description=(
            "N(O) from Gatekeeper architecture. "
            "admission_evaluation N=4 but violation_record and audit_log are NON_ACTIVATION by default. "
            "CRYSTALLIZED ceiling: violation record exists but admission decision does not depend on "
            "its successful write. Substrate dependency (T019): Gatekeeper bounded by Kubernetes admission."
        ),
    )

    def __init__(self, violation_records: list[dict] | None = None,
                 audit_enabled: bool = False, webhook_active: bool = True):
        self._violations = violation_records or []
        self._audit = audit_enabled
        self._webhook = webhook_active

    def collect_operation_families(self): return GK_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [GK_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in GK_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        if op_family.name == "admission_evaluation" and self._violations:
            return [ExecutionInstance(
                operation_family="admission_evaluation",
                request_id=v.get("uid", f"gk-{i}"),
                timestamp=str(v.get("timestamp", "")),
                constraint_matched=True, webhook_invoked=self._webhook,
                violation_recorded=True, audit_log_present=self._audit,
                resource_kind=v.get("kind", ""), namespace=v.get("namespace", ""),
                decision="DENY", error=None, raw=v,
            ) for i, v in enumerate(self._violations)]
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            constraint_matched=True, webhook_invoked=self._webhook,
            violation_recorded=False, audit_log_present=self._audit,
            resource_kind="(structural)", namespace="", decision=None, error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in GK_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "constraint_template" in fam.declared_layers and inst.constraint_matched:
            k.append("constraint_template")
        if "admission_webhook" in fam.declared_layers and inst.webhook_invoked:
            k.append("admission_webhook")
        if "audit_log" in fam.declared_layers and inst.audit_log_present:
            k.append("audit_log")
        if "violation_record" in fam.declared_layers and inst.violation_recorded:
            k.append("violation_record")
        if "mutation_policy" in fam.declared_layers:
            k.append("mutation_policy")
        return k

    def assess_ear_state(self, op_family):
        # No GK operation reaches ACTIVE — violation_record is not constitutive
        if not self._webhook: return EARState.ABSENT
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
