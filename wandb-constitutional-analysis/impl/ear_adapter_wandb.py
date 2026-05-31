"""
ear_adapter_wandb.py — Weights & Biases (W&B) EAR Adapter
Wave 15 — System 72. Commercial ML experiment tracking and model governance.

Key finding: W&B extends MLflow (Wave 14, T1815) with a critical new
constitutional dimension: third-party governance custody. W&B, Comet, Neptune
and similar commercial ML platforms are third-party custody holders for
governance evidence — they hold experiment metadata, model versions, run
lineage, and deployment records externally to the organization.

New constitutional concept: third-party governance custody — governance
evidence held by a party the organization cannot unilaterally control.
The constitutional question: what happens to model governance evidence
if W&B: (a) has a service outage, (b) changes terms of service,
(c) is acquired, (d) suffers a data breach?

This is constitutionally Level 0 in the receipt hierarchy (T1683): governance
evidence held externally, like Certificate Transparency logs (T1779).
CT logs are constitutively external because CAs must submit to them.
W&B governance evidence is voluntarily external — the organization chooses
to store it at W&B. If W&B is unavailable, the governance evidence is unavailable.

W&B also introduces the commercial ML governance model vs open-source:
W&B enforces model access controls via Teams and Projects with RBAC.
This is CRYSTALLIZED — configurable, not constitutive.

No public CVEs of constitutional significance in corpus period.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; wandb_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; rbac_enforced: bool
    external_custody: bool; audit_logged: bool
    data_exportable: bool; sso_configured: bool
    project: str|None; artifact_version: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

WANDB_OPERATION_FAMILIES = [
    OperationFamily("run_logging",
        "Log experiment run metrics, parameters, artifacts to W&B",
        ["auth_required","rbac_check","external_custody","audit_log"], "log"),
    OperationFamily("artifact_registry",
        "Register model artifact version in W&B Artifact Registry",
        ["auth_required","rbac_check","external_custody","artifact_lineage"], "artifact"),
    OperationFamily("model_promotion",
        "Promote model version to production via W&B Registry aliases",
        ["auth_required","rbac_check","external_custody","approval_workflow"], "promote"),
    OperationFamily("data_access",
        "Access stored experiments, artifacts, or model runs",
        ["auth_required","rbac_check","external_custody","audit_log"], "access"),
    OperationFamily("governance_export",
        "Export governance evidence (runs, artifacts) for sovereignty",
        ["auth_required","external_custody","data_exportable"], "export"),
]

WANDB_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "W&B authentication (API key / SSO)", None),
    "rbac_check": GovernanceLayer("rbac_check",
        "W&B Teams/Projects RBAC — role-based access control", None),
    "external_custody": GovernanceLayer("external_custody",
        "Governance evidence stored at W&B (third-party custody)", "external"),
    "audit_log": GovernanceLayer("audit_log",
        "W&B audit log for enterprise tier", None, is_optional=True),
    "artifact_lineage": GovernanceLayer("artifact_lineage",
        "W&B artifact lineage — traces artifact through pipeline runs", "lineage"),
    "approval_workflow": GovernanceLayer("approval_workflow",
        "W&B Registry model approval workflow (enterprise)", None, is_optional=True),
    "data_exportable": GovernanceLayer("data_exportable",
        "Governance evidence exportable for organizational sovereignty", None, is_optional=True),
}

class WandBEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="W&B documentation + third-party custody analysis + CT log comparison T1779",
        strategy="DECLARED-N",
        description=(
            "N(O) from W&B architecture. run_logging N=4. "
            "New constitutional concept: third-party governance custody — "
            "governance evidence held by party organization cannot unilaterally control. "
            "W&B, Comet, Neptune: commercially hosted ML governance evidence. "
            "Constitutional comparison to CT logs (T1779): "
            "CT logs are constitutively external (CAs must submit). "
            "W&B governance evidence is voluntarily external. "
            "If W&B is unavailable: governance evidence unavailable. "
            "W&B service outage 2024: several documented outages affecting run logging. "
            "RBAC: CRYSTALLIZED — Teams/Projects with roles, not constitutive. "
            "Audit log: enterprise tier only (commercial governance paywalling analog to T1784). "
            "Model promotion approval: enterprise tier only. "
            "No public CVEs of constitutional significance in corpus period. "
            "Third-party custody means: organizational governance evidence sovereignty "
            "depends on W&B's service availability and terms."
        ),
    )
    def __init__(self, auth_enabled: bool=True, rbac_configured: bool=True,
                 audit_log_enabled: bool=False, data_exportable: bool=False):
        self._auth = auth_enabled
        self._rbac = rbac_configured
        self._audit = audit_log_enabled
        self._export = data_exportable

    def collect_operation_families(self): return WANDB_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [WANDB_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in WANDB_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, rbac_enforced=self._rbac,
            external_custody=True, audit_logged=self._audit,
            data_exportable=self._export, sso_configured=False,
            project=None, artifact_version=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in WANDB_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "external_custody" in fam.declared_layers: k.append("external_custody")  # always present
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "artifact_lineage" in fam.declared_layers: k.append("artifact_lineage")
        if "data_exportable" in fam.declared_layers and self._export: k.append("data_exportable")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED  # all W&B families CRYSTALLIZED max
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
