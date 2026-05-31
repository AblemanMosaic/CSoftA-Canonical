"""
ear_adapter_mlflow.py — MLflow EAR Adapter
Wave 14 — System 69. ML experiment tracking and model registry governance.

Key finding: MLflow introduces model governance — the receipt question for
ML systems: who authorized moving model fraud-detector-v2 to production,
on what evidence, with what governance receipt? This is ABSENT by default
in MLflow: there is no mandatory approval workflow for model stage transitions,
no signed provenance for model artifacts, and no constitutive receipt for
the production promotion decision.

New constitutional concept: model deployment governance gap — the governance
of which model runs in production is architecturally absent in most ML platforms.
MLflow tracks experiments and versions but does not require a receipted
authorization decision for production promotion.

Model artifact as attack vector (CVE-2025-15379, March 2026): command injection
via python_env.yaml embedded in model artifact. A malicious model artifact
can achieve RCE on any system that deploys it. The model registry becomes
a supply chain attack surface — distributing malicious models as legitimate
model versions.

CVE-2025-11201 (October 2025): directory traversal RCE on MLflow Tracking Server
with NO authentication required. Unauthenticated remote attackers can execute
arbitrary code by supplying crafted model file paths.

CVE-2024-0520 (CVSS 10.0): RCE via command injection in dataset source URL handling.
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
    name: str; description: str; declared_layers: list[str]; mlflow_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; audit_logged: bool
    approval_workflow: bool; artifact_signed: bool
    model_versioned: bool; access_controlled: bool
    model_name: str|None; stage: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

MLFLOW_OPERATION_FAMILIES = [
    OperationFamily("model_promotion",
        "Transition model version to Production/Staging/Archived",
        ["auth_required","approval_workflow","audit_log","model_version"], "promote"),
    OperationFamily("experiment_logging",
        "Log experiment run metrics, parameters, artifacts",
        ["auth_required","audit_log","artifact_integrity"], "log"),
    OperationFamily("model_deployment",
        "Deploy model for serving (load artifact, install dependencies)",
        ["auth_required","artifact_integrity","approval_workflow","audit_log"], "deploy"),
    OperationFamily("artifact_access",
        "Read/write model artifacts from artifact store",
        ["auth_required","audit_log","artifact_integrity"], "artifact"),
    OperationFamily("registry_governance",
        "Govern model registry — tags, descriptions, stage transitions",
        ["auth_required","approval_workflow","audit_log","model_version"], "registry"),
]

MLFLOW_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "MLflow tracking server authentication", None),
    "approval_workflow": GovernanceLayer("approval_workflow",
        "Production promotion approval — governed stage transition receipt", None, is_optional=True),
    "audit_log": GovernanceLayer("audit_log",
        "MLflow audit log for registry and experiment operations", None, is_optional=True),
    "model_version": GovernanceLayer("model_version",
        "Model versioning — immutable version numbers with run linkage", "version"),
    "artifact_integrity": GovernanceLayer("artifact_integrity",
        "Model artifact integrity — checksum/signature of model files", None, is_optional=True),
}

class MLflowEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="MLflow documentation + CVE-2025-15379 + CVE-2025-11201 + CVE-2024-0520",
        strategy="DECLARED-N",
        description=(
            "N(O) from MLflow architecture. model_promotion N=4. "
            "model_promotion: ABSENT governance receipt by default — "
            "no mandatory approval workflow; any user with registry write can promote. "
            "New constitutional concept: model deployment governance gap — "
            "the production promotion decision has no constitutive governance receipt. "
            "CVE-2025-11201 (October 2025): directory traversal RCE, NO AUTH required — "
            "unauthenticated RCE on MLflow Tracking Server via model file paths. "
            "CVE-2025-15379 (March 2026): command injection via python_env.yaml in model artifact — "
            "model artifact as execution surface; deploying a malicious model = RCE. "
            "CVE-2024-0520 (CVSS 10.0): RCE via dataset source URL command injection. "
            "Model registry as supply chain: distributing malicious model artifacts "
            "achieves execution on any system that loads the model for serving. "
            "CRYSTALLIZED ceiling with auth + approval workflow; no ACTIVE path by default."
        ),
    )
    def __init__(self, auth_enabled: bool=False, approval_workflow: bool=False,
                 audit_log_enabled: bool=False, artifact_signed: bool=False):
        self._auth = auth_enabled
        self._approval = approval_workflow
        self._audit = audit_log_enabled
        self._signed = artifact_signed

    def collect_operation_families(self): return MLFLOW_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [MLFLOW_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in MLFLOW_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, audit_logged=self._audit,
            approval_workflow=self._approval, artifact_signed=self._signed,
            model_versioned=True, access_controlled=self._auth,
            model_name=None, stage=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in MLFLOW_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "approval_workflow" in fam.declared_layers and self._approval: k.append("approval_workflow")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "model_version" in fam.declared_layers: k.append("model_version")  # always present
        if "artifact_integrity" in fam.declared_layers and self._signed: k.append("artifact_integrity")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name in ("model_promotion", "model_deployment"):
            if not self._auth: return EARState.ABSENT
            if self._approval: return EARState.CRYSTALLIZED
            return EARState.ABSENT  # no approval = no governance receipt for promotion
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
