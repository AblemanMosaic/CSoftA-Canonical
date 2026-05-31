"""
ear_adapter_tekton.py — Tekton Pipelines EAR Adapter
Wave 9 — System 43. Kubernetes-native CI/CD governance.

Key finding: Tekton Pipelines is the Kubernetes-native CI/CD governance case,
complementing GitHub Actions (cloud-hosted, Wave 6, T1686). Tekton executes
pipeline steps (Steps in Tasks, Tasks in Pipelines) as containers on Kubernetes.
Tekton Chains provides supply chain security — recording task runs and
signing results via Cosign, producing SLSA provenance for builds.
When Tekton Chains is enabled with OCI signing, TaskRun results are ACTIVE:
the signing is constitutive of the result being attested.
Without Chains, Tekton governance is CRYSTALLIZED: TaskRun records the
execution result but provenance is absent.
RBAC for Pipeline/Task submission governs who can run what, but the
ServiceAccount used for the pipeline step determines cloud access —
same SA scope gap as Argo Workflows (T1724).
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
    name: str; description: str; declared_layers: list[str]; tekton_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; chains_signing: bool
    provenance_attested: bool; sa_scoped: bool
    audit_logged: bool; results_signed: bool
    pipeline_name: str|None; namespace: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

TEKTON_OPERATION_FAMILIES = [
    OperationFamily("pipeline_execution",
        "Execute PipelineRun — sequence of Tasks",
        ["rbac_check","chains_signing","sa_scope","audit_log"], "pipeline"),
    OperationFamily("task_execution",
        "Execute TaskRun — containerized step sequence",
        ["rbac_check","chains_signing","sa_scope","audit_log","results_signing"], "task"),
    OperationFamily("result_attestation",
        "Attest TaskRun results with Tekton Chains (SLSA provenance)",
        ["chains_signing","rekor_transparency","oidc_identity","results_signing"], "attest"),
    OperationFamily("pipeline_management",
        "Create/update Pipeline or Task definition",
        ["rbac_check","audit_log","definition_provenance"], "manage"),
    OperationFamily("secret_access",
        "Access Kubernetes Secrets from pipeline step",
        ["rbac_check","sa_scope","audit_log"], "secret"),
]

TEKTON_GOVERNANCE_LAYERS = {
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC evaluated for PipelineRun/TaskRun submission", None),
    "chains_signing": GovernanceLayer("chains_signing",
        "Tekton Chains signing of TaskRun results — opt-in", None, is_optional=True),
    "sa_scope": GovernanceLayer("sa_scope",
        "Pipeline ServiceAccount scoped to least privilege", "serviceAccountName"),
    "audit_log": GovernanceLayer("audit_log",
        "Kubernetes audit log for Tekton CRD operations", None, is_optional=True),
    "results_signing": GovernanceLayer("results_signing",
        "TaskRun results signed with Cosign via Tekton Chains", None, is_optional=True),
    "rekor_transparency": GovernanceLayer("rekor_transparency",
        "Chains signature recorded in Rekor transparency log", None, is_optional=True),
    "oidc_identity": GovernanceLayer("oidc_identity",
        "OIDC identity bound to Chains signing certificate", None, is_optional=True),
    "definition_provenance": GovernanceLayer("definition_provenance",
        "Pipeline/Task definition provenance — version-controlled", None, is_optional=True),
}

class TektonEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Tekton Documentation + Tekton Chains documentation + SLSA for Tekton",
        strategy="DECLARED-N",
        description=(
            "N(O) from Tekton architecture. pipeline_execution N=4. "
            "result_attestation with Tekton Chains + Cosign: ACTIVE — "
            "TaskRun results are constitutively signed; unsigned results cannot be "
            "verified by downstream policy-controller enforcement. "
            "Without Chains: CRYSTALLIZED — TaskRun records execution, provenance absent. "
            "Same SA scope gap as Argo Workflows (T1724): "
            "pipeline steps inherit ServiceAccount permissions. "
            "Tekton Chains closes the pipeline-level supply chain gap — "
            "the Kubernetes-native equivalent of GitHub Actions SLSA provenance. "
            "CVE-2023-30845 (Tekton Pipelines, privilege escalation via pipeline step): "
            "steps with create pod permissions could bypass namespace restrictions."
        ),
    )
    def __init__(self, chains_enabled: bool=False, sa_scoped: bool=False,
                 audit_log_enabled: bool=False, rbac_scoped: bool=True):
        self._chains = chains_enabled
        self._sa = sa_scoped
        self._audit = audit_log_enabled
        self._rbac = rbac_scoped

    def collect_operation_families(self): return TEKTON_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [TEKTON_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in TEKTON_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=self._rbac, chains_signing=self._chains,
            provenance_attested=self._chains, sa_scoped=self._sa,
            audit_logged=self._audit, results_signed=self._chains,
            pipeline_name=None, namespace=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in TEKTON_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "chains_signing" in fam.declared_layers and self._chains: k.append("chains_signing")
        if "sa_scope" in fam.declared_layers and self._sa: k.append("sa_scope")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "results_signing" in fam.declared_layers and self._chains: k.append("results_signing")
        if "rekor_transparency" in fam.declared_layers and self._chains: k.append("rekor_transparency")
        if "oidc_identity" in fam.declared_layers and self._chains: k.append("oidc_identity")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        if op_family.name == "result_attestation" and self._chains: return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
