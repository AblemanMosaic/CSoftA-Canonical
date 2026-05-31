"""
ear_adapter_kubeflow.py — Kubeflow Pipelines EAR Adapter
Wave 15 — System 71. K8s-native ML pipeline orchestration.

Key finding: Kubeflow applies MLflow's model governance gap (T1810) to the
K8s-native pipeline execution layer. Kubeflow Pipelines runs ML training
jobs as Kubernetes workloads — which means every governance finding from
the K8s corpus applies (K8s RBAC T1742, Admission T1739, etc.), plus
the ML-specific surfaces: dataset provenance, training environment provenance,
and model artifact signing.

Kubeflow extends T1613 (upstream inheritance): Kubeflow pipeline governance
completeness is bounded by the K8s governance completeness of the cluster
it runs on. A Kubeflow pipeline that violates OPA admission (ACTIVE) cannot
complete without governance completing. But the ML-specific governance of
the pipeline artifact itself — the compiled pipeline YAML specifying
data sources, training steps, model outputs — is ABSENT by default.

Kubeflow 1.9 (2024) security enhancements: network policies, Oauth2-proxy,
CVE scanning in the release process, Argo Workflows backend upgraded
(accumulated CVEs resolved). This is CRYSTALLIZED-forward for pipeline
execution governance.

Kubeflow 1.10 (2025): platform release with CNCF incubation milestone.
Multi-user isolation via Kubernetes namespace RBAC — CRYSTALLIZED.
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
    name: str; description: str; declared_layers: list[str]; kf_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    k8s_rbac: bool; pipeline_signed: bool
    multi_user_isolated: bool; audit_logged: bool
    model_provenance: bool; argo_secured: bool
    namespace: str|None; pipeline_run: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

KF_OPERATION_FAMILIES = [
    OperationFamily("pipeline_run",
        "Execute Kubeflow pipeline run (ML training workflow)",
        ["k8s_rbac","audit_log","pipeline_provenance","multi_user_isolation"], "run"),
    OperationFamily("pipeline_upload",
        "Upload/register pipeline definition to Kubeflow",
        ["k8s_rbac","pipeline_provenance","audit_log"], "upload"),
    OperationFamily("model_promotion",
        "Promote trained model from pipeline output to registry",
        ["k8s_rbac","model_provenance","approval_workflow","audit_log"], "promote"),
    OperationFamily("notebook_access",
        "Access Kubeflow Jupyter notebook server",
        ["k8s_rbac","multi_user_isolation","network_policy","audit_log"], "nb"),
    OperationFamily("artifact_access",
        "Read/write ML artifacts (datasets, models, metrics) from artifact store",
        ["k8s_rbac","audit_log","artifact_integrity"], "artifact"),
]

KF_GOVERNANCE_LAYERS = {
    "k8s_rbac": GovernanceLayer("k8s_rbac",
        "Kubernetes RBAC governing Kubeflow namespace access", None),
    "audit_log": GovernanceLayer("audit_log",
        "Kubernetes audit log for Kubeflow API server operations", None, is_optional=True),
    "pipeline_provenance": GovernanceLayer("pipeline_provenance",
        "Pipeline component provenance — signed, versioned pipeline definitions", None, is_optional=True),
    "multi_user_isolation": GovernanceLayer("multi_user_isolation",
        "Multi-user profile namespace isolation (Kubeflow 1.x)", None),
    "model_provenance": GovernanceLayer("model_provenance",
        "Trained model provenance — pipeline run ID linked to model artifact", None, is_optional=True),
    "approval_workflow": GovernanceLayer("approval_workflow",
        "Production promotion approval gate for trained models", None, is_optional=True),
    "network_policy": GovernanceLayer("network_policy",
        "Kubernetes NetworkPolicy restricting cross-namespace communication", None, is_optional=True),
    "artifact_integrity": GovernanceLayer("artifact_integrity",
        "Artifact checksums/signatures for datasets and model files", None, is_optional=True),
}

class KubeflowEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Kubeflow 1.9/1.10 release notes + K8s RBAC corpus + MLflow T1810 extension",
        strategy="DECLARED-N",
        description=(
            "N(O) from Kubeflow architecture. pipeline_run N=4. "
            "Kubeflow governance ceiling bounded by K8s cluster governance (T1613 upstream inheritance). "
            "K8s RBAC: CRYSTALLIZED — governs pipeline run authorization. "
            "Pipeline provenance: ABSENT by default — no mandatory signing or versioning of pipeline YAML. "
            "Model promotion: extends T1810 (model deployment governance gap) to K8s-native ML. "
            "Multi-user isolation: CRYSTALLIZED — Kubeflow profiles + namespace RBAC. "
            "Kubeflow 1.9 security: network policies, Oauth2-proxy, CVE scanning in release. "
            "Argo Workflows backend (prior versions accumulated CVEs — resolved in 1.9). "
            "No Kubeflow family reaches ACTIVE — ML governance is ABSENT at pipeline and model layers."
        ),
    )
    def __init__(self, k8s_rbac: bool=True, multi_user_isolated: bool=True,
                 pipeline_signed: bool=False, approval_workflow: bool=False):
        self._rbac = k8s_rbac
        self._isolated = multi_user_isolated
        self._signed = pipeline_signed
        self._approval = approval_workflow

    def collect_operation_families(self): return KF_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [KF_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in KF_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            k8s_rbac=self._rbac, pipeline_signed=self._signed,
            multi_user_isolated=self._isolated, audit_logged=False,
            model_provenance=self._signed, argo_secured=True,
            namespace=None, pipeline_run=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in KF_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "k8s_rbac" in fam.declared_layers and self._rbac: k.append("k8s_rbac")
        if "multi_user_isolation" in fam.declared_layers and self._isolated: k.append("multi_user_isolation")
        if "pipeline_provenance" in fam.declared_layers and self._signed: k.append("pipeline_provenance")
        if "model_provenance" in fam.declared_layers and self._signed: k.append("model_provenance")
        if "approval_workflow" in fam.declared_layers and self._approval: k.append("approval_workflow")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        if op_family.name == "model_promotion" and not self._approval: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
