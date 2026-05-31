"""
ear_adapter_argo_workflows.py — Argo Workflows EAR Adapter
Wave 8 — System 38. Workflow orchestration governance.

Key finding: Argo Workflows is distinct from Argo CD (Wave 5, T1669).
Argo CD manages declarative GitOps deployments. Argo Workflows executes
arbitrary containerized workloads on demand — DAGs, CI pipelines,
data processing. The governance distinction: Argo CD's governance
declaration is a Git commit; Argo Workflows' governance declaration
is a Workflow template (YAML in Kubernetes), and each workflow step
executes as a container with a configured ServiceAccount.
The ServiceAccount used for workflow execution is the critical gap:
workflow steps inherit ServiceAccount permissions and can access
any Kubernetes resource those permissions allow. Workflows submitted
by users may use templateRefs pointing to externally-owned templates —
the same supply chain gap as GitHub Actions unpinned actions (T1702)
applied to workflow templates.
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
    name: str; description: str; declared_layers: list[str]; wf_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; service_account_scoped: bool
    audit_logged: bool; template_verified: bool
    artifact_signed: bool; secret_scoped: bool
    workflow_name: str|None; namespace: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

AWF_OPERATION_FAMILIES = [
    OperationFamily("workflow_submission",
        "Submit Workflow or WorkflowTemplate for execution",
        ["rbac_check","audit_log","template_provenance","service_account_scope"], "submit"),
    OperationFamily("step_execution",
        "Execute individual workflow step as container",
        ["service_account_scope","rbac_check","audit_log","secret_access"], "step"),
    OperationFamily("artifact_access",
        "Access workflow artifact (input/output from S3/GCS/etc.)",
        ["artifact_governance","service_account_scope","audit_log"], "artifact"),
    OperationFamily("template_management",
        "Create/update WorkflowTemplate or ClusterWorkflowTemplate",
        ["rbac_check","audit_log","template_provenance"], "template"),
    OperationFamily("secret_access",
        "Access Kubernetes Secret from workflow step",
        ["service_account_scope","rbac_check","audit_log","secret_scope"], "secret"),
]

AWF_GOVERNANCE_LAYERS = {
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC evaluation for workflow submission/template management", None),
    "audit_log": GovernanceLayer("audit_log",
        "Kubernetes audit log for Argo Workflows API operations", None, is_optional=True),
    "template_provenance": GovernanceLayer("template_provenance",
        "WorkflowTemplate provenance — source and integrity verification", None, is_optional=True),
    "service_account_scope": GovernanceLayer("service_account_scope",
        "Workflow ServiceAccount scope — least privilege for execution", "serviceAccountName"),
    "artifact_governance": GovernanceLayer("artifact_governance",
        "Artifact signing and provenance for workflow outputs", None, is_optional=True),
    "secret_access": GovernanceLayer("secret_access",
        "Secret access scope for workflow steps", None),
    "secret_scope": GovernanceLayer("secret_scope",
        "Secret scope restricted to workflow namespace", None),
}

class ArgoWorkflowsEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Argo Workflows Documentation + Argo Workflows Security docs + Argo CD comparison",
        strategy="DECLARED-N",
        description=(
            "N(O) from Argo Workflows architecture. workflow_submission N=4. "
            "CRYSTALLIZED ceiling: RBAC evaluated, audit log available but not default. "
            "Critical gap: service_account_scope — workflow steps inherit "
            "ServiceAccount permissions, which may be overly broad (workflow-controller "
            "default SA has significant cluster access). "
            "Template supply chain: templateRef allows referencing external templates — "
            "same supply chain gap as GitHub Actions unpinned actions (T1702). "
            "CVE-2023-22736 (Argo Workflows namespace bypass): workflows could be "
            "submitted with templateRef pointing to templates in other namespaces, "
            "bypassing namespace isolation. "
            "No Argo Workflows family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, rbac_scoped: bool=True, service_account_scoped: bool=False,
                 audit_log_enabled: bool=False, template_verified: bool=False,
                 artifact_signed: bool=False):
        self._rbac = rbac_scoped
        self._sa_scope = service_account_scoped
        self._audit = audit_log_enabled
        self._tmpl = template_verified
        self._artifact = artifact_signed

    def collect_operation_families(self): return AWF_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [AWF_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in AWF_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=self._rbac, service_account_scoped=self._sa_scope,
            audit_logged=self._audit, template_verified=self._tmpl,
            artifact_signed=self._artifact, secret_scoped=True,
            workflow_name=None, namespace=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in AWF_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "template_provenance" in fam.declared_layers and self._tmpl: k.append("template_provenance")
        if "service_account_scope" in fam.declared_layers and self._sa_scope: k.append("service_account_scope")
        if "artifact_governance" in fam.declared_layers and self._artifact: k.append("artifact_governance")
        if "secret_access" in fam.declared_layers: k.append("secret_access")
        if "secret_scope" in fam.declared_layers: k.append("secret_scope")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
