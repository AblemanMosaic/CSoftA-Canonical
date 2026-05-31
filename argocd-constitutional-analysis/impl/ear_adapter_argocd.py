"""
ear_adapter_argocd.py — Argo CD EAR Adapter
Wave 5 — System 22. GitOps continuous delivery for Kubernetes.

Key finding: Argo CD has a split governance profile. The Git commit IS a
governance declaration — the desired state is declared in Git with author,
timestamp, and content hash. But the sync operation (applying Git state to
Kubernetes) is CRYSTALLIZED: the sync produces an Application status update
but the sync receipt is not constitutive of the sync operation.
The Application resource tracks sync status but is not a mandatory receipt
per-sync. Most critically: RBAC misconfiguration has produced multiple
CVSS 10.0 vulnerabilities where project-scoped tokens accessed secrets
outside their declared scope — NON_ACTIVATION at the authorization
scope boundary layer.
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
    name: str; description: str; declared_layers: list[str]; argocd_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    git_commit_verified: bool; rbac_evaluated: bool
    sync_status_recorded: bool; audit_logged: bool
    app_name: str|None; revision: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ARGOCD_OPERATION_FAMILIES = [
    OperationFamily("git_sync",
        "Sync application state from Git to Kubernetes cluster",
        ["git_commit","rbac_policy","sync_status","audit_log"], "sync"),
    OperationFamily("application_management",
        "Create/update/delete Argo CD Application",
        ["rbac_policy","audit_log","app_resource"], "app"),
    OperationFamily("secret_access",
        "Access repository credentials or cluster secrets",
        ["rbac_policy","audit_log","credential_scope"], "secret"),
    OperationFamily("cluster_management",
        "Register/update cluster connection",
        ["rbac_policy","audit_log","cluster_secret"], "cluster"),
    OperationFamily("role_binding",
        "Assign RBAC roles to users or groups",
        ["rbac_policy","audit_log"], "rbac"),
]

ARGOCD_GOVERNANCE_LAYERS = {
    "git_commit": GovernanceLayer("git_commit",
        "Git commit — IS the governance declaration with author, hash, timestamp",
        "metadata.annotations.revision"),
    "rbac_policy": GovernanceLayer("rbac_policy",
        "Argo CD RBAC policy evaluated for operation", "argocd-rbac-cm"),
    "sync_status": GovernanceLayer("sync_status",
        "Application sync status — records sync outcome", "status.sync.status"),
    "audit_log": GovernanceLayer("audit_log",
        "Argo CD audit log (Kubernetes audit log upstream)", None, is_optional=True),
    "app_resource": GovernanceLayer("app_resource",
        "Application CRD resource in Argo CD", "spec.source.repoURL"),
    "credential_scope": GovernanceLayer("credential_scope",
        "Credential access scope validation — CVE-2025-55190 class", None),
    "cluster_secret": GovernanceLayer("cluster_secret",
        "Cluster connection secret in argocd namespace", "data.server"),
}

class ArgoCDEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Argo CD Documentation + Argo CD Security Considerations + CVE history",
        strategy="DECLARED-N",
        description=(
            "N(O) from Argo CD architecture. git_sync N=4. "
            "git_commit is a governance declaration: author, timestamp, content hash — "
            "the Git commit IS the declared desired state. "
            "git_sync: CRYSTALLIZED — sync_status records outcome but is not constitutive. "
            "secret_access: CRYSTALLIZED but with documented NON_ACTIVATION at scope boundary — "
            "CVE-2025-55190 (CVSS 10.0): project-scoped tokens accessed repo credentials "
            "outside declared scope. "
            "No Argo CD family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, rbac_enabled: bool=True, audit_log_enabled: bool=False,
                 credential_scope_enforced: bool=True):
        self._rbac = rbac_enabled; self._audit = audit_log_enabled
        self._cred_scope = credential_scope_enforced

    def collect_operation_families(self): return ARGOCD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ARGOCD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ARGOCD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            git_commit_verified=(op_family.name=="git_sync"),
            rbac_evaluated=self._rbac, sync_status_recorded=True,
            audit_logged=self._audit, app_name=None, revision=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ARGOCD_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "git_commit" in fam.declared_layers and inst.git_commit_verified: k.append("git_commit")
        if "rbac_policy" in fam.declared_layers and inst.rbac_evaluated: k.append("rbac_policy")
        if "sync_status" in fam.declared_layers and inst.sync_status_recorded: k.append("sync_status")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "app_resource" in fam.declared_layers: k.append("app_resource")
        if "credential_scope" in fam.declared_layers and self._cred_scope: k.append("credential_scope")
        if "cluster_secret" in fam.declared_layers: k.append("cluster_secret")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
