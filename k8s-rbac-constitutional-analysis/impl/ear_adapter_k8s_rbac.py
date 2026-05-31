"""
ear_adapter_k8s_rbac.py — Kubernetes RBAC EAR Adapter
Wave 9 — System 41. Authorization governance engine.

Key finding: Kubernetes RBAC is the primary authorization mechanism for all
Kubernetes API operations — every operation in every wave that involves a
Kubernetes API call is governed by RBAC. Yet the RBAC engine itself, as a
system, is CRYSTALLIZED at best: RBAC policies are evaluated per request
(constitutive of authorization decisions), but the policies themselves are
rarely audited, frequently contain wildcard permissions, and have well-documented
privilege escalation chains. KENSAI research: 58% of production clusters contain
RBAC misconfigs enabling escalation to cluster-admin.
Critical escalation verbs: bind, escalate, impersonate, create rolebindings.
These are governance-of-governance: a principal with 'create clusterrolebindings'
can grant themselves or others any permission in the cluster.
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
    name: str; description: str; declared_layers: list[str]; rbac_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; audit_logged: bool
    least_privilege_applied: bool; escalation_paths_reviewed: bool
    stale_bindings_removed: bool; wildcard_free: bool
    subject: str|None; resource: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

RBAC_OPERATION_FAMILIES = [
    OperationFamily("api_authorization",
        "Authorize Kubernetes API request via RBAC policy evaluation",
        ["rbac_policy","audit_log","least_privilege","escalation_control"], "authz"),
    OperationFamily("role_management",
        "Create/update/delete Role or ClusterRole",
        ["rbac_policy","audit_log","wildcard_guard","escalation_control"], "role"),
    OperationFamily("binding_management",
        "Create/update/delete RoleBinding or ClusterRoleBinding",
        ["rbac_policy","audit_log","binding_scope","escalation_control"], "bind"),
    OperationFamily("serviceaccount_governance",
        "Govern ServiceAccount token mounting and RBAC assignments",
        ["rbac_policy","audit_log","sa_token_scope","least_privilege"], "sa"),
    OperationFamily("rbac_audit",
        "Audit RBAC policies for privilege escalation paths",
        ["rbac_policy","audit_log","escalation_control","stale_binding_review"], "audit"),
]

RBAC_GOVERNANCE_LAYERS = {
    "rbac_policy": GovernanceLayer("rbac_policy",
        "RBAC policy evaluated for every API request", "authorization.k8s.io"),
    "audit_log": GovernanceLayer("audit_log",
        "Kubernetes audit log recording RBAC decisions", None, is_optional=True),
    "least_privilege": GovernanceLayer("least_privilege",
        "Least-privilege principle applied — no wildcards, minimal verbs", None),
    "escalation_control": GovernanceLayer("escalation_control",
        "Escalation verbs (bind/escalate/impersonate) restricted", None),
    "wildcard_guard": GovernanceLayer("wildcard_guard",
        "No wildcard apiGroups/resources/verbs in roles", None),
    "binding_scope": GovernanceLayer("binding_scope",
        "RoleBinding scope restricted to namespace; no cluster-admin bindings", None),
    "sa_token_scope": GovernanceLayer("sa_token_scope",
        "ServiceAccount token projection scoped to audience/time", None, is_optional=True),
    "stale_binding_review": GovernanceLayer("stale_binding_review",
        "Stale/orphaned RoleBindings reviewed and removed", None, is_optional=True),
}

class K8sRBACSEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Kubernetes RBAC Documentation + KENSAI cluster audit research + CIS K8s Benchmark",
        strategy="DECLARED-N",
        description=(
            "N(O) from Kubernetes RBAC architecture. api_authorization N=4. "
            "CRYSTALLIZED: RBAC policy evaluated per request — constitutive of authorization. "
            "But policy content governance is ABSENT by default: "
            "no mandatory least-privilege enforcement, no wildcard detection, "
            "no escalation verb restriction. "
            "KENSAI 2026 research: 58% of 12,000 production clusters have "
            "RBAC misconfigs enabling cluster-admin escalation. "
            "Average time from pod compromise to cluster-admin: 3.2 minutes "
            "using automated tools (peirates). "
            "Critical escalation primitives: create/update rolebindings, bind verb, "
            "escalate verb, impersonate verb — each sufficient for full privilege escalation. "
            "Governance-of-governance: RBAC governs all other K8s governance mechanisms."
        ),
    )
    def __init__(self, audit_log_enabled: bool=False, least_privilege_enforced: bool=False,
                 escalation_verbs_restricted: bool=False, wildcards_prohibited: bool=False,
                 stale_bindings_reviewed: bool=False):
        self._audit = audit_log_enabled
        self._lp = least_privilege_enforced
        self._escalation = escalation_verbs_restricted
        self._wildcards = wildcards_prohibited
        self._stale = stale_bindings_reviewed

    def collect_operation_families(self): return RBAC_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [RBAC_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in RBAC_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=True, audit_logged=self._audit,
            least_privilege_applied=self._lp, escalation_paths_reviewed=self._escalation,
            stale_bindings_removed=self._stale, wildcard_free=self._wildcards,
            subject=None, resource=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in RBAC_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rbac_policy" in fam.declared_layers: k.append("rbac_policy")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "least_privilege" in fam.declared_layers and self._lp: k.append("least_privilege")
        if "escalation_control" in fam.declared_layers and self._escalation: k.append("escalation_control")
        if "wildcard_guard" in fam.declared_layers and self._wildcards: k.append("wildcard_guard")
        if "binding_scope" in fam.declared_layers and self._lp: k.append("binding_scope")
        if "sa_token_scope" in fam.declared_layers and self._lp: k.append("sa_token_scope")
        if "stale_binding_review" in fam.declared_layers and self._stale: k.append("stale_binding_review")
        return k
    def assess_ear_state(self, op_family):
        # api_authorization: ACTIVE — RBAC is constitutive of API request processing
        if op_family.name == "api_authorization":
            return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
