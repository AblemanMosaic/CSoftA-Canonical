"""
ear_adapter_workload_identity.py — Workload Identity EAR Adapter
Wave 9 — System 44. Runtime pod-to-cloud identity federation.

Key finding: Workload Identity (AWS IRSA, GKE Workload Identity, Azure Workload
Identity) is the runtime identity federation mechanism that closes the long-lived
credential gap identified in Crossplane (T1731), Argo Workflows (T1724),
and Wave 5 Terraform (T1671). Instead of mounting cloud credentials as
Kubernetes Secrets, pods receive short-lived OIDC tokens from the Kubernetes
token projection API, which are exchanged for cloud provider temporary credentials.
The exchange is ACTIVE: the Kubernetes OIDC token is constitutive of the
cloud credential exchange — without a valid token from the projected ServiceAccount,
the cloud provider rejects the request. The OIDC token is short-lived
(configurable, typically 1h-12h) and bound to a specific ServiceAccount,
namespace, and cloud IAM role.
This is the upstream governance boundary solution: it converts the
governance quality of the cloud access from min(cluster, cloud provider)
to the cloud provider's IAM evaluation of the OIDC token claim.
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
    name: str; description: str; declared_layers: list[str]; wi_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    oidc_token_valid: bool; role_annotated: bool
    token_expiry_short: bool; cloudtrail_logged: bool
    sa_namespace_bound: bool; audience_restricted: bool
    service_account: str|None; cloud_role: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

WI_OPERATION_FAMILIES = [
    OperationFamily("credential_exchange",
        "Exchange Kubernetes OIDC token for cloud provider temporary credentials",
        ["oidc_token","role_annotation","cloudtrail_event","token_expiry"], "exchange"),
    OperationFamily("sa_annotation",
        "Annotate ServiceAccount with cloud IAM role ARN/identifier",
        ["role_annotation","rbac_check","sa_namespace_scope"], "annotate"),
    OperationFamily("token_projection",
        "Project short-lived OIDC token into pod via ServiceAccount token volume",
        ["oidc_token","token_expiry","audience_restriction"], "project"),
    OperationFamily("role_assumption",
        "Assume cloud IAM role via OIDC federation (STS AssumeRoleWithWebIdentity)",
        ["oidc_token","role_annotation","cloudtrail_event","iam_trust_policy"], "assume"),
    OperationFamily("trust_policy_governance",
        "Govern cloud IAM role trust policy for OIDC federation",
        ["iam_trust_policy","cloudtrail_event","role_annotation"], "trust"),
]

WI_GOVERNANCE_LAYERS = {
    "oidc_token": GovernanceLayer("oidc_token",
        "Kubernetes-projected OIDC token — short-lived, SA-bound, constitutive of exchange", None),
    "role_annotation": GovernanceLayer("role_annotation",
        "ServiceAccount annotated with cloud IAM role identifier", "eks.amazonaws.com/role-arn"),
    "cloudtrail_event": GovernanceLayer("cloudtrail_event",
        "CloudTrail/cloud audit event for credential exchange (STS AssumeRoleWithWebIdentity)", None),
    "token_expiry": GovernanceLayer("token_expiry",
        "Token expiry configured short (default 1h for IRSA)", None),
    "sa_namespace_scope": GovernanceLayer("sa_namespace_scope",
        "ServiceAccount annotation scoped to specific namespace and SA", None),
    "audience_restriction": GovernanceLayer("audience_restriction",
        "Token audience restricted to cloud provider STS endpoint", None),
    "iam_trust_policy": GovernanceLayer("iam_trust_policy",
        "IAM role trust policy restricts to specific K8s ServiceAccount/namespace", None),
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC governs ServiceAccount annotation (who can annotate)", None),
}

class WorkloadIdentityEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS IRSA documentation + GKE Workload Identity + Azure Workload Identity docs",
        strategy="DECLARED-N",
        description=(
            "N(O) from Workload Identity architecture. credential_exchange N=4. "
            "credential_exchange: ACTIVE — OIDC token constitutive of credential exchange; "
            "without valid projected SA token, cloud provider rejects request. "
            "Closes the long-lived credential gap: "
            "no Kubernetes Secrets with cloud credentials, no rotation burden, "
            "no credential theft via Secret read. "
            "Closes T1731 (Crossplane provider creds), T1724 (Argo Workflows SA), "
            "T1671 (Terraform provider credentials in state). "
            "Trust policy governance is the remaining gap: "
            "an overly broad trust policy (allowing any SA in any namespace) "
            "negates the namespace-scoping benefit. "
            "Same T1613 upstream chain: cloud IAM trust evaluation is upstream boundary."
        ),
    )
    def __init__(self, oidc_configured: bool=True, token_expiry_short: bool=True,
                 trust_policy_scoped: bool=False, cloudtrail_enabled: bool=True,
                 audience_restricted: bool=True):
        self._oidc = oidc_configured
        self._expiry = token_expiry_short
        self._trust = trust_policy_scoped
        self._ct = cloudtrail_enabled
        self._audience = audience_restricted

    def collect_operation_families(self): return WI_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [WI_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in WI_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            oidc_token_valid=self._oidc, role_annotated=True,
            token_expiry_short=self._expiry, cloudtrail_logged=self._ct,
            sa_namespace_bound=self._trust, audience_restricted=self._audience,
            service_account=None, cloud_role=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in WI_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "oidc_token" in fam.declared_layers and self._oidc: k.append("oidc_token")
        if "role_annotation" in fam.declared_layers: k.append("role_annotation")
        if "cloudtrail_event" in fam.declared_layers and self._ct: k.append("cloudtrail_event")
        if "token_expiry" in fam.declared_layers and self._expiry: k.append("token_expiry")
        if "sa_namespace_scope" in fam.declared_layers and self._trust: k.append("sa_namespace_scope")
        if "audience_restriction" in fam.declared_layers and self._audience: k.append("audience_restriction")
        if "iam_trust_policy" in fam.declared_layers and self._trust: k.append("iam_trust_policy")
        if "rbac_check" in fam.declared_layers: k.append("rbac_check")
        return k
    def assess_ear_state(self, op_family):
        if not self._oidc: return EARState.ABSENT
        if op_family.name in ("credential_exchange", "role_assumption"): return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
