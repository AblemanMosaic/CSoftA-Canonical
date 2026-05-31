"""
ear_adapter_aws_sso.py — AWS IAM Identity Center (SSO) EAR Adapter
Wave 7 — System 33. Federated identity governance.

Key finding: AWS IAM Identity Center (formerly AWS SSO) extends the
AWS IAM analysis (Wave 4, T1630) to the federated identity layer.
Identity Center governs which users/groups from an IdP (Okta, Azure AD,
Entra) get which permission sets in which AWS accounts. The permission set
assignment is constitutively enforced: without an assignment, the user
cannot access the account. CloudTrail records Identity Center events.
The gap: permission set assignments can be overly broad (predefined
PowerUserAccess or AdministratorAccess), IdP synchronization failures
can leave stale assignments, and the federation trust relationship itself
is a governance surface (if the IdP is compromised, all federated
identities are compromised).
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
    name: str; description: str; declared_layers: list[str]; sso_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    cloudtrail_logged: bool; assignment_verified: bool
    mfa_verified: bool; session_scoped: bool
    idp_synced: bool; permission_set_reviewed: bool
    account_id: str|None; principal: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

SSO_OPERATION_FAMILIES = [
    OperationFamily("federated_login",
        "User authenticates via IdP and receives AWS SSO session",
        ["cloudtrail_event","idp_assertion","permission_set","mfa_context"], "login"),
    OperationFamily("permission_set_assignment",
        "Assign permission set to user/group in AWS account",
        ["cloudtrail_event","permission_set","assignment_scope"], "assign"),
    OperationFamily("session_credential_issuance",
        "Issue temporary credentials for SSO session to account",
        ["cloudtrail_event","permission_set","sts_session"], "session"),
    OperationFamily("idp_synchronization",
        "Sync users/groups from external IdP into Identity Center",
        ["cloudtrail_event","idp_sync_log","group_membership"], "sync"),
    OperationFamily("permission_set_management",
        "Create/update/delete permission set definition",
        ["cloudtrail_event","permission_set","audit_trail"], "perm_set"),
]

SSO_GOVERNANCE_LAYERS = {
    "cloudtrail_event": GovernanceLayer("cloudtrail_event",
        "CloudTrail event for Identity Center operation", "eventSource: sso.amazonaws.com"),
    "idp_assertion": GovernanceLayer("idp_assertion",
        "SAML/OIDC assertion from external IdP", "saml:Assertion"),
    "permission_set": GovernanceLayer("permission_set",
        "Permission set granting policies in target account", "PermissionSetArn"),
    "mfa_context": GovernanceLayer("mfa_context",
        "MFA context from IdP authentication", None, is_optional=True),
    "assignment_scope": GovernanceLayer("assignment_scope",
        "Scope of permission set assignment (account/OU)", "PrincipalType"),
    "sts_session": GovernanceLayer("sts_session",
        "STS temporary credential issued for SSO session", "Credentials"),
    "idp_sync_log": GovernanceLayer("idp_sync_log",
        "SCIM sync log from IdP to Identity Center", None),
    "group_membership": GovernanceLayer("group_membership",
        "Group membership determining account access", "GroupId"),
    "audit_trail": GovernanceLayer("audit_trail",
        "CloudTrail audit trail for permission set changes", None),
}

class AWSSSOEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS IAM Identity Center Documentation + AWS CloudTrail + AWS Security Reference Architecture",
        strategy="DECLARED-N",
        description=(
            "N(O) from Identity Center architecture. federated_login N=4. "
            "session_credential_issuance: ACTIVE — temporary credentials constitutive "
            "of account access; CloudTrail records issuance. "
            "permission_set_assignment: CRYSTALLIZED — assignment exists in Identity Center "
            "but permission set scope (PowerUserAccess, AdministratorAccess) may be overly broad. "
            "IdP compromise propagation: if IdP (Okta, Azure AD) is compromised, "
            "all federated identities are compromised — the federation trust is "
            "the upstream governance boundary (T1613 upstream inheritance applies). "
            "IdP sync staleness: group membership changes in IdP may not propagate "
            'immediately to Identity Center — CRYSTALLIZED "stale assignment" gap.'
        ),
    )
    def __init__(self, cloudtrail_enabled: bool=True, mfa_required: bool=False,
                 permission_set_reviewed: bool=False, idp_synced: bool=True):
        self._ct = cloudtrail_enabled
        self._mfa = mfa_required
        self._reviewed = permission_set_reviewed
        self._synced = idp_synced

    def collect_operation_families(self): return SSO_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [SSO_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in SSO_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            cloudtrail_logged=self._ct, assignment_verified=True,
            mfa_verified=self._mfa, session_scoped=True,
            idp_synced=self._synced, permission_set_reviewed=self._reviewed,
            account_id=None, principal=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in SSO_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "cloudtrail_event" in fam.declared_layers and self._ct: k.append("cloudtrail_event")
        if "idp_assertion" in fam.declared_layers: k.append("idp_assertion")
        if "permission_set" in fam.declared_layers: k.append("permission_set")
        if "mfa_context" in fam.declared_layers and self._mfa: k.append("mfa_context")
        if "assignment_scope" in fam.declared_layers: k.append("assignment_scope")
        if "sts_session" in fam.declared_layers: k.append("sts_session")
        if "idp_sync_log" in fam.declared_layers and self._synced: k.append("idp_sync_log")
        if "group_membership" in fam.declared_layers and self._synced: k.append("group_membership")
        if "audit_trail" in fam.declared_layers and self._ct: k.append("audit_trail")
        return k
    def assess_ear_state(self, op_family):
        if not self._ct: return EARState.ABSENT
        if op_family.name == "session_credential_issuance": return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
