"""
ear_adapter_aws_iam.py — AWS IAM EAR Adapter
Wave 4 — System 16. Cloud identity and access management at scale.

Key finding: AWS IAM is the corpus's canonical large-scale IAM case.
CloudTrail is ACTIVE-EAR for most IAM operations when enabled and
configured for all regions with log file validation — the API call
cannot be made without CloudTrail recording it (when CloudTrail is
properly configured). However, CloudTrail is opt-in and not enabled
by default on all accounts — ABSENT in unconfigured accounts.
IAM policy evaluation itself is CRYSTALLIZED: policy decisions
are computed but not structurally receipted separately from CloudTrail.
The key gap: IAM has no built-in mandatory audit that cannot be disabled
by a sufficiently privileged actor — the root account can delete
CloudTrail logs and disable CloudTrail entirely.
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
    name: str; description: str; declared_layers: list[str]; iam_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    cloudtrail_recorded: bool; policy_evaluated: bool
    mfa_verified: bool; sts_token_used: bool
    principal: str | None; resource: str | None
    decision: str | None; error: str | None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

IAM_OPERATION_FAMILIES = [
    OperationFamily("api_call_authorization",
        "Authorize API call against IAM policies",
        ["cloudtrail_event","iam_policy","session_context"], "authz"),
    OperationFamily("credential_issuance",
        "Issue temporary credentials via STS AssumeRole",
        ["cloudtrail_event","sts_token","role_trust_policy","mfa_context"], "sts"),
    OperationFamily("policy_management",
        "Create/update/delete IAM policy",
        ["cloudtrail_event","iam_policy","resource_tag"], "policy"),
    OperationFamily("access_analyzer",
        "Analyze resource policy for public/cross-account access",
        ["analyzer_finding","cloudtrail_event","resource_policy"], "analyzer"),
    OperationFamily("root_operation",
        "Operation performed by root account",
        ["cloudtrail_event","mfa_context"], "root"),
]

IAM_GOVERNANCE_LAYERS = {
    "cloudtrail_event": GovernanceLayer("cloudtrail_event",
        "CloudTrail event record — constitutive when CloudTrail enabled with validation",
        "eventID"),
    "iam_policy": GovernanceLayer("iam_policy",
        "IAM policy evaluated for authorization decision", "PolicyDocument"),
    "session_context": GovernanceLayer("session_context",
        "Session context (assumed role, source identity)", "sessionIssuer"),
    "mfa_context": GovernanceLayer("mfa_context",
        "MFA authentication context for sensitive operations", "mfaAuthenticated",
        is_optional=True),
    "sts_token": GovernanceLayer("sts_token",
        "STS temporary credential — short-lived, scoped to role", "Credentials.SessionToken"),
    "role_trust_policy": GovernanceLayer("role_trust_policy",
        "Role trust policy evaluated for AssumeRole", "AssumeRolePolicyDocument"),
    "resource_tag": GovernanceLayer("resource_tag",
        "Resource tag for attribute-based access control", "Tags"),
    "analyzer_finding": GovernanceLayer("analyzer_finding",
        "IAM Access Analyzer finding for public/cross-account exposure", "findingId"),
    "resource_policy": GovernanceLayer("resource_policy",
        "Resource-based policy on S3/KMS/Lambda/etc.", "Policy"),
}

class AWSIAMEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "AWS IAM Documentation + AWS CloudTrail Documentation + "
            "AWS Security Reference Architecture + CIS AWS Foundations Benchmark"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) from AWS IAM architecture. api_call_authorization N=4. "
            "CloudTrail event: ACTIVE when CloudTrail enabled with log file validation "
            "across all regions and management events — every API call is recorded. "
            "ABSENT when CloudTrail not configured (default for new accounts). "
            "Critical gap: root account can delete CloudTrail logs and disable CloudTrail — "
            "no IAM-native protection prevents this. "
            "credential_issuance (STS AssumeRole): ACTIVE with CloudTrail — "
            "short-lived tokens are the credential-as-receipt pattern. "
            "root_operation: CloudTrail records root operations but root can delete logs — "
            "structural bypass exists at the apex of the trust hierarchy."
        ),
    )

    def __init__(self, cloudtrail_enabled: bool=True,
                 cloudtrail_log_validation: bool=True,
                 all_regions_enabled: bool=True,
                 mfa_required: bool=False,
                 is_root: bool=False):
        self._ct = cloudtrail_enabled
        self._ct_validation = cloudtrail_log_validation
        self._all_regions = all_regions_enabled
        self._mfa = mfa_required
        self._root = is_root

    def collect_operation_families(self): return IAM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [IAM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in IAM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        ct_active = self._ct and self._ct_validation and self._all_regions
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            cloudtrail_recorded=ct_active,
            policy_evaluated=True,
            mfa_verified=self._mfa,
            sts_token_used=(op_family.name=="credential_issuance"),
            principal="arn:aws:iam::123456789:user/test" if not self._root else "root",
            resource="*", decision="Allow", error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in IAM_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "cloudtrail_event" in fam.declared_layers and inst.cloudtrail_recorded:
            k.append("cloudtrail_event")
        if "iam_policy" in fam.declared_layers and inst.policy_evaluated:
            k.append("iam_policy")
        if "session_context" in fam.declared_layers and not self._root:
            k.append("session_context")
        if "mfa_context" in fam.declared_layers and inst.mfa_verified:
            k.append("mfa_context")
        if "sts_token" in fam.declared_layers and inst.sts_token_used:
            k.append("sts_token")
        if "role_trust_policy" in fam.declared_layers:
            k.append("role_trust_policy")
        if "analyzer_finding" in fam.declared_layers:
            k.append("analyzer_finding")
        if "resource_policy" in fam.declared_layers:
            k.append("resource_policy")
        return k

    def assess_ear_state(self, op_family):
        ct_full = self._ct and self._ct_validation and self._all_regions
        if not ct_full: return EARState.ABSENT
        # root_operation: CRYSTALLIZED even with CloudTrail — root can delete logs
        if op_family.name == "root_operation": return EARState.CRYSTALLIZED
        # credential_issuance: ACTIVE — STS token is credential-as-receipt
        if op_family.name == "credential_issuance": return EARState.ACTIVE
        # api_call_authorization: ACTIVE with full CloudTrail
        if op_family.name == "api_call_authorization": return EARState.ACTIVE
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
