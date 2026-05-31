"""
ear_adapter_aws_secrets_manager.py — AWS Secrets Manager EAR Adapter
Wave 9 — System 45. Managed secrets governance.

Key finding: AWS Secrets Manager is the AWS-native managed secrets case,
complementing HashiCorp Vault (Wave 1, T1652). The critical difference from
Vault: Secrets Manager provides automatic rotation via Lambda functions —
when rotation is configured, secret rotation is constitutive (the rotation
happens on schedule; the secret consumer gets the new value transparently).
The rotation is ACTIVE in the sense that it happens without operator
intervention, but the rotation event itself is CRYSTALLIZED: it is recorded
in CloudTrail but the secret consumer does not know when rotation happened.
Access to Secrets Manager secrets is governed by resource-based secret
policies combined with IAM policies — the same dual-evaluation model as
KMS key policies. The KMS encryption dependency (T1723) applies: secrets
are encrypted with KMS CMKs or AWS-managed keys.
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
    name: str; description: str; declared_layers: list[str]; sm_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    cloudtrail_logged: bool; secret_policy_evaluated: bool
    rotation_enabled: bool; kms_encrypted: bool
    cross_account_restricted: bool; resource_policy_set: bool
    secret_arn: str|None; principal: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

SM_OPERATION_FAMILIES = [
    OperationFamily("secret_read",
        "Read secret value (GetSecretValue API)",
        ["secret_policy","cloudtrail_event","kms_encryption","rotation_state"], "read"),
    OperationFamily("secret_rotation",
        "Rotate secret automatically via Lambda function",
        ["rotation_config","cloudtrail_event","kms_encryption","lambda_execution"], "rotate"),
    OperationFamily("secret_management",
        "Create/update/delete secret or secret metadata",
        ["secret_policy","cloudtrail_event","kms_encryption","deletion_protection"], "manage"),
    OperationFamily("cross_account_access",
        "Access secret from a different AWS account",
        ["secret_policy","cloudtrail_event","cross_account_guard"], "cross"),
    OperationFamily("secret_policy_management",
        "Create/update resource-based secret policy",
        ["secret_policy","cloudtrail_event","least_privilege_policy"], "policy"),
]

SM_GOVERNANCE_LAYERS = {
    "secret_policy": GovernanceLayer("secret_policy",
        "Resource-based secret policy + IAM policy evaluated", "ResourcePolicy"),
    "cloudtrail_event": GovernanceLayer("cloudtrail_event",
        "CloudTrail event for Secrets Manager API operation", "eventSource: secretsmanager"),
    "kms_encryption": GovernanceLayer("kms_encryption",
        "Secret encrypted with CMK (not AWS-managed key)", "KmsKeyId"),
    "rotation_state": GovernanceLayer("rotation_state",
        "Secret rotation status (enabled/disabled, last rotated)", "RotationEnabled"),
    "rotation_config": GovernanceLayer("rotation_config",
        "Rotation Lambda function and schedule configured", "RotationLambdaARN"),
    "lambda_execution": GovernanceLayer("lambda_execution",
        "Lambda function executes rotation — automatic", None),
    "deletion_protection": GovernanceLayer("deletion_protection",
        "Deletion protection via resource policy Deny", None, is_optional=True),
    "cross_account_guard": GovernanceLayer("cross_account_guard",
        "Cross-account access restricted in secret policy", None),
    "least_privilege_policy": GovernanceLayer("least_privilege_policy",
        "Secret policy grants only needed actions per principal", None),
}

class AWSSecretsManagerEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS Secrets Manager Documentation + CIS AWS Benchmark + Vault comparison",
        strategy="DECLARED-N",
        description=(
            "N(O) from Secrets Manager architecture. secret_read N=4. "
            "secret_rotation (when configured): ACTIVE-adjacent — rotation happens "
            'automatically without operator intervention; KMS encryption + CloudTrail '
            'record each rotation. But rotation trigger is scheduled, not per-read. '
            "Complements Vault (T1652): Vault = self-hosted dynamic secrets; "
            "Secrets Manager = AWS-managed static secrets with automatic rotation. "
            "KMS dependency (T1723): secrets encrypted with CMK — "
            "KMS governance quality bounds Secrets Manager governance. "
            "Cross-account access via resource policy: broader attack surface "
            "than single-account secrets. "
            "GuardDuty finding: GetSecretValue from known threat actor IP "
            "— CRYSTALLIZED detection after the read."
        ),
    )
    def __init__(self, cloudtrail_enabled: bool=True, rotation_enabled: bool=False,
                 kms_cmk: bool=False, cross_account_restricted: bool=True,
                 deletion_protected: bool=False):
        self._ct = cloudtrail_enabled
        self._rotation = rotation_enabled
        self._kms = kms_cmk
        self._cross = cross_account_restricted
        self._delete = deletion_protected

    def collect_operation_families(self): return SM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [SM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in SM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            cloudtrail_logged=self._ct, secret_policy_evaluated=True,
            rotation_enabled=self._rotation, kms_encrypted=self._kms,
            cross_account_restricted=self._cross, resource_policy_set=True,
            secret_arn=None, principal=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in SM_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "secret_policy" in fam.declared_layers: k.append("secret_policy")
        if "cloudtrail_event" in fam.declared_layers and self._ct: k.append("cloudtrail_event")
        if "kms_encryption" in fam.declared_layers and self._kms: k.append("kms_encryption")
        if "rotation_state" in fam.declared_layers and self._rotation: k.append("rotation_state")
        if "rotation_config" in fam.declared_layers and self._rotation: k.append("rotation_config")
        if "lambda_execution" in fam.declared_layers and self._rotation: k.append("lambda_execution")
        if "deletion_protection" in fam.declared_layers and self._delete: k.append("deletion_protection")
        if "cross_account_guard" in fam.declared_layers and self._cross: k.append("cross_account_guard")
        if "least_privilege_policy" in fam.declared_layers: k.append("least_privilege_policy")
        return k
    def assess_ear_state(self, op_family):
        if not self._ct: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
