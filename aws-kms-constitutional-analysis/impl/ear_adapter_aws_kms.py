"""
ear_adapter_aws_kms.py — AWS KMS EAR Adapter
Wave 8 — System 37. Cryptographic governance.

Key finding: AWS KMS is the cryptographic primitive underlying the entire
AWS encryption corpus. S3 SSE-KMS, EBS encryption, Secrets Manager, RDS
encryption all depend on KMS. KMS key policy is the primary access control
mechanism — unlike IAM resources, KMS key policies are evaluated first
and IAM policies cannot override a restrictive key policy.
Key deletion is ACTIVE-adjacent: the 7-30 day pending deletion period
is constitutive of key deletion — you cannot immediately delete a key,
and CloudTrail records the scheduling. But it is not ACTIVE because
a scheduled deletion can be cancelled.
BYOK ransomware (Codefinger, January 2025): attackers with valid AWS
credentials used SSE-C (customer-provided keys) to re-encrypt S3 objects
and then deleted the key material, leaving victims unable to decrypt data.
This is not a KMS bug — it is a KMS governance gap: no mandatory
immutability constraint on SSE-C key material.
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
    name: str; description: str; declared_layers: list[str]; kms_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    cloudtrail_logged: bool; key_policy_evaluated: bool
    key_rotation_enabled: bool; deletion_protected: bool
    grants_reviewed: bool; cross_account_guarded: bool
    key_id: str|None; principal: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

KMS_OPERATION_FAMILIES = [
    OperationFamily("encrypt_decrypt",
        "Encrypt or decrypt data using KMS key",
        ["key_policy","cloudtrail_event","key_rotation","cross_account_guard"], "crypt"),
    OperationFamily("key_management",
        "Create, enable, disable, or delete KMS key",
        ["key_policy","cloudtrail_event","deletion_protection","grants"], "key"),
    OperationFamily("key_policy_management",
        "Create or update KMS key policy",
        ["key_policy","cloudtrail_event","least_privilege_policy"], "policy"),
    OperationFamily("grant_management",
        "Create or retire grant for KMS key access delegation",
        ["key_policy","cloudtrail_event","grants"], "grant"),
    OperationFamily("key_deletion",
        "Schedule key deletion with mandatory pending period",
        ["key_policy","cloudtrail_event","deletion_protection","pending_deletion"], "delete"),
]

KMS_GOVERNANCE_LAYERS = {
    "key_policy": GovernanceLayer("key_policy",
        "KMS key policy — primary access control, evaluated before IAM", "Policy"),
    "cloudtrail_event": GovernanceLayer("cloudtrail_event",
        "CloudTrail event for KMS operation", "eventSource: kms.amazonaws.com"),
    "key_rotation": GovernanceLayer("key_rotation",
        "Annual key rotation enabled (automatic, CMK only)", "KeyRotationEnabled"),
    "cross_account_guard": GovernanceLayer("cross_account_guard",
        "Cross-account access restricted in key policy", None),
    "deletion_protection": GovernanceLayer("deletion_protection",
        "Deletion protection via key policy Deny on ScheduleKeyDeletion", None, is_optional=True),
    "grants": GovernanceLayer("grants",
        "Grants reviewed for least privilege", None),
    "least_privilege_policy": GovernanceLayer("least_privilege_policy",
        "Key policy grants only needed actions", None),
    "pending_deletion": GovernanceLayer("pending_deletion",
        "Mandatory 7-30 day pending deletion period", "PendingWindowInDays"),
}

class AWSKMSEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS KMS Documentation + CIS AWS Benchmark + Codefinger ransomware analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from KMS architecture. encrypt_decrypt N=4. "
            "CloudTrail records all KMS API calls constitutively when CloudTrail enabled — "
            "the KMS governance receipt depends on CloudTrail (T1721 dependency). "
            "key_deletion: pending period is constitutive (cannot immediately delete) — "
            "CRYSTALLIZED, not ACTIVE (deletion can be cancelled). "
            "BYOK ransomware (Codefinger, January 2025): attackers used SSE-C to re-encrypt "
            "S3 objects, then deleted customer-provided key material — no recovery possible. "
            "SSE-C key governance is the critical gap: AWS does not retain SSE-C keys, "
            "and there is no Object Lock equivalent for the SSE-C encryption key. "
            "Key policy with Principal:* and no conditions is publicly accessible CMK — "
            "analogous to a public S3 bucket for encryption keys."
        ),
    )
    def __init__(self, cloudtrail_enabled: bool=True, key_rotation_enabled: bool=False,
                 deletion_protected: bool=False, cross_account_restricted: bool=True,
                 grants_reviewed: bool=False):
        self._ct = cloudtrail_enabled
        self._rotation = key_rotation_enabled
        self._deletion = deletion_protected
        self._cross_acct = cross_account_restricted
        self._grants = grants_reviewed

    def collect_operation_families(self): return KMS_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [KMS_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in KMS_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            cloudtrail_logged=self._ct, key_policy_evaluated=True,
            key_rotation_enabled=self._rotation, deletion_protected=self._deletion,
            grants_reviewed=self._grants, cross_account_guarded=self._cross_acct,
            key_id=None, principal=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in KMS_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "key_policy" in fam.declared_layers: k.append("key_policy")
        if "cloudtrail_event" in fam.declared_layers and self._ct: k.append("cloudtrail_event")
        if "key_rotation" in fam.declared_layers and self._rotation: k.append("key_rotation")
        if "cross_account_guard" in fam.declared_layers and self._cross_acct: k.append("cross_account_guard")
        if "deletion_protection" in fam.declared_layers and self._deletion: k.append("deletion_protection")
        if "grants" in fam.declared_layers and self._grants: k.append("grants")
        if "least_privilege_policy" in fam.declared_layers: k.append("least_privilege_policy")
        if "pending_deletion" in fam.declared_layers: k.append("pending_deletion")
        return k
    def assess_ear_state(self, op_family):
        if not self._ct: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
