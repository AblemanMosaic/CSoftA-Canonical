"""
ear_adapter_aws_s3.py — AWS S3 EAR Adapter
Wave 6 — System 29. Object storage governance.

Key finding: AWS S3 is the corpus's canonical data storage governance case
and the single most common source of large-scale data breaches by volume.
Access logging, server-side encryption, bucket versioning, and Object Lock
are all opt-in. A new S3 bucket is ABSENT for most governance surfaces by
default. The only constitutive governance is access control (bucket ACLs
and bucket policies): a correctly configured private bucket cannot be
accessed without credentials. But the public bucket default is ABSENT —
any bucket created without explicit private ACL is potentially public.
AWS Block Public Access (BPA) is the configuration that moves the
public access gap from ABSENT to non-exploitable, but it is not
the default for all accounts.
S3 Object Lock is the closest to ACTIVE: objects in COMPLIANCE mode
cannot be deleted or modified even by the bucket owner — constitutive
immutability governance.
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
    name: str; description: str; declared_layers: list[str]; s3_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    access_logged: bool; encryption_applied: bool
    versioning_enabled: bool; block_public_access: bool
    object_lock: bool; cloudtrail_logged: bool
    bucket: str|None; key: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

S3_OPERATION_FAMILIES = [
    OperationFamily("object_read",
        "Read/GET object from S3 bucket",
        ["access_control","server_logging","cloudtrail_event","encryption_at_rest"], "read"),
    OperationFamily("object_write",
        "Write/PUT object to S3 bucket",
        ["access_control","server_logging","cloudtrail_event","encryption_at_rest","versioning"], "write"),
    OperationFamily("bucket_policy_management",
        "Create/update bucket policy or ACL",
        ["access_control","cloudtrail_event","block_public_access"], "policy"),
    OperationFamily("object_lock",
        "Apply Object Lock WORM protection to object",
        ["object_lock_compliance","cloudtrail_event"], "lock"),
    OperationFamily("public_access",
        "Access object from public internet (no credentials)",
        ["block_public_access","access_control","server_logging"], "public"),
]

S3_GOVERNANCE_LAYERS = {
    "access_control": GovernanceLayer("access_control",
        "Bucket policy / IAM policy / ACL controlling access", "BucketPolicy"),
    "server_logging": GovernanceLayer("server_logging",
        "S3 server access logging — opt-in, not default", "LoggingEnabled", is_optional=True),
    "cloudtrail_event": GovernanceLayer("cloudtrail_event",
        "CloudTrail data event for S3 — opt-in (data events not default)", None, is_optional=True),
    "encryption_at_rest": GovernanceLayer("encryption_at_rest",
        "Server-side encryption (SSE-S3, SSE-KMS, SSE-C)", "ServerSideEncryption"),
    "versioning": GovernanceLayer("versioning",
        "S3 versioning — preserves object history", "Status"),
    "block_public_access": GovernanceLayer("block_public_access",
        "Block Public Access setting — prevents unintended public exposure", "BlockPublicAcls"),
    "object_lock_compliance": GovernanceLayer("object_lock_compliance",
        "Object Lock COMPLIANCE mode — immutable, cannot be overridden", "ObjectLockMode"),
}

class AWSS3EARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS S3 Documentation + AWS Security Reference Architecture + CIS AWS Benchmark",
        strategy="DECLARED-N",
        description=(
            "N(O) from S3 architecture. object_read N=4. "
            "object_lock (COMPLIANCE mode): ACTIVE — objects cannot be deleted or modified "
            "by anyone including bucket owner during lock period. Constitutive immutability. "
            "object_read/write: ABSENT without server_logging and cloudtrail data events "
            "(both opt-in). access_control present but governance audit ABSENT. "
            "public_access: ABSENT without Block Public Access — "
            "new bucket without explicit private ACL is potentially public. "
            "Block Public Access not default for all accounts (legacy behavior). "
            "S3 is the most common source of large-scale data breaches in the corpus."
        ),
    )
    def __init__(self, server_logging: bool=False, cloudtrail_data_events: bool=False,
                 encryption: bool=False, versioning: bool=False,
                 block_public_access: bool=True, object_lock: bool=False):
        self._logging = server_logging
        self._ct = cloudtrail_data_events
        self._enc = encryption
        self._ver = versioning
        self._bpa = block_public_access
        self._lock = object_lock

    def collect_operation_families(self): return S3_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [S3_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in S3_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            access_logged=self._logging, encryption_applied=self._enc,
            versioning_enabled=self._ver, block_public_access=self._bpa,
            object_lock=self._lock, cloudtrail_logged=self._ct,
            bucket=None, key=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in S3_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "access_control" in fam.declared_layers: k.append("access_control")
        if "server_logging" in fam.declared_layers and self._logging: k.append("server_logging")
        if "cloudtrail_event" in fam.declared_layers and self._ct: k.append("cloudtrail_event")
        if "encryption_at_rest" in fam.declared_layers and self._enc: k.append("encryption_at_rest")
        if "versioning" in fam.declared_layers and self._ver: k.append("versioning")
        if "block_public_access" in fam.declared_layers and self._bpa: k.append("block_public_access")
        if "object_lock_compliance" in fam.declared_layers and self._lock: k.append("object_lock_compliance")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "object_lock" and self._lock: return EARState.ACTIVE
        if op_family.name == "public_access" and not self._bpa: return EARState.ABSENT
        if not self._logging and not self._ct: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
