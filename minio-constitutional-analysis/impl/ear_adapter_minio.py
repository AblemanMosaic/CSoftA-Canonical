"""
ear_adapter_minio.py — MinIO EAR Adapter
Wave 14 — System 68. Self-hosted S3-compatible object storage governance.

Key finding: MinIO is the self-hosted analog of AWS S3 (Wave 6, T1694).
The constitutional comparison reveals what the AWS security backstop provides:
AWS S3 + GuardDuty + CloudTrail + Config = layered governance.
MinIO deployed alone = self-managed governance with no backstop.

MinIO governance surfaces:
- IAM policies (S3-compatible, STS-based)
- Audit logging (ABSENT by default, must be explicitly configured)
- Bucket versioning + Object Lock (governance retention mode)
- Encryption at rest (SSE-S3, SSE-KMS, SSE-C)

CVE-2025-31489 (April 2025, auth bypass via signature validation):
valid access-key with arbitrary secret passes authorization checks — BYPASS
at the HMAC signature validation boundary. Allows arbitrary object writes.

CVE-2026-03-17 (March 2026, OIDC JWT algorithm confusion):
attacker knowing OIDC ClientSecret can forge identity tokens and obtain
S3 credentials with any policy including consoleAdmin — BYPASS at
the OIDC token validation boundary.

CVE-2025-62506 (October 2025, session policy bypass):
service accounts bypass inline session policy restrictions via self-operations.
NON_ACTIVATION at session policy scope boundary.

Evil MinIO (2023, active exploitation): chained CVE-2023-28432 (env vars disclosure)
+ CVE-2023-28434 (update URL manipulation) to replace MinIO binary with backdoor.
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
    name: str; description: str; declared_layers: list[str]; minio_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    audit_logged: bool; versioning_enabled: bool
    object_lock: bool; iam_policy: bool
    principal: str|None; bucket: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

MINIO_OPERATION_FAMILIES = [
    OperationFamily("object_put",
        "Upload object to MinIO bucket",
        ["auth_required","tls_transport","audit_log","iam_policy"], "put"),
    OperationFamily("object_get",
        "Download object from MinIO bucket",
        ["auth_required","tls_transport","audit_log","iam_policy"], "get"),
    OperationFamily("bucket_management",
        "Create/delete/configure buckets",
        ["auth_required","tls_transport","audit_log","iam_policy"], "bucket"),
    OperationFamily("object_lock",
        "Apply object lock / governance/compliance retention",
        ["auth_required","object_lock_governance","audit_log","versioning"], "lock"),
    OperationFamily("iam_management",
        "Manage MinIO IAM users, service accounts, STS",
        ["auth_required","tls_transport","audit_log","iam_policy"], "iam"),
]

MINIO_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "MinIO access-key + secret-key authentication", None),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS for MinIO API connections", None),
    "audit_log": GovernanceLayer("audit_log",
        "MinIO audit log — ABSENT by default, requires explicit webhook/Kafka config", None, is_optional=True),
    "iam_policy": GovernanceLayer("iam_policy",
        "MinIO IAM policy evaluated for S3 operations", "policy"),
    "object_lock_governance": GovernanceLayer("object_lock_governance",
        "Object Lock governance/compliance mode — prevents deletion during retention", None, is_optional=True),
    "versioning": GovernanceLayer("versioning",
        "Bucket versioning — preserves object history", None, is_optional=True),
}

class MinIOEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="MinIO documentation + CVE-2025-31489 + CVE-2026-03-17 + Evil MinIO incident",
        strategy="DECLARED-N",
        description=(
            "N(O) from MinIO architecture. object_put N=4. "
            "CRYSTALLIZED ceiling: auth + TLS + IAM policy evaluated. "
            "Audit log: ABSENT by default — requires explicit webhook/Kafka/HTTP target configuration. "
            "Same audit gap as AWS S3 default (T1694): data operations ungoverned without explicit logging. "
            "Constitutional distinction from AWS S3 (T1694): "
            "no AWS security backstop (GuardDuty, CloudTrail, Config) — all governance is self-managed. "
            "CVE-2025-31489 (auth bypass via HMAC signature validation): "
            "valid access-key + arbitrary secret passes auth checks — BYPASS at signature validation. "
            "CVE-2026-03-17 (OIDC JWT algorithm confusion → consoleAdmin): "
            "BYPASS at OIDC token validation boundary. "
            "CVE-2025-62506 (session policy bypass via self-operations): "
            "NON_ACTIVATION at session policy scope boundary. "
            "Evil MinIO (2023, CISA KEV): chained env vars disclosure + update URL manipulation "
            "→ binary replacement with backdoor — ABSENT update integrity governance."
        ),
    )
    def __init__(self, auth_enabled: bool=True, tls_enabled: bool=True,
                 audit_log_enabled: bool=False, object_lock: bool=False):
        self._auth = auth_enabled
        self._tls = tls_enabled
        self._audit = audit_log_enabled
        self._lock = object_lock

    def collect_operation_families(self): return MINIO_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [MINIO_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in MINIO_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, tls_enforced=self._tls,
            audit_logged=self._audit, versioning_enabled=False,
            object_lock=self._lock, iam_policy=self._auth,
            principal=None, bucket=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in MINIO_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "iam_policy" in fam.declared_layers and self._auth: k.append("iam_policy")
        if "object_lock_governance" in fam.declared_layers and self._lock: k.append("object_lock_governance")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        if self._audit: return EARState.CRYSTALLIZED
        return EARState.CRYSTALLIZED  # auth + IAM = CRYSTALLIZED even without audit
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
