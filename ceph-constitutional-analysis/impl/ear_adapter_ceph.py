"""ear_adapter_ceph.py — Ceph Distributed Storage. Wave 16 System 78."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"
class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; ceph_scope: str
@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False
@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    audit_logged: bool; rbac_evaluated: bool
    encryption_enabled: bool; s3_compatible: bool
    pool: str|None; client: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)
@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CEPH_FAMILIES = [
    OperationFamily("rados_object","RADOS object read/write to Ceph cluster",
        ["auth_required","tls_transport","audit_log","rbac_check"],"rados"),
    OperationFamily("s3_object","S3-compatible object operation via RGW",
        ["auth_required","tls_transport","audit_log","rbac_check"],"s3"),
    OperationFamily("cephx_auth","CephX authentication for client connections",
        ["cephx_auth","tls_transport"],"cephx"),
    OperationFamily("pool_management","Create/manage Ceph storage pools and CRUSH maps",
        ["auth_required","audit_log","rbac_check"],"pool"),
    OperationFamily("dashboard_access","Ceph Dashboard administrative access",
        ["auth_required","tls_transport","audit_log"],"dash"),
]
CEPH_LAYERS = {
    "auth_required": GovernanceLayer("auth_required","Ceph client authentication (CephX or RGW credentials)",None),
    "tls_transport": GovernanceLayer("tls_transport","TLS for Ceph monitor and RGW connections",None,is_optional=True),
    "audit_log": GovernanceLayer("audit_log","Ceph RGW access log / audit log",None,is_optional=True),
    "rbac_check": GovernanceLayer("rbac_check","Ceph capability flags (r/w/x per pool) and S3 ACLs",None),
    "cephx_auth": GovernanceLayer("cephx_auth","CephX challenge-response authentication",None),
    "encryption_at_rest": GovernanceLayer("encryption_at_rest","OSD-level encryption with LUKS",None,is_optional=True),
}

class CephEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Ceph documentation + CephX authentication analysis + Ceph security audit 2024",
        strategy="DECLARED-N",
        description=(
            "N(O) from Ceph architecture. rados_object N=4. "
            "Ceph is the self-hosted distributed storage backend for OpenShift, OpenStack, Rook. "
            "CephX authentication: mandatory for Ceph cluster clients — "
            "credentials required to mount RADOS block devices or access pools. "
            "Audit log: ABSENT for RADOS by default; "
            "S3-compatible RGW gateway has access logging (CRYSTALLIZED when configured). "
            "CRYSTALLIZED ceiling: CephX auth + TLS + capability flags. "
            "Constitutional comparison to MinIO (T1814): "
            "both are self-hosted object storage; Ceph is the distributed backend "
            "for enterprise deployments (OpenShift/OpenStack); MinIO for standalone S3 compat. "
            "Ceph 2024 security audit (Cure53): found several medium-severity findings. "
            "No CVEs of constitutional significance in corpus period."
        ),
    )
    def __init__(self, auth_enabled: bool=True, tls_enabled: bool=False,
                 audit_log_enabled: bool=False, rbac_configured: bool=True):
        self._auth=auth_enabled; self._tls=tls_enabled
        self._audit=audit_log_enabled; self._rbac=rbac_configured
    def collect_operation_families(self): return CEPH_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CEPH_LAYERS[n] for n in op_family.declared_layers if n in CEPH_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(op_family.name,f"synthetic:{op_family.name}","",
            self._auth,self._tls,self._audit,self._rbac,False,True,None,None,None,None,{})]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in CEPH_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "cephx_auth" in fam.declared_layers and self._auth: k.append("cephx_auth")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
