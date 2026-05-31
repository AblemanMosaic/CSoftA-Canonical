"""
ear_adapter_mongodb.py — MongoDB EAR Adapter
Wave 12 — System 56. Document database governance.

Key finding: MongoDB confirms the default ABSENT pattern with one new finding:
the oplog (change stream) is the governance receipt surface for document
operations — and it is CRYSTALLIZED when enabled, but opt-in in Atlas free tier
and not auditable in community deployments without MongoDB Enterprise.
The oplog records all write operations constitutively (it exists because
MongoDB replication requires it), but accessing the oplog as a governance
audit tool requires either MongoDB Enterprise Audit or Atlas advanced audit
configured on top.

CVE-2025-14847 "MongoBleed" (December 2025): unauthenticated memory leak
via malformed zlib-compressed wire protocol messages. 87,000+ vulnerable
servers discovered. No authentication required. Attackers could extract
cleartext credentials, session tokens, and sensitive data from server memory.
This is ABSENT governance combined with a new protocol-layer vulnerability:
the network wire protocol itself exposes memory without authentication.
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
    name: str; description: str; declared_layers: list[str]; mongo_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    enterprise_audit: bool; oplog_enabled: bool
    rbac_evaluated: bool; field_level_encryption: bool
    user: str|None; collection: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

MONGO_OPERATION_FAMILIES = [
    OperationFamily("document_write",
        "Insert/update/delete document in collection",
        ["auth_required","tls_transport","enterprise_audit","rbac_check"], "write"),
    OperationFamily("document_read",
        "Find/aggregate documents from collection",
        ["auth_required","tls_transport","enterprise_audit","rbac_check"], "read"),
    OperationFamily("collection_management",
        "Create/drop collections and indexes",
        ["auth_required","tls_transport","enterprise_audit","rbac_check"], "coll"),
    OperationFamily("change_stream",
        "Subscribe to change stream (oplog-backed) for real-time changes",
        ["auth_required","tls_transport","oplog_governance","rbac_check"], "stream"),
    OperationFamily("user_management",
        "Create/modify database users and roles",
        ["auth_required","tls_transport","enterprise_audit","rbac_check"], "user"),
]

MONGO_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "MongoDB authentication required (--auth flag)", "security.authorization"),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS on MongoDB connections", "net.tls.mode"),
    "enterprise_audit": GovernanceLayer("enterprise_audit",
        "MongoDB Enterprise Audit — structured audit log (commercial only)", None),
    "rbac_check": GovernanceLayer("rbac_check",
        "MongoDB RBAC role-based access control", "roles"),
    "oplog_governance": GovernanceLayer("oplog_governance",
        "Oplog access controlled for change stream governance", None, is_optional=True),
}

class MongoDBEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="MongoDB Security docs + CVE-2025-14847 MongoBleed + Atlas audit docs",
        strategy="DECLARED-N",
        description=(
            "N(O) from MongoDB architecture. document_write N=4. "
            "Default MongoDB community: ABSENT — auth disabled by default "
            "until MongoDB 7.x in some configurations. "
            "CVE-2025-14847 (MongoBleed, December 2025): unauthenticated memory leak "
            "via malformed zlib-compressed protocol. 87,000+ vulnerable servers. "
            "No auth required to trigger. Cleartext credentials leakable from heap. "
            "Enterprise Audit: ACTIVE for document operations — commercial paywall "
            "(same pattern as MySQL T1781). Community: ABSENT structured audit. "
            "Oplog as governance surface: change streams record all writes constitutively "
            "for replication — but oplog access for audit requires Enterprise configuration. "
            "Field-level encryption (CSFLE): ACTIVE encryption-as-governance for "
            "specific fields — strongest governance surface in MongoDB."
        ),
    )
    def __init__(self, auth_enabled: bool=False, tls_enabled: bool=False,
                 enterprise_audit: bool=False, rbac_configured: bool=False):
        self._auth = auth_enabled
        self._tls = tls_enabled
        self._enterprise = enterprise_audit
        self._rbac = rbac_configured

    def collect_operation_families(self): return MONGO_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [MONGO_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in MONGO_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, tls_enforced=self._tls,
            enterprise_audit=self._enterprise, oplog_enabled=True,
            rbac_evaluated=self._rbac, field_level_encryption=False,
            user=None, collection=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in MONGO_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "enterprise_audit" in fam.declared_layers and self._enterprise: k.append("enterprise_audit")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        if self._enterprise: return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
