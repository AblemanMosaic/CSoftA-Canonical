"""
ear_adapter_elasticsearch.py — Elasticsearch / OpenSearch EAR Adapter
Wave 11 — System 51. Log storage governance.

Key finding: Elasticsearch is the log storage system that organizations use to
store and query their governance evidence — SIEM backends, audit log storage,
security analytics. The constitutional significance: this is the first system
in the corpus that is ITSELF the storage layer for governance evidence from other
systems. When Elasticsearch has ABSENT governance, the governance evidence of
every system whose logs are stored in it is compromised.

Default Elasticsearch (OSS, pre-8.0): no authentication, no TLS, no audit log.
Any process that can reach port 9200 can read every document in every index.
Security features were proprietary (X-Pack) until 7.x when they were open-sourced.
But even in 8.x, the default single-node dev mode disables security.

New constitutional concept: the governance evidence layer — the system that stores
governance receipts from other systems. When this layer is ABSENT, all stored
governance evidence is accessible and modifiable by any attacker who can reach it.
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
    name: str; description: str; declared_layers: list[str]; es_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    audit_logged: bool; rbac_evaluated: bool
    index_encrypted: bool; field_security: bool
    user: str|None; index: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ES_OPERATION_FAMILIES = [
    OperationFamily("document_index",
        "Index document into Elasticsearch index",
        ["auth_required","tls_transport","audit_log","rbac_check"], "index"),
    OperationFamily("document_search",
        "Search and retrieve documents from Elasticsearch",
        ["auth_required","tls_transport","audit_log","rbac_check","field_security"], "search"),
    OperationFamily("index_management",
        "Create/delete/manage indices and mappings",
        ["auth_required","tls_transport","audit_log","rbac_check"], "mgmt"),
    OperationFamily("cluster_management",
        "Manage cluster settings, nodes, snapshots",
        ["auth_required","tls_transport","audit_log","rbac_check"], "cluster"),
    OperationFamily("api_key_management",
        "Create/revoke API keys for authentication",
        ["auth_required","tls_transport","audit_log","rbac_check"], "apikey"),
]

ES_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "Authentication required for all API requests", "security.enabled"),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS on HTTP and transport layers", "xpack.security.http.ssl.enabled"),
    "audit_log": GovernanceLayer("audit_log",
        "Elasticsearch audit logging (xpack.security.audit.enabled)", None, is_optional=True),
    "rbac_check": GovernanceLayer("rbac_check",
        "Role-based access control for index and cluster permissions", None),
    "field_security": GovernanceLayer("field_security",
        "Field-level security restricting which fields users can access", None, is_optional=True),
    "index_encryption": GovernanceLayer("index_encryption",
        "Encryption at rest for Elasticsearch indices", None, is_optional=True),
}

class ElasticsearchEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Elasticsearch Security docs + CVE-2025-37731 + Kaduu disclosure Nov 2025",
        strategy="DECLARED-N",
        description=(
            "N(O) from Elasticsearch architecture. document_search N=5. "
            "ABSENT by default in OSS/dev mode: no auth, no TLS, no audit log. "
            "The governance evidence layer: Elasticsearch stores security logs, "
            "SIEM data, audit trails from other systems — ABSENT governance here "
            "means all stored governance evidence is accessible without authentication. "
            "New constitutional concept: governance evidence storage system — "
            "when this layer is ABSENT, every system whose logs are stored here "
            "loses its governance evidence integrity simultaneously. "
            "CVE-2025-37731 (PKI realm auth bypass): crafted client certificates "
            "allowed user impersonation — NON_ACTIVATION at PKI validation boundary. "
            "CVE-2020-7009 (privilege escalation via API key + token): "
            "ACTIVE auth but scope boundary of combined token/key auth was exploitable. "
            "Maximum CRYSTALLIZED with full stack: auth + TLS + audit + RBAC. "
            "No Elasticsearch family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, auth_enabled: bool=False, tls_enabled: bool=False,
                 audit_log_enabled: bool=False, rbac_configured: bool=False,
                 field_security: bool=False):
        self._auth = auth_enabled
        self._tls = tls_enabled
        self._audit = audit_log_enabled
        self._rbac = rbac_configured
        self._field = field_security

    def collect_operation_families(self): return ES_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ES_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ES_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, tls_enforced=self._tls,
            audit_logged=self._audit, rbac_evaluated=self._rbac,
            index_encrypted=False, field_security=self._field,
            user=None, index=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ES_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "field_security" in fam.declared_layers and self._field: k.append("field_security")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
