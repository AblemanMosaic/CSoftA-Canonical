"""
ear_adapter_postgresql.py — PostgreSQL EAR Adapter
Wave 5 — System 23. Relational database.

Key finding: PostgreSQL's governance surface is CRYSTALLIZED with significant
ABSENT defaults. pgaudit (structured audit logging) is an extension — opt-in,
not installed by default. The default PostgreSQL log provides some query logging
but is not structured, not queryable as a governance artifact, and not constitutive.
Row-level security (RLS) is CRYSTALLIZED: policies are declared and enforced
but multiple CVEs show policy bypass via query planning (optimizer statistics
leakage, policy caching bugs). CVE-2025-1094 (SQL injection → RCE, exploited
in BeyondTrust/US Treasury breach) confirms that query execution governance
is incomplete when input validation fails upstream.
pg_audit is the closest to ACTIVE: when enabled, queries cannot complete
without being logged — but pg_audit is an extension, not a core feature.
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
    name: str; description: str; declared_layers: list[str]; pg_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    pgaudit_logged: bool; rls_applied: bool; acl_evaluated: bool
    query_hash: str|None; role: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PG_OPERATION_FAMILIES = [
    OperationFamily("query_execution",
        "Execute SQL query (SELECT/INSERT/UPDATE/DELETE)",
        ["pgaudit_log","acl_grant","rls_policy"], "query"),
    OperationFamily("ddl_operation",
        "Execute DDL statement (CREATE/ALTER/DROP)",
        ["pgaudit_log","acl_grant","connection_log"], "ddl"),
    OperationFamily("role_management",
        "Create/alter/drop role or grant privileges",
        ["pgaudit_log","acl_grant","connection_log"], "role"),
    OperationFamily("connection_establishment",
        "Client connects to database",
        ["ssl_auth","pgaudit_log","connection_log","pg_hba"], "connection"),
    OperationFamily("rls_enforcement",
        "Row-level security policy applied to query",
        ["rls_policy","pgaudit_log","acl_grant"], "rls"),
]

PG_GOVERNANCE_LAYERS = {
    "pgaudit_log": GovernanceLayer("pgaudit_log",
        "pgaudit extension log — structured, constitutive when enabled", None),
    "acl_grant": GovernanceLayer("acl_grant",
        "GRANT/REVOKE ACL evaluated for operation", "has_table_privilege"),
    "rls_policy": GovernanceLayer("rls_policy",
        "Row-level security policy — enforced but bypass CVEs exist", None),
    "connection_log": GovernanceLayer("connection_log",
        "Connection/disconnection log — log_connections=on", None),
    "ssl_auth": GovernanceLayer("ssl_auth",
        "SSL/TLS client certificate authentication", "ssl"),
    "pg_hba": GovernanceLayer("pg_hba",
        "pg_hba.conf access control — host-based authentication", "pg_hba.conf"),
}

class PostgreSQLEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="PostgreSQL Documentation + pgaudit documentation + PostgreSQL CVE list",
        strategy="DECLARED-N",
        description=(
            "N(O) from PostgreSQL architecture. query_execution N=4. "
            "pgaudit: ACTIVE when installed and configured — queries cannot complete "
            "without being logged. But pgaudit is an extension (opt-in). "
            "Default PostgreSQL: ABSENT for structured query audit. "
            "RLS: CRYSTALLIZED — enforced but multiple CVEs show bypass via "
            "query planning (CVE-2023-2455 cached plan policy bypass, "
            "optimizer statistics leakage). "
            "CVE-2025-1094: SQL injection → RCE exploited in BeyondTrust/US Treasury breach — "
            "query execution governance incomplete when input validation fails upstream."
        ),
    )
    def __init__(self, pgaudit_enabled: bool=False, rls_enabled: bool=False,
                 ssl_required: bool=False, log_connections: bool=False):
        self._pgaudit = pgaudit_enabled; self._rls = rls_enabled
        self._ssl = ssl_required; self._log_conn = log_connections

    def collect_operation_families(self): return PG_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PG_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in PG_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            pgaudit_logged=self._pgaudit, rls_applied=self._rls,
            acl_evaluated=True, query_hash=None, role=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in PG_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "pgaudit_log" in fam.declared_layers and inst.pgaudit_logged: k.append("pgaudit_log")
        if "acl_grant" in fam.declared_layers and inst.acl_evaluated: k.append("acl_grant")
        if "rls_policy" in fam.declared_layers and inst.rls_applied: k.append("rls_policy")
        if "connection_log" in fam.declared_layers and self._log_conn: k.append("connection_log")
        if "ssl_auth" in fam.declared_layers and self._ssl: k.append("ssl_auth")
        if "pg_hba" in fam.declared_layers: k.append("pg_hba")
        return k
    def assess_ear_state(self, op_family):
        # query_execution: ACTIVE when pgaudit enabled (constitutive)
        if self._pgaudit and op_family.name in ("query_execution","ddl_operation","role_management","rls_enforcement"):
            return EARState.ACTIVE
        if not self._pgaudit: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
