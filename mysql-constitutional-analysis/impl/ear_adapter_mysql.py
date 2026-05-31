"""
ear_adapter_mysql.py — MySQL / MariaDB EAR Adapter
Wave 11 — System 55. Most-deployed RDBMS governance.

Key finding: MySQL confirms and extends the PostgreSQL pattern (Wave 5, T1670)
with one critical difference: the ACTIVE audit path is proprietary.
PostgreSQL + pgaudit achieves ACTIVE query governance via an open-source
extension available in all distributions. MySQL Enterprise Audit — which
provides ACTIVE query governance — is only available in MySQL Enterprise Edition
(commercial). OSS MySQL (Community Edition) has general_log (CRYSTALLIZED,
performance impact, not structured) and no query audit at all by default.
This introduces a new constitutional dimension: governance quality that
requires a commercial license. The governance gap is not just a configuration
decision — it is a purchasing decision.

New constitutional concept: commercial governance paywalling — the ACTIVE
governance path is gated by commercial license, not configuration.

CVE-2026-3494 (MariaDB/Aurora MySQL, March 2026): MariaDB audit plugin
comment bypass — SQL statements prefixed with -- or # comments are not logged
when server_audit_events filtering is enabled. This is NON_ACTIVATION at the
audit filter parsing boundary: the audit layer is present and configured but
the filter logic has a scope boundary that SQL comments exploit.
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
    name: str; description: str; declared_layers: list[str]; mysql_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    enterprise_audit: bool; general_log: bool
    rls_equivalent: bool; auth_evaluated: bool
    tls_required: bool; audit_structured: bool
    user: str|None; db: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

MYSQL_OPERATION_FAMILIES = [
    OperationFamily("query_execution",
        "Execute DML query (SELECT/INSERT/UPDATE/DELETE)",
        ["enterprise_audit","general_log","auth_check","tls_connection"], "query"),
    OperationFamily("ddl_operation",
        "Execute DDL (CREATE/ALTER/DROP tables, databases)",
        ["enterprise_audit","general_log","auth_check","tls_connection"], "ddl"),
    OperationFamily("privilege_grant",
        "Grant/revoke database privileges",
        ["enterprise_audit","general_log","auth_check"], "priv"),
    OperationFamily("connection_establishment",
        "Establish authenticated database connection",
        ["auth_check","tls_connection","general_log"], "conn"),
    OperationFamily("stored_procedure_exec",
        "Execute stored procedure or function",
        ["enterprise_audit","general_log","auth_check"], "proc"),
]

MYSQL_GOVERNANCE_LAYERS = {
    "enterprise_audit": GovernanceLayer("enterprise_audit",
        "MySQL Enterprise Audit — ACTIVE query governance (commercial only)", None),
    "general_log": GovernanceLayer("general_log",
        "MySQL general_log — CRYSTALLIZED, high performance impact, not default", "general_log"),
    "auth_check": GovernanceLayer("auth_check",
        "MySQL authentication evaluated for connection", "authentication_string"),
    "tls_connection": GovernanceLayer("tls_connection",
        "TLS required for MySQL connections (require_secure_transport)", None, is_optional=True),
}

class MySQLEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="MySQL Enterprise documentation + CVE-2026-3494 + Aurora MySQL audit analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from MySQL architecture. query_execution N=4. "
            "query_execution with MySQL Enterprise Audit: ACTIVE — "
            "queries constitutively logged, structured, fail-closed. "
            "query_execution without Enterprise Audit (Community Edition): "
            "general_log = CRYSTALLIZED (exists, high perf impact, not default); "
            "no structured audit = ABSENT by default. "
            "New constitutional concept: commercial governance paywalling — "
            "ACTIVE query governance requires commercial license (MySQL EE). "
            "PostgreSQL + pgaudit (T1670): ACTIVE via open-source extension. "
            "MySQL Community: ABSENT by default with no open-source ACTIVE path. "
            "CVE-2026-3494 (MariaDB audit plugin, March 2026): "
            "SQL statements prefixed with -- or # comments bypass server_audit_events filtering. "
            "NON_ACTIVATION at audit filter parsing boundary — "
            "the filter is present but its parsing logic has a comment-evasion gap. "
            "Audit bypass via comment prefix: same evasion class as CloudTrail "
            "log padding (T1727) but at the database audit layer."
        ),
    )
    def __init__(self, enterprise_audit: bool=False, general_log: bool=False,
                 tls_required: bool=False, auth_configured: bool=True):
        self._enterprise = enterprise_audit
        self._general = general_log
        self._tls = tls_required
        self._auth = auth_configured

    def collect_operation_families(self): return MYSQL_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [MYSQL_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in MYSQL_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            enterprise_audit=self._enterprise, general_log=self._general,
            rls_equivalent=False, auth_evaluated=self._auth,
            tls_required=self._tls, audit_structured=self._enterprise,
            user=None, db=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in MYSQL_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "enterprise_audit" in fam.declared_layers and self._enterprise: k.append("enterprise_audit")
        if "general_log" in fam.declared_layers and self._general: k.append("general_log")
        if "auth_check" in fam.declared_layers and self._auth: k.append("auth_check")
        if "tls_connection" in fam.declared_layers and self._tls: k.append("tls_connection")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "connection_establishment": return EARState.CRYSTALLIZED
        if self._enterprise: return EARState.ACTIVE
        if self._general: return EARState.CRYSTALLIZED
        return EARState.ABSENT
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
