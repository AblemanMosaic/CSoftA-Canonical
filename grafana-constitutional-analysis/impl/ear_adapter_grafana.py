"""
ear_adapter_grafana.py — Grafana EAR Adapter
Wave 14 — System 70. Observability visualization and alerting governance.

Key finding: Grafana is the visualization and alerting layer over
Prometheus/Loki/Tempo/Elasticsearch — completing the observability stack.
It extends the T1701 observability governance family with a new governance
surface: Grafana stores credentials for every backend it queries.
Data source credentials (Prometheus URLs, CloudWatch keys, Elasticsearch passwords,
Azure Monitor credentials) are stored in Grafana's database.

New constitutional concept: visualization layer as credential store —
the observability frontend stores credentials for all backends. Compromising
Grafana achieves read access to all observability data AND access to the
credentials for every monitored system.

CVE-2025-3260 (dashboard API auth bypass): authenticated users bypass
folder/dashboard permissions via /apis/dashboard.grafana.app/* endpoints.
Viewers gain read access to ALL dashboards regardless of folder permissions.

CVE-2024-1442 (data source wildcard UID): user with data source create permission
sets UID to * → gains read/query access to ALL data sources and their credentials.
NON_ACTIVATION at the UID validation boundary.

CVE-2024-9264 (SQL injection via DuckDB plugin in Grafana Explore):
SQL injection in experimental feature allows file read and RCE.

Grafana RBAC: CRYSTALLIZED — roles exist (Viewer/Editor/Admin/ServiceAccount)
but the permission model has recurrent bypass vulnerabilities.
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
    name: str; description: str; declared_layers: list[str]; grafana_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; rbac_enforced: bool
    audit_logged: bool; datasource_secured: bool
    tls_enforced: bool; sso_configured: bool
    user: str|None; dashboard: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

GRAFANA_OPERATION_FAMILIES = [
    OperationFamily("dashboard_access",
        "Read/edit Grafana dashboard and panel data",
        ["auth_required","rbac_check","audit_log","folder_permissions"], "dash"),
    OperationFamily("datasource_query",
        "Execute query against data source via Grafana proxy",
        ["auth_required","rbac_check","datasource_rbac","audit_log"], "query"),
    OperationFamily("datasource_management",
        "Create/modify data source with credentials",
        ["auth_required","rbac_check","credential_scope","audit_log"], "ds"),
    OperationFamily("alert_governance",
        "Create/manage/fire Grafana alerting rules",
        ["auth_required","rbac_check","alert_rbac","audit_log"], "alert"),
    OperationFamily("admin_operation",
        "Grafana admin operations (users, orgs, plugins)",
        ["auth_required","rbac_check","audit_log"], "admin"),
]

GRAFANA_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "Grafana authentication — local, SSO, LDAP, SAML", None),
    "rbac_check": GovernanceLayer("rbac_check",
        "Grafana RBAC — Viewer/Editor/Admin/ServiceAccount role evaluation", None),
    "audit_log": GovernanceLayer("audit_log",
        "Grafana audit log for admin and data access operations", None, is_optional=True),
    "folder_permissions": GovernanceLayer("folder_permissions",
        "Folder-level permission control for dashboard organization", None),
    "datasource_rbac": GovernanceLayer("datasource_rbac",
        "Data source access control — restrict which users can query which sources", None),
    "credential_scope": GovernanceLayer("credential_scope",
        "Data source credential storage scope — encrypted in Grafana DB", None),
    "alert_rbac": GovernanceLayer("alert_rbac",
        "Alert rule access control — who can create/modify alert conditions", None, is_optional=True),
}

class GrafanaEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Grafana documentation + CVE-2025-3260 + CVE-2024-1442 + CVE-2024-9264",
        strategy="DECLARED-N",
        description=(
            "N(O) from Grafana architecture. dashboard_access N=4. "
            "CRYSTALLIZED ceiling: RBAC governs access; audit log opt-in. "
            "New constitutional concept: visualization layer as credential store — "
            "Grafana stores credentials for all backends (Prometheus, CloudWatch, "
            "Elasticsearch, Azure Monitor). Compromising Grafana achieves "
            "read access to all observability data AND backend credentials. "
            "CVE-2025-3260 (dashboard API auth bypass): viewers gain all-dashboard read "
            "via /apis/dashboard.grafana.app/* — BYPASS at API endpoint permission check. "
            "CVE-2024-1442 (data source wildcard UID): UID=* gives access to all data sources — "
            "NON_ACTIVATION at UID validation boundary. "
            "CVE-2024-9264 (SQL injection via DuckDB): file read + RCE via experimental feature. "
            "CVE-2024-1313 (BOLA — snapshot cross-org delete): BOLA at snapshot isolation boundary. "
            "Completes observability stack: Prometheus metrics (T1692) + OTel collection (T1632) "
            "+ Grafana visualization (THIS) = full observability governance picture."
        ),
    )
    def __init__(self, auth_enabled: bool=True, rbac_configured: bool=True,
                 audit_log_enabled: bool=False, datasource_rbac: bool=False):
        self._auth = auth_enabled
        self._rbac = rbac_configured
        self._audit = audit_log_enabled
        self._ds_rbac = datasource_rbac

    def collect_operation_families(self): return GRAFANA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [GRAFANA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in GRAFANA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, rbac_enforced=self._rbac,
            audit_logged=self._audit, datasource_secured=self._ds_rbac,
            tls_enforced=True, sso_configured=False,
            user=None, dashboard=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in GRAFANA_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "folder_permissions" in fam.declared_layers and self._rbac: k.append("folder_permissions")
        if "datasource_rbac" in fam.declared_layers and self._ds_rbac: k.append("datasource_rbac")
        if "credential_scope" in fam.declared_layers: k.append("credential_scope")  # always present
        if "alert_rbac" in fam.declared_layers and self._rbac: k.append("alert_rbac")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
