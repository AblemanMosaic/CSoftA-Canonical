"""
ear_adapter_prometheus.py — Prometheus / Alertmanager EAR Adapter
Wave 6 — System 30. Metrics governance — meta-governance case 3.

Key finding: Prometheus completes the observability governance trilogy
with OpenTelemetry (Wave 4) and Falco (Wave 5). All three are meta-governance
systems — they govern governance data — and all three have governance gaps
in their own operation. Prometheus has no authentication by default,
no audit log, and no constitutive receipt for metric scrape decisions.
The Prometheus data model does not record whether a scrape succeeded or failed
constitutively — a missed scrape produces no receipt. Alertmanager delivers
alerts (CRYSTALLIZED) but alert delivery is not constitutive of the
evaluated condition existing. Authentication for Prometheus endpoints
requires external proxy (no native auth in core Prometheus).
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
    name: str; description: str; declared_layers: list[str]; prom_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    scrape_logged: bool; auth_verified: bool; alert_delivered: bool
    rule_version_tracked: bool; tls_enabled: bool
    target: str|None; metric_name: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PROM_OPERATION_FAMILIES = [
    OperationFamily("metric_scrape",
        "Scrape metrics from target endpoint",
        ["auth_config","scrape_log","tls_config","target_config"], "scrape"),
    OperationFamily("alert_evaluation",
        "Evaluate alerting rule against metric data",
        ["rule_version","alert_log","scrape_log"], "alert_eval"),
    OperationFamily("alert_delivery",
        "Deliver alert to Alertmanager and notification channel",
        ["alert_log","delivery_receipt","auth_config"], "alert_deliver"),
    OperationFamily("api_query",
        "Query Prometheus HTTP API (PromQL)",
        ["auth_config","api_log","tls_config"], "query"),
    OperationFamily("config_management",
        "Reload Prometheus configuration",
        ["config_hash","audit_log"], "config"),
]

PROM_GOVERNANCE_LAYERS = {
    "auth_config": GovernanceLayer("auth_config",
        "Authentication config (basic auth / bearer / TLS) — opt-in, no default auth",
        None),
    "scrape_log": GovernanceLayer("scrape_log",
        "Scrape log recording target, success/failure, duration", None),
    "tls_config": GovernanceLayer("tls_config",
        "TLS configuration for scrape and API endpoints", None),
    "target_config": GovernanceLayer("target_config",
        "Static/SD target configuration", "scrape_configs"),
    "rule_version": GovernanceLayer("rule_version",
        "Alerting/recording rule version tracking", None),
    "alert_log": GovernanceLayer("alert_log",
        "Alert evaluation and firing log", None),
    "delivery_receipt": GovernanceLayer("delivery_receipt",
        "Alertmanager delivery acknowledgment", None, is_optional=True),
    "api_log": GovernanceLayer("api_log",
        "API access log — not native to Prometheus, requires proxy", None, is_optional=True),
    "config_hash": GovernanceLayer("config_hash",
        "Hash of Prometheus config at load/reload", None),
    "audit_log": GovernanceLayer("audit_log",
        "Audit log for config changes — not native to Prometheus", None, is_optional=True),
}

class PrometheusEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Prometheus Documentation + Alertmanager Documentation + Prometheus Security guide",
        strategy="DECLARED-N",
        description=(
            "N(O) from Prometheus architecture. metric_scrape N=4. "
            "Meta-governance case 3 (after OTel Wave 4, Falco Wave 5). "
            "No authentication by default for Prometheus HTTP API or scrape endpoints — "
            "ABSENT access governance in default deployment. "
            "Missed scrape: no constitutive receipt — the metric is absent with "
            "no record distinguishing 'target down' from 'scrape failed'. "
            "Alert delivery: CRYSTALLIZED — delivery may fail, no meta-alert for drop. "
            "Same drop gap pattern as OTel (Wave 4) and Falco (Wave 5). "
            "No Prometheus family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, auth_enabled: bool=False, tls_enabled: bool=False,
                 rule_version_tracked: bool=False, delivery_receipt: bool=False,
                 config_hash_tracked: bool=False):
        self._auth = auth_enabled
        self._tls = tls_enabled
        self._rule_ver = rule_version_tracked
        self._delivery = delivery_receipt
        self._config_hash = config_hash_tracked

    def collect_operation_families(self): return PROM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PROM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in PROM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            scrape_logged=True, auth_verified=self._auth,
            alert_delivered=True, rule_version_tracked=self._rule_ver,
            tls_enabled=self._tls, target=None, metric_name=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in PROM_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_config" in fam.declared_layers and self._auth: k.append("auth_config")
        if "scrape_log" in fam.declared_layers: k.append("scrape_log")
        if "tls_config" in fam.declared_layers and self._tls: k.append("tls_config")
        if "target_config" in fam.declared_layers: k.append("target_config")
        if "rule_version" in fam.declared_layers and self._rule_ver: k.append("rule_version")
        if "alert_log" in fam.declared_layers: k.append("alert_log")
        if "delivery_receipt" in fam.declared_layers and self._delivery: k.append("delivery_receipt")
        if "config_hash" in fam.declared_layers and self._config_hash: k.append("config_hash")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
