"""
ear_adapter_splunk.py — Splunk SIEM EAR Adapter
Wave 13 — System 63. Commercial SIEM as governance evidence meta-layer.

Key finding: Splunk is the most widely deployed commercial SIEM — the system
where governance evidence from other systems is ingested, indexed, and queried.
Like Elasticsearch (Wave 11, System 51), Splunk is a governance evidence
meta-layer: its governance quality determines the reliability of governance
evidence from every system feeding into it.

Splunk extends the Elasticsearch finding with a commercial SIEM perspective:
Splunk's access controls (RBAC) govern who can see what security evidence;
its forwarder infrastructure governs whether evidence arrives at all.
The Universal Forwarder is the most critical governance surface — it runs on
every monitored host and its compromise converts the monitoring system
from a governance evidence layer into an attacker-controlled evidence layer.

CVE-2026-20140 (February 2026, DLL hijacking → SYSTEM): Splunk Enterprise
running as SYSTEM on Windows, attackers with local low-privileged access
can place malicious DLL, gain SYSTEM privileges. The SIEM itself becomes
the escalation target — gaining SYSTEM on the SIEM achieves governance
evidence tampering capability.

New constitutional concept: SIEM as target vs SIEM as monitor.
The governance evidence layer is itself a high-value target. Compromising
Splunk achieves: (1) access to all indexed security events, (2) ability to
create false detections or suppress real ones, (3) privilege escalation
via Splunk's elevated runtime context.
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
    name: str; description: str; declared_layers: list[str]; splunk_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; audit_logged: bool
    forwarder_secured: bool; index_access_controlled: bool
    search_logged: bool; forwarder_integrity: bool
    user: str|None; index: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

SPLUNK_OPERATION_FAMILIES = [
    OperationFamily("search_execution",
        "Execute Splunk search against security indexes",
        ["rbac_check","search_audit","index_access","ssl_transport"], "search"),
    OperationFamily("data_ingestion",
        "Ingest security events via Universal Forwarder or HEC",
        ["forwarder_auth","ssl_transport","forwarder_integrity","index_routing"], "ingest"),
    OperationFamily("alert_action",
        "Execute Splunk alert action (notable event, ticket, response)",
        ["rbac_check","search_audit","alert_governance"], "alert"),
    OperationFamily("forwarder_management",
        "Manage Universal Forwarder deployment and configuration",
        ["rbac_check","audit_log","forwarder_integrity","ssl_transport"], "forwarder"),
    OperationFamily("admin_operation",
        "Splunk admin operations (user/role/index management)",
        ["rbac_check","audit_log","ssl_transport"], "admin"),
]

SPLUNK_GOVERNANCE_LAYERS = {
    "rbac_check": GovernanceLayer("rbac_check",
        "Splunk RBAC — roles control index access and capabilities", None),
    "search_audit": GovernanceLayer("search_audit",
        "Splunk search audit log — records who searched what", "_audit index"),
    "index_access": GovernanceLayer("index_access",
        "Index-level access control — users see only authorized indexes", None),
    "ssl_transport": GovernanceLayer("ssl_transport",
        "TLS for Splunk web, forwarder, and indexer communications", None),
    "forwarder_auth": GovernanceLayer("forwarder_auth",
        "Universal Forwarder authentication to indexers", None),
    "forwarder_integrity": GovernanceLayer("forwarder_integrity",
        "Forwarder binary integrity — prevents attacker-controlled evidence injection", None),
    "index_routing": GovernanceLayer("index_routing",
        "Inputs.conf governance — controls what data sources are forwarded", None),
    "alert_governance": GovernanceLayer("alert_governance",
        "Alert action governance — who can create/modify alerts", None),
    "audit_log": GovernanceLayer("audit_log",
        "Splunk internal audit trail for admin operations", "_audit index"),
}

class SplunkEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Splunk Enterprise Security docs + CVE-2026-20140 DLL hijack + forwarder security analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Splunk architecture. search_execution N=4. "
            "CRYSTALLIZED ceiling: Splunk RBAC + audit log provide governance; "
            "all governance is post-hoc (searches already executed when logged). "
            "Meta-governance case 4 (extends T1701 OTel/Falco/Prometheus trilogy): "
            "Splunk stores governance evidence from other systems; "
            "its compromise means attacker can read and suppress all security evidence. "
            "CVE-2026-20140 (February 2026, CVSS 7.7): DLL hijacking → SYSTEM "
            "on Splunk Enterprise Windows deployment — the SIEM becomes the escalation target. "
            "CVE-2025-20386/20387 (December 2025): incorrect file permissions allow "
            "non-admin privilege escalation on Windows. "
            "Universal Forwarder governance gap: forwarder inputs.conf governs which "
            "security events are forwarded; an attacker with forwarder access can "
            "selectively stop forwarding their own activity — ABSENT evidence governance. "
            "SIEM as target: Splunk runs with elevated privileges; "
            "governance evidence is accessible to any user with search access to indexes; "
            "forwarder compromise = attacker-controlled evidence injection."
        ),
    )
    def __init__(self, rbac_configured: bool=True, ssl_enabled: bool=True,
                 forwarder_secured: bool=False, search_audited: bool=False):
        self._rbac = rbac_configured
        self._ssl = ssl_enabled
        self._forwarder = forwarder_secured
        self._audit = search_audited

    def collect_operation_families(self): return SPLUNK_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [SPLUNK_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in SPLUNK_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=self._rbac, audit_logged=self._audit,
            forwarder_secured=self._forwarder, index_access_controlled=self._rbac,
            search_logged=self._audit, forwarder_integrity=self._forwarder,
            user=None, index=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in SPLUNK_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "search_audit" in fam.declared_layers and self._audit: k.append("search_audit")
        if "index_access" in fam.declared_layers and self._rbac: k.append("index_access")
        if "ssl_transport" in fam.declared_layers and self._ssl: k.append("ssl_transport")
        if "forwarder_auth" in fam.declared_layers and self._forwarder: k.append("forwarder_auth")
        if "forwarder_integrity" in fam.declared_layers and self._forwarder: k.append("forwarder_integrity")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
