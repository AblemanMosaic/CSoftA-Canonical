"""ear_adapter_jaeger.py — Jaeger Distributed Tracing. Wave 16 System 76."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"
class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; jaeger_scope: str
@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False
@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    rbac_check: bool; sampling_governed: bool
    backend_secured: bool; pii_redacted: bool
    service: str|None; trace_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)
@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

JAEGER_FAMILIES = [
    OperationFamily("trace_ingestion","Ingest span data from services via OTLP/Jaeger protocol",
        ["auth_required","tls_transport","sampling_governance","pii_governance"],"ingest"),
    OperationFamily("trace_query","Query stored traces via Jaeger UI or API",
        ["auth_required","rbac_check","tls_transport","audit_log"],"query"),
    OperationFamily("backend_storage","Store traces in Elasticsearch/Cassandra/Badger",
        ["auth_required","tls_transport","rbac_check"],"storage"),
    OperationFamily("sampling_governance","Govern trace sampling policy (head/tail)",
        ["sampling_governance","auth_required"],"sampling"),
    OperationFamily("pii_governance","Govern PII/sensitive data in trace spans",
        ["pii_governance","auth_required","rbac_check"],"pii"),
]
JAEGER_LAYERS = {
    "auth_required": GovernanceLayer("auth_required","Jaeger UI/API authentication",None),
    "tls_transport": GovernanceLayer("tls_transport","TLS on OTLP/Jaeger collectors",None),
    "rbac_check": GovernanceLayer("rbac_check","Jaeger query service RBAC (plugin-based)",None,is_optional=True),
    "sampling_governance": GovernanceLayer("sampling_governance","Sampling policy — which requests are traced",None),
    "pii_governance": GovernanceLayer("pii_governance","PII redaction in trace spans before storage",None,is_optional=True),
    "audit_log": GovernanceLayer("audit_log","Access log for trace query operations",None,is_optional=True),
}

class JaegerEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Jaeger documentation + OTel corpus (T1632) + observability governance analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Jaeger architecture. trace_query N=4. "
            "Jaeger completes the distributed tracing pillar of observability: "
            "Prometheus (metrics/T1692) + OTel (collection/T1632) + Jaeger (tracing). "
            "ABSENT auth by default in open-source Jaeger — query API accessible to anyone. "
            "PII in traces: ABSENT governance by default — trace spans may contain request bodies, "
            "user identifiers, authentication tokens as span attributes. "
            "CRYSTALLIZED ceiling with auth + TLS. "
            "Jaeger largely superseded by OTel collector + backend for new deployments. "
            "Constitutional significance: tracing backends hold PII-containing request data "
            "with weaker governance than application databases holding the same data."
        ),
    )
    def __init__(self, auth_enabled: bool=False, tls_enabled: bool=False,
                 rbac_configured: bool=False, pii_redacted: bool=False):
        self._auth=auth_enabled; self._tls=tls_enabled
        self._rbac=rbac_configured; self._pii=pii_redacted
    def collect_operation_families(self): return JAEGER_FAMILIES
    def collect_governance_layers(self, op_family):
        return [JAEGER_LAYERS[n] for n in op_family.declared_layers if n in JAEGER_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(op_family.name,f"synthetic:{op_family.name}","",
            self._auth,self._tls,self._rbac,False,False,self._pii,None,None,None,None,{})]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in JAEGER_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "pii_governance" in fam.declared_layers and self._pii: k.append("pii_governance")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
