"""
ear_adapter_kafka.py — Apache Kafka EAR Adapter
Wave 5 — System 21. Event streaming platform.

Key finding: Kafka's governance surface is almost entirely ABSENT or CRYSTALLIZED.
ACLs are opt-in and disabled by default. There is no mandatory receipt for
producer or consumer operations — a message published to a topic produces no
constitutive governance record binding the message to the publishing principal.
The audit log (log4j-based) is not enabled by default, not structured, and
not queryable as a governance artifact. This makes Kafka the corpus's largest
governance gap relative to operational significance: trillion-message-per-day
systems with ABSENT governance by default.
mTLS between brokers and clients is the closest Kafka operation to ACTIVE-EAR:
the TLS handshake is constitutive of connection. But the governance receipt
for what was produced/consumed is still ABSENT.
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
    name: str; description: str; declared_layers: list[str]; kafka_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    acl_evaluated: bool; tls_verified: bool
    audit_logged: bool; offset_recorded: bool
    topic: str|None; principal: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

KAFKA_OPERATION_FAMILIES = [
    OperationFamily("produce",
        "Producer publishes message to topic",
        ["acl_authorization","tls_auth","audit_log","offset_receipt"], "produce"),
    OperationFamily("consume",
        "Consumer reads message from topic",
        ["acl_authorization","tls_auth","audit_log","consumer_group_commit"], "consume"),
    OperationFamily("topic_management",
        "Create/delete/alter topic",
        ["acl_authorization","tls_auth","audit_log"], "admin"),
    OperationFamily("acl_management",
        "Create/delete ACL entries",
        ["acl_authorization","tls_auth","audit_log"], "acl"),
    OperationFamily("broker_auth",
        "Client authenticates to broker via mTLS or SASL",
        ["tls_auth","sasl_auth","audit_log"], "auth"),
]

KAFKA_GOVERNANCE_LAYERS = {
    "acl_authorization": GovernanceLayer("acl_authorization",
        "ACL evaluated for operation — disabled by default", "acl.authorizer.class.name"),
    "tls_auth": GovernanceLayer("tls_auth",
        "mTLS authentication — constitutive of connection when enabled", "ssl.client.auth"),
    "audit_log": GovernanceLayer("audit_log",
        "Audit log entry (log4j-based, not structured, not default)", None),
    "offset_receipt": GovernanceLayer("offset_receipt",
        "Producer offset assigned — records message placement but not authorization", "offset"),
    "consumer_group_commit": GovernanceLayer("consumer_group_commit",
        "Consumer group offset commit — records consumption position", "__consumer_offsets"),
    "sasl_auth": GovernanceLayer("sasl_auth",
        "SASL authentication mechanism", "sasl.mechanism"),
}

class KafkaEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Apache Kafka Documentation + Kafka Security documentation + Confluent Platform docs",
        strategy="DECLARED-N",
        description=(
            "N(O) from Kafka architecture. produce N=4. "
            "ABSENT by default: ACLs disabled (allow.everyone.if.no.acl.found=true default), "
            "audit log not enabled, no mandatory produce/consume receipt. "
            "broker_auth with mTLS: ACTIVE when ssl.client.auth=required — "
            "TLS handshake constitutive of connection. "
            "All data operation families (produce/consume): ABSENT without ACLs. "
            "Largest governance gap relative to operational scale in the corpus: "
            "default Kafka deployment has ABSENT governance for all data operations."
        ),
    )
    def __init__(self, acl_enabled: bool=False, tls_required: bool=False,
                 audit_log_enabled: bool=False, sasl_enabled: bool=False):
        self._acl = acl_enabled; self._tls = tls_required
        self._audit = audit_log_enabled; self._sasl = sasl_enabled

    def collect_operation_families(self): return KAFKA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [KAFKA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in KAFKA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            acl_evaluated=self._acl, tls_verified=self._tls,
            audit_logged=self._audit, offset_recorded=True,
            topic="test-topic", principal=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in KAFKA_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "acl_authorization" in fam.declared_layers and inst.acl_evaluated: k.append("acl_authorization")
        if "tls_auth" in fam.declared_layers and inst.tls_verified: k.append("tls_auth")
        if "audit_log" in fam.declared_layers and inst.audit_logged: k.append("audit_log")
        if "offset_receipt" in fam.declared_layers and inst.offset_recorded: k.append("offset_receipt")
        if "consumer_group_commit" in fam.declared_layers: k.append("consumer_group_commit")
        if "sasl_auth" in fam.declared_layers and self._sasl: k.append("sasl_auth")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "broker_auth" and self._tls: return EARState.ACTIVE
        if not self._acl: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
