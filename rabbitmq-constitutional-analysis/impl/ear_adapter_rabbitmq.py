"""
ear_adapter_rabbitmq.py — RabbitMQ EAR Adapter
Wave 15 — System 75. AMQP message broker governance.

Key finding: RabbitMQ provides a constitutional comparison to Kafka (Wave 5, T1671)
and NATS (Wave 14, T1812). The governance model differs: RabbitMQ uses
AMQP with virtual hosts (vhosts) as the primary isolation boundary.
Each vhost has its own exchanges, queues, and bindings. ACL permissions
are granted per user per vhost.

RabbitMQ default configuration: guest user with password 'guest' restricted
to localhost. Remote access requires explicit user creation.
Management UI: accessible on port 15672 with username/password.

CVE-2024-GHSA (queue deletion permission bypass, November 2024):
HTTP API queue deletion endpoint did not verify `configure` permission.
Users with valid credentials and some permissions could delete queues
without deletion permission — NON_ACTIVATION at the HTTP API permission check.

CVE-2025-50200 (June 2025): authorization headers logged in plaintext
base64 in audit logs — ABSENT governance of credentials in log evidence.
Same pattern as Nomad CVE-2025-1296.

CVE-2022-37026 (Erlang/OTP, CVSS 9.8, inherited): authentication bypass
when TLS or DTLS authentication configured — BYPASS at TLS auth layer.
RabbitMQ inherits CVEs from Erlang/OTP runtime.

RabbitMQ message auditing: ABSENT by default.
The message broker logs connections, channel operations, and management API calls
(CRYSTALLIZED), but the content and routing of individual messages is not auditable.
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
    name: str; description: str; declared_layers: list[str]; rmq_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    vhost_isolated: bool; message_audit: bool
    management_secured: bool; permission_checked: bool
    vhost: str|None; user: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

RMQ_OPERATION_FAMILIES = [
    OperationFamily("message_publish",
        "Publish message to RabbitMQ exchange",
        ["auth_required","tls_transport","vhost_isolation","permission_check"], "pub"),
    OperationFamily("message_consume",
        "Consume message from RabbitMQ queue",
        ["auth_required","tls_transport","vhost_isolation","permission_check"], "consume"),
    OperationFamily("queue_management",
        "Create/delete/configure queues and exchanges",
        ["auth_required","tls_transport","permission_check","management_audit"], "queue"),
    OperationFamily("vhost_management",
        "Create/manage virtual hosts and user permissions",
        ["auth_required","tls_transport","management_audit"], "vhost"),
    OperationFamily("shovel_federation",
        "Shovel/Federation plugin cross-broker message forwarding",
        ["auth_required","tls_transport","federation_credential_governance"], "shovel"),
]

RMQ_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "RabbitMQ AMQP authentication (username/password, TLS cert, OAuth2)", None),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS on AMQP/AMQPS and management UI connections", None),
    "vhost_isolation": GovernanceLayer("vhost_isolation",
        "Virtual host isolation — per-vhost queues, exchanges, permissions", None),
    "permission_check": GovernanceLayer("permission_check",
        "Per-user-per-vhost configure/read/write permissions", None),
    "management_audit": GovernanceLayer("management_audit",
        "RabbitMQ management audit logging for admin operations", None, is_optional=True),
    "federation_credential_governance": GovernanceLayer("federation_credential_governance",
        "Shovel/Federation plugin credentials management", None, is_optional=True),
}

class RabbitMQEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="RabbitMQ docs + CVE-2024-GHSA queue delete + CVE-2025-50200 + CVE-2022-37026",
        strategy="DECLARED-N",
        description=(
            "N(O) from RabbitMQ architecture. message_publish N=4. "
            "Default: guest user localhost-only. Remote requires explicit user creation. "
            "CRYSTALLIZED ceiling: auth + vhost isolation + permission check. "
            "ABSENT: message content auditing — message content not auditable by default. "
            "Constitutional comparison to Kafka (T1671): "
            "RabbitMQ vhost = Kafka ACL per-topic; AMQP vs Kafka protocol; "
            "both have ABSENT message content audit by default. "
            "CVE-2024-GHSA (queue delete permission bypass): "
            "HTTP API delete did not verify configure permission — "
            "NON_ACTIVATION at HTTP API permission check boundary. "
            "CVE-2025-50200 (June 2025): basic auth header logged in base64 in audit logs — "
            "ABSENT credential governance in log evidence (same pattern as Nomad CVE-2025-1296). "
            "CVE-2022-37026 (Erlang/OTP CVSS 9.8): TLS auth bypass — "
            "BYPASS via Erlang runtime dependency. "
            "RabbitMQ Shovel/Federation: predictable credential obfuscation seed (historic CVE)."
        ),
    )
    def __init__(self, auth_enabled: bool=True, tls_enabled: bool=True,
                 vhost_isolated: bool=True, management_audit: bool=False):
        self._auth = auth_enabled
        self._tls = tls_enabled
        self._vhost = vhost_isolated
        self._audit = management_audit

    def collect_operation_families(self): return RMQ_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [RMQ_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in RMQ_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, tls_enforced=self._tls,
            vhost_isolated=self._vhost, message_audit=False,
            management_secured=self._auth, permission_checked=self._auth,
            vhost=None, user=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in RMQ_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "vhost_isolation" in fam.declared_layers and self._vhost: k.append("vhost_isolation")
        if "permission_check" in fam.declared_layers and self._auth: k.append("permission_check")
        if "management_audit" in fam.declared_layers and self._audit: k.append("management_audit")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
