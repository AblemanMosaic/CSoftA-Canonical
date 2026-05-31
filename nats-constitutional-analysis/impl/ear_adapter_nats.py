"""
ear_adapter_nats.py — NATS Messaging EAR Adapter
Wave 14 — System 66. Cloud-native messaging governance.

Key finding: NATS uses an Operator/Account/User hierarchy for multi-tenant
governance — the primary constitutional surface is account isolation.
The $JS. (JetStream) management subject namespace should be restricted
per account; CVE-2025-30215 exposed that JetStream management APIs could
be reached cross-account, allowing any user with JetStream admin rights
in any account to destroy streams in other accounts.

NATS default: no authentication — any TCP client can publish/subscribe.
Authentication modes: token (simple), username/password, TLS, NKeys (Ed25519),
JWT-based (decentralized, scalable). JWT+NKey is the production governance model.

JetStream persistence: the governance receipt for message delivery is the
ack receipt (CRYSTALLIZED when ack policy is configured; ABSENT for fire-and-forget).
Account isolation boundary: cross-account access is the primary governance gap.

CVE-2025-30215 (April 2025): cross-account JetStream management —
user in Account A could call $JS.API.STREAM.DELETE against Account B streams.
NON_ACTIVATION at the account isolation scope boundary.

CVE-2023-47090: auth bypass via implicit $G user when only system account is configured.
NON_ACTIVATION at the configuration interpretation boundary.
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
    name: str; description: str; declared_layers: list[str]; nats_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    account_isolated: bool; ack_policy: bool
    audit_logged: bool; nkey_auth: bool
    account: str|None; subject: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

NATS_OPERATION_FAMILIES = [
    OperationFamily("message_publish",
        "Publish message to NATS subject",
        ["auth_required","tls_transport","account_isolation","subject_permissions"], "pub"),
    OperationFamily("message_subscribe",
        "Subscribe to NATS subject",
        ["auth_required","tls_transport","account_isolation","subject_permissions"], "sub"),
    OperationFamily("jetstream_management",
        "Create/delete JetStream streams and consumers",
        ["auth_required","account_isolation","jetstream_account_scope","audit_log"], "jsmgmt"),
    OperationFamily("jetstream_message",
        "Publish/consume JetStream persistent messages",
        ["auth_required","account_isolation","ack_policy","jetstream_account_scope"], "jsmsg"),
    OperationFamily("account_management",
        "Manage NATS accounts (operator-level)",
        ["auth_required","operator_jwt","account_isolation"], "acct"),
]

NATS_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "NATS authentication (token/NKey/JWT) required", None),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS on NATS connections", "tls_required"),
    "account_isolation": GovernanceLayer("account_isolation",
        "Account isolation — subjects not visible across accounts", None),
    "subject_permissions": GovernanceLayer("subject_permissions",
        "User-level subject publish/subscribe permissions", None),
    "jetstream_account_scope": GovernanceLayer("jetstream_account_scope",
        "JetStream API scope restricted to own account", None),
    "ack_policy": GovernanceLayer("ack_policy",
        "JetStream ack policy — delivery receipt for consumer", None, is_optional=True),
    "audit_log": GovernanceLayer("audit_log",
        "NATS server audit/access log", None, is_optional=True),
    "operator_jwt": GovernanceLayer("operator_jwt",
        "Operator JWT — signed account/user hierarchy", None, is_optional=True),
}

class NATSEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="NATS documentation + CVE-2025-30215 + CVE-2023-47090 + NATS security self-assessment",
        strategy="DECLARED-N",
        description=(
            "N(O) from NATS architecture. message_publish N=4. "
            "Default NATS: ABSENT — no authentication, any TCP client can pub/sub. "
            "With JWT+NKey: CRYSTALLIZED — account isolation enforced, subject permissions. "
            "CVE-2025-30215 (April 2025): cross-account JetStream management — "
            "user in Account A can delete streams in Account B via $JS.API. "
            "NON_ACTIVATION at account isolation scope boundary for JetStream management. "
            "CVE-2023-47090: implicit $G user provides auth bypass when only system account configured. "
            "NON_ACTIVATION at configuration interpretation boundary. "
            "JetStream ack policy: CRYSTALLIZED — delivery receipt when configured. "
            "ABSENT by default for fire-and-forget messaging. "
            "Account isolation is the primary governance surface — "
            "violation means cross-tenant data access in multi-tenant deployments."
        ),
    )
    def __init__(self, auth_enabled: bool=False, tls_enabled: bool=False,
                 account_isolated: bool=False, ack_policy: bool=False):
        self._auth = auth_enabled
        self._tls = tls_enabled
        self._acct = account_isolated
        self._ack = ack_policy

    def collect_operation_families(self): return NATS_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [NATS_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in NATS_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, tls_enforced=self._tls,
            account_isolated=self._acct, ack_policy=self._ack,
            audit_logged=False, nkey_auth=self._auth,
            account=None, subject=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in NATS_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "account_isolation" in fam.declared_layers and self._acct: k.append("account_isolation")
        if "subject_permissions" in fam.declared_layers and self._auth: k.append("subject_permissions")
        if "jetstream_account_scope" in fam.declared_layers and self._acct: k.append("jetstream_account_scope")
        if "ack_policy" in fam.declared_layers and self._ack: k.append("ack_policy")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
