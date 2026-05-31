"""
ear_adapter_consul.py — HashiCorp Consul EAR Adapter
Wave 3 — System 13. Service mesh, service discovery, key/value store.

Key finding: Consul has the most complex governance profile in Wave 3.
ACL system is CRYSTALLIZED (audit log opt-in). Service mesh intentions
are CRYSTALLIZED (decision not constitutively receipted). Consul Connect
mTLS approaches ACTIVE — certificate issuance is constitutive of
service mesh membership. Audit log is an enterprise feature, not available
in open-source Consul — ABSENT by default.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE = "ACTIVE"; CRYSTALLIZED = "CRYSTALLIZED"; ABSENT = "ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"; ABSENCE = "ABSENCE"; BYPASS = "BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; consul_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    acl_evaluated: bool; intention_checked: bool
    cert_issued: bool; audit_logged: bool
    enterprise_edition: bool; service_name: str | None
    decision: str | None; error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CL_OPERATION_FAMILIES = [
    OperationFamily("service_registration",
        "Register service in Consul catalog",
        ["acl_token", "service_catalog", "audit_log"], "catalog"),
    OperationFamily("acl_authorization",
        "Evaluate ACL policy for API request",
        ["acl_policy", "acl_token", "audit_log"], "acl"),
    OperationFamily("connect_certificate",
        "Issue SPIFFE SVID via Consul Connect CA for service mesh",
        ["acl_token", "connect_ca", "svid_receipt"], "connect"),
    OperationFamily("intention_enforcement",
        "Evaluate service-to-service intention for Connect traffic",
        ["intention_policy", "connect_ca", "audit_log"], "intention"),
    OperationFamily("kv_operation",
        "Read/write key-value store entry",
        ["acl_policy", "acl_token", "audit_log"], "kv"),
]

CL_GOVERNANCE_LAYERS = {
    "acl_token": GovernanceLayer("acl_token", "ACL token presented for authorization", "X-Consul-Token"),
    "acl_policy": GovernanceLayer("acl_policy", "ACL policy evaluated against token", "rules"),
    "audit_log": GovernanceLayer("audit_log",
        "Consul audit log (Enterprise only — ABSENT in open source)", None),
    "service_catalog": GovernanceLayer("service_catalog", "Service registered in catalog", "ServiceID"),
    "connect_ca": GovernanceLayer("connect_ca", "Connect CA issues SPIFFE SVID", "CertPEM"),
    "svid_receipt": GovernanceLayer("svid_receipt",
        "SVID leaf certificate — IS the receipt of Connect membership", "CertPEM"),
    "intention_policy": GovernanceLayer("intention_policy",
        "Intention policy governing service-to-service traffic", "Action"),
}

class ConsulEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Consul Documentation + Consul Connect Architecture + Consul ACL System",
        strategy="DECLARED-N",
        description=(
            "N(O) from Consul architecture. acl_authorization N=3. "
            "Critical finding: audit_log is an Enterprise-only feature — "
            "ABSENT in open-source Consul. ACL authorization is CRYSTALLIZED (Enterprise) "
            "or ABSENT (open source) — never ACTIVE. "
            "connect_certificate approaches ACTIVE: SVID issuance constitutive "
            "of Connect mesh membership, analogous to SPIFFE/SPIRE. "
            "Consul Connect is Consul's SPIFFE-compatible layer — "
            "strongest governance surface in Consul."
        ),
    )

    def __init__(self, enterprise: bool = False, connect_enabled: bool = True,
                 acl_enabled: bool = True):
        self._enterprise = enterprise
        self._connect = connect_enabled
        self._acl = acl_enabled

    def collect_operation_families(self): return CL_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CL_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in CL_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            acl_evaluated=self._acl,
            intention_checked=(op_family.name == "intention_enforcement"),
            cert_issued=(op_family.name == "connect_certificate" and self._connect),
            audit_logged=self._enterprise,
            enterprise_edition=self._enterprise,
            service_name=None, decision=None, error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in CL_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "acl_token" in fam.declared_layers and inst.acl_evaluated:
            k.append("acl_token")
        if "acl_policy" in fam.declared_layers and inst.acl_evaluated:
            k.append("acl_policy")
        if "audit_log" in fam.declared_layers and inst.audit_logged:
            k.append("audit_log")
        if "service_catalog" in fam.declared_layers:
            k.append("service_catalog")
        if "connect_ca" in fam.declared_layers and inst.cert_issued:
            k.append("connect_ca")
        if "svid_receipt" in fam.declared_layers and inst.cert_issued:
            k.append("svid_receipt")
        if "intention_policy" in fam.declared_layers and inst.intention_checked:
            k.append("intention_policy")
        return k

    def assess_ear_state(self, op_family):
        if not self._acl and op_family.name != "connect_certificate":
            return EARState.ABSENT
        # Connect certificate: ACTIVE (SVID constitutive, same as SPIFFE)
        if op_family.name == "connect_certificate" and self._connect:
            return EARState.ACTIVE
        # ACL authorization: CRYSTALLIZED (Enterprise) or ABSENT (open source)
        if op_family.name == "acl_authorization":
            return EARState.CRYSTALLIZED if self._enterprise else EARState.ABSENT
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
