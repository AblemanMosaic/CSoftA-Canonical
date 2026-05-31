"""
ear_adapter_spiffe.py — SPIFFE/SPIRE EAR Adapter
Wave 2 — System 10. Cryptographic workload identity.

Key finding: svid_issuance approaches ACTIVE-EAR. Workload attestation IS constitutive.
The SVID itself is the governance receipt. Wave 2 strongest governance case.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE = "ACTIVE"; CRYSTALLIZED = "CRYSTALLIZED"; ABSENT = "ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"; ABSENCE = "ABSENCE"; BYPASS = "BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; spiffe_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    workload_attested: bool; node_attested: bool
    svid_issued: bool; rotation_logged: bool
    spiffe_id: str | None; ttl_seconds: int
    error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

SP_OPERATION_FAMILIES = [
    OperationFamily("svid_issuance",
        "Issue X.509 SVID to attested workload",
        ["workload_attestation", "node_attestation", "svid_receipt"], "issuance"),
    OperationFamily("workload_registration",
        "Register workload entry (RegistrationEntry) in SPIRE server",
        ["registration_entry", "admin_auth"], "registration"),
    OperationFamily("node_attestation_op",
        "Attest a SPIRE agent node to SPIRE server",
        ["node_attestation", "node_selectors"], "node"),
    OperationFamily("svid_rotation",
        "Rotate an expiring SVID before expiry",
        ["workload_attestation", "svid_receipt"], "rotation"),
    OperationFamily("bundle_federation",
        "Federate trust bundles with external SPIFFE trust domains",
        ["federation_endpoint", "bundle_receipt"], "federation"),
]

SP_GOVERNANCE_LAYERS = {
    "workload_attestation": GovernanceLayer("workload_attestation",
        "Workload attestation via platform plugin — constitutive of SVID issuance", "selectors"),
    "node_attestation": GovernanceLayer("node_attestation",
        "Node attestation — SPIRE agent attests node to SPIRE server", "attestation_data"),
    "svid_receipt": GovernanceLayer("svid_receipt",
        "X.509 SVID issued — the receipt IS the identity credential", "certificate"),
    "registration_entry": GovernanceLayer("registration_entry",
        "RegistrationEntry declaring workload selector and SPIFFE ID", "spec.spiffeId"),
    "admin_auth": GovernanceLayer("admin_auth",
        "Administrative auth for server management API", "token"),
    "node_selectors": GovernanceLayer("node_selectors",
        "Node selectors used in node attestation", "selectors"),
    "federation_endpoint": GovernanceLayer("federation_endpoint",
        "Federation endpoint config for cross-domain trust", "address"),
    "bundle_receipt": GovernanceLayer("bundle_receipt",
        "Trust bundle received from federated SPIFFE domain", "bundle"),
}

class SPIFFEEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="SPIFFE Specification + SPIRE Documentation + SPIRE GitHub + RFC 7518",
        strategy="DECLARED-N",
        description=(
            "N(O) from SPIFFE spec + SPIRE architecture. svid_issuance N=3. "
            "svid_issuance approaches ACTIVE-EAR: workload attestation IS constitutive — "
            "SPIRE cannot issue an SVID without completing attestation. "
            "The SVID itself is the governance receipt: cryptographically encodes SPIFFE ID, "
            "validity, and issuing authority. "
            "Distinction from ACTIVE: attestation decision audit trail not in a mandatory "
            "separate receipt. Short-lived SVIDs (default 1h) enforce re-attestation. "
            "Wave 2 strongest governance case — analog of Vault in Wave 1."
        ),
    )

    def __init__(self, attestation_plugin: str = "k8s_psat",
                 svid_ttl_seconds: int = 3600,
                 audit_log_enabled: bool = False,
                 federation_enabled: bool = False):
        self._plugin = attestation_plugin
        self._ttl = svid_ttl_seconds
        self._audit = audit_log_enabled
        self._federation = federation_enabled

    def collect_operation_families(self): return SP_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [SP_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in SP_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        attested = bool(self._plugin)
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            workload_attested=attested, node_attested=attested,
            svid_issued=(op_family.name in ("svid_issuance", "svid_rotation")),
            rotation_logged=self._audit,
            spiffe_id=f"spiffe://example.org/ns/default/{op_family.name}" if attested else None,
            ttl_seconds=self._ttl,
            error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in SP_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "workload_attestation" in fam.declared_layers and inst.workload_attested:
            k.append("workload_attestation")
        if "node_attestation" in fam.declared_layers and inst.node_attested:
            k.append("node_attestation")
        if "svid_receipt" in fam.declared_layers and inst.svid_issued:
            k.append("svid_receipt")
        if "registration_entry" in fam.declared_layers:
            k.append("registration_entry")
        if "admin_auth" in fam.declared_layers:
            k.append("admin_auth")
        if "node_selectors" in fam.declared_layers and inst.node_attested:
            k.append("node_selectors")
        if "federation_endpoint" in fam.declared_layers and self._federation:
            k.append("federation_endpoint")
        if "bundle_receipt" in fam.declared_layers and self._federation:
            k.append("bundle_receipt")
        return k

    def assess_ear_state(self, op_family):
        # svid_issuance: ACTIVE — workload attestation IS constitutive
        # SPIRE cannot issue SVID without completing attestation plugin chain
        if op_family.name == "svid_issuance":
            return EARState.ACTIVE
        # svid_rotation: same constitutive property
        if op_family.name == "svid_rotation":
            return EARState.ACTIVE
        # All other families: CRYSTALLIZED
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
