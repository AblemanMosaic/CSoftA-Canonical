"""
ear_adapter_cert_manager.py — cert-manager EAR Adapter
Wave 3 — System 11. Kubernetes-native X.509 certificate lifecycle management.

Key finding: certificate issuance approaches ACTIVE-EAR — Certificate resource
state is constitutive of issuance. The Certificate resource IS the governance
receipt: it encodes the issued certificate, expiry, and issuer. Closest to
SPIFFE/SPIRE in Wave 3. CRYSTALLIZED for most administrative operations.
Substrate dependency: cert-manager governance bounded by Kubernetes admission.
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
    name: str; description: str; declared_layers: list[str]; cm_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    certificate_issued: bool; issuer_verified: bool
    certificate_resource_updated: bool; renewal_triggered: bool
    secret_written: bool; namespace: str
    common_name: str | None; expiry: str | None
    error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CM_OPERATION_FAMILIES = [
    OperationFamily("certificate_issuance",
        "Issue X.509 certificate from Issuer/ClusterIssuer",
        ["certificate_resource", "issuer_verification", "secret_write", "renewal_schedule"], "issuance"),
    OperationFamily("certificate_renewal",
        "Renew certificate before expiry (automated)",
        ["certificate_resource", "issuer_verification", "secret_write"], "renewal"),
    OperationFamily("issuer_management",
        "Create/update Issuer or ClusterIssuer",
        ["issuer_resource", "issuer_verification"], "issuer"),
    OperationFamily("certificate_signing_request",
        "Process CertificateSigningRequest (CSR)",
        ["csr_resource", "issuer_verification", "certificate_resource"], "csr"),
]

CM_GOVERNANCE_LAYERS = {
    "certificate_resource": GovernanceLayer("certificate_resource",
        "Certificate CRD — IS the governance receipt; encodes cert, expiry, issuer", "status.certificate"),
    "issuer_verification": GovernanceLayer("issuer_verification",
        "Issuer/ClusterIssuer verified before signing", "spec.issuerRef"),
    "secret_write": GovernanceLayer("secret_write",
        "TLS Secret written with issued certificate", "spec.secretName"),
    "renewal_schedule": GovernanceLayer("renewal_schedule",
        "Renewal trigger at renewBefore threshold", "spec.renewBefore"),
    "issuer_resource": GovernanceLayer("issuer_resource",
        "Issuer/ClusterIssuer CRD declaration", "spec.ca"),
    "csr_resource": GovernanceLayer("csr_resource",
        "CertificateSigningRequest CRD", "spec.request"),
}

class CertManagerEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="cert-manager Documentation + cert-manager API reference + Kubernetes SIG-Auth",
        strategy="DECLARED-N",
        description=(
            "N(O) from cert-manager architecture. certificate_issuance N=4. "
            "certificate_issuance: ACTIVE — Certificate resource is constitutive of issuance. "
            "Cannot issue cert without Certificate resource being created/updated. "
            "The Certificate resource IS the receipt: encodes cert data, expiry, issuer. "
            "Analog of SPIFFE/SPIRE svid_issuance in Wave 2. "
            "Substrate dependency: cert-manager bounded by Kubernetes admission (T019)."
        ),
    )

    def __init__(self, issuer_type: str = "letsencrypt",
                 renewal_enabled: bool = True, webhook_active: bool = True):
        self._issuer = issuer_type
        self._renewal = renewal_enabled
        self._webhook = webhook_active

    def collect_operation_families(self): return CM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in CM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            certificate_issued=(op_family.name in ("certificate_issuance","certificate_renewal","certificate_signing_request")),
            issuer_verified=bool(self._issuer),
            certificate_resource_updated=True,
            renewal_triggered=(op_family.name == "certificate_renewal" and self._renewal),
            secret_written=(op_family.name in ("certificate_issuance","certificate_renewal")),
            namespace="default", common_name=None, expiry=None, error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in CM_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "certificate_resource" in fam.declared_layers and inst.certificate_resource_updated:
            k.append("certificate_resource")
        if "issuer_verification" in fam.declared_layers and inst.issuer_verified:
            k.append("issuer_verification")
        if "secret_write" in fam.declared_layers and inst.secret_written:
            k.append("secret_write")
        if "renewal_schedule" in fam.declared_layers and self._renewal:
            k.append("renewal_schedule")
        if "issuer_resource" in fam.declared_layers:
            k.append("issuer_resource")
        if "csr_resource" in fam.declared_layers and inst.certificate_issued:
            k.append("csr_resource")
        return k

    def assess_ear_state(self, op_family):
        # Certificate issuance and renewal: ACTIVE
        # Certificate resource is constitutive — cannot issue without it
        if op_family.name in ("certificate_issuance", "certificate_renewal"):
            return EARState.ACTIVE
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
