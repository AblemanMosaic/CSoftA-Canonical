"""
ear_adapter_cert_manager_acme.py — cert-manager ACME EAR Adapter
Wave 10 — System 47. TLS certificate lifecycle governance.

Key finding: Wave 3 covered cert-manager generically (T1662). Wave 10
examines the ACME protocol integration: automated TLS certificate issuance
and renewal with Let's Encrypt or other ACME CAs. Certificate issuance is
ACTIVE when cert-manager is healthy: a certificate that expires or is
revoked prevents TLS connections — the certificate is constitutive of the
secure connection. Certificate transparency (CT) logs record all issued
certificates publicly. The ACME challenge governance (DNS-01/HTTP-01) is
the critical security surface: a DNS-01 challenge requires write access to
DNS records; an HTTP-01 challenge requires serving a token at /.well-known/.
Misconfigured ACME account keys or solver configurations produce ABSENT
certificate issuance — services fail silently without TLS.
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
    name: str; description: str; declared_layers: list[str]; acme_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    cert_issued: bool; challenge_completed: bool
    ct_logged: bool; renewal_automated: bool
    account_key_secured: bool; solver_scoped: bool
    domain: str|None; issuer: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ACME_OPERATION_FAMILIES = [
    OperationFamily("cert_issuance",
        "Issue TLS certificate via ACME protocol",
        ["acme_challenge","cert_transparency","cert_validity","issuer_trust"], "issue"),
    OperationFamily("cert_renewal",
        "Automatically renew expiring TLS certificate",
        ["acme_challenge","cert_transparency","renewal_automation","cert_validity"], "renew"),
    OperationFamily("challenge_completion",
        "Complete ACME DNS-01 or HTTP-01 challenge to prove domain control",
        ["challenge_solver","acme_challenge","solver_rbac"], "challenge"),
    OperationFamily("cert_revocation",
        "Revoke compromised TLS certificate",
        ["cert_transparency","revocation_check","issuer_trust"], "revoke"),
    OperationFamily("account_governance",
        "Govern ACME account key and registration",
        ["acme_account","account_key_security","issuer_trust"], "account"),
]

ACME_GOVERNANCE_LAYERS = {
    "acme_challenge": GovernanceLayer("acme_challenge",
        "ACME challenge (DNS-01/HTTP-01) proves domain control", "challenge"),
    "cert_transparency": GovernanceLayer("cert_transparency",
        "Certificate Transparency log entry — public record of all issued certs", "Certificate"),
    "cert_validity": GovernanceLayer("cert_validity",
        "Certificate validity period (90 days for LE) and expiry monitoring", "NotAfter"),
    "issuer_trust": GovernanceLayer("issuer_trust",
        "CA trust chain — issuer trusted by browsers/clients", "Issuer"),
    "renewal_automation": GovernanceLayer("renewal_automation",
        "cert-manager automated renewal before expiry", "renewBefore"),
    "challenge_solver": GovernanceLayer("challenge_solver",
        "ACME solver configuration (dns01/http01) for challenge completion", "solvers"),
    "solver_rbac": GovernanceLayer("solver_rbac",
        "RBAC scope for DNS solver (least-privilege DNS zone access)", None),
    "revocation_check": GovernanceLayer("revocation_check",
        "OCSP/CRL revocation status check for issued certificates", None, is_optional=True),
    "acme_account": GovernanceLayer("acme_account",
        "ACME account registration with CA", "email"),
    "account_key_security": GovernanceLayer("account_key_security",
        "ACME account private key stored in K8s Secret with encryption", None),
}

class CertManagerACMEEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="cert-manager Documentation + Let's Encrypt documentation + ACME RFC 8555",
        strategy="DECLARED-N",
        description=(
            "N(O) from cert-manager ACME architecture. cert_issuance N=4. "
            "cert_issuance: ACTIVE — valid certificate is constitutive of TLS connection; "
            "expired/revoked certificate prevents all connections. "
            "cert_renewal: ACTIVE — cert-manager automates renewal before expiry; "
            "renewal failure = service unavailability. "
            "Certificate Transparency: CRYSTALLIZED — all issued certs publicly logged; "
            "certificate misissuance is detectable but not preventable post-hoc. "
            "DNS-01 solver RBAC gap: solver needs DNS write access — "
            "overly broad DNS permissions give cert-manager zone-wide control. "
            "Account key: K8s Secret — same credential security considerations as other secrets."
        ),
    )
    def __init__(self, ct_monitored: bool=True, renewal_automated: bool=True,
                 solver_scoped: bool=False, account_key_encrypted: bool=False):
        self._ct = ct_monitored
        self._renewal = renewal_automated
        self._solver = solver_scoped
        self._account_key = account_key_encrypted

    def collect_operation_families(self): return ACME_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ACME_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ACME_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            cert_issued=True, challenge_completed=True,
            ct_logged=self._ct, renewal_automated=self._renewal,
            account_key_secured=self._account_key, solver_scoped=self._solver,
            domain=None, issuer=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ACME_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "acme_challenge" in fam.declared_layers: k.append("acme_challenge")
        if "cert_transparency" in fam.declared_layers and self._ct: k.append("cert_transparency")
        if "cert_validity" in fam.declared_layers: k.append("cert_validity")
        if "issuer_trust" in fam.declared_layers: k.append("issuer_trust")
        if "renewal_automation" in fam.declared_layers and self._renewal: k.append("renewal_automation")
        if "challenge_solver" in fam.declared_layers: k.append("challenge_solver")
        if "solver_rbac" in fam.declared_layers and self._solver: k.append("solver_rbac")
        if "acme_account" in fam.declared_layers: k.append("acme_account")
        if "account_key_security" in fam.declared_layers and self._account_key: k.append("account_key_security")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name in ("cert_issuance","cert_renewal"): return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
