"""
ear_adapter_cosign.py — Cosign / Sigstore EAR Adapter
Wave 8 — System 39. Supply chain signing governance.

Key finding: Cosign/Sigstore is the corpus's dedicated supply chain signing
governance case — it directly addresses the gaps identified in Packer (T1719),
Helm (T1708), and GitHub Actions (T1702). Cosign provides container image
signing and verification; Sigstore provides the transparent ledger (Rekor)
for signature transparency; keyless signing uses OIDC tokens (from GitHub
Actions, etc.) to sign without long-lived keys.
The constitutional significance: when Cosign is used with policy-controller,
image signature verification becomes ACTIVE for container deployment —
a container image that has not been signed by a trusted party cannot be
admitted to the cluster (constitutive of deployment). This is the first
system in the corpus that directly makes a governance gap from another
system ACTIVE through verification.
Rekor transparency log: append-only log of all signatures, monitored
by Sigstore's transparency monitoring infrastructure. CRYSTALLIZED:
the log records signatures, but monitoring detects tampering post-hoc.
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
    name: str; description: str; declared_layers: list[str]; sigstore_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    signature_verified: bool; policy_enforced: bool
    rekor_logged: bool; oidc_identity_verified: bool
    sbom_attested: bool; provenance_verified: bool
    image_ref: str|None; signer_identity: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

COSIGN_OPERATION_FAMILIES = [
    OperationFamily("image_verification",
        "Verify container image signature before admission",
        ["signature_verification","policy_enforcement","rekor_transparency","oidc_identity"], "verify"),
    OperationFamily("image_signing",
        "Sign container image with Cosign (keyless or keyed)",
        ["signature_record","rekor_transparency","oidc_identity","signing_key_governance"], "sign"),
    OperationFamily("policy_enforcement",
        "Enforce signature policy via policy-controller admission webhook",
        ["policy_enforcement","signature_verification","admission_receipt"], "policy"),
    OperationFamily("provenance_attestation",
        "Attach SLSA provenance attestation to image",
        ["provenance_record","rekor_transparency","oidc_identity"], "provenance"),
    OperationFamily("sbom_attestation",
        "Attach SBOM attestation to image",
        ["sbom_record","rekor_transparency","signature_record"], "sbom"),
]

COSIGN_GOVERNANCE_LAYERS = {
    "signature_verification": GovernanceLayer("signature_verification",
        "Cosign signature verified against trusted key or identity", None),
    "policy_enforcement": GovernanceLayer("policy_enforcement",
        "policy-controller enforces signature policy at admission", None),
    "rekor_transparency": GovernanceLayer("rekor_transparency",
        "Rekor transparency log entry for signature", "rekorUUID"),
    "oidc_identity": GovernanceLayer("oidc_identity",
        "OIDC identity binding signer to workflow/CI identity", None),
    "signature_record": GovernanceLayer("signature_record",
        "OCI signature stored in registry alongside image", None),
    "signing_key_governance": GovernanceLayer("signing_key_governance",
        "Key management for keyed signing (KMS, hardware)", None, is_optional=True),
    "admission_receipt": GovernanceLayer("admission_receipt",
        "Admission controller decision receipt", None),
    "provenance_record": GovernanceLayer("provenance_record",
        "SLSA provenance record attached to image", None),
    "sbom_record": GovernanceLayer("sbom_record",
        "SBOM record attached to image in registry", None),
}

class CosignEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Cosign Documentation + Sigstore documentation + policy-controller documentation",
        strategy="DECLARED-N",
        description=(
            "N(O) from Cosign/Sigstore architecture. image_verification N=4. "
            "policy_enforcement with signature_verification: ACTIVE — "
            "policy-controller is constitutive of admission: unsigned images are rejected. "
            "This is the corpus's first system where a supply chain governance gap "
            "(Packer T1719, Helm T1708, GitHub Actions T1702) can be made ACTIVE "
            "through verification enforcement at the admission point. "
            "image_signing: CRYSTALLIZED — signature recorded in Rekor, "
            "but signing is opt-in; unsigned images can still be built and stored. "
            "Rekor transparency: CRYSTALLIZED — append-only log detects tampering "
            "post-hoc; monitoring required to detect signature gaps. "
            "Keyless signing via OIDC: strongest identity binding available — "
            "links signature to GitHub Actions workflow or CI identity, not to a "
            "long-lived key that can be stolen."
        ),
    )
    def __init__(self, policy_enforced: bool=False, signature_verified: bool=False,
                 rekor_logged: bool=True, oidc_signing: bool=False,
                 sbom_attested: bool=False, provenance_attested: bool=False):
        self._policy = policy_enforced
        self._verify = signature_verified
        self._rekor = rekor_logged
        self._oidc = oidc_signing
        self._sbom = sbom_attested
        self._provenance = provenance_attested

    def collect_operation_families(self): return COSIGN_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [COSIGN_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in COSIGN_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            signature_verified=self._verify, policy_enforced=self._policy,
            rekor_logged=self._rekor, oidc_identity_verified=self._oidc,
            sbom_attested=self._sbom, provenance_verified=self._provenance,
            image_ref=None, signer_identity=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in COSIGN_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "signature_verification" in fam.declared_layers and self._verify: k.append("signature_verification")
        if "policy_enforcement" in fam.declared_layers and self._policy: k.append("policy_enforcement")
        if "rekor_transparency" in fam.declared_layers and self._rekor: k.append("rekor_transparency")
        if "oidc_identity" in fam.declared_layers and self._oidc: k.append("oidc_identity")
        if "signature_record" in fam.declared_layers and self._verify: k.append("signature_record")
        if "admission_receipt" in fam.declared_layers and self._policy: k.append("admission_receipt")
        if "provenance_record" in fam.declared_layers and self._provenance: k.append("provenance_record")
        if "sbom_record" in fam.declared_layers and self._sbom: k.append("sbom_record")
        return k
    def assess_ear_state(self, op_family):
        # policy_enforcement with signature verification = ACTIVE
        if op_family.name == "policy_enforcement" and self._policy and self._verify:
            return EARState.ACTIVE
        if not self._verify: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
