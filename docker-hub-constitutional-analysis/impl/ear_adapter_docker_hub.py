"""
ear_adapter_docker_hub.py — Docker Hub / OCI Registry EAR Adapter
Wave 13 — System 62. Container registry governance.

Key finding: Docker Hub / OCI registries are the supply chain middle layer
between image build (Packer Wave 7, T1719) and image admission (Cosign/PSA Wave 8-10).
This completes the supply chain triangle:
- Build-time provenance gap (Packer, T1719): ABSENT by default
- Registry-time governance gap (Docker Hub, THIS): mutable tags are ABSENT
- Admission-time closure (Cosign, T1739): ACTIVE when configured

Pulling nginx:latest from Docker Hub: ABSENT provenance — mutable tag can
point to different digest each pull; no mandatory signature verification;
no provenance attestation requirement for anonymous pulls.

Trivy scanner supply chain compromise (March 2026): attacker re-pointed the
:latest tag on the Trivy container image on Docker Hub to malicious content.
Mutable tag = ABSENT governance of which bytes you actually pull.
This confirms the registry-time governance gap directly.

Docker Hardened Images (DHI, December 2025, Apache 2.0): SLSA Build Level 3
provenance + CycloneDX/SPDX SBOMs + VEX + Cosign signing per image.
DHI = CRYSTALLIZED-forward for public registry images.
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
    name: str; description: str; declared_layers: list[str]; registry_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    signature_verified: bool; provenance_present: bool
    digest_pinned: bool; registry_auth: bool
    vulnerability_scanned: bool; sbom_present: bool
    image_ref: str|None; registry: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

REGISTRY_OPERATION_FAMILIES = [
    OperationFamily("image_pull",
        "Pull container image from registry",
        ["digest_pin","signature_verify","provenance_attest","registry_auth"], "pull"),
    OperationFamily("image_push",
        "Push container image to registry (publish)",
        ["registry_auth","signature_sign","provenance_generate","vulnerability_scan"], "push"),
    OperationFamily("tag_mutation",
        "Reassign mutable image tag to different digest",
        ["registry_auth","audit_log","signature_sign"], "tag"),
    OperationFamily("provenance_verification",
        "Verify image build provenance attestation",
        ["signature_verify","provenance_attest","transparency_log"], "prov"),
    OperationFamily("vulnerability_governance",
        "Govern image vulnerability status before pull/deployment",
        ["vulnerability_scan","vex_metadata","sbom_present"], "vuln"),
]

REGISTRY_GOVERNANCE_LAYERS = {
    "digest_pin": GovernanceLayer("digest_pin",
        "Image reference uses digest (sha256:...) not mutable tag", None),
    "signature_verify": GovernanceLayer("signature_verify",
        "Cosign signature verification at pull time", "cosign verify"),
    "provenance_attest": GovernanceLayer("provenance_attest",
        "SLSA provenance attestation present and verified", "attestation"),
    "registry_auth": GovernanceLayer("registry_auth",
        "Authenticated pull — no anonymous access to private images", None),
    "signature_sign": GovernanceLayer("signature_sign",
        "Image signed with Cosign at push time", None),
    "provenance_generate": GovernanceLayer("provenance_generate",
        "SLSA provenance attestation generated at build time", None),
    "vulnerability_scan": GovernanceLayer("vulnerability_scan",
        "Image scanned for known vulnerabilities before use", None, is_optional=True),
    "audit_log": GovernanceLayer("audit_log",
        "Registry audit log for push/tag mutation events", None, is_optional=True),
    "transparency_log": GovernanceLayer("transparency_log",
        "Sigstore Rekor transparency log entry for signature", "rekorURI", is_optional=True),
    "vex_metadata": GovernanceLayer("vex_metadata",
        "VEX (Vulnerability Exploitability eXchange) metadata for CVE exploitability", None, is_optional=True),
    "sbom_present": GovernanceLayer("sbom_present",
        "Software Bill of Materials attached to image as OCI attestation", None, is_optional=True),
}

class DockerHubEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Docker Hub + OCI spec + Trivy compromise (March 2026) + Docker Hardened Images (DHI)",
        strategy="DECLARED-N",
        description=(
            "N(O) from Docker Hub / OCI registry architecture. image_pull N=4. "
            "image_pull with mutable tag (latest, v1.2, etc.): ABSENT — "
            "tag can be silently re-pointed to different digest; no signature verification. "
            "image_pull with digest pin only: CRYSTALLIZED — "
            "same bytes every time; no provenance verification. "
            "image_pull with digest + signature verification: CRYSTALLIZED — "
            "highest attainable at registry consumption layer without policy enforcement. "
            "Trivy scanner compromise (March 2026): attacker re-pointed :latest "
            "on Docker Hub multiple times to malicious content. "
            "Mutable tag = ABSENT governance of supply chain middle layer. "
            "Docker Hardened Images (DHI, Dec 2025, Apache 2.0): "
            "SLSA L3 provenance + SBOM + VEX per image — CRYSTALLIZED-forward. "
            "Supply chain triangle: Packer build-time (T1719) + Docker Hub registry-time "
            "(THIS) + Cosign admission-time (T1739). "
            "No registry family reaches ACTIVE at the registry layer alone — "
            "admission gate (Cosign policy-controller) is required for ACTIVE closure."
        ),
    )
    def __init__(self, digest_pinned: bool=False, signature_verified: bool=False,
                 provenance_verified: bool=False, registry_auth: bool=True):
        self._digest = digest_pinned
        self._sig = signature_verified
        self._prov = provenance_verified
        self._auth = registry_auth

    def collect_operation_families(self): return REGISTRY_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [REGISTRY_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in REGISTRY_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            signature_verified=self._sig, provenance_present=self._prov,
            digest_pinned=self._digest, registry_auth=self._auth,
            vulnerability_scanned=False, sbom_present=False,
            image_ref=None, registry=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in REGISTRY_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "digest_pin" in fam.declared_layers and self._digest: k.append("digest_pin")
        if "signature_verify" in fam.declared_layers and self._sig: k.append("signature_verify")
        if "provenance_attest" in fam.declared_layers and self._prov: k.append("provenance_attest")
        if "registry_auth" in fam.declared_layers and self._auth: k.append("registry_auth")
        if "signature_sign" in fam.declared_layers and self._sig: k.append("signature_sign")
        if "provenance_generate" in fam.declared_layers and self._prov: k.append("provenance_generate")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "image_pull":
            if not self._digest: return EARState.ABSENT
            return EARState.CRYSTALLIZED
        if op_family.name == "tag_mutation":
            return EARState.ABSENT  # tag mutation is always ungoverned without registry policies
        return EARState.CRYSTALLIZED if self._auth else EARState.ABSENT
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
