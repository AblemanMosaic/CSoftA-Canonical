"""
ear_adapter_packer.py — HashiCorp Packer EAR Adapter
Wave 7 — System 31. Image build governance.

Key finding: Packer is the build pipeline governance case — the system that
produces AMIs, Docker images, and VM templates that everything else runs on.
The built image is a governance artifact but its provenance is ABSENT by default:
Packer produces build logs (CRYSTALLIZED) but no mandatory receipt binding
the output artifact to the declared build configuration, input sources, and
build environment. SLSA provenance attestation for builds is opt-in.
Image signing (Cosign, AWS AMI signing) is opt-in.
The closest to ACTIVE: Packer's HCP Packer Registry records build lineage
(what base image was used, what configuration produced it) — but this is
a commercial/cloud feature, not the OSS default.
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
    name: str; description: str; declared_layers: list[str]; packer_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    build_log_written: bool; image_signed: bool
    provenance_attested: bool; sbom_generated: bool
    checksum_recorded: bool; registry_logged: bool
    template: str|None; artifact_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PACKER_OPERATION_FAMILIES = [
    OperationFamily("image_build",
        "Build machine image from template",
        ["build_log","image_checksum","provenance_attestation","image_signing"], "build"),
    OperationFamily("base_image_pull",
        "Pull base image for build",
        ["image_checksum","base_image_provenance","build_log"], "base"),
    OperationFamily("image_publication",
        "Publish built image to registry or cloud",
        ["build_log","image_checksum","image_signing","registry_receipt"], "publish"),
    OperationFamily("build_registry",
        "Record build lineage in HCP Packer Registry",
        ["registry_receipt","build_log","image_checksum"], "registry"),
    OperationFamily("sbom_generation",
        "Generate Software Bill of Materials for built image",
        ["sbom_artifact","build_log","image_checksum"], "sbom"),
]

PACKER_GOVERNANCE_LAYERS = {
    "build_log": GovernanceLayer("build_log",
        "Packer build log — records build steps and output", None),
    "image_checksum": GovernanceLayer("image_checksum",
        "Checksum/digest of produced image artifact", "artifact.id"),
    "provenance_attestation": GovernanceLayer("provenance_attestation",
        "SLSA provenance attestation for build — opt-in", None, is_optional=True),
    "image_signing": GovernanceLayer("image_signing",
        "Image signature (Cosign, AMI signing) — opt-in", None, is_optional=True),
    "base_image_provenance": GovernanceLayer("base_image_provenance",
        "Provenance of base image used in build", None, is_optional=True),
    "registry_receipt": GovernanceLayer("registry_receipt",
        "HCP Packer Registry build lineage record — commercial/cloud feature", None, is_optional=True),
    "sbom_artifact": GovernanceLayer("sbom_artifact",
        "SBOM artifact (CycloneDX/SPDX) for image — opt-in", None, is_optional=True),
}

class PackerEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="HashiCorp Packer Documentation + HCP Packer Registry docs + SLSA Build L3",
        strategy="DECLARED-N",
        description=(
            "N(O) from Packer architecture. image_build N=4. "
            "CRYSTALLIZED ceiling for OSS Packer: build log exists, checksum recorded, "
            "but no mandatory receipt binding output artifact to declared build config. "
            "Image signing and SLSA provenance are opt-in. "
            "HCP Packer Registry (commercial): CRYSTALLIZED — build lineage recorded "
            "but registry is a downstream artifact, not constitutive of build execution. "
            "The build pipeline produces an artifact whose provenance is "
            "attestable but not constitutively attested by default."
        ),
    )
    def __init__(self, image_signed: bool=False, provenance_attested: bool=False,
                 sbom_generated: bool=False, registry_enabled: bool=False):
        self._signed = image_signed
        self._provenance = provenance_attested
        self._sbom = sbom_generated
        self._registry = registry_enabled

    def collect_operation_families(self): return PACKER_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PACKER_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in PACKER_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            build_log_written=True, image_signed=self._signed,
            provenance_attested=self._provenance, sbom_generated=self._sbom,
            checksum_recorded=True, registry_logged=self._registry,
            template=None, artifact_id=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in PACKER_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "build_log" in fam.declared_layers: k.append("build_log")
        if "image_checksum" in fam.declared_layers: k.append("image_checksum")
        if "provenance_attestation" in fam.declared_layers and self._provenance: k.append("provenance_attestation")
        if "image_signing" in fam.declared_layers and self._signed: k.append("image_signing")
        if "base_image_provenance" in fam.declared_layers and self._provenance: k.append("base_image_provenance")
        if "registry_receipt" in fam.declared_layers and self._registry: k.append("registry_receipt")
        if "sbom_artifact" in fam.declared_layers and self._sbom: k.append("sbom_artifact")
        return k
    def assess_ear_state(self, op_family):
        # No OSS Packer family reaches ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
