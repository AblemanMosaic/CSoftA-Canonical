"""
ear_adapter_pypi.py — PyPI / pip EAR Adapter
Wave 11 — System 52. Python package registry governance.

Key finding: PyPI is the Python supply chain governance case. npm (Wave 1)
established the package registry template; PyPI extends it with two new
constitutional findings:
(1) PEP 740 / Trusted Publishing + Sigstore attestations: CRYSTALLIZED-forward
    state — attestations cryptographically bind packages to their build
    provenance using Sigstore. Over 30,000 packages use Trusted Publishing.
    But client-side verification (pip/uv) is NOT yet mandatory — attestations
    provide transparency and auditability but not active protection during install.
(2) Mini Shai-Hulud campaign (September 2025–May 2026, CVE-2026-45321):
    TeamPCP compromised packages carrying valid SLSA Build Level 3 provenance
    attestations. This is the policy correctness gap (T1777) applied to supply
    chain provenance: the attestation mechanism was ACTIVE (constitutively signing)
    but the policy that signed them was corrupted. ACTIVE signing of malicious
    packages produces ACTIVE wrong attestations — the second-order governance gap
    at the supply chain layer.
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
    name: str; description: str; declared_layers: list[str]; pypi_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    attestation_present: bool; trusted_publishing: bool
    mfa_enforced: bool; quarantine_active: bool
    sigstore_verified: bool; pip_verification: bool
    package_name: str|None; version: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PYPI_OPERATION_FAMILIES = [
    OperationFamily("package_install",
        "Install Python package via pip/uv from PyPI",
        ["attestation_verification","trusted_publishing","sigstore_transparency","mfa_maintainer"], "install"),
    OperationFamily("package_publish",
        "Publish package to PyPI",
        ["trusted_publishing","mfa_maintainer","attestation_generation","sigstore_transparency"], "publish"),
    OperationFamily("provenance_attestation",
        "Generate and verify SLSA provenance attestation",
        ["attestation_generation","sigstore_transparency","trusted_publishing"], "provenance"),
    OperationFamily("maintainer_authentication",
        "Authenticate package maintainer for upload",
        ["mfa_maintainer","trusted_publishing","audit_trail"], "auth"),
    OperationFamily("dependency_resolution",
        "Resolve transitive dependencies from PyPI",
        ["attestation_verification","sigstore_transparency","dependency_lock"], "deps"),
]

PYPI_GOVERNANCE_LAYERS = {
    "attestation_verification": GovernanceLayer("attestation_verification",
        "Client-side verification of PEP 740 attestations during install", None, is_optional=True),
    "trusted_publishing": GovernanceLayer("trusted_publishing",
        "PyPI Trusted Publishing via OIDC — eliminates API token for publish", "trusted_publisher"),
    "mfa_maintainer": GovernanceLayer("mfa_maintainer",
        "MFA required for maintainer accounts", None),
    "attestation_generation": GovernanceLayer("attestation_generation",
        "PEP 740 Sigstore attestation generated at build time", "attestation"),
    "sigstore_transparency": GovernanceLayer("sigstore_transparency",
        "Sigstore transparency log entry for published package", "rekorURI"),
    "audit_trail": GovernanceLayer("audit_trail",
        "PyPI audit log for maintainer actions", None),
    "dependency_lock": GovernanceLayer("dependency_lock",
        "Dependencies pinned by hash (requirements.txt with --hash)", None, is_optional=True),
}

class PyPIEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="PyPI documentation + PEP 740 + Trail of Bits supply chain analysis + Mini Shai-Hulud",
        strategy="DECLARED-N",
        description=(
            "N(O) from PyPI architecture. package_install N=4. "
            "package_install: ABSENT by default — pip does not verify attestations. "
            "provenance_attestation generation: CRYSTALLIZED — Sigstore records, "
            "but client verification is opt-in. "
            "Mini Shai-Hulud (CVE-2026-45321, Sept 2025–May 2026): TeamPCP "
            "compromised packages carrying valid SLSA Build Level 3 attestations. "
            "84 malicious TanStack package versions published with valid Sigstore signatures. "
            "Constitutional finding: ACTIVE attestation signing of malicious packages "
            "produces ACTIVE wrong provenance — the T1777 policy correctness gap "
            "at the supply chain attestation layer. "
            "Ultralytics compromise (December 2024): GitHub Actions cache poisoning "
            "published cryptominer to package with 80M weekly downloads. "
            "Sigstore transparency log: CRYSTALLIZED — detected after publish, not before. "
            "PEP 740 Trusted Publishing: eliminates API token theft vector — strongest "
            "maintainer authentication improvement in PyPI history."
        ),
    )
    def __init__(self, attestation_verification: bool=False, trusted_publishing: bool=False,
                 mfa_enforced: bool=False, dependency_locked: bool=False):
        self._verify = attestation_verification
        self._tp = trusted_publishing
        self._mfa = mfa_enforced
        self._lock = dependency_locked

    def collect_operation_families(self): return PYPI_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PYPI_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in PYPI_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            attestation_present=self._verify, trusted_publishing=self._tp,
            mfa_enforced=self._mfa, quarantine_active=True,
            sigstore_verified=self._verify, pip_verification=self._verify,
            package_name=None, version=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in PYPI_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "attestation_verification" in fam.declared_layers and self._verify: k.append("attestation_verification")
        if "trusted_publishing" in fam.declared_layers and self._tp: k.append("trusted_publishing")
        if "mfa_maintainer" in fam.declared_layers and self._mfa: k.append("mfa_maintainer")
        if "attestation_generation" in fam.declared_layers and self._tp: k.append("attestation_generation")
        if "sigstore_transparency" in fam.declared_layers: k.append("sigstore_transparency")
        if "audit_trail" in fam.declared_layers: k.append("audit_trail")
        if "dependency_lock" in fam.declared_layers and self._lock: k.append("dependency_lock")
        return k
    def assess_ear_state(self, op_family):
        # With mandatory client verification: package_install would be ACTIVE
        if op_family.name == "package_install" and self._verify: return EARState.CRYSTALLIZED
        if op_family.name == "package_install": return EARState.ABSENT
        if op_family.name == "provenance_attestation" and self._tp: return EARState.CRYSTALLIZED
        return EARState.CRYSTALLIZED if (self._tp or self._mfa) else EARState.ABSENT
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
