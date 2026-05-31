"""
ear_adapter_helm.py — Helm EAR Adapter
Wave 7 — System 35. Kubernetes package management.

Key finding: Helm is the deployment packaging governance case.
Chart provenance verification (Helm chart signing with GPG/Cosign)
is opt-in and rarely used in practice. Helm chart values may contain
sensitive credentials stored as Kubernetes Secrets (CRYSTALLIZED).
Helm hooks execute with the ServiceAccount permissions of the deploying
principal — hook governance is CRYSTALLIZED. The chart repository is
the supply chain boundary: an attacker who compromises a chart repository
or a chart maintainer's credentials can publish malicious charts that
will be deployed without provenance verification.
Helm release history (stored in Kubernetes Secrets) provides a CRYSTALLIZED
audit trail of deployments. No Helm operation reaches ACTIVE.
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
    name: str; description: str; declared_layers: list[str]; helm_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    release_recorded: bool; chart_verified: bool
    rbac_evaluated: bool; values_encrypted: bool
    provenance_checked: bool; hook_receipted: bool
    release_name: str|None; chart_version: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

HELM_OPERATION_FAMILIES = [
    OperationFamily("chart_install",
        "Install Helm chart as release in Kubernetes namespace",
        ["release_record","chart_provenance","rbac_check","values_governance"], "install"),
    OperationFamily("chart_upgrade",
        "Upgrade existing Helm release to new chart version",
        ["release_record","chart_provenance","rbac_check","values_governance"], "upgrade"),
    OperationFamily("hook_execution",
        "Execute Helm lifecycle hook (pre-install, post-upgrade, etc.)",
        ["release_record","rbac_check","hook_log"], "hook"),
    OperationFamily("chart_pull",
        "Pull chart from OCI registry or Helm repository",
        ["chart_provenance","chart_checksum","registry_auth"], "pull"),
    OperationFamily("secret_management",
        "Manage Helm values containing sensitive credentials",
        ["values_governance","release_record","secrets_encryption"], "secret"),
]

HELM_GOVERNANCE_LAYERS = {
    "release_record": GovernanceLayer("release_record",
        "Helm release stored as Kubernetes Secret — deployment history", "helm.sh/release"),
    "chart_provenance": GovernanceLayer("chart_provenance",
        "Chart provenance verification (GPG signature, Cosign) — opt-in", None, is_optional=True),
    "chart_checksum": GovernanceLayer("chart_checksum",
        "SHA256 digest of chart archive", "digest"),
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC check for Helm deployment in target namespace", None),
    "values_governance": GovernanceLayer("values_governance",
        "Values governance — secret values should use external secrets", None),
    "hook_log": GovernanceLayer("hook_log",
        "Hook execution log in Helm release notes", None),
    "registry_auth": GovernanceLayer("registry_auth",
        "Authentication to OCI registry for chart pull", None),
    "secrets_encryption": GovernanceLayer("secrets_encryption",
        "Encryption of Helm values secrets (helm-secrets plugin)", None, is_optional=True),
}

class HelmEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Helm Documentation + Helm Security + OCI Helm charts + helm-secrets documentation",
        strategy="DECLARED-N",
        description=(
            "N(O) from Helm architecture. chart_install N=4. "
            "release_record: CRYSTALLIZED — release stored as K8s Secret, "
            "provides deployment history but is not constitutive of install. "
            "chart_provenance: ABSENT by default — chart signing opt-in, "
            "rarely verified in practice. "
            "CVE-2019-25210 (Helm --dry-run secret disclosure): "
            "sensitive values displayed in dry-run output. "
            "CVE-2024-25620 (path traversal in chart name). "
            "SUSE Fleet CVE-2024-52284: Helm values stored in plaintext in BundleDeployment. "
            "Supply chain: chart repository compromise can publish malicious charts "
            "deployed without verification — same gap class as GitHub Actions unpinned actions."
        ),
    )
    def __init__(self, chart_provenance_verified: bool=False, rbac_scoped: bool=True,
                 values_encrypted: bool=False, registry_auth: bool=True):
        self._provenance = chart_provenance_verified
        self._rbac = rbac_scoped
        self._enc = values_encrypted
        self._reg_auth = registry_auth

    def collect_operation_families(self): return HELM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [HELM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in HELM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            release_recorded=True, chart_verified=self._provenance,
            rbac_evaluated=self._rbac, values_encrypted=self._enc,
            provenance_checked=self._provenance, hook_receipted=True,
            release_name=None, chart_version=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in HELM_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "release_record" in fam.declared_layers: k.append("release_record")
        if "chart_provenance" in fam.declared_layers and self._provenance: k.append("chart_provenance")
        if "chart_checksum" in fam.declared_layers: k.append("chart_checksum")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "values_governance" in fam.declared_layers: k.append("values_governance")
        if "hook_log" in fam.declared_layers: k.append("hook_log")
        if "registry_auth" in fam.declared_layers and self._reg_auth: k.append("registry_auth")
        if "secrets_encryption" in fam.declared_layers and self._enc: k.append("secrets_encryption")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "chart_pull" and not self._provenance: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
