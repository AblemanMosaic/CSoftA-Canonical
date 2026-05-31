"""
ear_adapter_crossplane.py — Crossplane EAR Adapter
Wave 8 — System 40. Kubernetes-native infrastructure composition.

Key finding: Crossplane is the Kubernetes-native IaC governance case,
complementing Terraform (Wave 5, T1671). Crossplane manages cloud resources
via Kubernetes CRDs and controllers (Providers). The governance profile
differs from Terraform in one significant way: there is no state drift gap.
Crossplane continuously reconciles — if a cloud resource is modified
outside Crossplane, the next reconciliation loop detects drift and
restores the declared state. This is the closest Kubernetes-native
infrastructure management comes to ACTIVE: the reconciliation loop
is constitutive of the declared state being maintained.
However, Crossplane's RBAC for Composite Resource Claims (XRCs) and
the Provider's cloud credentials (stored as Kubernetes Secrets) are
the critical governance surfaces. Provider credentials grant the
Provider controller broad cloud access — CRYSTALLIZED.
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
    name: str; description: str; declared_layers: list[str]; xp_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; audit_logged: bool
    drift_detected: bool; provider_credentials_scoped: bool
    composition_verified: bool; claim_approved: bool
    resource_name: str|None; provider: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

XP_OPERATION_FAMILIES = [
    OperationFamily("resource_provisioning",
        "Provision cloud resource via Composite Resource or Claim",
        ["rbac_check","audit_log","provider_credentials","drift_reconciliation"], "provision"),
    OperationFamily("drift_reconciliation",
        "Detect and correct infrastructure drift via continuous reconciliation",
        ["drift_reconciliation","audit_log","provider_credentials"], "drift"),
    OperationFamily("provider_management",
        "Configure Provider and ProviderConfig (cloud credentials)",
        ["rbac_check","audit_log","provider_credentials","credentials_scope"], "provider"),
    OperationFamily("composition_management",
        "Create or update Composition or CompositeResourceDefinition",
        ["rbac_check","audit_log","composition_governance"], "composition"),
    OperationFamily("claim_management",
        "Submit Composite Resource Claim",
        ["rbac_check","audit_log","claim_approval"], "claim"),
]

XP_GOVERNANCE_LAYERS = {
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC evaluation for Crossplane resource operations", None),
    "audit_log": GovernanceLayer("audit_log",
        "Kubernetes audit log for Crossplane CRD operations", None, is_optional=True),
    "provider_credentials": GovernanceLayer("provider_credentials",
        "Cloud provider credentials (AWS/GCP/Azure) for Provider controller", None),
    "drift_reconciliation": GovernanceLayer("drift_reconciliation",
        "Continuous reconciliation detecting and correcting drift", None),
    "credentials_scope": GovernanceLayer("credentials_scope",
        "Provider credentials scoped to least-privilege", None, is_optional=True),
    "composition_governance": GovernanceLayer("composition_governance",
        "Composition validated for least-privilege resource templates", None, is_optional=True),
    "claim_approval": GovernanceLayer("claim_approval",
        "Claim approval gate (OPA/Kyverno policy on XRC admission)", None, is_optional=True),
}

class CrossplaneEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Crossplane Documentation + Crossplane Security docs + Terraform comparison",
        strategy="DECLARED-N",
        description=(
            "N(O) from Crossplane architecture. resource_provisioning N=4. "
            "drift_reconciliation: closest to ACTIVE — continuous reconciliation "
            "is constitutive of the declared state being maintained; "
            "drift is detected and corrected automatically. "
            "But the reconciliation itself is CRYSTALLIZED: it records what was "
            "reconciled but does not produce a mandatory per-operation receipt. "
            "Provider credentials gap: cloud credentials stored as K8s Secrets, "
            "granting Provider controller broad cloud access — CRYSTALLIZED. "
            "Removes Terraform's state drift ABSENT gap (T1684): "
            "Crossplane eliminates the 'silently diverges from reality' problem "
            "through continuous reconciliation. "
            "Provider credentials with Workload Identity (no long-lived keys): "
            "closes the credentials-in-state gap (Terraform T1684 analog)."
        ),
    )
    def __init__(self, rbac_scoped: bool=True, audit_log_enabled: bool=False,
                 credentials_scoped: bool=False, drift_reconciliation: bool=True,
                 composition_governed: bool=False):
        self._rbac = rbac_scoped
        self._audit = audit_log_enabled
        self._cred_scope = credentials_scoped
        self._drift = drift_reconciliation
        self._comp = composition_governed

    def collect_operation_families(self): return XP_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [XP_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in XP_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=self._rbac, audit_logged=self._audit,
            drift_detected=self._drift, provider_credentials_scoped=self._cred_scope,
            composition_verified=self._comp, claim_approved=False,
            resource_name=None, provider=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in XP_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "provider_credentials" in fam.declared_layers: k.append("provider_credentials")
        if "drift_reconciliation" in fam.declared_layers and self._drift: k.append("drift_reconciliation")
        if "credentials_scope" in fam.declared_layers and self._cred_scope: k.append("credentials_scope")
        if "composition_governance" in fam.declared_layers and self._comp: k.append("composition_governance")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        # drift_reconciliation is the distinguishing surface
        if op_family.name == "drift_reconciliation" and self._drift: return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
