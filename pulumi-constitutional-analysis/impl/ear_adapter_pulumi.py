"""
ear_adapter_pulumi.py — Pulumi IaC EAR Adapter
Wave 13 — System 65. General-purpose language IaC governance.

Key finding: Pulumi completes the IaC trilogy: Terraform (Wave 5, T1671)
is HCL-based declarative with state drift gap; Crossplane (Wave 8, T1726)
is K8s-native with continuous reconciliation ACTIVE; Pulumi is general-
purpose language IaC (Python, TypeScript, Go, Java, .NET) with a state
model similar to Terraform but with different governance architecture.

Pulumi shares Terraform's fundamental constitutional properties:
- State file records what Pulumi knows, not what exists (T1684)
- State drift (external modifications) produces no governance event (ABSENT)
- State lock (Pulumi Cloud backend) prevents concurrent modification

Pulumi differentiates with policy-as-code (CrossGuard policies in
real programming languages) and Pulumi Cloud's stack audit log:
- CrossGuard policy stack: ACTIVE for policy evaluation (policy cannot be
  bypassed without config change) — same admission-gate ACTIVE pattern
- Pulumi Cloud audit log: CRYSTALLIZED — records stack updates and previews

Notable: Pulumi Insights (2025) adds continuous drift detection for
managed and unmanaged cloud resources — addresses the Terraform state drift
gap by continuous cloud API comparison. This moves drift_detection from
ABSENT toward CRYSTALLIZED with continuous monitoring.
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
    name: str; description: str; declared_layers: list[str]; pulumi_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    state_backend: bool; stack_locked: bool
    crossguard_active: bool; audit_logged: bool
    drift_detected: bool; esc_secrets: bool
    stack_name: str|None; program_language: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PULUMI_OPERATION_FAMILIES = [
    OperationFamily("stack_update",
        "pulumi up — update infrastructure stack",
        ["state_backend","stack_lock","audit_log","crossguard_policy","drift_check"], "update"),
    OperationFamily("stack_preview",
        "pulumi preview — show planned changes",
        ["state_backend","audit_log","crossguard_policy"], "preview"),
    OperationFamily("policy_enforcement",
        "CrossGuard policy evaluation before stack update",
        ["crossguard_policy","audit_log","state_backend"], "policy"),
    OperationFamily("secret_access",
        "Access Pulumi ESC secrets or encrypted stack config",
        ["esc_governance","audit_log","state_backend"], "secret"),
    OperationFamily("drift_detection",
        "Pulumi Insights continuous cloud resource drift detection",
        ["drift_monitoring","audit_log","state_backend"], "drift"),
]

PULUMI_GOVERNANCE_LAYERS = {
    "state_backend": GovernanceLayer("state_backend",
        "Pulumi Cloud or self-hosted backend for encrypted state storage", None),
    "stack_lock": GovernanceLayer("stack_lock",
        "Stack locking prevents concurrent updates — constitutive of state consistency", None),
    "audit_log": GovernanceLayer("audit_log",
        "Pulumi Cloud audit log — records all stack update and config operations", None),
    "crossguard_policy": GovernanceLayer("crossguard_policy",
        "CrossGuard policy-as-code evaluation — enforced before stack update completes", None, is_optional=True),
    "drift_check": GovernanceLayer("drift_check",
        "Pre-update drift check — identifies external modifications before applying", None, is_optional=True),
    "esc_governance": GovernanceLayer("esc_governance",
        "Pulumi ESC (Environments, Secrets, Config) — RBAC-governed secret management", None, is_optional=True),
    "drift_monitoring": GovernanceLayer("drift_monitoring",
        "Pulumi Insights continuous drift detection against cloud provider APIs", None, is_optional=True),
}

class PulumiEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Pulumi documentation + CrossGuard + Pulumi Insights drift detection 2025",
        strategy="DECLARED-N",
        description=(
            "N(O) from Pulumi architecture. stack_update N=5. "
            "stack_update with remote state + lock: ACTIVE for concurrent modification — "
            "same as Terraform state_management ACTIVE (T1671). "
            "CrossGuard policy enforcement: ACTIVE — policy evaluation is constitutive; "
            "stack update cannot complete if policy fails. "
            "Drift detection: ABSENT by default (like Terraform); "
            "Pulumi Insights (2025) adds continuous drift monitoring — CRYSTALLIZED-forward. "
            "State drift (external modifications): same ABSENT gap as T1684 — "
            "external modifications produce no governance event without Insights. "
            "General-purpose language programs: same supply chain gap as "
            "GitHub Actions (T1702) — imported packages execute with Pulumi credentials. "
            "Pulumi ESC: CRYSTALLIZED — centralized secret management with RBAC and audit. "
            "Extends T1671 (Terraform) and T1726 (Crossplane) to complete IaC trilogy: "
            "Terraform: state-based HCL, drift ABSENT; "
            "Crossplane: K8s-native continuous reconciliation ACTIVE; "
            "Pulumi: general-purpose language, drift ABSENT/CrossGuard ACTIVE."
        ),
    )
    def __init__(self, remote_backend: bool=True, crossguard_enabled: bool=False,
                 audit_log_enabled: bool=False, drift_monitoring: bool=False,
                 esc_configured: bool=False):
        self._backend = remote_backend
        self._crossguard = crossguard_enabled
        self._audit = audit_log_enabled
        self._drift = drift_monitoring
        self._esc = esc_configured

    def collect_operation_families(self): return PULUMI_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PULUMI_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in PULUMI_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            state_backend=self._backend, stack_locked=self._backend,
            crossguard_active=self._crossguard, audit_logged=self._audit,
            drift_detected=self._drift, esc_secrets=self._esc,
            stack_name=None, program_language=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in PULUMI_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "state_backend" in fam.declared_layers and self._backend: k.append("state_backend")
        if "stack_lock" in fam.declared_layers and self._backend: k.append("stack_lock")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "crossguard_policy" in fam.declared_layers and self._crossguard: k.append("crossguard_policy")
        if "drift_check" in fam.declared_layers and self._drift: k.append("drift_check")
        if "esc_governance" in fam.declared_layers and self._esc: k.append("esc_governance")
        if "drift_monitoring" in fam.declared_layers and self._drift: k.append("drift_monitoring")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "policy_enforcement" and self._crossguard: return EARState.ACTIVE
        if op_family.name == "stack_update" and self._backend: return EARState.CRYSTALLIZED
        if not self._backend: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
