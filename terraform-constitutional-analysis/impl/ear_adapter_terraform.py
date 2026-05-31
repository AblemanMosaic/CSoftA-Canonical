"""
ear_adapter_terraform.py — Terraform / OpenTofu EAR Adapter
Wave 5 — System 24. Infrastructure-as-code.

Key finding: Terraform introduces the IaC governance surface — the state file
as governance receipt. The Terraform state file records what was deployed,
but it is not a constitutive receipt: infrastructure can exist without a
state file (manually created resources), state can be modified directly
(terraform state manipulate commands), and the plan/apply split means the
governance declaration (plan) and the governance execution (apply) are
separate artifacts that may diverge. The state file is CRYSTALLIZED:
it records what Terraform knows about, not what actually exists.
State drift is the canonical governance gap: resources modified outside
Terraform produce no state update and no gap assertion.
Remote state backends with locking provide the closest approach to ACTIVE:
state changes require acquiring a lock, producing a receipt of the lock
acquisition and release.
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
    name: str; description: str; declared_layers: list[str]; tf_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    state_recorded: bool; plan_approved: bool; lock_acquired: bool
    drift_detected: bool; audit_logged: bool
    workspace: str|None; run_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

TF_OPERATION_FAMILIES = [
    OperationFamily("apply_operation",
        "Execute terraform apply — provision/modify infrastructure",
        ["state_file","plan_approval","state_lock","audit_log","drift_check"], "apply"),
    OperationFamily("plan_operation",
        "Execute terraform plan — compute infrastructure diff",
        ["state_file","plan_receipt","audit_log"], "plan"),
    OperationFamily("state_management",
        "Directly manipulate state file (terraform state mv/rm/import)",
        ["state_file","state_lock","audit_log"], "state"),
    OperationFamily("drift_detection",
        "Detect infrastructure drift from declared state",
        ["state_file","drift_check","audit_log"], "drift"),
    OperationFamily("secret_management",
        "Access sensitive variables or provider credentials",
        ["state_file","secret_backend","audit_log"], "secret"),
]

TF_GOVERNANCE_LAYERS = {
    "state_file": GovernanceLayer("state_file",
        "Terraform state file — records known infrastructure state", "terraform.tfstate"),
    "plan_approval": GovernanceLayer("plan_approval",
        "Plan approval gate before apply — required in Terraform Cloud/Enterprise", None, True),
    "plan_receipt": GovernanceLayer("plan_receipt",
        "Plan output file — records intended changes", "tfplan"),
    "state_lock": GovernanceLayer("state_lock",
        "State file lock — prevents concurrent modifications", ".terraform.lock.hcl"),
    "audit_log": GovernanceLayer("audit_log",
        "Terraform Cloud/Enterprise audit log — not available in OSS", None, True),
    "drift_check": GovernanceLayer("drift_check",
        "Drift detection via terraform plan -refresh-only", None, True),
    "secret_backend": GovernanceLayer("secret_backend",
        "Vault or other secret backend for sensitive variables", None, True),
}

class TerraformEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Terraform Documentation + OpenTofu Documentation + Terraform Cloud docs",
        strategy="DECLARED-N",
        description=(
            "N(O) from Terraform/OpenTofu architecture. apply_operation N=5. "
            "State file: CRYSTALLIZED — records what Terraform knows, not what exists. "
            "State drift: ABSENT gap — resources modified outside Terraform "
            "produce no state update, no gap assertion. "
            "State lock with remote backend: ACTIVE — lock acquisition is constitutive "
            "of state modification, producing a receipt. "
            "plan_approval (Terraform Cloud): CRYSTALLIZED — plan approved before apply, "
            "but approval is a separate workflow artifact. "
            "Sensitive values in state: security gap — state files may contain secrets "
            "in plaintext if not using external secret backends. "
            "OSS Terraform: no audit log. Terraform Cloud/Enterprise: audit log available."
        ),
    )
    def __init__(self, remote_backend: bool=False, state_locking: bool=False,
                 plan_approval_required: bool=False, audit_log_enabled: bool=False,
                 drift_detection_enabled: bool=False):
        self._remote = remote_backend; self._lock = state_locking
        self._plan_approval = plan_approval_required
        self._audit = audit_log_enabled; self._drift = drift_detection_enabled

    def collect_operation_families(self): return TF_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [TF_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in TF_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            state_recorded=True, plan_approved=self._plan_approval,
            lock_acquired=self._lock, drift_detected=self._drift,
            audit_logged=self._audit, workspace=None, run_id=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in TF_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "state_file" in fam.declared_layers and inst.state_recorded: k.append("state_file")
        if "plan_approval" in fam.declared_layers and inst.plan_approved: k.append("plan_approval")
        if "plan_receipt" in fam.declared_layers: k.append("plan_receipt")
        if "state_lock" in fam.declared_layers and inst.lock_acquired: k.append("state_lock")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "drift_check" in fam.declared_layers and self._drift: k.append("drift_check")
        if "secret_backend" in fam.declared_layers and self._remote: k.append("secret_backend")
        return k
    def assess_ear_state(self, op_family):
        # state_management with remote locking: ACTIVE — lock is constitutive
        if op_family.name == "state_management" and self._lock and self._remote:
            return EARState.ACTIVE
        if not self._remote: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
