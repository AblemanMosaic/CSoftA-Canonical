"""
ear_adapter_ansible.py — Ansible EAR Adapter
Wave 12 — System 58. Imperative configuration management governance.

Key finding: Ansible extends T1684 (IaC state file as governance receipt)
with a new constitutional concept: stateless IaC has ABSENT governance
receipt by architecture, not by misconfiguration.

Terraform has state drift as a gap — the state file can diverge. But it
has a state file. Ansible has no state: playbooks execute imperatively
against current host state, with no persistent record of what was applied.
Every playbook run is a fresh execution. There is no "desired state" that
can drift — there is only "current state" plus "what the playbook would do."
The governance receipt for an Ansible execution is the execution log
(CRYSTALLIZED at best with AWX/Tower) or nothing at all (ABSENT with CLI).

New constitutional concept: stateless IaC — imperative execution with
no state model produces ABSENT governance receipt by architectural choice.
The receipt gap is not a bug or misconfiguration: it is a design property
of the imperative execution model.

AWX/Ansible Tower changes this: CRYSTALLIZED — job execution logs, role
assignments, approval workflows. But AWX is opt-in infrastructure on top
of Ansible's stateless core.
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
    name: str; description: str; declared_layers: list[str]; ansible_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    awx_managed: bool; audit_logged: bool
    vault_encrypted: bool; rbac_check: bool
    check_mode: bool; idempotent: bool
    playbook: str|None; target_hosts: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ANSIBLE_OPERATION_FAMILIES = [
    OperationFamily("playbook_execution",
        "Execute Ansible playbook against target hosts",
        ["awx_audit","execution_log","vault_secrets","rbac_gate"], "playbook"),
    OperationFamily("task_execution",
        "Execute individual Ansible task (module) on target host",
        ["execution_log","awx_audit","idempotency_check"], "task"),
    OperationFamily("secret_access",
        "Access Ansible Vault encrypted secrets",
        ["vault_encryption","awx_audit","rbac_gate"], "secret"),
    OperationFamily("inventory_management",
        "Manage Ansible inventory (host/group definitions)",
        ["rbac_gate","awx_audit","execution_log"], "inv"),
    OperationFamily("role_execution",
        "Execute Ansible role as part of playbook",
        ["execution_log","awx_audit","role_governance"], "role"),
]

ANSIBLE_GOVERNANCE_LAYERS = {
    "awx_audit": GovernanceLayer("awx_audit",
        "AWX/Tower job execution audit log (opt-in infrastructure)", None, is_optional=True),
    "execution_log": GovernanceLayer("execution_log",
        "Ansible execution log — console output, no structured receipt by default", None),
    "vault_encryption": GovernanceLayer("vault_encryption",
        "Ansible Vault encryption for secrets in playbooks/vars", None),
    "rbac_gate": GovernanceLayer("rbac_gate",
        "AWX/Tower RBAC for playbook execution authorization", None, is_optional=True),
    "idempotency_check": GovernanceLayer("idempotency_check",
        "Idempotency (check mode) — verify what would change before applying", None, is_optional=True),
    "role_governance": GovernanceLayer("role_governance",
        "Role source governance — Ansible Galaxy roles pinned and verified", None, is_optional=True),
}

class AnsibleEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Ansible documentation + AWX/Tower docs + configuration management governance analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Ansible architecture. playbook_execution N=4. "
            "CLI execution (raw ansible-playbook): ABSENT governance receipt — "
            "no state file, no structured execution log, no RBAC. "
            "AWX/Tower execution: CRYSTALLIZED — job logs, approval workflows, RBAC. "
            "New constitutional concept: stateless IaC — no state model means "
            "no drift detection, no state receipt, no convergence proof. "
            "Extends T1684 (Terraform state drift ABSENT): "
            "Terraform has a state that drifts; Ansible has no state to drift. "
            "The ABSENT receipt gap is architecturally inherent, not misconfiguration. "
            "Ansible Galaxy role supply chain: roles installed from Galaxy without "
            "verification — same supply chain gap as npm/PyPI package install. "
            "No Ansible family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, awx_managed: bool=False, vault_encrypted: bool=False,
                 rbac_configured: bool=False):
        self._awx = awx_managed
        self._vault = vault_encrypted
        self._rbac = rbac_configured

    def collect_operation_families(self): return ANSIBLE_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ANSIBLE_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ANSIBLE_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            awx_managed=self._awx, audit_logged=self._awx,
            vault_encrypted=self._vault, rbac_check=self._rbac,
            check_mode=False, idempotent=True,
            playbook=None, target_hosts=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ANSIBLE_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "awx_audit" in fam.declared_layers and self._awx: k.append("awx_audit")
        if "execution_log" in fam.declared_layers: k.append("execution_log")  # always present (console)
        if "vault_encryption" in fam.declared_layers and self._vault: k.append("vault_encryption")
        if "rbac_gate" in fam.declared_layers and self._rbac: k.append("rbac_gate")
        return k
    def assess_ear_state(self, op_family):
        if self._awx: return EARState.CRYSTALLIZED
        return EARState.ABSENT
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
