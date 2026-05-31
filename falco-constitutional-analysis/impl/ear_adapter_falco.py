"""
ear_adapter_falco.py — Falco EAR Adapter
Wave 5 — System 25. Runtime security monitoring.

Key finding: Falco is the corpus's second meta-governance case after
OpenTelemetry — it is governance technology whose own operation has
governance gaps. Falco monitors runtime behavior and generates security alerts,
but the governance of Falco's own detection decisions is CRYSTALLIZED:
alert generation is not constitutive of the detected event, rules can be
bypassed by evading the syscall capture layer, and rule changes have no
mandatory change receipt.
New constitutional concept: the security alert as governance receipt.
A Falco alert records that a governed event occurred — but the alert
is generated after the event, not before. CRYSTALLIZED by architecture:
the event occurs whether or not the alert is generated.
The ebpf/kernel module capture layer is the closest to ACTIVE:
if Falco cannot load its kernel module, it fails — constitutive of monitoring.
But this is availability governance, not event governance.
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
    name: str; description: str; declared_layers: list[str]; falco_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rule_matched: bool; alert_generated: bool; alert_delivered: bool
    syscall_captured: bool; rule_version_recorded: bool
    rule_name: str|None; priority: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

FALCO_OPERATION_FAMILIES = [
    OperationFamily("syscall_detection",
        "Detect policy violation in syscall stream",
        ["syscall_capture","rule_match","alert_output","rule_version"], "detection"),
    OperationFamily("alert_delivery",
        "Deliver security alert to output sink",
        ["alert_output","delivery_receipt","rule_version"], "alert"),
    OperationFamily("rule_management",
        "Load/update/reload Falco rules",
        ["rule_version","rule_hash","audit_log"], "rules"),
    OperationFamily("kernel_module_load",
        "Load Falco kernel module or eBPF probe",
        ["kernel_module","load_receipt"], "kernel"),
    OperationFamily("container_monitoring",
        "Monitor container process and file activity",
        ["syscall_capture","rule_match","alert_output","container_metadata"], "container"),
]

FALCO_GOVERNANCE_LAYERS = {
    "syscall_capture": GovernanceLayer("syscall_capture",
        "Kernel module/eBPF syscall capture — constitutive of monitoring",
        "falco_version"),
    "rule_match": GovernanceLayer("rule_match",
        "Rule matching against syscall event", "rule"),
    "alert_output": GovernanceLayer("alert_output",
        "Alert output channel (stdout/file/gRPC/webhook)", None),
    "rule_version": GovernanceLayer("rule_version",
        "Rule version used for detection decision", "rules_version"),
    "delivery_receipt": GovernanceLayer("delivery_receipt",
        "Alert delivery acknowledgment from sink", None, True),
    "rule_hash": GovernanceLayer("rule_hash",
        "Hash of rules file — change detection", None),
    "audit_log": GovernanceLayer("audit_log",
        "Audit log for rule management operations", None, True),
    "kernel_module": GovernanceLayer("kernel_module",
        "Kernel module or eBPF probe loaded", "driver_version"),
    "load_receipt": GovernanceLayer("load_receipt",
        "Kernel module load status receipt", None),
    "container_metadata": GovernanceLayer("container_metadata",
        "Container metadata enriching detection context", "container.id"),
}

class FalcoEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Falco Documentation + Falco Rules documentation + Falco Security advisories",
        strategy="DECLARED-N",
        description=(
            "N(O) from Falco architecture. syscall_detection N=4. "
            "Meta-governance case: Falco monitors runtime governance events "
            "but Falco's own operation is CRYSTALLIZED. "
            "Alert generation is not constitutive of the detected event — "
            "the event occurs whether or not the alert is generated. "
            "syscall_capture: ACTIVE when kernel module loaded — "
            "constitutive of monitoring availability (if module fails, Falco fails). "
            "But event governance (alert-per-event) remains CRYSTALLIZED. "
            "Rule bypass: container with ptrace capability can manipulate "
            "its own syscall stream to evade detection. "
            "Alert delivery gap: alert generated but delivery may fail "
            "(network issue, sink unavailable) — CRYSTALLIZED."
        ),
    )
    def __init__(self, kernel_module_loaded: bool=True, alert_delivery_verified: bool=False,
                 rule_version_tracked: bool=False, rule_hash_monitored: bool=False):
        self._kernel = kernel_module_loaded; self._delivery = alert_delivery_verified
        self._version = rule_version_tracked; self._hash = rule_hash_monitored

    def collect_operation_families(self): return FALCO_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [FALCO_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in FALCO_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rule_matched=True, alert_generated=True,
            alert_delivered=self._delivery, syscall_captured=self._kernel,
            rule_version_recorded=self._version, rule_name=None, priority=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in FALCO_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "syscall_capture" in fam.declared_layers and inst.syscall_captured: k.append("syscall_capture")
        if "rule_match" in fam.declared_layers and inst.rule_matched: k.append("rule_match")
        if "alert_output" in fam.declared_layers and inst.alert_generated: k.append("alert_output")
        if "rule_version" in fam.declared_layers and self._version: k.append("rule_version")
        if "delivery_receipt" in fam.declared_layers and self._delivery: k.append("delivery_receipt")
        if "rule_hash" in fam.declared_layers and self._hash: k.append("rule_hash")
        if "kernel_module" in fam.declared_layers and self._kernel: k.append("kernel_module")
        if "load_receipt" in fam.declared_layers and self._kernel: k.append("load_receipt")
        if "container_metadata" in fam.declared_layers: k.append("container_metadata")
        return k
    def assess_ear_state(self, op_family):
        # kernel_module_load: ACTIVE — constitutive of monitoring availability
        if op_family.name == "kernel_module_load" and self._kernel:
            return EARState.ACTIVE
        if not self._kernel: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
