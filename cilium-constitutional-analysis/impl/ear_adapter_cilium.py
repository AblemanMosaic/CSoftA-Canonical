"""
ear_adapter_cilium.py — Cilium / Tetragon eBPF EAR Adapter
Wave 12 — System 59. Kernel-level governance enforcement.

Key finding: Cilium/Tetragon introduces the strongest enforcement model
in the corpus — kernel-level eBPF enforcement that is constitutive at
a layer below all userspace governance. This extends T1640 (compile-time
ACTIVE-EAR via Rust) with a new ACTIVE class: kernel-time enforcement.

When Tetragon applies an enforcement policy (a TracingPolicy with an
enforcement action), the policy is evaluated in the kernel via eBPF LSM
hooks. A process that violates the policy is blocked at the kernel level
before the system call completes. This cannot be bypassed by:
- Privileged containers (PSA bypass route does not exist at eBPF LSM level)
- Admission controller failure (failurePolicy:Ignore — eBPF policy is not
  an admission webhook and has no failurePolicy concept)
- Container runtime vulnerabilities (eBPF operates below the container)

New constitutional concept: kernel-time enforcement — policy evaluated
and enforced within the kernel before system call completion. Stronger
than admission-gate ACTIVE (T1739) because it operates below the container
runtime layer, and stronger than PSA enforce (which governs admission)
because it governs runtime behavior after admission.
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
    name: str; description: str; declared_layers: list[str]; cilium_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    ebpf_policy_active: bool; enforcement_mode: bool
    hubble_observing: bool; network_policy_enforced: bool
    lsm_hook_active: bool; tetragon_deployed: bool
    pod_name: str|None; namespace: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CILIUM_OPERATION_FAMILIES = [
    OperationFamily("syscall_enforcement",
        "Enforce TracingPolicy on system calls via eBPF LSM hooks",
        ["ebpf_enforcement","lsm_hook","tetragon_policy","hubble_log"], "syscall"),
    OperationFamily("network_enforcement",
        "Enforce CiliumNetworkPolicy via eBPF dataplane",
        ["ebpf_enforcement","network_policy","hubble_log","cilium_rbac"], "network"),
    OperationFamily("process_execution",
        "Monitor and enforce process execution policy via Tetragon",
        ["ebpf_enforcement","tetragon_policy","hubble_log","lsm_hook"], "process"),
    OperationFamily("file_access",
        "Monitor and enforce file access policy via Tetragon",
        ["ebpf_enforcement","tetragon_policy","hubble_log"], "file"),
    OperationFamily("network_observability",
        "Observe network flows via Hubble (Cilium observability layer)",
        ["hubble_log","ebpf_enforcement","network_policy"], "observe"),
]

CILIUM_GOVERNANCE_LAYERS = {
    "ebpf_enforcement": GovernanceLayer("ebpf_enforcement",
        "eBPF enforcement program loaded into kernel — constitutive enforcement", None),
    "lsm_hook": GovernanceLayer("lsm_hook",
        "eBPF LSM (Linux Security Module) hook — below container runtime", None),
    "tetragon_policy": GovernanceLayer("tetragon_policy",
        "Tetragon TracingPolicy defining enforcement actions", "TracingPolicy"),
    "hubble_log": GovernanceLayer("hubble_log",
        "Hubble network and security event observability", None, is_optional=True),
    "network_policy": GovernanceLayer("network_policy",
        "CiliumNetworkPolicy enforced via eBPF dataplane", "CiliumNetworkPolicy"),
    "cilium_rbac": GovernanceLayer("cilium_rbac",
        "Cilium RBAC for policy management operations", None),
}

class CiliumEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Cilium/Tetragon documentation + eBPF LSM research + Tetragon enforcement docs",
        strategy="DECLARED-N",
        description=(
            "N(O) from Cilium/Tetragon architecture. syscall_enforcement N=4. "
            "syscall_enforcement with Tetragon TracingPolicy enforcement: ACTIVE — "
            "eBPF LSM hooks evaluate policy in-kernel before syscall completes; "
            "violating process is blocked at kernel level. "
            "New constitutional concept: kernel-time enforcement — "
            "policy evaluated within the Linux kernel via eBPF LSM. "
            "Cannot be bypassed via privileged containers, admission webhook failure, "
            "or container runtime vulnerabilities. "
            "Stronger than PSA enforce (admission-gate ACTIVE): "
            "PSA prevents admission; Tetragon prevents runtime behavior. "
            "Eliminates TOCTOU gap: eBPF checks occur synchronously in-kernel, "
            "not via user-space agents that can be killed or evaded. "
            "XZ Utils backdoor (CVE-2024-3094): Tetragon could detect anomalous "
            "process execution chains from sshd process before CVE disclosure — "
            "kernel-level observability detected behavioral anomaly. "
            "network_enforcement: ACTIVE via eBPF dataplane — "
            "network policy enforced at the packet level, not iptables post-routing."
        ),
    )
    def __init__(self, tetragon_deployed: bool=False, enforcement_mode: bool=False,
                 hubble_enabled: bool=False, network_policy_enforced: bool=False):
        self._tetragon = tetragon_deployed
        self._enforce = enforcement_mode
        self._hubble = hubble_enabled
        self._netpol = network_policy_enforced

    def collect_operation_families(self): return CILIUM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CILIUM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in CILIUM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            ebpf_policy_active=self._tetragon, enforcement_mode=self._enforce,
            hubble_observing=self._hubble, network_policy_enforced=self._netpol,
            lsm_hook_active=self._enforce, tetragon_deployed=self._tetragon,
            pod_name=None, namespace=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in CILIUM_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "ebpf_enforcement" in fam.declared_layers and self._tetragon: k.append("ebpf_enforcement")
        if "lsm_hook" in fam.declared_layers and self._enforce: k.append("lsm_hook")
        if "tetragon_policy" in fam.declared_layers and self._tetragon: k.append("tetragon_policy")
        if "hubble_log" in fam.declared_layers and self._hubble: k.append("hubble_log")
        if "network_policy" in fam.declared_layers and self._netpol: k.append("network_policy")
        if "cilium_rbac" in fam.declared_layers: k.append("cilium_rbac")
        return k
    def assess_ear_state(self, op_family):
        if not self._tetragon: return EARState.ABSENT
        if op_family.name in ("syscall_enforcement","process_execution","file_access") and self._enforce:
            return EARState.ACTIVE
        if op_family.name == "network_enforcement" and self._netpol: return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
