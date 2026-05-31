"""
ear_adapter_network_policy.py — Kubernetes NetworkPolicy EAR Adapter
Wave 7 — System 32. Network segmentation governance.

Key finding: Kubernetes NetworkPolicy is the network segmentation governance
case. Default Kubernetes: all pods can reach all pods (ABSENT egress and ingress
governance). NetworkPolicy resources declare allowed traffic but require a
CNI plugin that enforces them — without a NetworkPolicy-capable CNI
(Calico, Cilium, Weave, etc.), NetworkPolicy objects exist but are unenforced.
This is the Istio sidecar analog: the governance declaration exists but
enforcement depends on infrastructure that is separately configured.
When CNI enforcement is present, NetworkPolicy reaches CRYSTALLIZED:
traffic decisions are made but not constitutively receipted per flow.
No Kubernetes NetworkPolicy family reaches ACTIVE — network traffic
decisions are not constitutively logged by the policy layer itself.
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
    name: str; description: str; declared_layers: list[str]; np_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    policy_declared: bool; cni_enforcing: bool
    flow_logged: bool; default_deny: bool
    namespace: str|None; src_pod: str|None; dst_pod: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

NP_OPERATION_FAMILIES = [
    OperationFamily("ingress_control",
        "Allow/deny inbound traffic to pod based on NetworkPolicy",
        ["network_policy","cni_enforcement","flow_log","default_deny"], "ingress"),
    OperationFamily("egress_control",
        "Allow/deny outbound traffic from pod based on NetworkPolicy",
        ["network_policy","cni_enforcement","flow_log","default_deny"], "egress"),
    OperationFamily("policy_declaration",
        "Create/update NetworkPolicy resource in namespace",
        ["network_policy","rbac_check"], "policy"),
    OperationFamily("namespace_isolation",
        "Enforce namespace-level isolation via default-deny policies",
        ["network_policy","cni_enforcement","default_deny"], "isolation"),
    OperationFamily("flow_audit",
        "Audit network flows against declared policies",
        ["network_policy","cni_enforcement","flow_log"], "audit"),
]

NP_GOVERNANCE_LAYERS = {
    "network_policy": GovernanceLayer("network_policy",
        "NetworkPolicy CRD resource — declares allowed traffic", "spec.podSelector"),
    "cni_enforcement": GovernanceLayer("cni_enforcement",
        "CNI plugin enforcement of NetworkPolicy rules", None),
    "flow_log": GovernanceLayer("flow_log",
        "Network flow log from CNI (opt-in, e.g. Cilium Hubble)", None, is_optional=True),
    "default_deny": GovernanceLayer("default_deny",
        "Default-deny NetworkPolicy in namespace — opt-in, not default", None),
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC check for NetworkPolicy creation/modification", None),
}

class NetworkPolicyEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Kubernetes NetworkPolicy Documentation + CNI plugin docs + CIS Kubernetes Benchmark",
        strategy="DECLARED-N",
        description=(
            "N(O) from Kubernetes NetworkPolicy architecture. ingress_control N=4. "
            "ABSENT by default: no NetworkPolicy = all-allow (Kubernetes default). "
            "CNI dependency: NetworkPolicy objects without CNI enforcement are unenforced "
            "declarations — same pattern as Istio sidecar dependency (T019). "
            "CRYSTALLIZED with CNI enforcement: traffic decisions made, "
            "not constitutively receipted per flow. "
            "flow_log: opt-in (Cilium Hubble, Calico flow logs) — "
            "not default, not constitutive of policy evaluation. "
            "No NetworkPolicy family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, network_policy_declared: bool=True, cni_enforcing: bool=True,
                 flow_logging: bool=False, default_deny: bool=False):
        self._np = network_policy_declared
        self._cni = cni_enforcing
        self._flow = flow_logging
        self._deny = default_deny

    def collect_operation_families(self): return NP_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [NP_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in NP_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            policy_declared=self._np, cni_enforcing=self._cni,
            flow_logged=self._flow, default_deny=self._deny,
            namespace=None, src_pod=None, dst_pod=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in NP_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "network_policy" in fam.declared_layers and self._np: k.append("network_policy")
        if "cni_enforcement" in fam.declared_layers and self._cni: k.append("cni_enforcement")
        if "flow_log" in fam.declared_layers and self._flow: k.append("flow_log")
        if "default_deny" in fam.declared_layers and self._deny: k.append("default_deny")
        if "rbac_check" in fam.declared_layers: k.append("rbac_check")
        return k
    def assess_ear_state(self, op_family):
        if not self._np or not self._cni: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
