"""
ear_adapter_pod_security.py — Kubernetes Pod Security Admission EAR Adapter
Wave 10 — System 50. Workload security standards governance.

Key finding: Pod Security Admission (PSA, successor to PodSecurityPolicy)
enforces Kubernetes security profiles (privileged/baseline/restricted) at
the namespace level via the built-in admission controller. PSA is ACTIVE
when set to 'enforce' mode: pods that violate the profile cannot be created.
'warn' and 'audit' modes are CRYSTALLIZED — violations are recorded but not
prevented. PSA completes the K8s workload security governance: RBAC (T1742)
governs who can submit resources; admission controllers (T1748) validate
resources; PSA governs the security profile of the workloads themselves.
Container escape vulnerabilities (privileged containers, hostPath mounts,
hostNetwork, hostPID) are prevented by PSA 'restricted' profile.
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
    name: str; description: str; declared_layers: list[str]; psa_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    profile_enforced: bool; profile_level: str
    audit_logged: bool; warn_enabled: bool
    namespace_labeled: bool; profile_reviewed: bool
    namespace: str|None; pod_name: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PSA_OPERATION_FAMILIES = [
    OperationFamily("pod_admission",
        "Admit or reject pod creation based on security profile",
        ["psa_enforce","audit_log","warn_mode","namespace_label"], "admit"),
    OperationFamily("privileged_restriction",
        "Prevent privileged container creation in non-privileged namespace",
        ["psa_enforce","audit_log","namespace_label"], "priv"),
    OperationFamily("escape_prevention",
        "Prevent container escape vectors (hostPath, hostNetwork, hostPID)",
        ["psa_enforce","audit_log","namespace_label"], "escape"),
    OperationFamily("profile_governance",
        "Govern PSA profile level selection per namespace",
        ["namespace_label","rbac_check","audit_log","profile_review"], "profile"),
    OperationFamily("seccomp_enforcement",
        "Enforce seccomp profile for containers",
        ["psa_enforce","namespace_label","audit_log"], "seccomp"),
]

PSA_GOVERNANCE_LAYERS = {
    "psa_enforce": GovernanceLayer("psa_enforce",
        "PSA enforce mode — pods violating profile cannot be created (ACTIVE)", "enforce"),
    "audit_log": GovernanceLayer("audit_log",
        "PSA audit mode — violations logged but pods admitted (CRYSTALLIZED)", "audit"),
    "warn_mode": GovernanceLayer("warn_mode",
        "PSA warn mode — violations warned but pods admitted", "warn"),
    "namespace_label": GovernanceLayer("namespace_label",
        "Namespace labeled with pod-security.kubernetes.io/enforce", "pod-security.kubernetes.io"),
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC governing who can label namespaces with PSA profiles", None),
    "profile_review": GovernanceLayer("profile_review",
        "Security profile level reviewed for namespace workload requirements", None, is_optional=True),
}

class PodSecurityEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Kubernetes Pod Security Admission documentation + CIS K8s Benchmark + PSP migration guide",
        strategy="DECLARED-N",
        description=(
            "N(O) from PSA architecture. pod_admission N=4. "
            "pod_admission with psa_enforce (restricted/baseline): ACTIVE — "
            "pods violating profile cannot be created; constitutive enforcement. "
            "pod_admission with audit/warn mode only: CRYSTALLIZED — violations "
            "recorded or warned, pods admitted. "
            "Default Kubernetes namespaces: no PSA labels = privileged profile "
            "(all pods admitted). ABSENT enforcement by default. "
            "Prevents container escape vectors: privileged containers, hostPath, "
            "hostNetwork, hostPID, hostIPC — CVE-class attack surfaces. "
            "Completes K8s workload security layer: RBAC (who submits) + "
            "admission controllers (what is valid) + PSA (workload security profile)."
        ),
    )
    def __init__(self, enforce_mode: bool=False, audit_mode: bool=True,
                 warn_mode: bool=True, all_namespaces_labeled: bool=False):
        self._enforce = enforce_mode
        self._audit = audit_mode
        self._warn = warn_mode
        self._labeled = all_namespaces_labeled

    def collect_operation_families(self): return PSA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PSA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in PSA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            profile_enforced=self._enforce, profile_level="restricted",
            audit_logged=self._audit, warn_enabled=self._warn,
            namespace_labeled=self._labeled, profile_reviewed=True,
            namespace=None, pod_name=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in PSA_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "psa_enforce" in fam.declared_layers and self._enforce: k.append("psa_enforce")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "warn_mode" in fam.declared_layers and self._warn: k.append("warn_mode")
        if "namespace_label" in fam.declared_layers and self._labeled: k.append("namespace_label")
        if "rbac_check" in fam.declared_layers: k.append("rbac_check")
        return k
    def assess_ear_state(self, op_family):
        if not self._labeled: return EARState.ABSENT
        if self._enforce: return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
