"""
ear_adapter_nomad.py — HashiCorp Nomad EAR Adapter
Wave 15 — System 74. Multi-runtime workload orchestration.

Key finding: Nomad is the Kubernetes alternative for workload orchestration
supporting containers, VMs, Java JARs, and raw executables in a single scheduler.
Its governance model uses namespace-based ACL policies rather than K8s RBAC.

Constitutional comparison to Kubernetes (T1603): same three-tier governance model
(identity/policy/admission), different implementation. Nomad ACL policies are
Sentinel-based (enterprise) or HCL-based (community) — structurally different
from K8s admission controllers.

CVE-2025-1296 (March 2025): workload identity tokens and client secret tokens
exposed in audit logs — ABSENT governance of credential material in audit receipts.
The audit log itself becomes the credential exposure surface.

CVE-2025-4922 (June 2025): prefix-based ACL policy lookup leads to incorrect
rule application and policy shadowing — NON_ACTIVATION at the ACL policy
lookup boundary. Jobs can receive incorrect ACL policies, potentially gaining
unauthorized access to namespaces.

CVE-2024-12678: privilege escalation within namespace via unredacted
workload identity tokens in allocation metadata.

CVE-2025-3744 (Nomad Enterprise): Sentinel policy override bypass —
NON_ACTIVATION at the Sentinel policy evaluation boundary.

Nomad audit log: Enterprise tier only — same commercial governance paywalling
pattern as MySQL T1784 and MongoDB T1795.
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
    name: str; description: str; declared_layers: list[str]; nomad_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    acl_evaluated: bool; tls_enforced: bool
    enterprise_audit: bool; namespace_isolated: bool
    workload_identity: bool; sentinel_policy: bool
    namespace: str|None; job_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

NOMAD_OPERATION_FAMILIES = [
    OperationFamily("job_submission",
        "Submit job definition to Nomad scheduler",
        ["acl_policy","tls_transport","enterprise_audit","namespace_isolation"], "job"),
    OperationFamily("job_execution",
        "Execute scheduled workload allocation on Nomad client",
        ["acl_policy","tls_transport","workload_identity","enterprise_audit"], "exec"),
    OperationFamily("secret_access",
        "Access Vault secrets via Nomad workload identity",
        ["acl_policy","workload_identity","tls_transport"], "secret"),
    OperationFamily("acl_management",
        "Manage Nomad ACL policies, tokens, and roles",
        ["acl_policy","tls_transport","enterprise_audit"], "acl"),
    OperationFamily("volume_management",
        "Manage CSI volumes and storage for workloads",
        ["acl_policy","tls_transport","namespace_isolation"], "vol"),
]

NOMAD_GOVERNANCE_LAYERS = {
    "acl_policy": GovernanceLayer("acl_policy",
        "Nomad ACL policy evaluation (HCL-based community / Sentinel enterprise)", None),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS for Nomad agent-to-server communication", None),
    "enterprise_audit": GovernanceLayer("enterprise_audit",
        "Nomad Enterprise audit log (commercial only)", None, is_optional=True),
    "namespace_isolation": GovernanceLayer("namespace_isolation",
        "Nomad namespace isolation — jobs and resources scoped per namespace", None),
    "workload_identity": GovernanceLayer("workload_identity",
        "Nomad Workload Identity — OIDC-based short-lived JWT for service identity", None, is_optional=True),
    "sentinel_policy": GovernanceLayer("sentinel_policy",
        "Sentinel policy-as-code enforcement (enterprise)", None, is_optional=True),
}

class NomadEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Nomad docs + CVE-2025-1296 + CVE-2025-4922 + CVE-2024-12678 + CVE-2025-3744",
        strategy="DECLARED-N",
        description=(
            "N(O) from Nomad architecture. job_submission N=4. "
            "Default Nomad: ACL disabled — any node can submit jobs without authentication. "
            "With ACL enabled: CRYSTALLIZED. "
            "Enterprise audit log: commercial governance paywalling (T1784 pattern). "
            "CVE-2025-1296: workload identity tokens exposed in audit logs — "
            "the audit receipt itself becomes a credential exposure surface. "
            "CVE-2025-4922: prefix-based ACL lookup → policy shadowing — "
            "NON_ACTIVATION at ACL policy lookup boundary. "
            "CVE-2024-12678: unredacted workload identity tokens in allocation metadata — "
            "privilege escalation within namespace. "
            "CVE-2025-3744 (Enterprise): Sentinel policy override bypass — "
            "NON_ACTIVATION at Sentinel evaluation boundary. "
            "Constitutional comparison to K8s (T1603): "
            "Nomad has Sentinel (admission-analog) vs K8s admission controllers; "
            "multi-runtime support (containers/VMs/Java/raw binaries) broadens surface."
        ),
    )
    def __init__(self, acl_enabled: bool=False, tls_enabled: bool=True,
                 enterprise_audit: bool=False, namespace_isolated: bool=False):
        self._acl = acl_enabled
        self._tls = tls_enabled
        self._enterprise = enterprise_audit
        self._ns = namespace_isolated

    def collect_operation_families(self): return NOMAD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [NOMAD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in NOMAD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            acl_evaluated=self._acl, tls_enforced=self._tls,
            enterprise_audit=self._enterprise, namespace_isolated=self._ns,
            workload_identity=False, sentinel_policy=False,
            namespace=None, job_id=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in NOMAD_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "acl_policy" in fam.declared_layers and self._acl: k.append("acl_policy")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "enterprise_audit" in fam.declared_layers and self._enterprise: k.append("enterprise_audit")
        if "namespace_isolation" in fam.declared_layers and self._ns: k.append("namespace_isolation")
        return k
    def assess_ear_state(self, op_family):
        if not self._acl: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
