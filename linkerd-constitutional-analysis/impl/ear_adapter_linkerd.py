"""
ear_adapter_linkerd.py — Linkerd Service Mesh EAR Adapter
Wave 14 — System 67. Lightweight Rust-proxy service mesh governance.

Key finding: Linkerd provides a constitutional comparison to Istio (Wave 2, T1610).
The primary distinction: Linkerd's proxy is written in Rust (linkerd2-proxy),
not Envoy. Linkerd uses CNI plugin or initContainers for injection — this means
it does NOT depend on the Kubernetes admission webhook path that Istio requires.
Istio's governance completeness is bounded by K8s admission governance (T1613);
Linkerd's governance ceiling is different because its injection mechanism
avoids the admission webhook dependency.

mTLS in Linkerd: ACTIVE for meshed service-to-service communication —
mTLS is automatic and mandatory for all communication between meshed pods.
The certificate is tied to the Kubernetes ServiceAccount identity.
Unlike Istio's permissive mode (which defaults to CRYSTALLIZED), Linkerd
defaults to strict mTLS for all meshed traffic.

Authorization Policy: MeshTLSAuthentication and AuthorizationPolicy resources
— CRYSTALLIZED, require explicit configuration per route.

CVE-2025-43915 (proxy metrics resource exhaustion): DoS via crafted URLs.
Notably LOW CVE surface overall — 2 total CVEs vs Istio's much larger CVE history.
Linkerd 2024 security audit (7ASecurity/OSTIF/CNCF): no critical findings.
Linkerd 2.19 (October 2025): post-quantum TLS (ML-KEM-768 / X25519 hybrid).
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
    name: str; description: str; declared_layers: list[str]; linkerd_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    mtls_enforced: bool; authz_policy: bool
    proxy_injected: bool; tap_enabled: bool
    viz_enabled: bool; audit_logged: bool
    src_service: str|None; dst_service: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

LINKERD_OPERATION_FAMILIES = [
    OperationFamily("service_communication",
        "HTTP/gRPC call between meshed services (mTLS enforced)",
        ["proxy_injection","mtls_enforcement","authz_policy","tap_observability"], "svc"),
    OperationFamily("mtls_certificate",
        "mTLS certificate issuance and rotation for meshed pods",
        ["proxy_injection","mtls_enforcement","cert_rotation"], "cert"),
    OperationFamily("authorization_policy",
        "MeshTLSAuthentication / AuthorizationPolicy evaluation",
        ["authz_policy","mtls_enforcement","proxy_injection"], "authz"),
    OperationFamily("ingress_governance",
        "Linkerd governance of ingress traffic (external to mesh)",
        ["proxy_injection","mtls_enforcement","ingress_policy"], "ingress"),
    OperationFamily("mesh_observability",
        "Linkerd Viz metrics and tap for meshed traffic",
        ["tap_observability","viz_enabled","proxy_injection"], "obs"),
]

LINKERD_GOVERNANCE_LAYERS = {
    "proxy_injection": GovernanceLayer("proxy_injection",
        "Linkerd proxy injected via CNI/initContainer (not admission webhook)", None),
    "mtls_enforcement": GovernanceLayer("mtls_enforcement",
        "mTLS automatic and mandatory for all meshed service communication", "tls"),
    "authz_policy": GovernanceLayer("authz_policy",
        "MeshTLSAuthentication / AuthorizationPolicy for route-level access control", None, is_optional=True),
    "tap_observability": GovernanceLayer("tap_observability",
        "Linkerd Tap — real-time traffic inspection for governance evidence", None, is_optional=True),
    "cert_rotation": GovernanceLayer("cert_rotation",
        "Automatic mTLS certificate rotation (cert-manager integration)", None),
    "viz_enabled": GovernanceLayer("viz_enabled",
        "Linkerd Viz — Golden metrics and traffic topology visualization", None, is_optional=True),
    "ingress_policy": GovernanceLayer("ingress_policy",
        "Server and HTTPRoute policies for ingress traffic authorization", None, is_optional=True),
}

class LinkerdEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Linkerd documentation + 2024 security audit (7ASecurity/OSTIF) + CVE-2025-43915",
        strategy="DECLARED-N",
        description=(
            "N(O) from Linkerd architecture. service_communication N=4. "
            "service_communication between meshed pods: ACTIVE — "
            "mTLS is automatic, mandatory, and tied to ServiceAccount identity. "
            "Cannot be disabled per-connection; all meshed traffic is encrypted+authenticated. "
            "Constitutional distinction from Istio (T1610): "
            "Linkerd proxy injected via CNI/initContainer, NOT admission webhook. "
            "Istio's governance ceiling bounded by K8s admission governance (T1613). "
            "Linkerd's injection mechanism avoids that dependency — "
            "does not rely on failurePolicy:Fail admission webhook for injection. "
            "Authorization Policy: CRYSTALLIZED — MeshTLSAuthentication exists, "
            "requires explicit Server and HTTPRoute policy configuration. "
            "CVE-2025-43915: proxy metrics resource exhaustion (DoS) — "
            "not a governance gap, a reliability gap. "
            "Linkerd 2024 security audit: no critical findings (7ASecurity/OSTIF/CNCF). "
            "2 total CVEs vs Istio's larger CVE surface — Rust proxy architectural advantage. "
            "Linkerd 2.19 (October 2025): post-quantum TLS (ML-KEM-768 / X25519 hybrid)."
        ),
    )
    def __init__(self, proxy_injected: bool=True, authz_policy: bool=False,
                 tap_enabled: bool=False, viz_enabled: bool=False):
        self._injected = proxy_injected
        self._authz = authz_policy
        self._tap = tap_enabled
        self._viz = viz_enabled

    def collect_operation_families(self): return LINKERD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [LINKERD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in LINKERD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            mtls_enforced=self._injected, authz_policy=self._authz,
            proxy_injected=self._injected, tap_enabled=self._tap,
            viz_enabled=self._viz, audit_logged=False,
            src_service=None, dst_service=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in LINKERD_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "proxy_injection" in fam.declared_layers and self._injected: k.append("proxy_injection")
        if "mtls_enforcement" in fam.declared_layers and self._injected: k.append("mtls_enforcement")
        if "authz_policy" in fam.declared_layers and self._authz: k.append("authz_policy")
        if "tap_observability" in fam.declared_layers and self._tap: k.append("tap_observability")
        if "cert_rotation" in fam.declared_layers and self._injected: k.append("cert_rotation")
        if "viz_enabled" in fam.declared_layers and self._viz: k.append("viz_enabled")
        return k
    def assess_ear_state(self, op_family):
        if not self._injected: return EARState.ABSENT
        if op_family.name in ("service_communication", "mtls_certificate"):
            return EARState.ACTIVE  # mTLS mandatory for meshed traffic
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
