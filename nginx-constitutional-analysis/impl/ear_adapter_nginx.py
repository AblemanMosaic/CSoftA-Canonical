"""
ear_adapter_nginx.py — Nginx / ingress-nginx EAR Adapter
Wave 6 — System 28. Network boundary governance.

Key finding: Nginx is the network boundary governance case. Every HTTP
request to a Kubernetes workload passes through ingress-nginx. The access
log is CRYSTALLIZED: it records requests but is not constitutive of request
handling. TLS termination is the closest to ACTIVE: a request cannot be
decrypted without the private key, but the governance of what is done with
the decrypted request is CRYSTALLIZED. CVE-2025-1974 (IngressNightmare,
CVSS 9.8): annotation injection via the admission webhook allowing
unauthenticated RCE from any pod on the network, affecting 43% of cloud
environments (6,500+ clusters including Fortune 500). The annotation
governance surface — which annotations are permitted and which are
validated — is the constitutional gap.
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
    name: str; description: str; declared_layers: list[str]; nginx_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    access_logged: bool; tls_terminated: bool
    annotation_validated: bool; admission_checked: bool
    rate_limited: bool; waf_applied: bool
    host: str|None; path: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

NGINX_OPERATION_FAMILIES = [
    OperationFamily("request_proxying",
        "Proxy HTTP/HTTPS request to upstream service",
        ["access_log","tls_termination"], "proxy"),
    OperationFamily("tls_termination",
        "Terminate TLS connection and decrypt request",
        ["tls_cert","access_log","tls_policy"], "tls"),
    OperationFamily("ingress_admission",
        "Validate Ingress object via admission webhook",
        ["annotation_validation","admission_log","rbac_check"], "admission"),
    OperationFamily("annotation_processing",
        "Process Ingress annotation to configure NGINX",
        ["annotation_validation","admission_log"], "annotation"),
    OperationFamily("config_reload",
        "Reload NGINX configuration from Ingress objects",
        ["config_hash","admission_log","access_log"], "config"),
]

NGINX_GOVERNANCE_LAYERS = {
    "access_log": GovernanceLayer("access_log",
        "NGINX access log — records request details", "access_log"),
    "tls_termination": GovernanceLayer("tls_termination",
        "TLS termination — decryption requires private key", None),
    "tls_cert": GovernanceLayer("tls_cert",
        "TLS certificate — constitutive of HTTPS connection", "ssl_certificate"),
    "tls_policy": GovernanceLayer("tls_policy",
        "TLS protocol/cipher policy", "ssl_protocols"),
    "rate_limit": GovernanceLayer("rate_limit",
        "Rate limiting via limit_req_zone", "limit_req", is_optional=True),
    "waf": GovernanceLayer("waf",
        "Web Application Firewall (ModSecurity/NAXSI)", None, is_optional=True),
    "annotation_validation": GovernanceLayer("annotation_validation",
        "Ingress annotation validation in admission webhook", None),
    "admission_log": GovernanceLayer("admission_log",
        "Admission webhook decision log", None, is_optional=True),
    "rbac_check": GovernanceLayer("rbac_check",
        "Kubernetes RBAC check for Ingress object creation", None),
    "config_hash": GovernanceLayer("config_hash",
        "Hash of generated NGINX config for change detection", None, is_optional=True),
}

class NginxEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="NGINX Documentation + ingress-nginx security guide + IngressNightmare advisory",
        strategy="DECLARED-N",
        description=(
            "N(O) from NGINX/ingress-nginx architecture. request_proxying N=4. "
            "tls_termination: ACTIVE — TLS cert constitutive of HTTPS connection; "
            "cannot decrypt without private key. "
            "request_proxying: CRYSTALLIZED — access log records but is not constitutive. "
            "ingress_admission: CRYSTALLIZED with annotation_validation; "
            "ABSENT without (CVE-2025-1974 class: annotation injection bypasses validation). "
            "Critical finding: annotation processing governance gap — "
            "configuration-snippet and auth-tls-match-cn annotations allowed "
            "arbitrary NGINX config injection, producing cluster-wide RCE. "
            "43% of cloud environments affected (Wiz Research, March 2025)."
        ),
    )
    def __init__(self, tls_enabled: bool=True, access_log_enabled: bool=True,
                 annotation_validation: bool=True, waf_enabled: bool=False,
                 rate_limiting: bool=False):
        self._tls = tls_enabled
        self._access_log = access_log_enabled
        self._ann_val = annotation_validation
        self._waf = waf_enabled
        self._rate = rate_limiting

    def collect_operation_families(self): return NGINX_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [NGINX_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in NGINX_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            access_logged=self._access_log, tls_terminated=self._tls,
            annotation_validated=self._ann_val, admission_checked=True,
            rate_limited=self._rate, waf_applied=self._waf,
            host=None, path=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in NGINX_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "access_log" in fam.declared_layers and self._access_log: k.append("access_log")
        if "tls_termination" in fam.declared_layers and self._tls: k.append("tls_termination")
        if "tls_cert" in fam.declared_layers and self._tls: k.append("tls_cert")
        if "tls_policy" in fam.declared_layers and self._tls: k.append("tls_policy")
        if "rate_limit" in fam.declared_layers and self._rate: k.append("rate_limit")
        if "waf" in fam.declared_layers and self._waf: k.append("waf")
        if "annotation_validation" in fam.declared_layers and self._ann_val: k.append("annotation_validation")
        if "rbac_check" in fam.declared_layers: k.append("rbac_check")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "tls_termination" and self._tls: return EARState.ACTIVE
        if op_family.name == "ingress_admission" and not self._ann_val: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
