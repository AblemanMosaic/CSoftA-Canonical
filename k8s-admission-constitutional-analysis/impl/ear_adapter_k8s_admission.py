"""
ear_adapter_k8s_admission.py — Kubernetes Admission Controllers EAR Adapter
Wave 10 — System 48. Admission webhook governance synthesis.

Key finding: Kubernetes admission controllers are the general governance
synthesis case — the final enforcement boundary for all resource creation
and modification in a Kubernetes cluster. This analysis synthesizes the
admission control patterns from: Gatekeeper (Wave 2, T1658),
Kyverno (Wave 2, T1659), ingress-nginx (Wave 6, T1688),
Cosign policy-controller (Wave 8, T1725), Argo CD (Wave 5, T1669).
ValidatingWebhookConfiguration + MutatingWebhookConfiguration are
ACTIVE: resources that fail validation cannot be created. The governance
gap: webhook failures (network errors, timeout) may default to allow
(failurePolicy: Ignore) rather than deny (failurePolicy: Fail).
A webhook with failurePolicy:Ignore has a bypass route via webhook failure.
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
    name: str; description: str; declared_layers: list[str]; adm_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    webhook_evaluated: bool; policy_matched: bool
    fail_closed: bool; audit_logged: bool
    tls_verified: bool; webhook_healthy: bool
    resource_kind: str|None; namespace: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ADM_OPERATION_FAMILIES = [
    OperationFamily("validating_admission",
        "Validate resource via ValidatingWebhookConfiguration",
        ["webhook_config","audit_log","fail_policy","tls_webhook"], "validate"),
    OperationFamily("mutating_admission",
        "Mutate resource via MutatingWebhookConfiguration",
        ["webhook_config","audit_log","fail_policy","tls_webhook"], "mutate"),
    OperationFamily("policy_evaluation",
        "Evaluate admission policy (OPA/Kyverno/CEL) against resource",
        ["webhook_config","policy_rule","audit_log","fail_policy"], "policy"),
    OperationFamily("webhook_governance",
        "Govern ValidatingWebhookConfiguration lifecycle",
        ["webhook_config","rbac_check","audit_log","fail_policy"], "webhook"),
    OperationFamily("supply_chain_enforcement",
        "Enforce image signing policy at admission (Cosign policy-controller)",
        ["webhook_config","signature_policy","audit_log","fail_policy"], "signing"),
]

ADM_GOVERNANCE_LAYERS = {
    "webhook_config": GovernanceLayer("webhook_config",
        "ValidatingWebhookConfiguration or MutatingWebhookConfiguration resource", None),
    "audit_log": GovernanceLayer("audit_log",
        "Kubernetes audit log recording admission decisions", None, is_optional=True),
    "fail_policy": GovernanceLayer("fail_policy",
        "failurePolicy: Fail (closed) vs Ignore (open) — constitutive safety property", "failurePolicy"),
    "tls_webhook": GovernanceLayer("tls_webhook",
        "TLS-secured webhook endpoint — CA bundle verification", "caBundle"),
    "policy_rule": GovernanceLayer("policy_rule",
        "Policy rule evaluated against resource manifest", None),
    "rbac_check": GovernanceLayer("rbac_check",
        "RBAC governing who can modify webhook configurations", None),
    "signature_policy": GovernanceLayer("signature_policy",
        "Image signature policy (Cosign ClusterImagePolicy)", None),
}

class K8sAdmissionEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Kubernetes Admission Controllers documentation + ValidatingWebhookConfiguration spec",
        strategy="DECLARED-N",
        description=(
            "N(O) from K8s admission architecture. validating_admission N=4. "
            "validating_admission with failurePolicy:Fail: ACTIVE — "
            "resources violating policy cannot be created. Constitutive enforcement. "
            "validating_admission with failurePolicy:Ignore: ABSENT bypass — "
            "webhook failure (network error, timeout) allows resource creation. "
            "This is the BYPASS gap form: a failure in the governance mechanism "
            "produces governance absence. "
            "TLS verification for webhook endpoint: CRYSTALLIZED — "
            "ensures webhook is genuine, not a governance bypass. "
            "Synthesizes Gatekeeper (T1658), Kyverno (T1659), "
            "ingress-nginx annotation validation (T1688), Cosign (T1725)."
        ),
    )
    def __init__(self, fail_closed: bool=True, audit_log_enabled: bool=False,
                 tls_verified: bool=True, webhook_healthy: bool=True):
        self._fail_closed = fail_closed
        self._audit = audit_log_enabled
        self._tls = tls_verified
        self._healthy = webhook_healthy

    def collect_operation_families(self): return ADM_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ADM_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ADM_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            webhook_evaluated=True, policy_matched=True,
            fail_closed=self._fail_closed, audit_logged=self._audit,
            tls_verified=self._tls, webhook_healthy=self._healthy,
            resource_kind=None, namespace=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ADM_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "webhook_config" in fam.declared_layers: k.append("webhook_config")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "fail_policy" in fam.declared_layers and self._fail_closed: k.append("fail_policy")
        if "tls_webhook" in fam.declared_layers and self._tls: k.append("tls_webhook")
        if "policy_rule" in fam.declared_layers: k.append("policy_rule")
        if "rbac_check" in fam.declared_layers: k.append("rbac_check")
        if "signature_policy" in fam.declared_layers: k.append("signature_policy")
        return k
    def assess_ear_state(self, op_family):
        if not self._healthy: return EARState.ABSENT
        if not self._fail_closed: return EARState.ABSENT  # failurePolicy:Ignore = bypass
        return EARState.ACTIVE
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
