"""
ear_adapter_kubernetes.py — Kubernetes EAR Adapter

Implements the EARAdapter interface for Kubernetes.
Primary input: Kubernetes audit log (JSON lines, kube-apiserver format).
Secondary: namespace annotations (PSS mode), admission webhook config.

Kubernetes is the canonical N-determination challenge and the GCG
framework's origin system. Default cluster: N=5, k=1 (RBAC only),
gap magnitude=4. (PCM-0333-191)

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
GCG Codex Binding 1: Cloud-Native Orchestration (PCM-0333-187..191)
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ── Enumerations ──────────────────────────────────────────────────────────────

class EARState(Enum):
    ACTIVE       = "ACTIVE"
    CRYSTALLIZED = "CRYSTALLIZED"
    ABSENT       = "ABSENT"


class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"
    ABSENCE        = "ABSENCE"
    BYPASS         = "BYPASS"


@dataclass
class OperationFamily:
    name:            str
    description:     str
    declared_layers: list[str]
    api_groups:      list[str]   # e.g. ['', 'apps', 'batch']
    resource_verbs:  list[str]   # e.g. ['create', 'update']


@dataclass
class GovernanceLayer:
    name:          str
    description:   str
    audit_field:   str | None = None
    is_optional:   bool = False


@dataclass
class ExecutionInstance:
    """One Kubernetes API server request from audit log."""
    operation_family:          str
    request_id:                str
    timestamp:                 str
    verb:                      str
    resource:                  str
    namespace:                 str
    user:                      str
    user_groups:               list[str]
    # RBAC decision
    rbac_decision:             str        # 'allow' | 'deny' | 'unknown'
    rbac_reason:               str
    # Admission controllers
    admission_webhooks_called: list[str]  # webhook names that evaluated
    # PSS
    pss_mode:                  str | None # 'Privileged' | 'Baseline' | 'Restricted' | None
    pss_evaluated:             bool
    # NetworkPolicy
    network_policy_exists:     bool
    # Audit log
    audit_log_present:         bool
    # Raw
    raw:                       dict = field(default_factory=dict)


@dataclass
class GovernanceDeclaration:
    source:      str
    strategy:    str
    description: str


# ── Kubernetes governance layer registry ──────────────────────────────────────

K8S_GOVERNANCE_LAYERS = {
    "rbac": GovernanceLayer(
        name="rbac",
        description="RBAC — Role-Based Access Control, evaluates every API request",
        audit_field="authorization.k8s.io/reason",
    ),
    "admission_controllers": GovernanceLayer(
        name="admission_controllers",
        description="Admission webhooks — mutating and validating admission controllers",
        audit_field="annotations.admission.k8s.io",
        is_optional=True,
    ),
    "pod_security_standards": GovernanceLayer(
        name="pod_security_standards",
        description="Pod Security Standards — enforce pod-level security policy per namespace",
        audit_field="annotations.pod-security.kubernetes.io",
        is_optional=True,
    ),
    "network_policy": GovernanceLayer(
        name="network_policy",
        description="NetworkPolicy — restrict pod-to-pod and pod-to-external traffic",
        audit_field=None,
        is_optional=True,
    ),
    "audit_logging": GovernanceLayer(
        name="audit_logging",
        description="Audit logging — durable structured record of all API requests",
        audit_field=None,
        is_optional=False,
    ),
}


# ── Kubernetes operation family registry ──────────────────────────────────────

K8S_OPERATION_FAMILIES: list[OperationFamily] = [
    OperationFamily(
        name="pod_create",
        description="Create a Pod in a namespace (the canonical GCG origin case)",
        declared_layers=["rbac", "admission_controllers", "pod_security_standards",
                         "network_policy", "audit_logging"],
        api_groups=["", "v1"],
        resource_verbs=["create"],
    ),
    OperationFamily(
        name="pod_privileged_create",
        description="Create a Pod with hostNetwork:true or privileged:true",
        declared_layers=["rbac", "admission_controllers", "pod_security_standards",
                         "network_policy", "audit_logging"],
        api_groups=["", "v1"],
        resource_verbs=["create"],
    ),
    OperationFamily(
        name="secret_read",
        description="Read a Secret resource",
        declared_layers=["rbac", "audit_logging"],
        api_groups=["", "v1"],
        resource_verbs=["get", "list", "watch"],
    ),
    OperationFamily(
        name="rbac_escalation",
        description="Create ClusterRoleBinding or RoleBinding (privilege escalation path)",
        declared_layers=["rbac", "admission_controllers", "audit_logging"],
        api_groups=["rbac.authorization.k8s.io"],
        resource_verbs=["create", "update", "patch"],
    ),
    OperationFamily(
        name="workload_create",
        description="Create Deployments, StatefulSets, DaemonSets, Jobs",
        declared_layers=["rbac", "admission_controllers", "pod_security_standards",
                         "audit_logging"],
        api_groups=["apps", "batch"],
        resource_verbs=["create", "update"],
    ),
]


# ── Kubernetes EAR Adapter ────────────────────────────────────────────────────

class KubernetesEARAdapter:
    """
    EAR Adapter for Kubernetes.

    Primary: audit log (kube-apiserver audit, JSON lines).
    Secondary: namespace PSS annotations, webhook configuration.

    The audit log is Kubernetes's CRYSTALLIZED receipt surface:
    it exists, it records API requests, but it is opt-in and
    does not record non-participation by other governance layers.
    """

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "Kubernetes Security Documentation + CIS Kubernetes Benchmark v1.8 + "
            "NIST SP 800-190 + Kubernetes Audit Policy documentation"
        ),
        strategy="MINIMUM-N",
        description=(
            "N(O) uses MINIMUM-N for this architectural analysis: "
            "N=5 for pod_create (RBAC + admission + PSS + NetworkPolicy + audit). "
            "This is the minimum declared applicable layer set per CIS Benchmark. "
            "PER-CONTEXT-N (per namespace, per webhook registration) would give "
            "more precise gap magnitudes but is deployment-specific. "
            "The GCG codex canonical case: default cluster k=1 (RBAC only), "
            "gap magnitude=4. (PCM-0333-191)"
        ),
    )

    def __init__(
        self,
        audit_log_lines:           list[str] | None = None,
        audit_log_path:            str | None = None,
        admission_webhooks:        list[str] | None = None,
        namespace_pss_modes:       dict[str, str] | None = None,
        audit_policy_enabled:      bool | None = None,
        has_network_policies:      bool = False,
    ):
        self._log_lines       = audit_log_lines
        self._log_path        = audit_log_path
        self._webhooks        = admission_webhooks or []
        self._pss_modes       = namespace_pss_modes or {}
        self._audit_enabled   = audit_policy_enabled
        self._has_netpol      = has_network_policies
        self._entries: list[dict] = []
        self._loaded          = False

    def load(self) -> None:
        if self._loaded:
            return
        lines: list[str] = self._log_lines or []
        if not lines and self._log_path:
            lines = Path(self._log_path).read_text().splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                self._entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        self._loaded = True

    # ── C-01 ─────────────────────────────────────────────────────────────

    def collect_operation_families(self) -> list[OperationFamily]:
        return K8S_OPERATION_FAMILIES

    # ── C-02 ─────────────────────────────────────────────────────────────

    def collect_governance_layers(
        self, op_family: OperationFamily
    ) -> list[GovernanceLayer]:
        return [K8S_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in K8S_GOVERNANCE_LAYERS]

    # ── C-03 ─────────────────────────────────────────────────────────────

    def collect_executions(
        self, op_family: OperationFamily
    ) -> list[ExecutionInstance]:
        self.load()
        instances = []

        for entry in self._entries:
            inst = self._parse_entry(entry, op_family)
            if inst:
                instances.append(inst)

        return instances

    def _parse_entry(
        self, entry: dict, op_family: OperationFamily
    ) -> ExecutionInstance | None:
        """Parse one audit log entry into an ExecutionInstance."""
        verb       = entry.get("verb", "")
        obj_ref    = entry.get("objectRef", {}) or {}
        resource   = obj_ref.get("resource", "")
        api_group  = obj_ref.get("apiGroup", "")
        namespace  = obj_ref.get("namespace", "")
        user_info  = entry.get("user", {}) or {}
        user       = user_info.get("username", "")
        groups     = user_info.get("groups") or []
        req_id     = entry.get("auditID", entry.get("requestURI", "")[:40])
        timestamp  = entry.get("stageTimestamp", entry.get("requestReceivedTimestamp", ""))

        # Match operation family
        if op_family.name == "pod_create":
            if not (resource == "pods" and verb == "create"):
                return None
            # Exclude privileged pods (they belong to pod_privileged_create)
            req_obj = entry.get("requestObject", {}) or {}
            spec    = req_obj.get("spec", {}) or {}
            if self._is_privileged_pod(spec):
                return None

        elif op_family.name == "pod_privileged_create":
            if not (resource == "pods" and verb == "create"):
                return None
            req_obj = entry.get("requestObject", {}) or {}
            spec    = req_obj.get("spec", {}) or {}
            if not self._is_privileged_pod(spec):
                return None

        elif op_family.name == "secret_read":
            if not (resource == "secrets" and verb in ("get", "list", "watch")):
                return None

        elif op_family.name == "rbac_escalation":
            if not (api_group == "rbac.authorization.k8s.io" and
                    resource in ("clusterrolebindings", "rolebindings") and
                    verb in ("create", "update", "patch")):
                return None

        elif op_family.name == "workload_create":
            if not (api_group in ("apps", "batch") and
                    resource in ("deployments", "statefulsets", "daemonsets",
                                 "jobs", "cronjobs") and
                    verb in ("create", "update")):
                return None
        else:
            return None

        # Extract audit annotations
        annotations = entry.get("annotations", {}) or {}

        # RBAC decision
        rbac_reason = annotations.get("authorization.k8s.io/reason", "")
        rbac_decision = "allow" if entry.get("responseStatus", {}).get("code", 0) < 400 else "deny"

        # Admission webhooks
        webhook_anns = {k: v for k, v in annotations.items()
                        if "admission" in k.lower() and "webhook" in k.lower()}
        webhooks_called = list(webhook_anns.keys())
        if not webhooks_called and self._webhooks:
            webhooks_called = []  # webhooks registered but no annotation = non-participation

        # PSS
        pss_mode = self._pss_modes.get(namespace)
        pss_ann  = {k: v for k, v in annotations.items()
                    if "pod-security" in k.lower()}
        pss_evaluated = bool(pss_ann)

        return ExecutionInstance(
            operation_family=op_family.name,
            request_id=req_id,
            timestamp=timestamp,
            verb=verb,
            resource=resource,
            namespace=namespace,
            user=user,
            user_groups=groups,
            rbac_decision=rbac_decision,
            rbac_reason=rbac_reason,
            admission_webhooks_called=webhooks_called,
            pss_mode=pss_mode,
            pss_evaluated=pss_evaluated,
            network_policy_exists=self._has_netpol,
            audit_log_present=True,  # presence in log = audit participated
            raw=entry,
        )

    def _is_privileged_pod(self, spec: dict) -> bool:
        """Check if a Pod spec requests host-level access."""
        if spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC"):
            return True
        for container in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            sc = container.get("securityContext") or {}
            if sc.get("privileged"):
                return True
            caps = sc.get("capabilities") or {}
            if "SYS_ADMIN" in (caps.get("add") or []):
                return True
        return False

    # ── assess_k ─────────────────────────────────────────────────────────

    def assess_k(self, inst: ExecutionInstance) -> list[str]:
        """
        Kubernetes-specific k(O,e) assessment.
        Key finding: in default config, only RBAC participates reliably.
        """
        k = []

        # RBAC: always participates (every API request evaluated)
        k.append("rbac")

        # audit_logging: if this entry is in the log, audit participated
        if inst.audit_log_present:
            k.append("audit_logging")

        # admission_controllers: participated only if webhooks were called
        # AND produced an annotation. If no annotation despite webhooks
        # being registered = Non-Activation (layer exists, not called).
        if inst.admission_webhooks_called:
            k.append("admission_controllers")

        # pod_security_standards: participated only if PSS annotation present
        # AND mode is not Privileged (Privileged = non-activation per PCM-0333-190)
        if (inst.pss_evaluated and
                inst.pss_mode not in ("Privileged", None)):
            k.append("pod_security_standards")

        # network_policy: participates if network policies exist in namespace
        # This is a structural assessment — NetworkPolicy only restricts traffic
        # if policies are actually deployed (Layer Absence if none exist)
        if inst.network_policy_exists:
            k.append("network_policy")

        return k

    # ── EAR state ────────────────────────────────────────────────────────

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """
        Kubernetes EAR state per operation family.

        All families: CRYSTALLIZED at best.
        - Audit log exists and records API requests
        - But does NOT record which governance layers did NOT participate
        - Non-participation record absence is the diagnostic signature (DI-05)
        - The audit log is an opt-in ledger, not a mandatory ledger
        """
        if self._audit_enabled is False:
            return EARState.ABSENT
        # Even with audit enabled: CRYSTALLIZED, not ACTIVE
        # Reason: audit log records outcomes, not governance layer participation
        # policyresults.grantingpolicies equivalent doesn't exist for all layers
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self) -> GovernanceDeclaration:
        return self.GOVERNANCE_DECLARATION

    def summary(self) -> dict:
        self.load()
        families = self.collect_operation_families()
        return {
            "total_audit_entries":   len(self._entries),
            "audit_policy_enabled":  self._audit_enabled,
            "webhooks_registered":   self._webhooks,
            "namespace_pss_modes":   self._pss_modes,
            "has_network_policies":  self._has_netpol,
            "ear_states": {
                f.name: self.assess_ear_state(f).value for f in families
            },
        }
