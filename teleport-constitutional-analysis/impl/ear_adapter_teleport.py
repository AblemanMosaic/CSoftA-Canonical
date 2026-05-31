"""
ear_adapter_teleport.py — Teleport EAR Adapter
Wave 3 — System 14. Identity-aware access proxy for SSH, K8s, databases, apps.

Key finding: Teleport is Wave 3's strongest governance case alongside cert-manager.
Session recording is the defining governance surface: when enabled, session
recording is constitutive of session establishment — the session cannot be
established without the recording backend being available (when configured
with strict mode). The session recording IS the governance receipt.
Access requests and certificates are CRYSTALLIZED (audit log exists, not constitutive).
Audit log is Teleport's most complete governance surface — structured, queryable,
covers all access events.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE = "ACTIVE"; CRYSTALLIZED = "CRYSTALLIZED"; ABSENT = "ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"; ABSENCE = "ABSENCE"; BYPASS = "BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; teleport_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    cert_issued: bool; session_recorded: bool; audit_logged: bool
    mfa_verified: bool; access_request_approved: bool
    recording_mode: str; user: str | None; node: str | None
    error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

TP_OPERATION_FAMILIES = [
    OperationFamily("session_establishment",
        "Establish SSH/K8s/DB/App session via Teleport proxy",
        ["teleport_certificate", "audit_log", "session_recording", "rbac_policy"], "session"),
    OperationFamily("certificate_issuance",
        "Issue short-lived certificate to authenticated user",
        ["user_authentication", "rbac_policy", "teleport_certificate"], "cert"),
    OperationFamily("access_request",
        "Submit and approve/deny privileged access request",
        ["access_request_resource", "rbac_policy", "audit_log"], "request"),
    OperationFamily("node_registration",
        "Register Teleport node/service with cluster",
        ["node_token", "teleport_certificate", "audit_log"], "node"),
]

TP_GOVERNANCE_LAYERS = {
    "teleport_certificate": GovernanceLayer("teleport_certificate",
        "Short-lived Teleport certificate — IS the access credential receipt", "cert"),
    "audit_log": GovernanceLayer("audit_log",
        "Teleport structured audit log — comprehensive, queryable", "events"),
    "session_recording": GovernanceLayer("session_recording",
        "Session recording — constitutive in strict mode", "sessionID"),
    "rbac_policy": GovernanceLayer("rbac_policy",
        "RBAC role/allow rule evaluated for access", "roles"),
    "user_authentication": GovernanceLayer("user_authentication",
        "User authentication (SSO/local/MFA)", "user"),
    "access_request_resource": GovernanceLayer("access_request_resource",
        "AccessRequest CRD for privileged access workflow", "spec.roles"),
    "node_token": GovernanceLayer("node_token",
        "Join token for node registration", "token"),
}

class TeleportEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Teleport Documentation + Teleport Audit Log spec + Teleport Session Recording",
        strategy="DECLARED-N",
        description=(
            "N(O) from Teleport architecture. session_establishment N=4. "
            "session_establishment: ACTIVE when session_recording in strict mode — "
            "session cannot be established if recording backend unavailable. "
            "Session recording IS the governance receipt for session operations. "
            "certificate_issuance: ACTIVE — Teleport certificate constitutive of access, "
            "short-lived (hours), cannot access resources without valid cert. "
            "Teleport audit log is the most structured governance receipt in Wave 3: "
            "comprehensive, queryable, covers all access events. "
            "Wave 3 analog of Vault (Wave 1) and SPIFFE/SPIRE (Wave 2)."
        ),
    )

    def __init__(self, recording_mode: str = "strict",
                 audit_log_enabled: bool = True, mfa_required: bool = False):
        self._recording = recording_mode  # strict | best_effort | off
        self._audit = audit_log_enabled
        self._mfa = mfa_required

    def collect_operation_families(self): return TP_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [TP_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in TP_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            cert_issued=True, session_recorded=(self._recording != "off"),
            audit_logged=self._audit, mfa_verified=self._mfa,
            access_request_approved=(op_family.name == "access_request"),
            recording_mode=self._recording, user=None, node=None, error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in TP_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "teleport_certificate" in fam.declared_layers and inst.cert_issued:
            k.append("teleport_certificate")
        if "audit_log" in fam.declared_layers and inst.audit_logged:
            k.append("audit_log")
        if "session_recording" in fam.declared_layers and inst.session_recorded:
            k.append("session_recording")
        if "rbac_policy" in fam.declared_layers:
            k.append("rbac_policy")
        if "user_authentication" in fam.declared_layers:
            k.append("user_authentication")
        if "access_request_resource" in fam.declared_layers and inst.access_request_approved:
            k.append("access_request_resource")
        if "node_token" in fam.declared_layers:
            k.append("node_token")
        return k

    def assess_ear_state(self, op_family):
        # session_establishment: ACTIVE in strict recording mode
        if op_family.name == "session_establishment":
            if self._recording == "strict" and self._audit:
                return EARState.ACTIVE
            if self._recording == "off" and not self._audit:
                return EARState.ABSENT
            return EARState.CRYSTALLIZED
        # certificate_issuance: ACTIVE — cert constitutive of access
        if op_family.name == "certificate_issuance":
            return EARState.ACTIVE
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
