"""
ear_adapter_boundary.py — HashiCorp Boundary EAR Adapter
Wave 3 — System 15. Identity-based access management for dynamic infrastructure.

Key finding: CRYSTALLIZED ceiling with one surface approaching ACTIVE.
Session authorization is CRYSTALLIZED: Boundary issues tokens and records
sessions but the session record is not constitutive of session establishment
in the way Teleport's strict recording mode is. Vault integration for
credential brokering is the highest-governance surface — when Vault issues
dynamic credentials, Vault's ACTIVE-EAR governs the fetch.
The Boundary session IS a receipt but session establishment does not depend
on the session record being durably written before access is granted.
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
    name: str; description: str; declared_layers: list[str]; boundary_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    token_issued: bool; session_recorded: bool; credential_brokered: bool
    vault_integrated: bool; oidc_verified: bool
    target_id: str | None; user_id: str | None
    error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

BD_OPERATION_FAMILIES = [
    OperationFamily("session_authorization",
        "Authorize and establish session to target resource",
        ["auth_token", "session_resource", "target_policy", "audit_log"], "session"),
    OperationFamily("credential_brokering",
        "Broker dynamic credentials from Vault for session",
        ["auth_token", "vault_credential", "session_resource", "audit_log"], "credential"),
    OperationFamily("user_authentication",
        "Authenticate user via OIDC/LDAP/password",
        ["oidc_token", "auth_token", "audit_log"], "auth"),
    OperationFamily("target_management",
        "Create/update target resource definition",
        ["auth_token", "target_resource", "audit_log"], "target"),
]

BD_GOVERNANCE_LAYERS = {
    "auth_token": GovernanceLayer("auth_token",
        "Boundary auth token — short-lived access credential", "token"),
    "session_resource": GovernanceLayer("session_resource",
        "Session record in Boundary database", "id"),
    "target_policy": GovernanceLayer("target_policy",
        "Target policy (host set, credential library) evaluated", "hostSets"),
    "audit_log": GovernanceLayer("audit_log",
        "Boundary event/audit log", None),
    "vault_credential": GovernanceLayer("vault_credential",
        "Dynamic credential from Vault credential library", "secret"),
    "oidc_token": GovernanceLayer("oidc_token",
        "OIDC token from identity provider", "sub"),
    "target_resource": GovernanceLayer("target_resource",
        "Target resource definition in Boundary", "address"),
}

class BoundaryEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="HashiCorp Boundary Documentation + Boundary Event System + Vault Integration guide",
        strategy="DECLARED-N",
        description=(
            "N(O) from Boundary architecture. session_authorization N=4. "
            "CRYSTALLIZED ceiling for most operations. "
            "Session resource exists and records session state but session establishment "
            "does not depend on session record being durably written before access is granted — "
            "contrast with Teleport strict recording mode. "
            "credential_brokering via Vault is highest governance surface: "
            "Vault's ACTIVE-EAR governs the credential fetch; "
            "Boundary's own governance of the brokering operation is CRYSTALLIZED."
        ),
    )

    def __init__(self, vault_integrated: bool = False,
                 audit_log_enabled: bool = True, oidc_enabled: bool = True):
        self._vault = vault_integrated
        self._audit = audit_log_enabled
        self._oidc = oidc_enabled

    def collect_operation_families(self): return BD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [BD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in BD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            token_issued=True, session_recorded=True,
            credential_brokered=(op_family.name == "credential_brokering" and self._vault),
            vault_integrated=self._vault, oidc_verified=self._oidc,
            target_id=None, user_id=None, error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in BD_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "auth_token" in fam.declared_layers and inst.token_issued:
            k.append("auth_token")
        if "session_resource" in fam.declared_layers and inst.session_recorded:
            k.append("session_resource")
        if "target_policy" in fam.declared_layers:
            k.append("target_policy")
        if "audit_log" in fam.declared_layers and self._audit:
            k.append("audit_log")
        if "vault_credential" in fam.declared_layers and inst.credential_brokered:
            k.append("vault_credential")
        if "oidc_token" in fam.declared_layers and inst.oidc_verified:
            k.append("oidc_token")
        if "target_resource" in fam.declared_layers:
            k.append("target_resource")
        return k

    def assess_ear_state(self, op_family):
        # No Boundary operation reaches ACTIVE in base configuration
        # credential_brokering with Vault: Vault's ACTIVE governs the fetch;
        # Boundary's own governance remains CRYSTALLIZED
        if not self._audit: return EARState.ABSENT
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
