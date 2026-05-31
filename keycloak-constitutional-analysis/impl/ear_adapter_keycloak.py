"""
ear_adapter_keycloak.py — Keycloak EAR Adapter

Implements the EARAdapter interface for Keycloak.
Primary input: Keycloak admin events API (JSON) and user events API.
Secondary: realm configuration (authorization services enabled, policies).

Keycloak is the Wave 1 identity governance case. It is the most
governance-complete identity system in the corpus — token introspection
is ACTIVE-EAR, session lifecycle is CRYSTALLIZED, authorization services
are CRYSTALLIZED by default (require explicit configuration).

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ── Enumerations ─────────────────────────────────────────────────────────────

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
    keycloak_scope:  str   # 'auth' | 'token' | 'admin' | 'authz'


@dataclass
class GovernanceLayer:
    name:           str
    description:    str
    event_type:     str | None = None   # Keycloak event type indicating participation
    is_optional:    bool = False


@dataclass
class ExecutionInstance:
    """One Keycloak event (admin event or user event)."""
    operation_family:         str
    request_id:               str
    timestamp:                str
    event_type:               str          # e.g. 'LOGIN', 'TOKEN_EXCHANGE', 'ADMIN'
    realm:                    str
    client_id:                str
    user_id:                  str
    # Auth layers
    realm_policy_evaluated:   bool
    client_policy_evaluated:  bool
    session_present:          bool
    # Token layers
    token_type:               str | None   # 'Bearer', 'refresh_token', etc.
    token_introspection_used: bool
    # Authz layers
    authz_service_evaluated:  bool
    authz_decision:           str | None   # 'PERMIT' | 'DENY' | None
    # Audit
    admin_event_recorded:     bool
    user_event_recorded:      bool
    # Error
    error:                    str | None
    raw:                      dict = field(default_factory=dict)


@dataclass
class GovernanceDeclaration:
    source:      str
    strategy:    str
    description: str


# ── Keycloak governance layer registry ───────────────────────────────────────

KC_GOVERNANCE_LAYERS = {
    "realm_authentication": GovernanceLayer(
        name="realm_authentication",
        description="Realm authentication flow — validates credentials against realm config",
        event_type="LOGIN",
    ),
    "realm_policy": GovernanceLayer(
        name="realm_policy",
        description="Realm-level policies — brute force protection, session limits, required actions",
        event_type="LOGIN",
    ),
    "client_policy": GovernanceLayer(
        name="client_policy",
        description="Client-level policies — scope restrictions, protocol mappers, flow overrides",
        event_type="CLIENT_LOGIN",
        is_optional=True,
    ),
    "token_validation": GovernanceLayer(
        name="token_validation",
        description="Token signature validation and expiry check",
        event_type="TOKEN_VERIFY",
    ),
    "session_management": GovernanceLayer(
        name="session_management",
        description="Session creation, validation, and revocation",
        event_type="LOGIN",
    ),
    "authorization_services": GovernanceLayer(
        name="authorization_services",
        description="Keycloak Authorization Services — fine-grained authz policies (UMA/RBAC/ABAC)",
        event_type="AUTHORIZATION_REQUEST",
        is_optional=True,
    ),
    "admin_audit": GovernanceLayer(
        name="admin_audit",
        description="Admin events — structured record of all administrative operations",
        event_type="ADMIN",
        is_optional=False,
    ),
    "user_event_audit": GovernanceLayer(
        name="user_event_audit",
        description="User events — structured record of authentication and token events",
        event_type="USER",
        is_optional=False,
    ),
}


# ── Keycloak operation family registry ───────────────────────────────────────

KC_OPERATION_FAMILIES: list[OperationFamily] = [
    OperationFamily(
        name="user_authentication",
        description="User login — credential validation, MFA, session creation",
        declared_layers=["realm_authentication", "realm_policy",
                         "session_management", "user_event_audit"],
        keycloak_scope="auth",
    ),
    OperationFamily(
        name="token_issuance",
        description="Token issuance — access token, refresh token, ID token creation",
        declared_layers=["token_validation", "session_management",
                         "client_policy", "user_event_audit"],
        keycloak_scope="token",
    ),
    OperationFamily(
        name="token_introspection",
        description="Token introspection — validate and inspect access tokens",
        declared_layers=["token_validation", "user_event_audit"],
        keycloak_scope="token",
    ),
    OperationFamily(
        name="token_refresh",
        description="Refresh token exchange — issue new access token from refresh token",
        declared_layers=["token_validation", "session_management",
                         "client_policy", "user_event_audit"],
        keycloak_scope="token",
    ),
    OperationFamily(
        name="authorization_decision",
        description="Authorization services decision — evaluate policies for resource access",
        declared_layers=["authorization_services", "realm_policy",
                         "admin_audit"],
        keycloak_scope="authz",
    ),
    OperationFamily(
        name="admin_operation",
        description="Administrative operations — realm config, user management, client config",
        declared_layers=["realm_authentication", "realm_policy",
                         "admin_audit"],
        keycloak_scope="admin",
    ),
]


# ── Keycloak EAR Adapter ─────────────────────────────────────────────────────

class KeycloakEARAdapter:
    """
    EAR Adapter for Keycloak.

    Primary: admin events (GET /admin/realms/{realm}/admin-events) and
             user events (GET /admin/realms/{realm}/events).
    Secondary: realm configuration (authorization services enabled,
               event listeners configured).
    """

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "Keycloak Documentation + Keycloak Security Best Practices + "
            "OAuth 2.0 / OIDC specifications + Keycloak Authorization Services Guide"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) derived from Keycloak's documented security model. "
            "token_introspection: N=2 (token_validation + user_event_audit) → ACTIVE-EAR. "
            "user_authentication: N=4 (realm_auth + realm_policy + session + event) → CRYSTALLIZED. "
            "authorization_decision: N=3 (authz_services + realm_policy + admin_audit) → "
            "CRYSTALLIZED by default (authz services must be explicitly enabled). "
            "admin_operation: N=3 (realm_auth + realm_policy + admin_audit) → CRYSTALLIZED."
        ),
    )

    def __init__(
        self,
        admin_events:              list[dict] | None = None,
        user_events:               list[dict] | None = None,
        admin_events_path:         str | None = None,
        user_events_path:          str | None = None,
        authz_services_enabled:    bool = False,
        user_events_enabled:       bool | None = None,
        admin_events_enabled:      bool | None = None,
        mfa_required:              bool = False,
    ):
        self._admin_events      = admin_events or []
        self._user_events       = user_events  or []
        self._admin_events_path = admin_events_path
        self._user_events_path  = user_events_path
        self._authz_enabled     = authz_services_enabled
        self._user_ev_enabled   = user_events_enabled
        self._admin_ev_enabled  = admin_events_enabled
        self._mfa_required      = mfa_required
        self._loaded            = False

    def load(self) -> None:
        if self._loaded:
            return
        if self._admin_events_path and not self._admin_events:
            try:
                self._admin_events = json.loads(
                    Path(self._admin_events_path).read_text()
                )
            except Exception:
                pass
        if self._user_events_path and not self._user_events:
            try:
                self._user_events = json.loads(
                    Path(self._user_events_path).read_text()
                )
            except Exception:
                pass
        self._loaded = True

    # ── C-01 ─────────────────────────────────────────────────────────────

    def collect_operation_families(self) -> list[OperationFamily]:
        return KC_OPERATION_FAMILIES

    # ── C-02 ─────────────────────────────────────────────────────────────

    def collect_governance_layers(
        self, op_family: OperationFamily
    ) -> list[GovernanceLayer]:
        return [KC_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in KC_GOVERNANCE_LAYERS]

    # ── C-03 ─────────────────────────────────────────────────────────────

    def collect_executions(
        self, op_family: OperationFamily
    ) -> list[ExecutionInstance]:
        self.load()
        instances = []

        if op_family.keycloak_scope in ("auth", "token"):
            for ev in self._user_events:
                inst = self._parse_user_event(ev, op_family)
                if inst:
                    instances.append(inst)

        elif op_family.keycloak_scope in ("admin", "authz"):
            for ev in self._admin_events:
                inst = self._parse_admin_event(ev, op_family)
                if inst:
                    instances.append(inst)

        # If no events loaded, return synthetic structural instances
        if not instances:
            instances = self._synthetic_instances(op_family)

        return instances

    def _parse_user_event(
        self, ev: dict, op_family: OperationFamily
    ) -> ExecutionInstance | None:
        """Parse a Keycloak user event."""
        ev_type = ev.get("type", "")

        family_event_map = {
            "user_authentication":  ["LOGIN", "LOGIN_ERROR"],
            "token_issuance":       ["CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR"],
            "token_introspection":  ["TOKEN_INTROSPECT", "INTROSPECT_TOKEN"],
            "token_refresh":        ["REFRESH_TOKEN", "REFRESH_TOKEN_ERROR"],
        }
        allowed = family_event_map.get(op_family.name, [])
        if ev_type not in allowed:
            return None

        details = ev.get("details", {}) or {}
        return ExecutionInstance(
            operation_family=op_family.name,
            request_id=str(ev.get("id", "")),
            timestamp=str(ev.get("time", "")),
            event_type=ev_type,
            realm=ev.get("realmId", ""),
            client_id=ev.get("clientId", ""),
            user_id=ev.get("userId", ""),
            realm_policy_evaluated=True,   # realm policies always evaluated on login
            client_policy_evaluated=bool(ev.get("clientId")),
            session_present=bool(ev.get("sessionId")),
            token_type=details.get("token_type"),
            token_introspection_used=(ev_type in ("TOKEN_INTROSPECT", "INTROSPECT_TOKEN")),
            authz_service_evaluated=False,
            authz_decision=None,
            admin_event_recorded=False,
            user_event_recorded=True,
            error=ev.get("error"),
            raw=ev,
        )

    def _parse_admin_event(
        self, ev: dict, op_family: OperationFamily
    ) -> ExecutionInstance | None:
        """Parse a Keycloak admin event."""
        ev_type     = ev.get("operationType", "")
        resource    = ev.get("resourceType", "")

        if op_family.name == "admin_operation":
            if ev_type not in ("CREATE", "UPDATE", "DELETE", "ACTION"):
                return None
        elif op_family.name == "authorization_decision":
            if resource not in ("AUTHORIZATION_POLICY", "AUTHORIZATION_RESOURCE",
                                 "AUTHORIZATION_SCOPE"):
                return None
        else:
            return None

        return ExecutionInstance(
            operation_family=op_family.name,
            request_id=str(ev.get("id", "")),
            timestamp=str(ev.get("time", "")),
            event_type=f"ADMIN_{ev_type}",
            realm=ev.get("realmId", ""),
            client_id=ev.get("clientId") or "",
            user_id=ev.get("authDetails", {}).get("userId", ""),
            realm_policy_evaluated=True,
            client_policy_evaluated=False,
            session_present=False,
            token_type=None,
            token_introspection_used=False,
            authz_service_evaluated=(op_family.name == "authorization_decision"),
            authz_decision=ev.get("authDetails", {}).get("decision"),
            admin_event_recorded=True,
            user_event_recorded=False,
            error=None,
            raw=ev,
        )

    def _synthetic_instances(
        self, op_family: OperationFamily
    ) -> list[ExecutionInstance]:
        """Return structural synthetic instances when no events are available."""
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}",
            timestamp="",
            event_type="SYNTHETIC",
            realm="(structural)",
            client_id="",
            user_id="",
            realm_policy_evaluated=True,
            client_policy_evaluated=False,
            session_present=(op_family.name in
                             ("user_authentication", "token_issuance", "token_refresh")),
            token_type=None,
            token_introspection_used=(op_family.name == "token_introspection"),
            authz_service_evaluated=self._authz_enabled,
            authz_decision=None,
            admin_event_recorded=(op_family.keycloak_scope == "admin"),
            user_event_recorded=(op_family.keycloak_scope in ("auth", "token")),
            error=None,
            raw={},
        )]

    # ── assess_k ─────────────────────────────────────────────────────────

    def assess_k(self, inst: ExecutionInstance) -> list[str]:
        """Keycloak k(O,e) assessment."""
        k = []
        n = KC_OPERATION_FAMILIES
        fam = next((f for f in n if f.name == inst.operation_family), None)
        if fam is None:
            return k

        declared = fam.declared_layers

        if "realm_authentication" in declared and inst.realm_policy_evaluated:
            k.append("realm_authentication")

        if "realm_policy" in declared and inst.realm_policy_evaluated:
            k.append("realm_policy")

        if "client_policy" in declared and inst.client_policy_evaluated:
            k.append("client_policy")

        if "token_validation" in declared:
            # Token validation always participates when token event exists
            if inst.token_introspection_used or inst.token_type:
                k.append("token_validation")
            elif inst.event_type != "SYNTHETIC":
                k.append("token_validation")  # any token event = validation ran

        if "session_management" in declared and inst.session_present:
            k.append("session_management")

        if "authorization_services" in declared:
            if inst.authz_service_evaluated and self._authz_enabled:
                k.append("authorization_services")

        if "admin_audit" in declared and inst.admin_event_recorded:
            k.append("admin_audit")

        if "user_event_audit" in declared and inst.user_event_recorded:
            if self._user_ev_enabled is not False:
                k.append("user_event_audit")

        return k

    # ── EAR state ────────────────────────────────────────────────────────

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """
        Keycloak EAR state.

        token_introspection: ACTIVE — token validation constitutive,
          structured response with token claims (sub, exp, iat, active).
          This is Keycloak's strongest governance surface.

        user_authentication: CRYSTALLIZED — user events record login
          but are opt-in (must configure event listeners). Session creation
          is real but no per-login policy evaluation receipt.

        authorization_decision: CRYSTALLIZED — Authorization Services must
          be explicitly enabled per client. Most deployments: ABSENT.
          When enabled: structured decision with policy evaluation.

        token_refresh, token_issuance: CRYSTALLIZED — token events exist
          but session lifecycle governance receipt is incomplete.

        admin_operation: CRYSTALLIZED — admin events record changes but
          are opt-in and do not record pre-change authorization evaluation.
        """
        if op_family.name == "token_introspection":
            return EARState.ACTIVE

        if op_family.name == "authorization_decision":
            if not self._authz_enabled:
                return EARState.ABSENT   # not configured = structurally absent
            return EARState.CRYSTALLIZED  # exists but not constitutive

        if op_family.name == "user_authentication":
            if self._user_ev_enabled is False:
                return EARState.ABSENT
            return EARState.CRYSTALLIZED

        if op_family.name in ("token_issuance", "token_refresh"):
            if self._user_ev_enabled is False:
                return EARState.ABSENT
            return EARState.CRYSTALLIZED

        if op_family.name == "admin_operation":
            if self._admin_ev_enabled is False:
                return EARState.ABSENT
            return EARState.CRYSTALLIZED

        return EARState.CRYSTALLIZED

    def get_governance_declaration(self) -> GovernanceDeclaration:
        return self.GOVERNANCE_DECLARATION

    def summary(self) -> dict:
        self.load()
        families = self.collect_operation_families()
        return {
            "authz_services_enabled": self._authz_enabled,
            "user_events_enabled":    self._user_ev_enabled,
            "admin_events_enabled":   self._admin_ev_enabled,
            "ear_states": {
                f.name: self.assess_ear_state(f).value for f in families
            },
        }
