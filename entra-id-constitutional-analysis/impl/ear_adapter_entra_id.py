"""
ear_adapter_entra_id.py — Microsoft Entra ID (Azure Active Directory) EAR Adapter
Wave 11 — System 53. Enterprise cloud identity governance.

Key finding: Entra ID is the identity substrate for the majority of enterprise
organizations globally. It introduces a constitutional finding absent from the
entire existing corpus: BYPASS via legacy authentication protocol.

Modern authentication (OAuth 2.0 / OpenID Connect) is governed by Conditional
Access Policies (CAP) — ACTIVE when CAP requires MFA: the token cannot be issued
without MFA completing. Legacy authentication protocols (Basic Auth, NTLM, ESMTP
AUTH) bypass Conditional Access entirely. A CAP requiring MFA for all users is
ACTIVE for modern auth and ABSENT for legacy auth simultaneously.

CVE-2025-55241 (CVSS 10.0, September 2025): Actor tokens — undocumented legacy
service-to-service tokens from the Access Control Service — could be used to
impersonate any user in any Entra ID tenant globally. Actor tokens bypass
Conditional Access, bypass MFA, and generate NO LOGS in the target tenant.
This is the most severe example of the BYPASS gap form + ABSENT governance
evidence in the corpus: the attacker has no trail in the victim tenant.
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
    name: str; description: str; declared_layers: list[str]; entra_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    mfa_completed: bool; cap_evaluated: bool
    modern_auth: bool; legacy_blocked: bool
    sign_in_logged: bool; pim_active: bool
    user_principal: str|None; app_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ENTRA_OPERATION_FAMILIES = [
    OperationFamily("modern_authentication",
        "Authenticate via OAuth 2.0 / OIDC — subject to Conditional Access",
        ["conditional_access","mfa_enforcement","sign_in_log","modern_auth_only"], "modern"),
    OperationFamily("legacy_authentication",
        "Authenticate via Basic Auth / NTLM / legacy protocols — bypasses Conditional Access",
        ["legacy_auth_blocked","sign_in_log","modern_auth_only"], "legacy"),
    OperationFamily("privileged_role_assignment",
        "Assign privileged directory roles (Global Admin, Security Admin, etc.)",
        ["conditional_access","pim_jit","sign_in_log","mfa_enforcement"], "priv"),
    OperationFamily("token_issuance",
        "Issue OAuth2 access/refresh tokens",
        ["conditional_access","mfa_enforcement","sign_in_log","token_lifetime"], "token"),
    OperationFamily("cross_tenant_access",
        "Access resources in a different Entra ID tenant",
        ["conditional_access","mfa_enforcement","sign_in_log","cross_tenant_policy"], "cross"),
]

ENTRA_GOVERNANCE_LAYERS = {
    "conditional_access": GovernanceLayer("conditional_access",
        "Conditional Access Policy evaluation — governs modern auth only", "conditionalAccessStatus"),
    "mfa_enforcement": GovernanceLayer("mfa_enforcement",
        "MFA required via CAP for all authentication", None),
    "sign_in_log": GovernanceLayer("sign_in_log",
        "Entra ID Sign-in log — records modern auth events", "signInLogs"),
    "modern_auth_only": GovernanceLayer("modern_auth_only",
        "Legacy authentication protocols blocked", None),
    "legacy_auth_blocked": GovernanceLayer("legacy_auth_blocked",
        "Legacy auth blocked via CAP — eliminates CAP bypass route", None),
    "pim_jit": GovernanceLayer("pim_jit",
        "Privileged Identity Management JIT elevation — no permanent admin", None, is_optional=True),
    "token_lifetime": GovernanceLayer("token_lifetime",
        "Refresh token lifetime policy — limits credential persistence", None, is_optional=True),
    "cross_tenant_policy": GovernanceLayer("cross_tenant_policy",
        "Cross-tenant access settings governing B2B authentication", None, is_optional=True),
}

class EntraIDEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Entra ID documentation + CVE-2025-55241 + Midnight Blizzard analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Entra ID architecture. modern_authentication N=4. "
            "modern_authentication with CAP MFA: ACTIVE — "
            "token cannot be issued without MFA completing (constitutive). "
            "legacy_authentication: ABSENT — Basic Auth / NTLM bypass "
            "Conditional Access and MFA entirely; BYPASS gap form. "
            "The same identity policy is ACTIVE for one auth path and "
            "ABSENT for another — attacker chooses the path. "
            "CVE-2025-55241 (CVSS 10.0, Sept 2025): Actor tokens bypass "
            "Conditional Access, bypass MFA, and generate NO LOGS in target tenant. "
            "Attacker can impersonate Global Admin in any tenant worldwide. "
            "ABSENT governance evidence: Azure AD Graph API read ops generate no logs. "
            "Midnight Blizzard: exploited legacy auth to bypass MFA for initial access "
            "before pivoting to Microsoft corporate environments. "
            "New constitutional concept: split-path governance — same policy is "
            "ACTIVE for one authentication path and ABSENT for another."
        ),
    )
    def __init__(self, mfa_enforced: bool=False, legacy_auth_blocked: bool=False,
                 cap_configured: bool=False, pim_enabled: bool=False,
                 sign_in_logs_exported: bool=False):
        self._mfa = mfa_enforced
        self._legacy_blocked = legacy_auth_blocked
        self._cap = cap_configured
        self._pim = pim_enabled
        self._logs = sign_in_logs_exported

    def collect_operation_families(self): return ENTRA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ENTRA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ENTRA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            mfa_completed=self._mfa, cap_evaluated=self._cap,
            modern_auth=True, legacy_blocked=self._legacy_blocked,
            sign_in_logged=self._logs, pim_active=self._pim,
            user_principal=None, app_id=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ENTRA_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "conditional_access" in fam.declared_layers and self._cap: k.append("conditional_access")
        if "mfa_enforcement" in fam.declared_layers and self._mfa: k.append("mfa_enforcement")
        if "sign_in_log" in fam.declared_layers and self._logs: k.append("sign_in_log")
        if "modern_auth_only" in fam.declared_layers and self._legacy_blocked: k.append("modern_auth_only")
        if "legacy_auth_blocked" in fam.declared_layers and self._legacy_blocked: k.append("legacy_auth_blocked")
        if "pim_jit" in fam.declared_layers and self._pim: k.append("pim_jit")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "legacy_authentication":
            return EARState.ABSENT if not self._legacy_blocked else EARState.CRYSTALLIZED
        if op_family.name == "modern_authentication" and self._cap and self._mfa:
            return EARState.ACTIVE
        if not self._cap: return EARState.CRYSTALLIZED
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
