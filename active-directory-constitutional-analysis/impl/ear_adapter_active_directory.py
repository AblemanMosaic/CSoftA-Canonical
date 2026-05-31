"""
ear_adapter_active_directory.py — Active Directory EAR Adapter
Wave 13 — System 64. Enterprise on-premises identity substrate.

Key finding: Active Directory is the identity substrate for the majority of
enterprise organizations globally. It introduces the BYPASS gap form in its
most architectural expression: the Kerberoasting attack exploits inherent
properties of the Kerberos protocol to extract and crack service account
credentials offline — without generating suspicious alerts in the default
Active Directory audit configuration.

Kerberoasting constitutionally: ANY authenticated domain user can request
a service ticket for ANY Service Principal Name (SPN). The Key Distribution
Center (KDC) responds to service ticket requests as a normal protocol
operation — it cannot distinguish malicious from legitimate requests.
The service ticket is encrypted with the service account's password hash.
The attacker takes the encrypted ticket offline and cracks it.

This is a BYPASS gap form: the governance layer (authentication, authorization)
correctly evaluates the request as legitimate (any domain user CAN request
this ticket). The bypass is in the protocol design: the ticket encryption
uses the service account's password as the key, making it crackable offline.

Event 4769 (Kerberos service ticket request) is generated — CRYSTALLIZED
evidence — but in large environments, thousands of 4769 events are generated
daily, making anomaly detection difficult.

Ascension Health ransomware breach (May 2024): Kerberoasting of service
accounts with weak passwords led to domain controller compromise and
widespread ransomware deployment across 140 hospitals.

New constitutional concept: protocol-inherent bypass — a gap that exists
because the protocol itself exposes the governance credential (password hash)
in the normal authentication flow, not because of misconfiguration.
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
    name: str; description: str; declared_layers: list[str]; ad_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    kerberos_logged: bool; gmsas_used: bool
    aes_only: bool; privileged_protected: bool
    dc_auditing: bool; tiered_admin: bool
    principal: str|None; spn: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

AD_OPERATION_FAMILIES = [
    OperationFamily("kerberos_authentication",
        "Kerberos TGT and service ticket issuance",
        ["kerberos_audit","aes_enforcement","service_account_governance","gmsas"], "kerb"),
    OperationFamily("service_ticket_request",
        "Service ticket request for SPN (Kerberoasting attack surface)",
        ["kerberos_audit","aes_enforcement","spn_governance","gmsas"], "tgs"),
    OperationFamily("privileged_access",
        "Privileged account (Domain Admin, Enterprise Admin) usage",
        ["privileged_audit","tiered_admin","paw_governance","dc_auditing"], "priv"),
    OperationFamily("group_policy_application",
        "Group Policy Object applied to domain members",
        ["dc_auditing","gpo_governance","privileged_audit"], "gpo"),
    OperationFamily("replication_governance",
        "DC replication — DCSync attack surface",
        ["dc_auditing","replication_auth","privileged_audit"], "repl"),
]

AD_GOVERNANCE_LAYERS = {
    "kerberos_audit": GovernanceLayer("kerberos_audit",
        "Event 4769 logging for Kerberos service ticket requests", "Event4769"),
    "aes_enforcement": GovernanceLayer("aes_enforcement",
        "AES-only Kerberos — disables RC4 encryption (cracks faster)", None),
    "service_account_governance": GovernanceLayer("service_account_governance",
        "Service accounts have long complex passwords (25+ chars) or gMSAs", None),
    "gmsas": GovernanceLayer("gmsas",
        "Group Managed Service Accounts — 120-char auto-rotating passwords", None, is_optional=True),
    "spn_governance": GovernanceLayer("spn_governance",
        "SPNs assigned only to necessary accounts, cleaned up regularly", None),
    "privileged_audit": GovernanceLayer("privileged_audit",
        "Privileged account audit logging — Event 4728, 4732, 4756", "PrivilegedEvents"),
    "tiered_admin": GovernanceLayer("tiered_admin",
        "Tiered administration model — Tier 0/1/2 isolation for privileged accounts", None, is_optional=True),
    "paw_governance": GovernanceLayer("paw_governance",
        "Privileged Access Workstations for domain admin activities", None, is_optional=True),
    "dc_auditing": GovernanceLayer("dc_auditing",
        "Domain controller advanced audit policy — replication, DSACCESS", None),
    "gpo_governance": GovernanceLayer("gpo_governance",
        "GPO change governance — event logging for GPO modifications", None),
    "replication_auth": GovernanceLayer("replication_auth",
        "DC replication authorization — prevents DCSync from non-DC accounts", None),
}

class ActiveDirectoryEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Active Directory security docs + Ascension Health (2024) + Kerberoasting analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Active Directory architecture. service_ticket_request N=4. "
            "kerberos_authentication: CRYSTALLIZED — Event 4769 logged but "
            "ticket requests are protocol-normal; attacker requests indistinguishable. "
            "service_ticket_request: ABSENT protection by protocol design — "
            "any domain user can request service tickets; encryption uses password hash. "
            "New constitutional concept: protocol-inherent bypass — "
            "the Kerberos protocol itself exposes the service account password hash "
            "in normal authentication flow; this is not misconfiguration. "
            "Kerberoasting bypass: governance correctly evaluates request as legitimate "
            "(any domain user CAN request ticket); password hash crackable offline. "
            "Ascension Health (May 2024): Kerberoasting → RC4 service ticket cracking → "
            "domain controller compromise → ransomware across 140 hospitals. "
            "gMSAs (Group Managed Service Accounts): 120-char auto-rotating passwords "
            "make Kerberoasting computationally infeasible — best mitigation. "
            "DCSync attack: any account with DS-Replication-Get-Changes-All permission "
            "can replicate all password hashes from DC — BYPASS at replication governance. "
            "Pass-the-Hash: NTLM authentication uses credential hash directly; "
            "lateral movement without password — BYPASS at authentication layer."
        ),
    )
    def __init__(self, aes_enforced: bool=False, gmsas_deployed: bool=False,
                 tiered_admin: bool=False, dc_auditing_enabled: bool=False):
        self._aes = aes_enforced
        self._gmsas = gmsas_deployed
        self._tiered = tiered_admin
        self._dc_audit = dc_auditing_enabled

    def collect_operation_families(self): return AD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [AD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in AD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            kerberos_logged=True, gmsas_used=self._gmsas,
            aes_only=self._aes, privileged_protected=self._tiered,
            dc_auditing=self._dc_audit, tiered_admin=self._tiered,
            principal=None, spn=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = ["kerberos_audit"]  # Event 4769 is default in most deployments
        fam = next((f for f in AD_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "aes_enforcement" in fam.declared_layers and self._aes: k.append("aes_enforcement")
        if "service_account_governance" in fam.declared_layers and self._gmsas: k.append("service_account_governance")
        if "gmsas" in fam.declared_layers and self._gmsas: k.append("gmsas")
        if "spn_governance" in fam.declared_layers: k.append("spn_governance")  # basic hygiene assumed
        if "privileged_audit" in fam.declared_layers: k.append("privileged_audit")
        if "tiered_admin" in fam.declared_layers and self._tiered: k.append("tiered_admin")
        if "dc_auditing" in fam.declared_layers and self._dc_audit: k.append("dc_auditing")
        return k
    def assess_ear_state(self, op_family):
        # Kerberoasting is a protocol-level bypass — no configuration makes it ACTIVE
        if op_family.name == "service_ticket_request":
            return EARState.CRYSTALLIZED  # only Event 4769; not constitutive
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
