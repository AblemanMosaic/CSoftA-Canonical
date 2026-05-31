"""ear_adapter_circleci.py — CircleCI CI/CD. Wave 16 System 77."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"
class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; cci_scope: str
@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False
@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; oidc_token: bool
    secret_scoped: bool; audit_logged: bool
    context_governed: bool; project_isolated: bool
    project: str|None; workflow: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)
@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CCI_FAMILIES = [
    OperationFamily("pipeline_execution","Execute CircleCI pipeline job",
        ["auth_required","oidc_federation","secret_scoping","audit_log"],"pipeline"),
    OperationFamily("secret_access","Access project environment variables and contexts",
        ["auth_required","context_governance","secret_scoping","audit_log"],"secret"),
    OperationFamily("oidc_federation","Exchange OIDC token for cloud provider credentials",
        ["oidc_federation","auth_required","token_audience"],"oidc"),
    OperationFamily("context_management","Manage CircleCI contexts (shared secret store)",
        ["auth_required","context_governance","audit_log"],"context"),
    OperationFamily("artifact_access","Access build artifacts stored by CircleCI",
        ["auth_required","audit_log","artifact_retention"],"artifact"),
]
CCI_LAYERS = {
    "auth_required": GovernanceLayer("auth_required","CircleCI authentication (GitHub/Bitbucket OAuth or SSO)",None),
    "oidc_federation": GovernanceLayer("oidc_federation","OIDC token for cloud federation (GitHub Actions analog)",None),
    "secret_scoping": GovernanceLayer("secret_scoping","Secrets scoped to project or context; not accessible globally",None),
    "audit_log": GovernanceLayer("audit_log","CircleCI audit log for admin and pipeline events",None,is_optional=True),
    "context_governance": GovernanceLayer("context_governance","Context-level access control — who can use shared context",None),
    "token_audience": GovernanceLayer("token_audience","OIDC token audience restricted to specific cloud role",None),
    "artifact_retention": GovernanceLayer("artifact_retention","Artifact retention policy and access control",None,is_optional=True),
}

class CircleCIEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="CircleCI documentation + CircleCI 2023 breach incident report",
        strategy="DECLARED-N",
        description=(
            "N(O) from CircleCI architecture. pipeline_execution N=4. "
            "CircleCI 2023 breach: malware on engineer laptop stole 2FA-backed SSO session cookie. "
            "Attacker accessed customer environment variables, OAuth tokens, encryption keys "
            "from running process — encrypted at rest did not prevent key exfiltration. "
            "Constitutional finding: CI/CD secret store is a single breach away from "
            "compromising all projects simultaneously. "
            "Same constitutional class as Jenkins credential store scope gap (T1791). "
            "OIDC federation (CircleCI 2022+): short-lived tokens replacing long-lived credentials — "
            "CRYSTALLIZED for cloud access when configured. "
            "Context governance: contexts are shared secret stores across projects — "
            "a single context compromise exposes all projects sharing it. "
            "CRYSTALLIZED ceiling."
        ),
    )
    def __init__(self, oidc_enabled: bool=False, secret_scoped: bool=False,
                 context_governed: bool=False, audit_log_enabled: bool=False):
        self._oidc=oidc_enabled; self._scope=secret_scoped
        self._ctx=context_governed; self._audit=audit_log_enabled
    def collect_operation_families(self): return CCI_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CCI_LAYERS[n] for n in op_family.declared_layers if n in CCI_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(op_family.name,f"synthetic:{op_family.name}","",
            True,self._oidc,self._scope,self._audit,self._ctx,True,None,None,None,None,{})]
    def assess_k(self, inst):
        k=["auth_required"]
        fam=next((f for f in CCI_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "oidc_federation" in fam.declared_layers and self._oidc: k.append("oidc_federation")
        if "secret_scoping" in fam.declared_layers and self._scope: k.append("secret_scoping")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "context_governance" in fam.declared_layers and self._ctx: k.append("context_governance")
        if "token_audience" in fam.declared_layers and self._oidc: k.append("token_audience")
        return k
    def assess_ear_state(self, op_family): return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
