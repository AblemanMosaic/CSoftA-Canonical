"""
ear_adapter_openfga.py — OpenFGA / Zanzibar EAR Adapter
Wave 12 — System 60. Relationship-based access control governance.

Key finding: OpenFGA implements the Google Zanzibar relationship-based
access control (ReBAC) model — the authorization paradigm used by Google,
GitHub, and Airbnb for fine-grained permission evaluation over relationship
graphs. This is architecturally distinct from all authorization systems in
the existing corpus:
- K8s RBAC (T1742): role-based, flat permission assignments
- OPA (T1762): policy-based, declarative rules over input documents
- OpenFGA: relationship-based, permission derived from relationship tuples
  (user:alice is member of group:eng; group:eng has viewer on document:x)

The governance receipt for an OpenFGA authorization check is the check
response (allowed/denied) — CRYSTALLIZED when audit log is configured.
The tuple store (the relationship data) is itself the primary governance
surface: the governance of the authorization model depends on the
governance of the tuples that define relationships.

New constitutional concept: relationship tuple store as governance surface —
the data structure that defines permissions is separate from the policy,
and its governance (who can write tuples, what tuples exist) is the
primary governance gap.
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
    name: str; description: str; declared_layers: list[str]; fga_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; audit_logged: bool
    tuple_write_governed: bool; model_versioned: bool
    check_logged: bool; store_encrypted: bool
    user: str|None; object_ref: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

FGA_OPERATION_FAMILIES = [
    OperationFamily("authorization_check",
        "Check if user has permission on object via relationship evaluation",
        ["auth_required","audit_log","model_version","check_receipt"], "check"),
    OperationFamily("tuple_write",
        "Write relationship tuple to OpenFGA store",
        ["auth_required","audit_log","tuple_governance","model_validation"], "write"),
    OperationFamily("tuple_read",
        "Read relationship tuples from OpenFGA store",
        ["auth_required","audit_log","tuple_governance"], "read"),
    OperationFamily("model_management",
        "Create/update authorization model (type definitions)",
        ["auth_required","audit_log","model_version"], "model"),
    OperationFamily("store_governance",
        "Govern OpenFGA store — multi-tenancy, access control",
        ["auth_required","audit_log","store_rbac"], "store"),
]

FGA_GOVERNANCE_LAYERS = {
    "auth_required": GovernanceLayer("auth_required",
        "Authentication required for OpenFGA API", None),
    "audit_log": GovernanceLayer("audit_log",
        "OpenFGA audit log for check requests and tuple writes", None, is_optional=True),
    "model_version": GovernanceLayer("model_version",
        "Authorization model version control — models are immutable once written", "authorization_model_id"),
    "check_receipt": GovernanceLayer("check_receipt",
        "Check API response as governance receipt — allowed/denied decision", None),
    "tuple_governance": GovernanceLayer("tuple_governance",
        "Governance of who can write tuples — the primary governance surface", None),
    "model_validation": GovernanceLayer("model_validation",
        "Tuple written validated against current authorization model", None),
    "store_rbac": GovernanceLayer("store_rbac",
        "Store-level RBAC for multi-tenant access control", None),
}

class OpenFGAEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="OpenFGA documentation + Google Zanzibar paper + OpenFGA security guide",
        strategy="DECLARED-N",
        description=(
            "N(O) from OpenFGA architecture. authorization_check N=4. "
            "authorization_check: CRYSTALLIZED — check API evaluated, "
            "response is decision receipt; audit log opt-in. "
            "New constitutional concept: relationship tuple store as governance surface — "
            "permissions derived from relationship tuples, not roles or policies. "
            "Tuple write governance: the primary gap — who can write tuples "
            "that grant permissions? If tuple write is ABSENT governance, "
            "the entire authorization model is undermined. "
            "Model versioning: ACTIVE in a narrow sense — authorization models "
            "are immutable once created; authorization_model_id is the receipt. "
            "Distinct from RBAC (T1742) and OPA (T1762): "
            "OpenFGA evaluates relationship graphs, not role assignments or policies. "
            "Zanzibar-model: Google's implementation powers Drive, YouTube, Maps — "
            "relationship-based access is the authorization paradigm for social graph "
            "and content ownership use cases that RBAC cannot express."
        ),
    )
    def __init__(self, auth_enabled: bool=True, audit_log_enabled: bool=False,
                 tuple_write_governed: bool=False, model_versioned: bool=True):
        self._auth = auth_enabled
        self._audit = audit_log_enabled
        self._tuple = tuple_write_governed
        self._model = model_versioned

    def collect_operation_families(self): return FGA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [FGA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in FGA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_evaluated=self._auth, audit_logged=self._audit,
            tuple_write_governed=self._tuple, model_versioned=self._model,
            check_logged=self._audit, store_encrypted=False,
            user=None, object_ref=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in FGA_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_required" in fam.declared_layers and self._auth: k.append("auth_required")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "model_version" in fam.declared_layers and self._model: k.append("model_version")
        if "check_receipt" in fam.declared_layers: k.append("check_receipt")
        if "tuple_governance" in fam.declared_layers and self._tuple: k.append("tuple_governance")
        if "model_validation" in fam.declared_layers: k.append("model_validation")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
