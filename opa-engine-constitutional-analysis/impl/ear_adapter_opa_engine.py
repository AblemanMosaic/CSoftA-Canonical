"""
ear_adapter_opa_engine.py — OPA Policy Engine EAR Adapter
Wave 10 — System 46. General-purpose policy-as-code governance.

Key finding: Wave 2 analyzed Gatekeeper (OPA as K8s admission controller).
Wave 10 analyzes OPA as a general-purpose policy engine used in:
API gateways, microservice authorization, Terraform plan evaluation (Conftest),
CI/CD policy gates, and data query authorization.
OPA policy evaluation is ACTIVE: a request that violates policy is denied
before processing — the policy decision is constitutive of the allowed action.
But OPA governance has its own governance gap: the policies themselves (Rego)
must be correct, current, and tested. An incorrect policy (one that allows
what should be denied) is a governance gap invisible at the ACTIVE evaluation
layer. OPA decision log is CRYSTALLIZED — records what was decided but
does not validate that the decision was correct.
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
    name: str; description: str; declared_layers: list[str]; opa_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    policy_evaluated: bool; decision_logged: bool
    policy_tested: bool; policy_versioned: bool
    bundle_signed: bool; audit_enabled: bool
    policy_path: str|None; decision: str|None; error: str|None
    raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

OPA_OPERATION_FAMILIES = [
    OperationFamily("policy_evaluation",
        "Evaluate OPA policy against input document",
        ["rego_policy","decision_log","policy_test","policy_version"], "eval"),
    OperationFamily("api_authorization",
        "Authorize API request via OPA policy evaluation",
        ["rego_policy","decision_log","policy_test","bundle_signing"], "authz"),
    OperationFamily("data_filtering",
        "Filter data query results via OPA partial evaluation",
        ["rego_policy","decision_log","policy_test"], "filter"),
    OperationFamily("terraform_plan_evaluation",
        "Evaluate Terraform plan against OPA policy (Conftest)",
        ["rego_policy","decision_log","policy_version","policy_test"], "tf"),
    OperationFamily("bundle_management",
        "Distribute OPA policy bundle to OPA instances",
        ["bundle_signing","bundle_integrity","policy_version"], "bundle"),
]

OPA_GOVERNANCE_LAYERS = {
    "rego_policy": GovernanceLayer("rego_policy",
        "Rego policy evaluated — constitutive of decision", "data.policy"),
    "decision_log": GovernanceLayer("decision_log",
        "OPA decision log recording input, policy, and decision", "decision_logs"),
    "policy_test": GovernanceLayer("policy_test",
        "Rego unit tests for policy correctness (opa test)", None),
    "policy_version": GovernanceLayer("policy_version",
        "Policy version control — policies in Git with change history", None),
    "bundle_signing": GovernanceLayer("bundle_signing",
        "Bundle signing to verify policy integrity at load time", "bundle.root"),
    "bundle_integrity": GovernanceLayer("bundle_integrity",
        "Bundle checksum/signature verified at load", None),
}

class OPAEngineEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="OPA Documentation + Rego documentation + OPA Security guidance",
        strategy="DECLARED-N",
        description=(
            "N(O) from OPA architecture. policy_evaluation N=4. "
            "policy_evaluation: ACTIVE — policy decision is constitutive; "
            "a request violating policy is denied before processing. "
            "Policy content governance gap: incorrect Rego policies allow "
            "what should be denied — the ACTIVE evaluation of a wrong policy "
            "produces wrong decisions. Policy testing (opa test) is opt-in. "
            "Decision log: CRYSTALLIZED — records decisions, "
            "does not validate correctness. "
            "Bundle signing: moves policy integrity from ABSENT to CRYSTALLIZED — "
            "tampered bundles rejected at load."
        ),
    )
    def __init__(self, decision_log_enabled: bool=False, policy_tested: bool=False,
                 policy_versioned: bool=False, bundle_signed: bool=False):
        self._log = decision_log_enabled
        self._test = policy_tested
        self._version = policy_versioned
        self._sign = bundle_signed

    def collect_operation_families(self): return OPA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [OPA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in OPA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            policy_evaluated=True, decision_logged=self._log,
            policy_tested=self._test, policy_versioned=self._version,
            bundle_signed=self._sign, audit_enabled=self._log,
            policy_path=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in OPA_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rego_policy" in fam.declared_layers: k.append("rego_policy")
        if "decision_log" in fam.declared_layers and self._log: k.append("decision_log")
        if "policy_test" in fam.declared_layers and self._test: k.append("policy_test")
        if "policy_version" in fam.declared_layers and self._version: k.append("policy_version")
        if "bundle_signing" in fam.declared_layers and self._sign: k.append("bundle_signing")
        if "bundle_integrity" in fam.declared_layers and self._sign: k.append("bundle_integrity")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name in ("policy_evaluation","api_authorization","data_filtering","terraform_plan_evaluation"):
            return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
