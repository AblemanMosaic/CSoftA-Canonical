"""ear_adapter_puppet.py — Puppet Configuration Management. Wave 16 System 79."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"
class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; puppet_scope: str
@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False
@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_evaluated: bool; tls_enforced: bool
    catalog_signed: bool; audit_logged: bool
    rbac_configured: bool; convergence_logged: bool
    node: str|None; catalog_version: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)
@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

PUPPET_FAMILIES = [
    OperationFamily("catalog_compilation","Compile Puppet catalog for node from Puppet Server",
        ["tls_auth","catalog_signing","rbac_check","audit_log"],"catalog"),
    OperationFamily("catalog_application","Apply Puppet catalog to node (convergence run)",
        ["tls_auth","convergence_log","catalog_signing"],"apply"),
    OperationFamily("hiera_lookup","Puppet Hiera data lookup (includes secrets)",
        ["tls_auth","rbac_check","audit_log"],"hiera"),
    OperationFamily("node_classification","Classify node — assign classes and parameters",
        ["tls_auth","rbac_check","audit_log"],"classify"),
    OperationFamily("code_deployment","Deploy Puppet code from control repo to Puppet Server",
        ["tls_auth","rbac_check","code_signing","audit_log"],"code"),
]
PUPPET_LAYERS = {
    "tls_auth": GovernanceLayer("tls_auth","Puppet TLS client certificate authentication",None),
    "catalog_signing": GovernanceLayer("catalog_signing","Catalog signing to prevent MITM catalog injection",None,is_optional=True),
    "rbac_check": GovernanceLayer("rbac_check","Puppet Enterprise RBAC (community: no RBAC)",None,is_optional=True),
    "audit_log": GovernanceLayer("audit_log","Puppet Enterprise activity service audit log",None,is_optional=True),
    "convergence_log": GovernanceLayer("convergence_log","Puppet run report — convergence receipt for each node",None),
    "code_signing": GovernanceLayer("code_signing","Code signing for Puppet modules",None,is_optional=True),
}

class PuppetEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Puppet documentation + configuration management governance analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Puppet architecture. catalog_compilation N=4. "
            "Puppet extends T1797 (Ansible stateless IaC) with a critical difference: "
            "Puppet has a catalog — the compiled desired state for a node. "
            "Catalog application produces a convergence report (CRYSTALLIZED receipt). "
            "This is CRYSTALLIZED, not ABSENT: unlike Ansible CLI (ABSENT), "
            "Puppet always produces a run report per node per convergence. "
            "RBAC: Puppet Enterprise only — community edition has no RBAC (paywall T1784). "
            "Audit log: Puppet Enterprise activity service only. "
            "Catalog injection attack: MITM Puppet Server can inject malicious catalog — "
            "catalog signing prevents this but is opt-in. "
            "Constitutional comparison: Ansible (ABSENT) < Puppet (CRYSTALLIZED convergence receipt) "
            "< Terraform (state with drift gap) < Crossplane (ACTIVE continuous reconciliation). "
            "Puppet is the pre-cloud era configuration management standard."
        ),
    )
    def __init__(self, tls_configured: bool=True, rbac_enabled: bool=False,
                 catalog_signed: bool=False, audit_log_enabled: bool=False):
        self._tls=tls_configured; self._rbac=rbac_enabled
        self._signed=catalog_signed; self._audit=audit_log_enabled
    def collect_operation_families(self): return PUPPET_FAMILIES
    def collect_governance_layers(self, op_family):
        return [PUPPET_LAYERS[n] for n in op_family.declared_layers if n in PUPPET_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(op_family.name,f"synthetic:{op_family.name}","",
            self._tls,self._tls,self._signed,self._audit,self._rbac,True,None,None,None,None,{})]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in PUPPET_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "tls_auth" in fam.declared_layers and self._tls: k.append("tls_auth")
        if "catalog_signing" in fam.declared_layers and self._signed: k.append("catalog_signing")
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "convergence_log" in fam.declared_layers: k.append("convergence_log")  # always present
        if "code_signing" in fam.declared_layers and self._signed: k.append("code_signing")
        return k
    def assess_ear_state(self, op_family):
        if not self._tls: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
