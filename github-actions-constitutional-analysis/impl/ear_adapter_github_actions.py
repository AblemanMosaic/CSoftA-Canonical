"""
ear_adapter_github_actions.py — GitHub Actions EAR Adapter
Wave 6 — System 26. CI/CD pipeline governance.

Key finding: GitHub Actions is the corpus's canonical CI/CD governance case.
Workflow execution produces a run log (CRYSTALLIZED) but the governance of
which actions run, what secrets they access, and whether third-party actions
are integrity-verified is ABSENT by default. Workflow OIDC token federation
is the closest to ACTIVE: the OIDC token is constitutive of cloud access —
the cloud provider cannot be accessed without it. Supply chain (third-party
actions from marketplace) is the critical ABSENT gap: actions are referenced
by tag by default, tags can be retroactively modified (CVE-2025-30066 —
tj-actions/changed-files compromise, 23,000+ repositories affected).
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
    name: str; description: str; declared_layers: list[str]; gha_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    run_log_written: bool; oidc_token_used: bool
    action_hash_pinned: bool; secret_scoped: bool
    workflow_permissions_declared: bool; audit_logged: bool
    repo: str|None; workflow: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

GHA_OPERATION_FAMILIES = [
    OperationFamily("workflow_execution",
        "Execute GitHub Actions workflow run",
        ["run_log","workflow_permissions","action_provenance","audit_log"], "run"),
    OperationFamily("secret_access",
        "Access repository or organization secret in workflow",
        ["secret_scope","workflow_permissions","run_log","oidc_token"], "secret"),
    OperationFamily("cloud_federation",
        "Federate to cloud provider via OIDC token",
        ["oidc_token","workflow_permissions","run_log"], "oidc"),
    OperationFamily("action_consumption",
        "Reference and execute third-party GitHub Action",
        ["action_provenance","action_hash","run_log","workflow_permissions"], "action"),
    OperationFamily("artifact_publication",
        "Publish package or release artifact from workflow",
        ["run_log","action_provenance","workflow_permissions","artifact_provenance"], "artifact"),
]

GHA_GOVERNANCE_LAYERS = {
    "run_log": GovernanceLayer("run_log",
        "Workflow run log — records execution output", "run_id"),
    "workflow_permissions": GovernanceLayer("workflow_permissions",
        "Permissions block limiting GITHUB_TOKEN scope", "permissions"),
    "action_provenance": GovernanceLayer("action_provenance",
        "Action reference — hash-pinned vs tag-pinned", "uses"),
    "action_hash": GovernanceLayer("action_hash",
        "SHA hash pin of third-party action — immutable reference", "uses@sha256"),
    "audit_log": GovernanceLayer("audit_log",
        "GitHub organization audit log for Actions events", None, is_optional=True),
    "secret_scope": GovernanceLayer("secret_scope",
        "Secret scope (repo/environment/org) and access declaration", None),
    "oidc_token": GovernanceLayer("oidc_token",
        "OIDC token — constitutive of cloud federation", "id-token: write"),
    "artifact_provenance": GovernanceLayer("artifact_provenance",
        "SLSA provenance attestation for published artifact", None, is_optional=True),
}

class GitHubActionsEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="GitHub Actions Documentation + GitHub Security Hardening Guide + SLSA for GitHub Actions",
        strategy="DECLARED-N",
        description=(
            "N(O) from GitHub Actions architecture. workflow_execution N=4. "
            "cloud_federation: ACTIVE — OIDC token constitutive of cloud provider access. "
            "Third-party action supply chain: ABSENT by default — "
            "tag references are mutable (CVE-2025-30066 confirmed: "
            "tj-actions/changed-files tags retroactively modified, 23,000+ repos affected). "
            "Hash pinning moves action_provenance from ABSENT to CRYSTALLIZED. "
            "workflow_permissions not declared by default — GITHUB_TOKEN has broad scope. "
            "Workflow run log: CRYSTALLIZED — records output but not governance decisions."
        ),
    )
    def __init__(self, hash_pinned: bool=False, workflow_permissions_declared: bool=False,
                 oidc_enabled: bool=False, audit_log_enabled: bool=False,
                 artifact_provenance: bool=False):
        self._hash = hash_pinned
        self._perms = workflow_permissions_declared
        self._oidc = oidc_enabled
        self._audit = audit_log_enabled
        self._provenance = artifact_provenance

    def collect_operation_families(self): return GHA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [GHA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in GHA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            run_log_written=True, oidc_token_used=self._oidc,
            action_hash_pinned=self._hash, secret_scoped=True,
            workflow_permissions_declared=self._perms,
            audit_logged=self._audit, repo=None, workflow=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in GHA_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "run_log" in fam.declared_layers: k.append("run_log")
        if "workflow_permissions" in fam.declared_layers and self._perms: k.append("workflow_permissions")
        if "action_provenance" in fam.declared_layers and self._hash: k.append("action_provenance")
        if "action_hash" in fam.declared_layers and self._hash: k.append("action_hash")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "secret_scope" in fam.declared_layers: k.append("secret_scope")
        if "oidc_token" in fam.declared_layers and self._oidc: k.append("oidc_token")
        if "artifact_provenance" in fam.declared_layers and self._provenance: k.append("artifact_provenance")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "cloud_federation" and self._oidc: return EARState.ACTIVE
        if op_family.name == "action_consumption" and not self._hash: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
