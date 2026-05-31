"""
ear_adapter_gitlab_ci.py — GitLab CI EAR Adapter
Wave 11 — System 54. Self-hosted CI/CD governance.

Key finding: GitLab CI is the dominant alternative to GitHub Actions for
self-hosted SCM+CI. The governance model differs materially:
(1) Runner trust tiers: GitLab uses shared runners (multi-tenant, shared
    infrastructure), group runners, and project-specific runners. Shared
    runners introduce a multi-tenant execution boundary not present in
    GitHub-hosted runners — a job in one project running on a shared runner
    can potentially access residual state from prior jobs.
(2) CI_JOB_TOKEN scope: GitLab CI jobs receive a CI_JOB_TOKEN that grants
    access to other projects' packages and registries. The scope of this token
    is configurable (allow_failure, project-level restrictions) but defaults
    allow cross-project access — same principal scope boundary issue as
    Argo CD's credential scope (T1674).
(3) OIDC federation (ID tokens): GitLab 15.7+ supports OIDC ID tokens for
    cloud federation (same model as GitHub Actions). When used, job credentials
    are ephemeral — closes long-lived credential gap.
CVE-2024-6678 (CVSS 9.9): trigger pipeline as any user under certain conditions.
CVE-2024-9164: unauthorized pipeline execution on arbitrary branches.
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
    name: str; description: str; declared_layers: list[str]; gl_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; audit_logged: bool
    oidc_token: bool; job_token_scoped: bool
    runner_isolated: bool; protected_branches: bool
    project: str|None; runner_type: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

GITLAB_CI_OPERATION_FAMILIES = [
    OperationFamily("pipeline_execution",
        "Execute CI/CD pipeline job on runner",
        ["rbac_check","audit_log","runner_isolation","protected_branch"], "pipeline"),
    OperationFamily("job_token_access",
        "Access other projects/packages via CI_JOB_TOKEN",
        ["job_token_scope","audit_log","rbac_check"], "token"),
    OperationFamily("cloud_federation",
        "Exchange OIDC ID token for cloud provider credentials",
        ["oidc_token","audit_log","rbac_check","token_scope"], "oidc"),
    OperationFamily("secret_access",
        "Access CI/CD variables and secrets in pipeline",
        ["rbac_check","audit_log","protected_vars","runner_isolation"], "secret"),
    OperationFamily("pipeline_trigger",
        "Trigger pipeline for another user or project",
        ["rbac_check","audit_log","trigger_scope"], "trigger"),
]

GITLAB_CI_GOVERNANCE_LAYERS = {
    "rbac_check": GovernanceLayer("rbac_check",
        "GitLab RBAC evaluated for pipeline operations", None),
    "audit_log": GovernanceLayer("audit_log",
        "GitLab audit log for pipeline and admin events", None, is_optional=True),
    "runner_isolation": GovernanceLayer("runner_isolation",
        "Runner isolation — dedicated runners vs shared multi-tenant runners", None),
    "protected_branch": GovernanceLayer("protected_branch",
        "Protected branch rules restrict who can trigger pipelines", None),
    "job_token_scope": GovernanceLayer("job_token_scope",
        "CI_JOB_TOKEN scope restricted to specific projects", "ci_job_token_scope"),
    "oidc_token": GovernanceLayer("oidc_token",
        "OIDC ID token for cloud federation (ephemeral credentials)", None),
    "token_scope": GovernanceLayer("token_scope",
        "ID token audience restricted to specific cloud role", None),
    "protected_vars": GovernanceLayer("protected_vars",
        "CI/CD variables marked protected — only accessible on protected branches", None),
    "trigger_scope": GovernanceLayer("trigger_scope",
        "Pipeline trigger authorization — prevents impersonation CVE class", None),
}

class GitLabCIEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="GitLab CI documentation + CVE-2024-6678 + CVE-2024-9164 + OIDC federation docs",
        strategy="DECLARED-N",
        description=(
            "N(O) from GitLab CI architecture. pipeline_execution N=4. "
            "cloud_federation with OIDC: CRYSTALLIZED — "
            "ID token is ephemeral (same as GitHub Actions Workload Identity). "
            "job_token_access: NON_ACTIVATION by default — "
            "CI_JOB_TOKEN allows cross-project package/registry access unless scoped. "
            "Shared runner: ABSENT isolation — multi-tenant execution boundary. "
            "CVE-2024-6678 (CVSS 9.9): trigger pipeline as arbitrary user — "
            "same principal impersonation pattern as Argo CD CVE-2025-55190 (T1674). "
            "CVE-2024-9164: unauthorized pipeline execution on arbitrary branches — "
            "protected branch governance NON_ACTIVATION. "
            "CVE-2025-2242: former instance admin retains elevated privileges post-demotion — "
            "RBAC state consistency gap. "
            "Self-hosted deployment: governance depends on runner infrastructure; "
            "no GitHub-equivalent shared runner security baseline guarantee."
        ),
    )
    def __init__(self, rbac_configured: bool=True, audit_log_enabled: bool=False,
                 oidc_enabled: bool=False, job_token_scoped: bool=False,
                 runner_isolated: bool=False, protected_branches: bool=True):
        self._rbac = rbac_configured
        self._audit = audit_log_enabled
        self._oidc = oidc_enabled
        self._jt_scope = job_token_scoped
        self._isolated = runner_isolated
        self._protected = protected_branches

    def collect_operation_families(self): return GITLAB_CI_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [GITLAB_CI_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in GITLAB_CI_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=self._rbac, audit_logged=self._audit,
            oidc_token=self._oidc, job_token_scoped=self._jt_scope,
            runner_isolated=self._isolated, protected_branches=self._protected,
            project=None, runner_type=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in GITLAB_CI_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "runner_isolation" in fam.declared_layers and self._isolated: k.append("runner_isolation")
        if "protected_branch" in fam.declared_layers and self._protected: k.append("protected_branch")
        if "job_token_scope" in fam.declared_layers and self._jt_scope: k.append("job_token_scope")
        if "oidc_token" in fam.declared_layers and self._oidc: k.append("oidc_token")
        if "token_scope" in fam.declared_layers and self._oidc: k.append("token_scope")
        if "protected_vars" in fam.declared_layers and self._protected: k.append("protected_vars")
        if "trigger_scope" in fam.declared_layers and self._rbac: k.append("trigger_scope")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
