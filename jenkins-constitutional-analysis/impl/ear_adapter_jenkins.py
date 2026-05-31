"""
ear_adapter_jenkins.py — Jenkins EAR Adapter
Wave 12 — System 57. Enterprise self-hosted CI/CD governance.

Key finding: Jenkins introduces long-lived self-hosted CI/CD infrastructure
with accumulated configuration drift as a constitutional concept not present
in GitHub Actions (ephemeral cloud) or Tekton (K8s-native declarative).
Jenkins instances accumulate over years: jobs stagnate, credentials become
stale, plugins diverge from security patches, and the overall governance
posture degrades continuously. The Jenkins credential store holds long-lived
secrets (cloud provider keys, deploy tokens, DB passwords) encrypted but
accessible to any user with Job/Execute permission — no Workload Identity.

Jenkins audit log: CRYSTALLIZED at best via the Jenkins Audit Trail plugin
(opt-in). The default Jenkins installation has ABSENT structured audit.
Credential governance: ABSENT by default — credentials stored in Jenkins
are accessible to pipeline jobs without per-job scoping, same structural
gap as Argo Workflows SA scope (T1724) applied to credential access.
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
    name: str; description: str; declared_layers: list[str]; jenkins_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    rbac_evaluated: bool; audit_logged: bool
    credential_scoped: bool; plugin_current: bool
    matrix_auth: bool; jcasc_configured: bool
    job_name: str|None; executor: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

JENKINS_OPERATION_FAMILIES = [
    OperationFamily("build_execution",
        "Execute Jenkins build/pipeline job",
        ["rbac_check","audit_log","credential_scope","plugin_security"], "build"),
    OperationFamily("credential_access",
        "Access Jenkins credential store from pipeline job",
        ["rbac_check","audit_log","credential_scope"], "cred"),
    OperationFamily("job_configuration",
        "Create/modify Jenkins job or pipeline definition",
        ["rbac_check","audit_log","jcasc_governance"], "config"),
    OperationFamily("plugin_management",
        "Install/update Jenkins plugins",
        ["rbac_check","audit_log","plugin_security"], "plugin"),
    OperationFamily("admin_configuration",
        "Modify Jenkins system configuration",
        ["rbac_check","audit_log","jcasc_governance"], "admin"),
]

JENKINS_GOVERNANCE_LAYERS = {
    "rbac_check": GovernanceLayer("rbac_check",
        "Jenkins Matrix Authorization or Role Strategy plugin RBAC", None),
    "audit_log": GovernanceLayer("audit_log",
        "Jenkins Audit Trail plugin — structured audit log (opt-in)", None, is_optional=True),
    "credential_scope": GovernanceLayer("credential_scope",
        "Credentials scoped to specific jobs/folders (not global)", None),
    "plugin_security": GovernanceLayer("plugin_security",
        "Plugins current, from Update Center, signed", None),
    "jcasc_governance": GovernanceLayer("jcasc_governance",
        "Jenkins Configuration as Code (JCasC) — declarative, version-controlled config", None, is_optional=True),
}

class JenkinsEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Jenkins Security docs + Jenkins Security Advisory history + Codecov breach analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Jenkins architecture. build_execution N=4. "
            "CRYSTALLIZED ceiling: Matrix Authorization provides RBAC; "
            "Audit Trail plugin provides opt-in structured log. "
            "Credential governance gap: global credentials accessible to all jobs "
            "with Execute permission — same SA scope gap as Argo Workflows (T1724). "
            "Long-lived configuration drift: Jenkins instances accumulate over years; "
            "stale jobs, outdated plugins, stale credentials. "
            "New constitutional concept: configuration drift as governance gap — "
            "governance posture degrades continuously in long-lived installations. "
            "Codecov breach (2021): Jenkins pipeline accessed Codecov with compromised "
            "bash script — supply chain attack via CI/CD pipeline. "
            "Jenkins plugin vulnerabilities: historically significant CVE surface; "
            "plugin signing only from Update Center prevents supply chain attacks."
        ),
    )
    def __init__(self, matrix_auth: bool=False, audit_trail: bool=False,
                 credential_scoped: bool=False, plugins_current: bool=False):
        self._rbac = matrix_auth
        self._audit = audit_trail
        self._cred = credential_scoped
        self._plugins = plugins_current

    def collect_operation_families(self): return JENKINS_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [JENKINS_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in JENKINS_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            rbac_evaluated=self._rbac, audit_logged=self._audit,
            credential_scoped=self._cred, plugin_current=self._plugins,
            matrix_auth=self._rbac, jcasc_configured=False,
            job_name=None, executor=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in JENKINS_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "rbac_check" in fam.declared_layers and self._rbac: k.append("rbac_check")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "credential_scope" in fam.declared_layers and self._cred: k.append("credential_scope")
        if "plugin_security" in fam.declared_layers and self._plugins: k.append("plugin_security")
        return k
    def assess_ear_state(self, op_family):
        if not self._rbac: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
