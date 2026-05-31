"""
ear_adapter_gcp_iam.py — GCP IAM / Cloud Audit Logs EAR Adapter
Wave 13 — System 61. Google Cloud Platform identity and access governance.

Key finding: GCP IAM completes the cloud provider triple (AWS IAM in Wave 4,
Azure Entra ID in Wave 11). GCP IAM introduces organization-level Policy
Constraints that interact with project-level IAM in a way that expresses
the T1613 upstream inheritance (min()) rule differently from AWS:
- AWS: IAM policies evaluated per-account; SCPs govern at organization level
- GCP: Organization Policies govern at org/folder/project hierarchy;
  project-level IAM evaluated within that constraint boundary

Cloud Audit Logs (Data Access audit logs) are ABSENT by default:
Admin Activity logs are always on; Data Access audit logs (who read what data)
must be explicitly enabled per service and are off by default.
This is the GCP equivalent of the CloudTrail data events gap (T1727).

ImageRunner vulnerability (January 2025, Tenable): Cloud Run identities with
run.services.update could deploy containers pulling from private Artifact
Registry without explicit read permission — NON_ACTIVATION at the
permission-scope boundary. Same constitutional form as Argo CD CVE-2025-55190.

Tag-based privilege escalation (March 2026, Mitiga): tagUser + viewer roles
can satisfy conditional IAM bindings via tag attachment, escalating to full
admin — NON_ACTIVATION at the conditional binding scope boundary.
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
    name: str; description: str; declared_layers: list[str]; gcp_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    iam_evaluated: bool; admin_activity_logged: bool
    data_access_logged: bool; org_policy_applied: bool
    workload_identity: bool; least_privilege: bool
    principal: str|None; resource: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

GCP_OPERATION_FAMILIES = [
    OperationFamily("api_authorization",
        "GCP service API call authorization via IAM",
        ["iam_policy","admin_activity_log","data_access_log","org_policy"], "api"),
    OperationFamily("data_access",
        "Access to GCP data resources (GCS, BigQuery, Spanner)",
        ["iam_policy","data_access_log","org_policy","workload_identity"], "data"),
    OperationFamily("service_account_usage",
        "Service account key or workload identity usage",
        ["iam_policy","admin_activity_log","workload_identity","key_rotation"], "sa"),
    OperationFamily("organization_policy",
        "Organization-level policy constraint application",
        ["org_policy","admin_activity_log","iam_policy"], "orgpol"),
    OperationFamily("privilege_escalation_check",
        "Governance of privilege escalation paths (ImageRunner, ConfusedFunction, tag-based)",
        ["iam_policy","org_policy","admin_activity_log","least_privilege"], "privesc"),
]

GCP_GOVERNANCE_LAYERS = {
    "iam_policy": GovernanceLayer("iam_policy",
        "GCP IAM policy evaluation for all API requests", "protoPayload.authorizationInfo"),
    "admin_activity_log": GovernanceLayer("admin_activity_log",
        "Admin Activity audit logs — always enabled, cannot be disabled", "protoPayload.methodName"),
    "data_access_log": GovernanceLayer("data_access_log",
        "Data Access audit logs — ABSENT by default, must be enabled per service", None, is_optional=True),
    "org_policy": GovernanceLayer("org_policy",
        "Organization Policy constraints applied at org/folder/project hierarchy", None, is_optional=True),
    "workload_identity": GovernanceLayer("workload_identity",
        "Workload Identity Federation — short-lived tokens instead of SA keys", None, is_optional=True),
    "key_rotation": GovernanceLayer("key_rotation",
        "Service account key rotation policy — limits long-lived credential exposure", None, is_optional=True),
    "least_privilege": GovernanceLayer("least_privilege",
        "Least privilege enforcement — no wildcard roles, no editor/owner at project", None, is_optional=True),
}

class GCPIAMEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="GCP IAM docs + Cloud Audit Logs + ImageRunner (Tenable 2025) + Mitiga tag escalation (2026)",
        strategy="DECLARED-N",
        description=(
            "N(O) from GCP IAM architecture. api_authorization N=4. "
            "admin_activity_log: ACTIVE — always on, cannot be disabled. "
            "data_access_log: ABSENT by default — must be explicitly enabled per service. "
            "Same CloudTrail data events gap (T1727) at GCP: "
            "data reads are ungoverned unless Data Access logs explicitly configured. "
            "ImageRunner (January 2025): run.services.update could pull private "
            "Artifact Registry images without registry read permission — "
            "NON_ACTIVATION at permission scope boundary. Same form as Argo CD T1674. "
            "Tag-based escalation (March 2026): tagUser + viewer satisfy conditional IAM bindings — "
            "NON_ACTIVATION at conditional binding scope boundary. "
            "ConfusedFunction (2024): Cloud Build default SA grants escalation path. "
            "Organization Policy constraints: CRYSTALLIZED — declared, not always enforced. "
            "Workload Identity Federation closes service account key gap (same as AWS IRSA T1759)."
        ),
    )
    def __init__(self, data_access_logs: bool=False, org_policy_applied: bool=False,
                 workload_identity: bool=False, least_privilege: bool=False):
        self._data_access = data_access_logs
        self._org_policy = org_policy_applied
        self._wif = workload_identity
        self._least_priv = least_privilege

    def collect_operation_families(self): return GCP_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [GCP_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in GCP_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            iam_evaluated=True, admin_activity_logged=True,
            data_access_logged=self._data_access,
            org_policy_applied=self._org_policy,
            workload_identity=self._wif, least_privilege=self._least_priv,
            principal=None, resource=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = ["iam_policy", "admin_activity_log"]  # always active
        fam = next((f for f in GCP_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "data_access_log" in fam.declared_layers and self._data_access: k.append("data_access_log")
        if "org_policy" in fam.declared_layers and self._org_policy: k.append("org_policy")
        if "workload_identity" in fam.declared_layers and self._wif: k.append("workload_identity")
        if "least_privilege" in fam.declared_layers and self._least_priv: k.append("least_privilege")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "api_authorization": return EARState.CRYSTALLIZED  # admin log always on
        if op_family.name == "data_access" and not self._data_access: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
