"""ear_adapter_aws_codepipeline.py — AWS CodePipeline. Wave 16 System 80."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"
class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; cp_scope: str
@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False
@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    iam_evaluated: bool; cloudtrail_logged: bool
    approval_required: bool; artifact_encrypted: bool
    oidc_federation: bool; cross_account: bool
    pipeline: str|None; execution_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)
@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CP_FAMILIES = [
    OperationFamily("pipeline_execution","Execute CodePipeline pipeline stages",
        ["iam_policy","cloudtrail_log","approval_gate","artifact_encryption"],"exec"),
    OperationFamily("approval_gate","Manual approval action in pipeline",
        ["iam_policy","cloudtrail_log","approval_gate"],"approval"),
    OperationFamily("artifact_management","Manage pipeline artifacts in S3",
        ["iam_policy","cloudtrail_log","artifact_encryption","s3_governance"],"artifact"),
    OperationFamily("cross_account_deploy","Deploy to different AWS account via assumed role",
        ["iam_policy","cloudtrail_log","cross_account_role"],"cross"),
    OperationFamily("connection_governance","Manage CodeStar Connections (GitHub/Bitbucket OAuth)",
        ["iam_policy","cloudtrail_log","connection_scope"],"conn"),
]
CP_LAYERS = {
    "iam_policy": GovernanceLayer("iam_policy","IAM policies governing CodePipeline service role and actions","aws:iam"),
    "cloudtrail_log": GovernanceLayer("cloudtrail_log","CloudTrail records all CodePipeline API calls",None),
    "approval_gate": GovernanceLayer("approval_gate","Manual approval action — constitutive gate before deploy",None,is_optional=True),
    "artifact_encryption": GovernanceLayer("artifact_encryption","Pipeline artifacts encrypted with KMS CMK",None,is_optional=True),
    "s3_governance": GovernanceLayer("s3_governance","S3 artifact bucket access control",None),
    "cross_account_role": GovernanceLayer("cross_account_role","Cross-account deployment via IAM role assumption",None,is_optional=True),
    "connection_scope": GovernanceLayer("connection_scope","CodeStar Connection OAuth scope restrictions",None),
}

class AWSCodePipelineEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS CodePipeline documentation + CloudTrail T1737 + IAM T1629",
        strategy="DECLARED-N",
        description=(
            "N(O) from CodePipeline architecture. pipeline_execution N=4. "
            "CodePipeline completes the CI/CD comparison: "
            "GitHub Actions (cloud/Wave 6) + GitLab CI (self-hosted/Wave 11) + "
            "Jenkins (enterprise/Wave 12) + CircleCI (SaaS/Wave 16) + CodePipeline (AWS-native). "
            "CloudTrail: ACTIVE for all CodePipeline API calls (T1737 carries). "
            "Approval gate: ACTIVE when configured — deployment cannot proceed without human approval. "
            "IAM service role: ACTIVE for AWS API calls made by pipeline actions (T1629 carries). "
            "AWS CodeStar Connections: CRYSTALLIZED for OAuth scope to GitHub/Bitbucket. "
            "Artifact encryption: CRYSTALLIZED with KMS CMK (ABSENT with default S3 SSE-S3). "
            "Constitutional note: CodePipeline is the most governed CI/CD in the corpus — "
            "benefits from the full AWS security backstop that CircleCI and GitHub Actions lack."
        ),
    )
    def __init__(self, approval_gate: bool=False, artifact_encrypted: bool=False,
                 cross_account: bool=False):
        self._approval=approval_gate; self._encrypted=artifact_encrypted
        self._cross=cross_account
    def collect_operation_families(self): return CP_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CP_LAYERS[n] for n in op_family.declared_layers if n in CP_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(op_family.name,f"synthetic:{op_family.name}","",
            True,True,self._approval,self._encrypted,False,self._cross,None,None,None,None,{})]
    def assess_k(self, inst):
        k=["iam_policy","cloudtrail_log"]
        fam=next((f for f in CP_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "approval_gate" in fam.declared_layers and self._approval: k.append("approval_gate")
        if "artifact_encryption" in fam.declared_layers and self._encrypted: k.append("artifact_encryption")
        if "s3_governance" in fam.declared_layers: k.append("s3_governance")
        if "cross_account_role" in fam.declared_layers and self._cross: k.append("cross_account_role")
        if "connection_scope" in fam.declared_layers: k.append("connection_scope")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "approval_gate" and self._approval: return EARState.ACTIVE
        return EARState.CRYSTALLIZED  # CloudTrail + IAM always present
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
