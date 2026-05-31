"""
ear_adapter_aws_lambda.py — AWS Lambda EAR Adapter
Wave 15 — System 73. Serverless function execution governance.

Key finding: AWS Lambda introduces serverless execution as a new governance
model distinct from all previous compute systems in the corpus:
- Container (Docker/K8s): persistent, addressable, governance via RBAC + PSA
- VM (EC2): persistent, long-lived, governance via OS-level controls
- Serverless (Lambda): ephemeral, event-driven, governance via IAM execution role

The primary governance surface for Lambda is the execution role — the IAM role
assumed by the function during execution. This is ACTIVE for resource access:
every AWS API call made by the function is evaluated by IAM (ACTIVE, per T1629).
But Lambda introduces two new gaps:

(1) Layer supply chain gap: Lambda Layers are versioned packages of code/libraries
that functions reference. Layers can be shared across accounts. A function
referencing a layer from another account has ABSENT provenance governance
for that layer (same supply chain gap as npm/PyPI/GitHub Actions).

(2) Internal execution ABSENT: Lambda's internal function execution (what the
code does WITHIN the function invocation) is ABSENT governance. CloudWatch Logs
capture function output (CRYSTALLIZED), but there is no governance receipt for
what happened inside the function before it made any external AWS API calls.

CVE-2025-55182 (React2Shell): in Lambda-hosted Next.js, this SSJI vulnerability
behaves differently — no child_process, read-only filesystem, but SSJI is still
possible via Webpack. AWS credentials in the Lambda environment become the attack
target, not a persistent shell.
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
    name: str; description: str; declared_layers: list[str]; lambda_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    iam_evaluated: bool; cloudwatch_logged: bool
    layer_pinned: bool; xray_traced: bool
    least_privilege_role: bool; vpc_isolated: bool
    function_name: str|None; invocation_id: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

LAMBDA_OPERATION_FAMILIES = [
    OperationFamily("function_invocation",
        "Invoke Lambda function (event trigger or API call)",
        ["iam_invoke_policy","cloudwatch_log","xray_trace","least_privilege_role"], "invoke"),
    OperationFamily("aws_api_call",
        "AWS API call made by Lambda function during execution",
        ["iam_execution_role","cloudwatch_log","cloudtrail_record"], "api"),
    OperationFamily("layer_consumption",
        "Lambda function loads code from Lambda Layer",
        ["layer_governance","iam_invoke_policy","layer_version_pin"], "layer"),
    OperationFamily("environment_variable",
        "Lambda function accesses environment variable secrets",
        ["iam_execution_role","encryption_at_rest","secrets_manager"], "env"),
    OperationFamily("vpc_execution",
        "Lambda function executes within VPC for private resource access",
        ["iam_execution_role","vpc_isolation","cloudwatch_log"], "vpc"),
]

LAMBDA_GOVERNANCE_LAYERS = {
    "iam_invoke_policy": GovernanceLayer("iam_invoke_policy",
        "IAM resource-based policy controlling who can invoke the function", "aws:iam"),
    "cloudwatch_log": GovernanceLayer("cloudwatch_log",
        "CloudWatch Logs capturing function stdout/stderr output", None, is_optional=True),
    "xray_trace": GovernanceLayer("xray_trace",
        "AWS X-Ray distributed tracing for function execution", None, is_optional=True),
    "least_privilege_role": GovernanceLayer("least_privilege_role",
        "Lambda execution role scoped to minimum required AWS permissions", None),
    "iam_execution_role": GovernanceLayer("iam_execution_role",
        "IAM execution role assumed by function — governs AWS API access", "iam:ExecutionRole"),
    "cloudtrail_record": GovernanceLayer("cloudtrail_record",
        "CloudTrail records AWS API calls made by function execution role", "cloudtrail"),
    "layer_governance": GovernanceLayer("layer_governance",
        "Lambda Layer provenance — signed layers, version pinning", None),
    "layer_version_pin": GovernanceLayer("layer_version_pin",
        "Layer referenced by ARN with version number (not :latest)", None),
    "encryption_at_rest": GovernanceLayer("encryption_at_rest",
        "Environment variables encrypted with customer KMS key", None, is_optional=True),
    "secrets_manager": GovernanceLayer("secrets_manager",
        "Secrets fetched from Secrets Manager at runtime (not env vars)", None, is_optional=True),
    "vpc_isolation": GovernanceLayer("vpc_isolation",
        "Function deployed in VPC for private network access", None, is_optional=True),
}

class AWSLambdaEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS Lambda documentation + serverless security analysis 2025 + CVE-2025-55182",
        strategy="DECLARED-N",
        description=(
            "N(O) from AWS Lambda architecture. function_invocation N=4. "
            "aws_api_call: ACTIVE — IAM execution role evaluated for every API call (T1629 carries). "
            "function_invocation: CRYSTALLIZED — IAM resource policy + CloudWatch logs. "
            "Layer supply chain: ABSENT by default — layers from other accounts "
            "have no mandatory provenance verification (same as npm/PyPI import). "
            "Internal function execution: ABSENT — CloudWatch captures output but "
            "not what happened INSIDE the function before external API calls. "
            "Overly permissive execution roles: primary attack target — "
            "Lambda with s3:* or iam:* can compromise entire cloud account. "
            "CVE-2025-55182 (React2Shell, SSJI in Lambda): "
            "no persistent shell possible (read-only FS, no child_process via Webpack), "
            "but SSJI achieves credential extraction (IMDS token, env vars). "
            "Environment variables as secret store: ABSENT governance — "
            "values visible in Lambda console, CloudTrail logs, and function logs. "
            "Secrets Manager integration: CRYSTALLIZED — fetch at runtime, not exposed in config."
        ),
    )
    def __init__(self, least_privilege_role: bool=False, cloudwatch_enabled: bool=True,
                 layer_pinned: bool=False, secrets_manager: bool=False):
        self._least_priv = least_privilege_role
        self._cw = cloudwatch_enabled
        self._layer = layer_pinned
        self._secrets = secrets_manager

    def collect_operation_families(self): return LAMBDA_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [LAMBDA_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in LAMBDA_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            iam_evaluated=True, cloudwatch_logged=self._cw,
            layer_pinned=self._layer, xray_traced=False,
            least_privilege_role=self._least_priv, vpc_isolated=False,
            function_name=None, invocation_id=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k = []
        fam = next((f for f in LAMBDA_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        k.append("iam_execution_role")  # always evaluated
        if "iam_invoke_policy" in fam.declared_layers: k.append("iam_invoke_policy")
        if "cloudwatch_log" in fam.declared_layers and self._cw: k.append("cloudwatch_log")
        if "cloudtrail_record" in fam.declared_layers: k.append("cloudtrail_record")
        if "least_privilege_role" in fam.declared_layers and self._least_priv: k.append("least_privilege_role")
        if "layer_governance" in fam.declared_layers and self._layer: k.append("layer_governance")
        if "layer_version_pin" in fam.declared_layers and self._layer: k.append("layer_version_pin")
        if "secrets_manager" in fam.declared_layers and self._secrets: k.append("secrets_manager")
        return k
    def assess_ear_state(self, op_family):
        # AWS API calls made by function: ACTIVE (IAM always evaluated — T1629)
        if op_family.name == "aws_api_call": return EARState.ACTIVE
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
