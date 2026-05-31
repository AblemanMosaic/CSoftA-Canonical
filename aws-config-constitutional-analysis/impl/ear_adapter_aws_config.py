"""
ear_adapter_aws_config.py — AWS Config EAR Adapter
Wave 10 — System 49. Cloud resource configuration governance.

Key finding: AWS Config is the resource configuration governance case for AWS.
Where CloudTrail records API events, Config records resource configuration states
and detects configuration drift from desired state. Config Rules evaluate
resource configurations against compliance policies — either AWS managed rules
or custom Lambda-based rules. Compliant resources remain in desired configuration;
non-compliant resources trigger findings and optional auto-remediation.
This is the AWS equivalent of Crossplane's drift_reconciliation (T1738) —
but CRYSTALLIZED: Config detects configuration drift after it occurs.
With auto-remediation via Systems Manager Automation or Lambda:
Config approaches ACTIVE for resources with immediate auto-remediation,
but the remediation is triggered after the drift, not before.
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
    name: str; description: str; declared_layers: list[str]; config_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    config_enabled: bool; rule_evaluated: bool
    auto_remediation: bool; configuration_recorder: bool
    multi_account: bool; s3_delivery: bool
    resource_type: str|None; rule_name: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CONFIG_OPERATION_FAMILIES = [
    OperationFamily("configuration_recording",
        "Record resource configuration state and configuration history",
        ["config_recorder","s3_delivery","cloudtrail_integration","encryption"], "record"),
    OperationFamily("rule_evaluation",
        "Evaluate resource configuration against Config Rule",
        ["config_recorder","config_rule","cloudtrail_integration","auto_remediation"], "rule"),
    OperationFamily("drift_detection",
        "Detect resource configuration drift from desired state",
        ["config_recorder","config_rule","cloudtrail_integration"], "drift"),
    OperationFamily("auto_remediation",
        "Automatically remediate non-compliant resources",
        ["config_rule","auto_remediation","cloudtrail_integration"], "remediate"),
    OperationFamily("compliance_aggregation",
        "Aggregate compliance status across accounts/regions via Aggregator",
        ["config_recorder","aggregator","multi_account_delivery"], "aggregate"),
]

CONFIG_GOVERNANCE_LAYERS = {
    "config_recorder": GovernanceLayer("config_recorder",
        "Configuration recorder enabled for all resource types", "RecordingGroup"),
    "s3_delivery": GovernanceLayer("s3_delivery",
        "Configuration snapshots delivered to S3 bucket", "S3BucketName"),
    "cloudtrail_integration": GovernanceLayer("cloudtrail_integration",
        "CloudTrail integration — Config uses CloudTrail for API event timing", None),
    "encryption": GovernanceLayer("encryption",
        "SNS topic and S3 bucket encrypted with KMS CMK", None, is_optional=True),
    "config_rule": GovernanceLayer("config_rule",
        "Config Rule evaluating resource compliance", "Source"),
    "auto_remediation": GovernanceLayer("auto_remediation",
        "Auto-remediation action attached to Config Rule", "RemediationAction", is_optional=True),
    "aggregator": GovernanceLayer("aggregator",
        "Config Aggregator for multi-account compliance view", "AggregatorName", is_optional=True),
    "multi_account_delivery": GovernanceLayer("multi_account_delivery",
        "Config data aggregated across AWS Organization", None, is_optional=True),
}

class AWSConfigEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS Config Documentation + CIS AWS Benchmark + AWS Security Reference Architecture",
        strategy="DECLARED-N",
        description=(
            "N(O) from AWS Config architecture. configuration_recording N=4. "
            "configuration_recording: CRYSTALLIZED — Config records state after changes, "
            "not before. Drift is detected after it occurs. "
            "auto_remediation (with SSM Automation): ACTIVE-adjacent — "
            "non-compliant resources automatically remediated; "
            "but remediation follows detection (CRYSTALLIZED → remediated). "
            "CloudTrail dependency (T1737): Config uses CloudTrail for event timing. "
            "Experian case: 80% reduction in S3 alerts, 2-5 min detection-to-remediation. "
            "Config is the resource-state complement to CloudTrail's event-stream: "
            'together they provide complete AWS governance evidence.'
        ),
    )
    def __init__(self, recorder_enabled: bool=True, auto_remediation: bool=False,
                 encryption: bool=False, aggregator_enabled: bool=False,
                 multi_account: bool=False):
        self._recorder = recorder_enabled
        self._remediation = auto_remediation
        self._enc = encryption
        self._agg = aggregator_enabled
        self._multi = multi_account

    def collect_operation_families(self): return CONFIG_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CONFIG_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in CONFIG_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            config_enabled=self._recorder, rule_evaluated=True,
            auto_remediation=self._remediation, configuration_recorder=self._recorder,
            multi_account=self._multi, s3_delivery=True,
            resource_type=None, rule_name=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in CONFIG_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "config_recorder" in fam.declared_layers and self._recorder: k.append("config_recorder")
        if "s3_delivery" in fam.declared_layers: k.append("s3_delivery")
        if "cloudtrail_integration" in fam.declared_layers: k.append("cloudtrail_integration")
        if "encryption" in fam.declared_layers and self._enc: k.append("encryption")
        if "config_rule" in fam.declared_layers: k.append("config_rule")
        if "auto_remediation" in fam.declared_layers and self._remediation: k.append("auto_remediation")
        if "aggregator" in fam.declared_layers and self._agg: k.append("aggregator")
        if "multi_account_delivery" in fam.declared_layers and self._multi: k.append("multi_account_delivery")
        return k
    def assess_ear_state(self, op_family):
        if not self._recorder: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
