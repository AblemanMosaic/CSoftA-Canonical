"""
ear_adapter_cloudtrail.py — AWS CloudTrail EAR Adapter
Wave 8 — System 36. Audit log governance.

Key finding: AWS CloudTrail is the governance-of-governance case for AWS —
every governance receipt in the AWS corpus (IAM, S3, SSO) depends on
CloudTrail being enabled and configured. CloudTrail itself has governance gaps:
management events are enabled by default in the free tier, but data events
(S3 object access, Lambda invocations) are opt-in. Log file integrity
validation is opt-in. Multi-region trails cover all regions but are not the
default. CloudTrail logging can be disabled by any principal with
cloudtrail:StopLogging permission — disabling CloudTrail is the canonical
AWS defense evasion technique documented by MITRE ATT&CK (T1562.008).
Log file validation is the closest to ACTIVE: when enabled, a hash chain
makes log tampering detectable. But the hash chain is generated after the
fact — an attacker who disables CloudTrail creates a logging gap, not a
detectable tamper event.
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
    name: str; description: str; declared_layers: list[str]; ct_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    trail_enabled: bool; multi_region: bool
    log_validation: bool; data_events: bool
    cloudwatch_integrated: bool; sns_notification: bool
    trail_name: str|None; region: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

CT_OPERATION_FAMILIES = [
    OperationFamily("management_event_logging",
        "Record management API calls (create/modify/delete resources)",
        ["trail_enabled","multi_region_trail","log_validation","cloudwatch_alarm"], "mgmt"),
    OperationFamily("data_event_logging",
        "Record data events (S3 GetObject, Lambda Invoke, etc.)",
        ["trail_enabled","data_events_enabled","log_validation"], "data"),
    OperationFamily("log_integrity",
        "Validate CloudTrail log file integrity via hash chain",
        ["log_validation","log_storage","trail_enabled"], "integrity"),
    OperationFamily("trail_governance",
        "Govern the CloudTrail trail configuration itself",
        ["trail_enabled","multi_region_trail","log_validation","stop_logging_alert"], "trail"),
    OperationFamily("insight_detection",
        "Detect unusual API activity via CloudTrail Insights",
        ["trail_enabled","insights_enabled","cloudwatch_alarm"], "insight"),
]

CT_GOVERNANCE_LAYERS = {
    "trail_enabled": GovernanceLayer("trail_enabled",
        "CloudTrail trail enabled and recording", "IsLogging"),
    "multi_region_trail": GovernanceLayer("multi_region_trail",
        "Multi-region trail covering all AWS regions", "IsMultiRegionTrail"),
    "log_validation": GovernanceLayer("log_validation",
        "Log file integrity validation — hash chain, opt-in", "LogFileValidationEnabled"),
    "cloudwatch_alarm": GovernanceLayer("cloudwatch_alarm",
        "CloudWatch metric filter + alarm for CloudTrail events", None, is_optional=True),
    "data_events_enabled": GovernanceLayer("data_events_enabled",
        "Data events (S3/Lambda) enabled — opt-in, additional cost", None, is_optional=True),
    "log_storage": GovernanceLayer("log_storage",
        "Secure log storage (S3 bucket with no public access, MFA delete)", "S3BucketName"),
    "stop_logging_alert": GovernanceLayer("stop_logging_alert",
        "Alert on CloudTrail StopLogging / DeleteTrail events", None, is_optional=True),
    "insights_enabled": GovernanceLayer("insights_enabled",
        "CloudTrail Insights for unusual API activity detection", None, is_optional=True),
}

class CloudTrailEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS CloudTrail Documentation + MITRE ATT&CK T1562.008 + CIS AWS Benchmark",
        strategy="DECLARED-N",
        description=(
            "N(O) from CloudTrail architecture. management_event_logging N=4. "
            "management_event_logging: CRYSTALLIZED — events recorded, "
            "but trail can be disabled by any principal with StopLogging permission. "
            "data_event_logging: ABSENT by default — S3 object access, Lambda invocations "
            "not logged without explicit data event configuration. "
            "log_validation: CRYSTALLIZED — hash chain detects post-hoc tampering "
            "but not pre-logging gaps (StopLogging creates gap, not tamper event). "
            "DisableCloudTrail is MITRE ATT&CK T1562.008 (Impair Defenses: Disable Cloud Logs) "
            "— the canonical AWS defense evasion step. "
            "No CloudTrail family reaches ACTIVE: the audit log can always be disabled "
            "by a sufficiently privileged principal."
        ),
    )
    def __init__(self, trail_enabled: bool=True, multi_region: bool=False,
                 log_validation: bool=False, data_events: bool=False,
                 stop_logging_alert: bool=False, insights_enabled: bool=False):
        self._trail = trail_enabled
        self._multi = multi_region
        self._validation = log_validation
        self._data = data_events
        self._alert = stop_logging_alert
        self._insights = insights_enabled

    def collect_operation_families(self): return CT_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [CT_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in CT_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            trail_enabled=self._trail, multi_region=self._multi,
            log_validation=self._validation, data_events=self._data,
            cloudwatch_integrated=self._alert, sns_notification=self._alert,
            trail_name=None, region=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in CT_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "trail_enabled" in fam.declared_layers and self._trail: k.append("trail_enabled")
        if "multi_region_trail" in fam.declared_layers and self._multi: k.append("multi_region_trail")
        if "log_validation" in fam.declared_layers and self._validation: k.append("log_validation")
        if "cloudwatch_alarm" in fam.declared_layers and self._alert: k.append("cloudwatch_alarm")
        if "data_events_enabled" in fam.declared_layers and self._data: k.append("data_events_enabled")
        if "log_storage" in fam.declared_layers and self._trail: k.append("log_storage")
        if "stop_logging_alert" in fam.declared_layers and self._alert: k.append("stop_logging_alert")
        if "insights_enabled" in fam.declared_layers and self._insights: k.append("insights_enabled")
        return k
    def assess_ear_state(self, op_family):
        if not self._trail: return EARState.ABSENT
        if op_family.name == "data_event_logging" and not self._data: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
