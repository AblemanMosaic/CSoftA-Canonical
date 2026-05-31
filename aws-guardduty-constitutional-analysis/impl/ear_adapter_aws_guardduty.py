"""
ear_adapter_aws_guardduty.py — AWS GuardDuty EAR Adapter
Wave 9 — System 42. Cloud threat detection governance.

Key finding: AWS GuardDuty is the threat detection governance case for AWS —
meta-governance case 4, completing the AWS security triad (CloudTrail=audit,
KMS=crypto, GuardDuty=threat detection). GuardDuty detects threats by
analyzing CloudTrail events, VPC Flow Logs, DNS queries, and runtime telemetry.
CRYSTALLIZED by architecture: findings are generated after threats occur,
not before. GuardDuty can be disabled (just like CloudTrail) — MITRE ATT&CK
T1562.008. The finding-per-event is CRYSTALLIZED: the threat event occurs
whether or not GuardDuty generates a finding.
Extended Threat Detection (December 2024): multi-stage attack sequence correlation,
producing critical-severity findings from correlated signals. Still CRYSTALLIZED —
the correlation happens after the events, not before.
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
    name: str; description: str; declared_layers: list[str]; gd_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    detector_enabled: bool; finding_generated: bool
    finding_delivered: bool; auto_remediation: bool
    multi_region: bool; s3_protection: bool
    detector_id: str|None; finding_type: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

GD_OPERATION_FAMILIES = [
    OperationFamily("threat_detection",
        "Analyze CloudTrail/VPC/DNS/runtime for threats and generate findings",
        ["detector_enabled","finding_generation","finding_delivery","multi_region_coverage"], "detect"),
    OperationFamily("finding_delivery",
        "Deliver finding to Security Hub / EventBridge / SNS",
        ["detector_enabled","finding_delivery","auto_remediation"], "deliver"),
    OperationFamily("detector_governance",
        "Govern the GuardDuty detector configuration and protection plans",
        ["detector_enabled","multi_region_coverage","disable_alert"], "detector"),
    OperationFamily("extended_threat_detection",
        "Correlate multi-stage attack signals into critical-severity attack sequence findings",
        ["detector_enabled","etd_enabled","finding_generation","finding_delivery"], "etd"),
    OperationFamily("s3_protection",
        "Monitor S3 data plane events for exfiltration and access anomalies",
        ["detector_enabled","s3_protection_enabled","finding_generation"], "s3"),
]

GD_GOVERNANCE_LAYERS = {
    "detector_enabled": GovernanceLayer("detector_enabled",
        "GuardDuty detector enabled in region", "DetectorId"),
    "finding_generation": GovernanceLayer("finding_generation",
        "Finding generated for detected threat — post-hoc, not constitutive", None),
    "finding_delivery": GovernanceLayer("finding_delivery",
        "Finding delivered to Security Hub / EventBridge / SNS", None),
    "multi_region_coverage": GovernanceLayer("multi_region_coverage",
        "Detector enabled in all regions — not default for all regions", None),
    "auto_remediation": GovernanceLayer("auto_remediation",
        "Automated remediation via EventBridge rule — opt-in", None, is_optional=True),
    "disable_alert": GovernanceLayer("disable_alert",
        "Alert on GuardDuty detector disable/suspend events", None, is_optional=True),
    "etd_enabled": GovernanceLayer("etd_enabled",
        "Extended Threat Detection enabled (multi-stage attack correlation)", None),
    "s3_protection_enabled": GovernanceLayer("s3_protection_enabled",
        "S3 Protection plan enabled for data plane monitoring", None, is_optional=True),
}

class AWSGuardDutyEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="AWS GuardDuty Documentation + MITRE ATT&CK T1562.008 + AWS security blog",
        strategy="DECLARED-N",
        description=(
            "N(O) from GuardDuty architecture. threat_detection N=4. "
            "Meta-governance case 4: completes AWS security triad "
            "(CloudTrail T1722, KMS T1723, GuardDuty T1742). "
            "CRYSTALLIZED by architecture: findings generated after threat events. "
            "GuardDuty can be disabled (MITRE T1562.008) — same vulnerability as CloudTrail. "
            "Extended Threat Detection (December 2024): correlates multi-stage signals "
            "into critical-severity attack sequence findings — still CRYSTALLIZED. "
            "S3 Protection: opt-in plan covering S3 data plane anomalies. "
            "Multi-region: detector must be enabled per-region — not automatic. "
            "November 2025: GuardDuty Extended Threat Detection identified active "
            "cryptomining campaign using compromised IAM credentials. "
            "No GuardDuty family reaches ACTIVE: all findings are post-hoc."
        ),
    )
    def __init__(self, detector_enabled: bool=True, multi_region: bool=False,
                 etd_enabled: bool=False, s3_protection: bool=False,
                 auto_remediation: bool=False, disable_alert: bool=False):
        self._detector = detector_enabled
        self._multi = multi_region
        self._etd = etd_enabled
        self._s3 = s3_protection
        self._auto = auto_remediation
        self._disable_alert = disable_alert

    def collect_operation_families(self): return GD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [GD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in GD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            detector_enabled=self._detector, finding_generated=True,
            finding_delivered=True, auto_remediation=self._auto,
            multi_region=self._multi, s3_protection=self._s3,
            detector_id=None, finding_type=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in GD_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "detector_enabled" in fam.declared_layers and self._detector: k.append("detector_enabled")
        if "finding_generation" in fam.declared_layers and self._detector: k.append("finding_generation")
        if "finding_delivery" in fam.declared_layers and self._detector: k.append("finding_delivery")
        if "multi_region_coverage" in fam.declared_layers and self._multi: k.append("multi_region_coverage")
        if "auto_remediation" in fam.declared_layers and self._auto: k.append("auto_remediation")
        if "disable_alert" in fam.declared_layers and self._disable_alert: k.append("disable_alert")
        if "etd_enabled" in fam.declared_layers and self._etd: k.append("etd_enabled")
        if "s3_protection_enabled" in fam.declared_layers and self._s3: k.append("s3_protection_enabled")
        return k
    def assess_ear_state(self, op_family):
        if not self._detector: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
