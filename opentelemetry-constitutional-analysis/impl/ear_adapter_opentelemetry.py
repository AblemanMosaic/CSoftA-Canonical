"""
ear_adapter_opentelemetry.py — OpenTelemetry Collector EAR Adapter
Wave 4 — System 18. Observability pipeline — governs governance data itself.

Key finding: The OpenTelemetry Collector is the corpus's meta-governance case.
It is the system that collects, processes, and exports the observability data
(traces, metrics, logs) that other systems use to provide their own governance
evidence. The Collector's own governance surface is CRYSTALLIZED:
pipeline configuration, processor decisions, and export outcomes are
not constitutively receipted by the Collector itself.
The profound finding: the system that governs governance data
has no constitutive governance receipts for its own operation.
If the Collector drops spans, misconfigures a processor, or fails silently,
the governance data for ALL downstream systems is degraded — with no
receipt recording that the degradation occurred.
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
    name: str; description: str; declared_layers: list[str]; otel_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    pipeline_configured: bool; data_received: bool
    data_exported: bool; drop_logged: bool
    processor_applied: bool; exporter_ack: bool
    error: str | None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

OTEL_OPERATION_FAMILIES = [
    OperationFamily("telemetry_ingestion",
        "Receive telemetry data (traces/metrics/logs) from instrumented service",
        ["pipeline_config","receiver_ack","processor_chain"], "ingestion"),
    OperationFamily("telemetry_processing",
        "Apply processor transformations (filter, sample, attribute)",
        ["pipeline_config","processor_chain","drop_log"], "processing"),
    OperationFamily("telemetry_export",
        "Export processed telemetry to backend (Jaeger, Prometheus, etc.)",
        ["pipeline_config","exporter_ack","export_log"], "export"),
    OperationFamily("pipeline_management",
        "Configure or reload Collector pipeline",
        ["pipeline_config","config_hash","reload_log"], "config"),
    OperationFamily("sampling_decision",
        "Apply tail/head sampling decision to trace",
        ["pipeline_config","sampling_policy","drop_log"], "sampling"),
]

OTEL_GOVERNANCE_LAYERS = {
    "pipeline_config": GovernanceLayer("pipeline_config",
        "Pipeline configuration declaring receivers/processors/exporters", "service.pipelines"),
    "receiver_ack": GovernanceLayer("receiver_ack",
        "Acknowledgment that data was received by Collector", None, is_optional=True),
    "processor_chain": GovernanceLayer("processor_chain",
        "Processor chain applied to telemetry before export", "processors"),
    "drop_log": GovernanceLayer("drop_log",
        "Log of dropped spans/metrics due to queue overflow or sampling", None),
    "exporter_ack": GovernanceLayer("exporter_ack",
        "ACK from export backend confirming receipt", None, is_optional=True),
    "export_log": GovernanceLayer("export_log",
        "Export outcome log (success/failure/retry)", None),
    "config_hash": GovernanceLayer("config_hash",
        "Hash of pipeline configuration for change detection", None),
    "reload_log": GovernanceLayer("reload_log",
        "Pipeline reload event log", None),
    "sampling_policy": GovernanceLayer("sampling_policy",
        "Sampling policy declaration", "processors.tail_sampling"),
}

class OpenTelemetryEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "OpenTelemetry Collector Documentation + OTel Specification + "
            "OpenTelemetry Governance SIG + CNCF Observability whitepaper"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) from OTel Collector architecture. telemetry_ingestion N=3. "
            "CRYSTALLIZED across all families: Collector processes telemetry but "
            "does not produce constitutive receipts for its own pipeline operations. "
            "Silent drops under queue pressure are the canonical gap: "
            "span dropped by Collector produces no receipt — "
            "the governance data is absent with no record of its absence. "
            "Meta-governance finding: the system governing governance data "
            "has governance gaps in its own operation. "
            "No OTel Collector family reaches ACTIVE."
        ),
    )

    def __init__(self, drop_logging_enabled: bool=False,
                 exporter_acks_enabled: bool=False,
                 config_hash_tracking: bool=False):
        self._drop_log = drop_logging_enabled
        self._exporter_ack = exporter_acks_enabled
        self._config_hash = config_hash_tracking

    def collect_operation_families(self): return OTEL_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [OTEL_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in OTEL_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            pipeline_configured=True, data_received=True,
            data_exported=True, drop_logged=self._drop_log,
            processor_applied=True, exporter_ack=self._exporter_ack,
            error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in OTEL_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "pipeline_config" in fam.declared_layers:
            k.append("pipeline_config")
        if "processor_chain" in fam.declared_layers and inst.processor_applied:
            k.append("processor_chain")
        if "drop_log" in fam.declared_layers and self._drop_log:
            k.append("drop_log")
        if "exporter_ack" in fam.declared_layers and self._exporter_ack:
            k.append("exporter_ack")
        if "export_log" in fam.declared_layers and inst.data_exported:
            k.append("export_log")
        if "config_hash" in fam.declared_layers and self._config_hash:
            k.append("config_hash")
        if "sampling_policy" in fam.declared_layers:
            k.append("sampling_policy")
        return k

    def assess_ear_state(self, op_family):
        # No OTel Collector family reaches ACTIVE
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
