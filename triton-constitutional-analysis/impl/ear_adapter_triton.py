"""
ear_adapter_triton.py — NVIDIA Triton Inference Server EAR Adapter
Wave 4 — System 20. AI inference governance.

Key finding: Triton is the corpus's AI inference case and introduces
the AI Inference Governance surface. Model serving is CRYSTALLIZED:
inference requests are served but the governance of which model version
served which request, with what configuration, is not constitutively receipted.
Model loading is the highest-governance surface: model repository
configuration is versioned and declared. But inference itself —
the operation that produces AI outputs — has no mandatory receipt
binding the output to the model version, parameters, and input hash
that produced it. This is the AI governance gap: outputs exist without
constitutive receipts linking them to governed model states.
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
    name: str; description: str; declared_layers: list[str]; triton_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    model_version_recorded: bool; input_hash_recorded: bool
    output_hash_recorded: bool; inference_logged: bool
    model_config_hash: str | None; serving_policy_applied: bool
    error: str | None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

TRITON_OPERATION_FAMILIES = [
    OperationFamily("inference_request",
        "Serve inference request from client",
        ["model_version","serving_policy","inference_log","input_hash"], "inference"),
    OperationFamily("model_loading",
        "Load model version into serving runtime",
        ["model_repository","model_config","model_version","load_receipt"], "load"),
    OperationFamily("model_version_management",
        "Pin, promote, or retire model version",
        ["model_repository","model_config","model_version","audit_log"], "version"),
    OperationFamily("ensemble_execution",
        "Execute multi-model pipeline (ensemble)",
        ["model_version","serving_policy","inference_log","ensemble_config"], "ensemble"),
    OperationFamily("metrics_collection",
        "Collect inference latency/throughput metrics",
        ["serving_policy","metrics_endpoint","inference_log"], "metrics"),
]

TRITON_GOVERNANCE_LAYERS = {
    "model_version": GovernanceLayer("model_version",
        "Model version serving the request", "model_version"),
    "serving_policy": GovernanceLayer("serving_policy",
        "Serving policy (dynamic batching, instance count)", "config.pbtxt"),
    "inference_log": GovernanceLayer("inference_log",
        "Inference request/response log", None, is_optional=True),
    "input_hash": GovernanceLayer("input_hash",
        "Hash of inference input — not captured by default", None, is_optional=True),
    "model_repository": GovernanceLayer("model_repository",
        "Model repository directory structure declaration", "model_repository_path"),
    "model_config": GovernanceLayer("model_config",
        "config.pbtxt model configuration file", "config.pbtxt"),
    "load_receipt": GovernanceLayer("load_receipt",
        "Model load status response", "ready_state"),
    "audit_log": GovernanceLayer("audit_log",
        "Audit log for model version operations", None, is_optional=True),
    "ensemble_config": GovernanceLayer("ensemble_config",
        "Ensemble pipeline configuration", "ensemble_scheduling"),
    "metrics_endpoint": GovernanceLayer("metrics_endpoint",
        "Prometheus metrics endpoint", "/metrics"),
}

class TritonEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "NVIDIA Triton Inference Server Documentation + "
            "Triton Model Repository specification + "
            "MLOps governance best practices + "
            "AI Bill of Materials (AIBOM) research"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) from Triton architecture. inference_request N=4. "
            "CRYSTALLIZED across all families. "
            "inference_request: no mandatory receipt binding output to model version, "
            "input hash, and configuration — the AI governance gap. "
            "model_loading: closest to ACTIVE — model config is declared and versioned, "
            "load status response exists. But model_loading is CRYSTALLIZED because "
            "the load receipt records that loading occurred, not that the loaded model "
            "is the governed version for all subsequent inference. "
            "Core AI inference governance gap: outputs produced without constitutive "
            "receipts linking them to governed model states. "
            "No Triton family reaches ACTIVE in standard configuration."
        ),
    )

    def __init__(self, inference_logging: bool=False,
                 input_hash_capture: bool=False,
                 model_version_pinned: bool=True):
        self._inf_log = inference_logging
        self._input_hash = input_hash_capture
        self._version_pinned = model_version_pinned

    def collect_operation_families(self): return TRITON_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [TRITON_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in TRITON_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            model_version_recorded=self._version_pinned,
            input_hash_recorded=self._input_hash,
            output_hash_recorded=False,
            inference_logged=self._inf_log,
            model_config_hash=None,
            serving_policy_applied=True,
            error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in TRITON_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "model_version" in fam.declared_layers and inst.model_version_recorded:
            k.append("model_version")
        if "serving_policy" in fam.declared_layers and inst.serving_policy_applied:
            k.append("serving_policy")
        if "inference_log" in fam.declared_layers and self._inf_log:
            k.append("inference_log")
        if "input_hash" in fam.declared_layers and self._input_hash:
            k.append("input_hash")
        if "model_repository" in fam.declared_layers:
            k.append("model_repository")
        if "model_config" in fam.declared_layers:
            k.append("model_config")
        if "load_receipt" in fam.declared_layers:
            k.append("load_receipt")
        if "ensemble_config" in fam.declared_layers:
            k.append("ensemble_config")
        if "metrics_endpoint" in fam.declared_layers:
            k.append("metrics_endpoint")
        return k

    def assess_ear_state(self, op_family):
        # No Triton family reaches ACTIVE — inference not constitutively receipted
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
