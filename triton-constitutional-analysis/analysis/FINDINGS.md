# FINDINGS: NVIDIA Triton Inference Server Constitutional Analysis
*Wave 4 — System 20 · EAR ceiling: CRYSTALLIZED · Fingerprint: `f23704ae199b7af1`*

## Executive Finding
NVIDIA Triton Inference Server is the corpus's AI inference governance case and introduces the AI Governance Gap: AI inference outputs are produced without constitutive receipts binding them to the governed model state that produced them. Triton serves inference requests from versioned models with declared configurations, but the connection between a specific output and the specific model version, input, and configuration that produced it is not constitutively recorded in standard deployment.

This is the constitutional gap that AI Bill of Materials (AIBOM) research, model cards, and AI audit requirements are attempting to address — and the corpus characterizes it precisely: the governance record (model version, configuration) exists as CRYSTALLIZED evidence but is not constitutively bound to each inference output.

## The AI Inference Governance Gap
The gap has three components: (1) model version governance — which version of which model served the request; (2) input governance — what input produced the output (input hash not captured by default); (3) configuration governance — what serving configuration (batching, precision, preprocessing) was active at inference time. All three are CRYSTALLIZED at best in standard Triton deployment.

The consequence: for any given AI output, an auditor cannot constitutively prove which model version, input, and configuration produced it. Post-hoc reconstruction requires correlating deployment logs, model repository state, and request logs — COMPOSITIONAL recoverability at best.

## Model Loading: Highest-Governance Surface
Model loading is the highest-governance surface in Triton — config.pbtxt is versioned, model repository state is declared, and loading status is returned. But model_loading is CRYSTALLIZED because the load event governs that a model became available, not that all subsequent inference is constitutively linked to that governed model state.

## Real-World Incident Mapping
The AI governance gap is currently being addressed regulatorily. The EU AI Act (2024, effective 2026) mandates audit trails for high-risk AI system decisions — exactly the constitutive inference receipt that Triton does not currently produce. Organizations subject to the EU AI Act running Triton in production must add the audit layer that Triton lacks structurally. This is the regulatory environment driving architectural change, analogous to PCI-DSS driving Stripe's ACTIVE architecture.

Model poisoning and supply chain attacks on ML models: if an attacker substitutes a backdoored model version for a legitimate one in the model repository, Triton will serve the backdoored model with no constitutive receipt distinguishing it from the legitimate model. The model_version layer is CRYSTALLIZED — it records which version is loaded, but without input/output hash capture, there is no constitutive evidence that the served outputs correspond to the declared model state.

## The Add-On: `triton-inference-receipt-generator`

A Triton extension and sidecar that produces constitutive inference receipts, closing the AI Inference Governance Gap. (1) Intercepts every inference request/response — records model name, version, input hash (SHA256 of serialized inputs), output hash, serving config hash, timestamp, latency. (2) Writes structured inference receipts to persistent audit backend — each receipt constitutively binds an output to the governed state that produced it. (3) Verifies model integrity on every model load — hashes all model files and validates against signed model manifest; rejects models failing verification. (4) Exposes inference receipt query API — auditors can retrieve receipt for any inference by request ID. (5) Produces EU AI Act Annex III compliance artifacts — per-inference logs in Article 12/17 format. Moves inference governance from CRYSTALLIZED toward ACTIVE by making the inference receipt constitutive.

## Summary
| Family | EAR State | Key gap |
|--------|-----------|---------|
| inference_request | CRYSTALLIZED | Output not constitutively bound to model+input+config |
| model_loading | CRYSTALLIZED | Load status exists; inference not constitutively linked |
| model_version_management | CRYSTALLIZED | Version declared; no mandatory change receipt |
| ensemble_execution | CRYSTALLIZED | Multi-model pipeline not receipted per step |
| metrics_collection | CRYSTALLIZED | Metrics exist; not constitutive of governance |
