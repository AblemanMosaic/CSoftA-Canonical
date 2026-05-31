# FINDINGS: MLflow Constitutional Analysis
*Wave 14 — System 69 · EAR ceiling: CRYSTALLIZED · model_promotion (no approval): ABSENT · Fingerprint: `6e312765ed4a19ce`*

## Executive Finding
MLflow introduces model governance as a new operation family not previously addressed in the corpus. The central constitutional question: what is the governance receipt for a production model promotion decision? Who authorized moving `fraud-detector-v2` to production, on what evidence, with what audit trail? In default MLflow: ABSENT. There is no mandatory approval workflow for stage transitions, no signed model artifact provenance, and no constitutive receipt for the decision that puts a model in front of users.

This introduces a new constitutional concept: the model deployment governance gap. Unlike code deployment (governed by CI/CD pipelines with commit signatures, test gates, and approval workflows), model deployment in most ML platforms lacks equivalent governance infrastructure. MLflow tracks what models exist and what experiments produced them, but it does not require a receipted authorization decision for production promotion.

The attack surface compounds: CVE-2025-15379 (March 2026) demonstrates the model artifact as an execution surface. A malicious `python_env.yaml` embedded in a model artifact achieves command injection when any system deploys that model with `env_manager=LOCAL`. The model registry becomes a supply chain attack vector — an adversary who can push to the model registry can achieve RCE on any system that serves the model.

CVE-2025-11201 (October 2025): directory traversal RCE on MLflow Tracking Server with NO authentication required. Unauthenticated remote attackers execute arbitrary code by supplying crafted model file paths. The most severe finding in the corpus for an unauthenticated RCE class: auth is not even required to exploit it.

## Real-World Incidents
CVE-2024-0520 (CVSS 10.0): RCE via command injection in dataset source URL — no authentication required in vulnerable deployments. MLflow has a pattern of path traversal and input sanitization vulnerabilities, reflecting its origin as a research tool deployed in production without security hardening. CVE-2025-15379 demonstrates the same pattern applied to the model artifact itself.

## The Add-On: `mlflow-governance-enforcer`
Model promotion approval gate and artifact integrity enforcer. Requires approval workflow for Production transitions; validates model artifact checksums before deployment; monitors for model promotion without associated test evidence; produces `mlflow_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| model_promotion | ABSENT (default) | No constitutive receipt for production decision |
| experiment_logging | CRYSTALLIZED | Metrics/params logged; no integrity guarantee |
| model_deployment | ABSENT (default) | CVE-2025-15379: model artifact = execution surface |
| artifact_access | CRYSTALLIZED | Auth governs access; integrity opt-in |
| registry_governance | CRYSTALLIZED (with approval) | Approval workflow closes primary gap |
