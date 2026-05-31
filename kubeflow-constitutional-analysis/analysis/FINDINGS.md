# FINDINGS: Kubeflow Pipelines Constitutional Analysis
*Wave 15 — System 71 · EAR ceiling: CRYSTALLIZED · Fingerprint: `aa3f56b4be222b83`*

## Executive Finding
Kubeflow applies the model deployment governance gap (T1810, MLflow Wave 14) to the K8s-native ML pipeline execution layer. Kubeflow runs ML training jobs as Kubernetes workloads, which means every K8s governance finding from the corpus applies via T1613 upstream inheritance — Kubeflow's governance ceiling is bounded by the K8s cluster governance beneath it. An admission webhook (OPA/Gatekeeper/Kyverno, all ACTIVE) can block a malformed Kubeflow pipeline CRD from being scheduled. But the ML-specific governance of the pipeline artifact itself — which data sources it uses, what training parameters it accepts, who reviewed and approved the pipeline definition — is ABSENT by default.

`model_promotion` in Kubeflow is ABSENT without an explicit approval workflow, extending T1810 to the K8s-native ML orchestration layer. The constitutional finding is the same: no constitutive receipt for the decision to promote a trained model to production.

## Kubeflow 1.9/1.10 Security Progress
Kubeflow 1.9 introduced network policies, Oauth2-proxy authentication, and CVE scanning in the release process. The Argo Workflows backend was upgraded from a version that had accumulated CVEs to a current patched version. Kubeflow 1.10 (KubeCon Europe 2025) reached CNCF incubation with established multi-user profile isolation via Kubernetes namespace RBAC. These represent CRYSTALLIZED-forward governance progress — mechanisms exist and are improving, but constitutive governance of ML pipeline artifacts and model promotion decisions remains ABSENT.

## The Add-On: `kubeflow-governance-enforcer`
Pipeline provenance enforcer and model promotion gater. Validates pipeline definitions are signed and versioned; validates K8s RBAC governs namespace access; validates model promotion requires approval workflow receipt; produces `kubeflow_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| pipeline_run | CRYSTALLIZED | K8s RBAC governs; pipeline provenance opt-in |
| pipeline_upload | CRYSTALLIZED | No mandatory signing; provenance ABSENT default |
| model_promotion | ABSENT (default) | No constitutive receipt; extends T1810 |
| notebook_access | CRYSTALLIZED | Profile namespace RBAC; network policy opt-in |
| artifact_access | CRYSTALLIZED | RBAC governs; integrity opt-in |
