# FINDINGS: Tekton Pipelines Constitutional Analysis
*Wave 9 — System 43 · result_attestation (Tekton Chains): ACTIVE · Fingerprint: `cf5ab4f02ed87f0a`*

## Executive Finding
Tekton Pipelines is the Kubernetes-native CI/CD governance case, complementing GitHub Actions (cloud-hosted, Wave 6). Tekton executes pipeline steps (Steps in Tasks, Tasks in Pipelines) as containers on Kubernetes. Tekton Chains provides supply chain security — recording TaskRun execution and signing results via Cosign with SLSA provenance. When Tekton Chains is enabled with OCI signing, `result_attestation` is ACTIVE: the signing is constitutive of the result being attested; unsigned results cannot be verified by downstream policy-controller enforcement.

The governance profile is stronger than GitHub Actions for supply chain governance because Chains is an in-cluster component, not an external third party. The OIDC identity binding for Chains signatures comes from the cluster's own OIDC provider, not from a third-party action owner.

## SA Scope Gap: Parallel to Argo Workflows
Like Argo Workflows (T1724), Tekton pipeline steps inherit the ServiceAccount permissions of the configured SA. The default SA in many Tekton deployments has overly broad access. A pipeline step with pod-creation permissions can escape namespace restrictions. CVE-2023-30845 confirmed this: pipeline steps could bypass namespace restrictions via pod creation.

## Real-World Incident Mapping
CVE-2023-30845 (Tekton Pipelines, privilege escalation): pipeline steps with create pod permissions could bypass namespace restriction policies, creating pods in unauthorized namespaces. Same constitutional gap class as Argo Workflows CVE-2023-22736 (T1729). The SA scope gap is structural across Kubernetes workflow engines.

Tekton Chains production adoption: organizations using Tekton with Chains + policy-controller achieve an end-to-end supply chain governance chain: source code → Tekton build → Chains signature → Rekor transparency → policy-controller admission. This is the Kubernetes-native implementation of the SLSA L3 build provenance chain.

## The Add-On: `tekton-governance-enforcer`
Chains deployment validator and SA scope auditor. Validates Chains enabled and signing configured; validates SA least-privilege per namespace; monitors for cross-namespace step execution; audits TaskRun results for signature coverage; produces `tekton_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| pipeline_execution | CRYSTALLIZED | RBAC governs submission; SA scope gap |
| task_execution | CRYSTALLIZED | Steps inherit SA permissions |
| result_attestation | **ACTIVE** | Chains signing constitutive of attestation |
| pipeline_management | CRYSTALLIZED | Template review not constitutive |
| secret_access | CRYSTALLIZED | SA scope determines Secret access |
