# FINDINGS: Argo Workflows Constitutional Analysis
*Wave 8 — System 38 · EAR ceiling: CRYSTALLIZED · Fingerprint: `be7bcbdaf7a6d88f`*

## Executive Finding
Argo Workflows is the Kubernetes workflow orchestration case, distinct from Argo CD (Wave 5, T1669). Where Argo CD manages declarative GitOps deployments, Argo Workflows executes arbitrary containerized workloads on demand — CI pipelines, data processing DAGs, ML training jobs. The governance distinction is significant: Argo CD's governance declaration is an immutable Git commit; Argo Workflows' governance declaration is a WorkflowTemplate in Kubernetes, and each step executes as a container with a configured ServiceAccount.

The ServiceAccount used for workflow execution is the critical governance gap. The `workflow-controller` ServiceAccount in default Argo Workflows deployments has significant cluster access. Workflow steps that reference the default SA inherit this access, potentially allowing workflows submitted by lower-privileged users to perform higher-privileged Kubernetes operations through the workflow execution context.

## Template Supply Chain: The GitHub Actions Analog
WorkflowTemplates can reference other templates via `templateRef`, including templates in other namespaces or ClusterWorkflowTemplates. This is the GitHub Actions unpinned action supply chain gap (T1702) applied to workflow templates: a user-submitted workflow can reference an externally-owned template, and if that template is modified, all workflows using it change behavior without the submitting user's knowledge.

## Real-World Incident Mapping
CVE-2023-22736 (Argo Workflows namespace bypass, CVSS 7.5): workflows could be submitted with `templateRef` pointing to templates in other namespaces, bypassing namespace isolation. An Argo Workflows user in one namespace could execute templates intended for other namespaces, potentially escalating privileges or accessing resources outside their declared scope. NON_ACTIVATION at the namespace scope boundary — the same pattern as Argo CD CVE-2023-40584 (Wave 7, T1711).

Argo Workflows default SA over-privilege: multiple security assessments have documented that default Argo Workflows installations grant the workflow-controller SA excessive cluster permissions. Workflows using the default SA have access to read all ConfigMaps, execute arbitrary pods, and in some configurations read Secrets cluster-wide.

## The Add-On: `argo-workflows-governance-enforcer`
ServiceAccount scope enforcer and template provenance validator. Validates workflow SA scoped to namespace; validates templateRef resolution against approved templates; monitors for cross-namespace template access; audits SA permissions against declared workflow scope; produces `workflows_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| workflow_submission | CRYSTALLIZED | RBAC evaluated; SA scope often overly broad |
| step_execution | CRYSTALLIZED | SA permissions inherited; audit log opt-in |
| artifact_access | CRYSTALLIZED | Artifact signing opt-in |
| template_management | CRYSTALLIZED | Template changes not mandatorily receipted |
| secret_access | CRYSTALLIZED | Secret scope depends on SA RBAC |
