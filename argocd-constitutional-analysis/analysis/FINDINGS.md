# FINDINGS: Argo CD Constitutional Analysis
*Wave 5 — System 22 · EAR ceiling: CRYSTALLIZED · Fingerprint: `536bf22a3c9f3584`*

## Executive Finding
Argo CD introduces the IaC/GitOps governance surface. The Git commit is a governance declaration — it records the desired state with author identity, timestamp, and content hash. This is more constitutionally complete than most governance declarations in the corpus: Git commits are immutable, author-attributed, and content-addressable. The governance declaration is ACTIVE in the Git sense. But the governance execution (the sync) is CRYSTALLIZED: the Application sync status records the outcome but is not constitutive of the sync operation.

The most important finding is the RBAC credential scope gap, expressed by CVE-2025-55190 (CVSS 10.0). Project-scoped API tokens could access repository credentials outside their declared scope. The RBAC policy was evaluated — `rbac_policy` was present and k included it — but the scope boundary of the authorization was insufficiently bounded. This is the NON_ACTIVATION form at the scope boundary layer: governance participated but did not fully participate.

## Git Commit as Governance Declaration
The Git commit is the corpus's first example of a version control commit as a governance artifact. The commit SHA is a content-addressed receipt of the desired state — it cannot be altered without changing the SHA. Author attribution, timestamp, and GPG signing (optional) make the commit a stronger governance declaration than most CRD resources in the corpus. The constitutional finding: Argo CD's governance declaration layer is more robust than its governance execution layer.

## Sync Drift Gap
Argo CD monitors for drift between the Git-declared state and the live cluster state — this is its core feature. But when drift is detected, the `OutOfSync` status on the Application resource is a CRYSTALLIZED record: it records that drift was detected, not that drift prevention failed at a constitutive point. An operator who manually modifies Kubernetes resources outside Argo CD creates drift with no receipt binding the manual modification to an authorized actor.

## Real-World Incident Mapping
CVE-2025-55190 (CVSS 10.0, September 2025): a critical vulnerability where project-level API tokens, or tokens with global project get permissions, could query the Project Details API endpoint and receive all repository credentials linked to the project — including usernames and passwords. Attackers holding those credentials could clone private codebases, inject malicious manifests, or attempt downstream supply chain attacks. Adopted by Adobe, Google, IBM, Red Hat, Capital One, BlackRock — making the blast radius significant. The constitutional finding: the credential_scope layer was declared applicable but not evaluated correctly for the project detailed endpoint. NON_ACTIVATION at the scope boundary layer.

CVE-2024-31989 (Redis cache privilege escalation): Argo CD stores Application state in Redis. A user with write access to the Redis cache could escalate privileges by modifying cached Application state. The constitutional finding: the rbac_policy layer was evaluated for Argo CD API operations, but the Redis cache was a bypass route — modifying cached state bypassed the RBAC layer entirely. BYPASS gap form.

CVE-2023-23947 (cluster secret privilege escalation): a user with update permission on one cluster secret could update any cluster secret. NON_ACTIVATION at the scope boundary: the update permission was evaluated but the scope of what it applied to was incorrect.

CVE-2022-29165 (authentication bypass via anonymous access): Argo CD could be configured with anonymous access enabled alongside SSO, allowing unauthenticated users to access the Argo CD UI and API. The rbac_policy layer was declared but had no effect for anonymous access paths — BYPASS form: an access path existed that bypassed the RBAC evaluation entirely.

CVE-2023-40584 (namespace bypass for Application controller sharding): when application controller sharding was enabled, the controller did not enforce the configured allowed namespace list when reconciling Applications. An authorized Argo CD user could deploy Applications into namespaces outside their declared AppProject scope — NON_ACTIVATION at namespace scope enforcement. The AppProject `sourceNamespaces` field acted as a secondary check but was insufficient when sharding was active.

These four CVEs (CVE-2025-55190, CVE-2024-31989, CVE-2023-23947, CVE-2022-29165) form a recurring constitutional pattern: each expresses the same gap form (NON_ACTIVATION at RBAC scope boundary or BYPASS via alternate access path) in a different part of the Argo CD API surface. The pattern is structural, not incidental.

## The Add-On: `argocd-governance-enforcer`
Deployment gate and runtime monitor for Argo CD. Validates RBAC configuration against known NON_ACTIVATION patterns (credential scope, cluster secret scope); requires GPG commit signing as a prerequisite for sync authorization; monitors Redis cache for unauthorized modification; produces per-Application sync receipts binding each sync to the Git commit, RBAC evaluation, and actor identity.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| git_sync | CRYSTALLIZED | sync_status not constitutive; Git commit is ACTIVE declaration |
| application_management | CRYSTALLIZED | RBAC evaluated; audit opt-in |
| secret_access | CRYSTALLIZED | CVE-2025-55190 class: scope boundary NON_ACTIVATION |
| cluster_management | CRYSTALLIZED | CVE-2023-23947 class: scope NON_ACTIVATION |
| role_binding | CRYSTALLIZED | RBAC changes not mandatorily receipted |
