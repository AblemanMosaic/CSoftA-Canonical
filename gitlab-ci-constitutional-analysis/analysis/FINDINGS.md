# FINDINGS: GitLab CI Constitutional Analysis
*Wave 11 — System 54 · EAR ceiling: CRYSTALLIZED · Fingerprint: `93b2408c4b3fccdf`*

## Executive Finding
GitLab CI is the dominant self-hosted CI/CD alternative to GitHub Actions, and its governance model has three structural differences that produce distinct constitutional findings. First: CI_JOB_TOKEN cross-project access — by default, GitLab CI jobs can access packages and registries of other projects in the same group via CI_JOB_TOKEN, without explicit authorization from those projects. This is the same principal scope boundary issue as Argo CD CVE-2025-55190 (T1674) applied to CI/CD token access. Second: shared runner multi-tenancy — shared runners execute jobs from multiple projects on the same infrastructure, introducing execution boundary concerns not present in GitHub-hosted runners or dedicated project runners. Third: self-hosted deployment means the runner infrastructure itself is the deployer's responsibility, with no baseline security guarantee from a cloud provider.

## CI_JOB_TOKEN Scope: The Cross-Project Access Gap
GitLab's CI_JOB_TOKEN is a short-lived token issued per job, but its default scope allows read access to packages and container registries of any project in the same group hierarchy. A job in Project A can pull images from Project B's registry without Project B granting explicit authorization. This creates a hidden dependency: a compromised job in any project can access artifacts from related projects.

GitLab introduced allowlist-based CI_JOB_TOKEN scope restriction in 15.9, but it requires opt-in per project — it is not the default. The constitutional finding: the authorization scope of CI_JOB_TOKEN is broader than its declared governance surface suggests, until explicitly restricted.

## Real-World Incidents
CVE-2024-6678 (GitLab CE/EE, CVSS 9.9): trigger pipeline jobs as any user under certain conditions — same principal impersonation pattern as Argo CD CVE-2025-55190. CVE-2024-9164: unauthorized pipeline execution on arbitrary branches, bypassing protected branch governance — NON_ACTIVATION at the branch protection scope boundary. CVE-2025-2242: former instance admin retains elevated privileges post-demotion — RBAC state consistency gap where privilege revocation is not constitutive (the role change doesn't immediately remove existing permissions). CVE-2024-8114: stolen PAT used to perform operations beyond declared scope — same NON_ACTIVATION at token scope boundary.

## The Add-On: `gitlab-ci-governance-enforcer`
Runner isolation enforcer and token scope auditor. Validates dedicated runners configured for sensitive projects; validates CI_JOB_TOKEN scope restricted to declared projects; validates OIDC ID tokens used for cloud access (not long-lived credentials); validates protected branches with required approvals; monitors for cross-project token access patterns; produces `gitlab_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| pipeline_execution | CRYSTALLIZED | RBAC evaluated; audit opt-in; shared runner gap |
| job_token_access | CRYSTALLIZED | Default scope broader than declared |
| cloud_federation | CRYSTALLIZED | OIDC ID tokens ephemeral; audience scope needed |
| secret_access | CRYSTALLIZED | Protected vars on protected branches only |
| pipeline_trigger | CRYSTALLIZED | CVE-2024-6678 class: trigger-as-arbitrary-user |
