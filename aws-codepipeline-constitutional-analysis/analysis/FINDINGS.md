# FINDINGS: AWS CodePipeline Constitutional Analysis
*Wave 16 — System 80 · approval_gate: ACTIVE · Fingerprint: `f89beb732eabf502`*

## Executive Finding
AWS CodePipeline completes the CI/CD governance quintuple: GitHub Actions (cloud), GitLab CI (self-hosted), Jenkins (enterprise), CircleCI (SaaS), CodePipeline (AWS-native). It is the most governed CI/CD platform in the corpus — it benefits from the full AWS security backstop that all three of the other platforms lack.

CloudTrail records every CodePipeline API call (T1737 carries). IAM governs the service role and all deployment actions (T1629 carries). The **manual approval gate** is ACTIVE when configured: a pipeline stage with an approval action cannot proceed without a human approval decision — the deployment is constitutively blocked until the approval is granted. This is the canonical admission-gate ACTIVE pattern (T1739) applied to CI/CD.

The contrast with CircleCI (T1826) is stark. CircleCI's 2023 breach demonstrated the SaaS platform as single breach point. CodePipeline is AWS-native: no external party holds the pipeline secrets — IAM roles are ephemeral, Secrets Manager integration stores credentials outside the pipeline definition, and CloudTrail provides an unconditional audit record. The AWS security backstop (GuardDuty, SecurityHub, Config) monitors CodePipeline infrastructure continuously.

CodeStar Connections govern OAuth scope to GitHub/Bitbucket for source integration — a scoped, auditable OAuth credential rather than a stored token.

## The Add-On: `codepipeline-governance-enforcer`
Approval gate validator and artifact encryption auditor. Validates approval gate configured for production deployments; validates artifact S3 bucket uses CMK not SSE-S3; validates pipeline execution role follows least-privilege; produces `codepipeline_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| pipeline_execution | CRYSTALLIZED | CloudTrail + IAM always present; T1737+T1629 |
| approval_gate | **ACTIVE** (when configured) | Deployment constitutively blocked without approval |
| artifact_management | CRYSTALLIZED | KMS encryption opt-in; SSE-S3 default |
| cross_account_deploy | CRYSTALLIZED | IAM role assumption; cross-account audit |
| connection_governance | CRYSTALLIZED | CodeStar Connection scoped OAuth |
