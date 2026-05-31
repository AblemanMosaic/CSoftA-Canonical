# FINDINGS: Pulumi IaC Constitutional Analysis
*Wave 13 — System 65 · policy_enforcement (CrossGuard): ACTIVE · Fingerprint: `3a4ba5c5dc5b8205`*

## Executive Finding
Pulumi completes the IaC trilogy (Terraform Wave 5, Crossplane Wave 8) with general-purpose language IaC. Pulumi shares Terraform's core constitutional properties: state-based, drift-gap-by-default, state lock on remote backend. It differentiates with CrossGuard (policy-as-code in real languages) which achieves ACTIVE governance for policy_enforcement: a stack update cannot complete if CrossGuard policy fails.

The IaC trilogy now spans three constitutional archetypes:

| IaC System | State model | Drift governance | Policy governance |
|---|---|---|---|
| Terraform (T1671) | HCL state file | ABSENT (no continuous detection) | CRYSTALLIZED (Sentinel opt-in) |
| Crossplane (T1726) | K8s resource objects | ACTIVE (continuous reconciliation) | ACTIVE (admission controller) |
| Pulumi (THIS) | JSON state file | ABSENT → CRYSTALLIZED (Insights 2025) | ACTIVE (CrossGuard) |

Pulumi Insights (2025) begins to address the state drift gap: continuous cloud API comparison against known state produces CRYSTALLIZED drift detection (records what drifted, does not prevent drift). This moves Pulumi ahead of Terraform on drift governance while still short of Crossplane's ACTIVE continuous reconciliation.

General-purpose language programs introduce a supply chain gap analogous to GitHub Actions (T1702): Pulumi programs import packages from npm/PyPI/crates.io. These packages execute with Pulumi's cloud credentials during `pulumi up`. The same mutable tag / ABSENT provenance gap that affects GitHub Actions applies to Pulumi program dependencies.

## Real-World Incidents
No Pulumi-specific CVEs of constitutional significance in the corpus period. The governance gaps are structural: state drift gap (same as Terraform, which has documented incidents), general-purpose language supply chain gap (same class as GitHub Actions tj-actions/reviewdog compromise 2025), and CrossGuard bypass via allowlist modification (requires privileged access — bounded). Pulumi ESC (Environments, Secrets, Config, 2024) provides structured secret management addressing the Terraform sensitive-values-in-state gap (T1676) — Pulumi ESC stores secrets externally with RBAC and audit.

## The Add-On: `pulumi-governance-enforcer`
CrossGuard policy enforcer and drift monitor. Validates remote state backend encrypted; validates CrossGuard policies active on all stacks; validates Pulumi Insights drift detection configured; validates ESC managing all sensitive configuration; validates Pulumi program dependencies pinned by hash; produces `pulumi_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| stack_update | CRYSTALLIZED | Remote state + lock; drift ABSENT (Insights = CRYSTALLIZED) |
| stack_preview | CRYSTALLIZED | Preview receipt; audit logged in Pulumi Cloud |
| policy_enforcement | **ACTIVE** (CrossGuard) | Policy constitutive of stack update completion |
| secret_access | CRYSTALLIZED | ESC provides RBAC + audit; secrets external to state |
| drift_detection | CRYSTALLIZED (Insights) | Continuous cloud API comparison; detection not prevention |
