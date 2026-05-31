# FINDINGS: OPA Policy Engine Constitutional Analysis
*Wave 10 — System 46 · policy_evaluation: ACTIVE · api_authorization: ACTIVE · Fingerprint: `4aef14d173b8db1c`*

## Executive Finding
OPA (Open Policy Agent) is the general-purpose policy-as-code governance case — extending beyond the Kubernetes admission controller use case covered in Wave 2 (Gatekeeper, T1658). OPA evaluates Rego policies against input documents in CI/CD pipelines, API gateways, microservice authorization, Terraform plan evaluation (Conftest), and data query filtering. Policy evaluation is ACTIVE: a request that violates policy is denied before processing — the decision is constitutive of the allowed action.

The constitutional gap specific to OPA: the policy evaluation may be ACTIVE while the policy content is wrong. An incorrect Rego policy that allows what should be denied produces incorrect ACTIVE decisions — the enforcement mechanism operates correctly, but the governance declaration is wrong. Policy testing (`opa test`) and policy versioning are the governance mechanisms for this gap, and both are opt-in.

## Policy Content Correctness: The Second-Order Governance Gap
OPA enforces what the policy says. If the policy says the wrong thing, OPA enforces the wrong thing — and the decision log records the wrong decision as having been made correctly. This is a new constitutional gap class not previously seen in the corpus: the ACTIVE governance mechanism faithfully enforcing an incorrect governance declaration. The constitutional implication: ACTIVE EAR state at the evaluation layer does not guarantee correct governance; policy correctness governance is a separate, independent layer.

## Real-World Incident Mapping
OPA Gatekeeper misconfiguration (multiple documented cases): constraints with incorrect Rego logic that appeared to enforce policy but contained logical errors allowing violations. The admission webhook was evaluated (ACTIVE) but the policy content was wrong (NON_ACTIVATION at the policy correctness layer). Policy review and `opa test` would have caught these.

Conftest Terraform evaluation gap: organizations using Conftest for Terraform plan evaluation without policy unit tests have deployed Conftest configurations that silently approved configurations they were intended to block — same policy content correctness gap confirmed in CI/CD context.

## The Add-On: `opa-governance-enforcer`
Policy correctness enforcer and decision log auditor. Validates policy test suite exists and passes (opa test); validates policies in version control; validates bundle signing; monitors decision log for unexpected allow decisions; produces `opa_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| policy_evaluation | **ACTIVE** | Decision constitutive; policy correctness separate gap |
| api_authorization | **ACTIVE** | Request denied before processing |
| data_filtering | **ACTIVE** | Query results filtered constitutively |
| terraform_plan_evaluation | **ACTIVE** | Plan denied before apply |
| bundle_management | CRYSTALLIZED | Bundle signing verifies integrity |
