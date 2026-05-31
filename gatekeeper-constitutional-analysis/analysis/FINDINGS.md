# FINDINGS: Gatekeeper Constitutional Analysis
*Wave 2 — System 7 · EAR ceiling: CRYSTALLIZED · Substrate dependency: Kubernetes · Fingerprint: dc5e6d6a0bd7fb41*

## Executive Finding
Gatekeeper is OPA embedded in Kubernetes via admission webhook. It inherits OPA's CRYSTALLIZED ceiling and adds a substrate dependency: Gatekeeper's governance completeness is bounded by Kubernetes admission governance completeness (T019 substrate precedence). A Kubernetes cluster with admission controller gaps also has Gatekeeper gaps.

## Primary Gap: Violation Record Non-Constitutivity
Gatekeeper records violations on constraint `.status.violations`. This is a record, not a receipt — the admission webhook returns ALLOW or DENY to the Kubernetes API server regardless of whether the violation status write succeeds. If the SPOF (Gatekeeper pod crash) causes violation record writes to fail, the API server may fall back to a default admission behavior (controlled by `failurePolicy`), but the violation record gap is structural.

## Substrate Dependency (T019)
If Kubernetes admission controllers are incomplete — missing PSS enforcement, no NetworkPolicy audit, no secondary admission webhooks — then Gatekeeper operates on a substrate that itself has governance gaps. Gatekeeper cannot exceed the governance quality of the Kubernetes admission layer it sits on.

## Audit Scan Gap
The periodic audit scan (`--audit-interval`) checks existing resources against constraints, but:
1. It runs on a schedule, not on every resource state change
2. Audit results are on constraint `.status.violations`, not in a structured audit log
3. Resources created between audit intervals may violate policies without being recorded


## Real-World Incident Mapping

**Finding: The Gatekeeper bypass playbook is documented and actively exploited.**

**Prefix matching bypass (February 2025, AquaSec):** A widely-deployed Gatekeeper ConstraintTemplate restricting container images to specific registries was bypassed because the allowed registry pattern `my-ecr.azurecr.io` was not terminated with `/`. An attacker registering `my-ecr.azurecr.io.attacker.com` could host malicious images that passed the prefix check. The policy appeared to be enforced — constraint objects showed no violations — while the governance gap was structurally present. This is the GCG NON_ACTIVATION form: the constraint_template layer was present and declared applicable, but the policy evaluation logic produced k < N with no record of the gap.

**The documented bypass playbook:** The attack surface for admission controller bypass is publicly documented and well-known: ephemeral containers, CronJob escalation, webhook DoS, and exempt namespace abuse. Exempt namespaces without RBAC restriction are a particularly common production failure mode — organizations add namespace exemptions during testing and never remove them, creating permanent governance gaps that are invisible to constraint violation monitoring because the exempt namespaces produce no violations by design.

**Webhook DoS → failurePolicy gap:** If the Gatekeeper webhook pod crashes or becomes unreachable, Kubernetes falls back to the `failurePolicy` setting. Many production deployments set `failurePolicy: Ignore` to prevent Gatekeeper outages from blocking all cluster operations. The result: any period of Gatekeeper unavailability becomes a governance gap with no record. This is structurally identical to Vault's audit device failure behavior — except Vault fails closed (stops serving requests) while Gatekeeper with `failurePolicy: Ignore` fails open (admits all requests).

**Audit scan periodicity gap in practice:** The periodic audit scan gap produces a real operational problem: an attacker who creates a violating resource and then quickly modifies or deletes it may not appear in the violation record if the modification occurs between audit intervals. Gatekeeper's constraint `.status.violations` reflects the state at the last audit, not the history of all states. This is the STRUCTURAL_NONLOCALITY recoverability finding: the governance record cannot reconstruct what happened between audit runs.

**Substrate dependency (T019) confirmed:** Kubernetes admission controller governance completeness is itself bounded, and Gatekeeper inherits those bounds. Every Kubernetes admission governance gap (missing PSS, no NetworkPolicy audit) is also a Gatekeeper gap — Gatekeeper cannot enforce policies that Kubernetes's own admission layer has already allowed to pass.

## The Add-On: `gatekeeper-constitutional-auditor`

*T1658* — Continuous operator monitoring Gatekeeper's own governance health. Monitors failurePolicy (BYPASS assertion if Ignore); watches Gatekeeper pod availability; tests constraint boundary conditions automatically (prefix/suffix bypass class); tracks audit scan timestamps; produces gatekeeper_posture.json. Governs the governance technology.

## Summary
| Family | EAR State | Key gap |
|--------|-----------|---------|
| admission_evaluation | CRYSTALLIZED | violation_record non-constitutive; audit_log opt-in |
| audit_scan | CRYSTALLIZED | scheduled, not continuous; no structured log |
| constraint_management | CRYSTALLIZED | no mandatory change audit |
| mutation | CRYSTALLIZED | no receipt of what mutation was applied |
