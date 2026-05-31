# FINDINGS: Kubernetes Admission Controllers Constitutional Analysis
*Wave 10 — System 48 · failurePolicy:Fail: ACTIVE · failurePolicy:Ignore: ABSENT · Fingerprint: `0a4619eb593054b4`*

## Executive Finding
Kubernetes Admission Controllers are the final governance enforcement boundary for all resource creation and modification. This analysis synthesizes the admission webhook patterns across the corpus: Gatekeeper (Wave 2, T1658), Kyverno (Wave 2, T1659), ingress-nginx annotation validation (Wave 6, T1688), Cosign policy-controller (Wave 8, T1725), Argo CD (Wave 5, T1669).

The constitutional property that determines ACTIVE vs ABSENT: `failurePolicy`. A webhook with `failurePolicy: Fail` is ACTIVE — resources violating policy cannot be created, even if the webhook is unavailable. A webhook with `failurePolicy: Ignore` is ABSENT — if the webhook fails (network error, timeout, webhook pod restart), the resource is admitted without policy evaluation. This is the BYPASS gap form: the governance mechanism failure produces governance absence.

## The failurePolicy Gap is Pervasive
Most Kubernetes distributions and operators default to `failurePolicy: Ignore` for admission webhooks to avoid cluster disruption from webhook outages. This is operationally pragmatic but constitutionally ABSENT: any scenario that causes the webhook to be unavailable (rolling update, network partition, pod eviction) allows resources to bypass governance during that window.

## Real-World Incident Mapping
OPA Gatekeeper bypass via webhook outage (documented in multiple security assessments): attackers or misconfigured deployments that caused the Gatekeeper webhook to be unavailable allowed resources that would normally be rejected. With `failurePolicy: Ignore`, the cluster admitted the resources without policy evaluation — confirmed BYPASS gap.

Cosign policy-controller bypass via webhook restart: when policy-controller pod restarts (e.g., during node maintenance), a brief window exists where images can be deployed without signature verification. This is the same BYPASS class — the ACTIVE supply chain closure (T1739) becomes ABSENT during the webhook restart window.

## The Add-On: `admission-webhook-governance-enforcer`
Webhook configuration auditor. Validates all critical webhooks use `failurePolicy: Fail`; validates webhook endpoint TLS certificates current; monitors webhook availability; alerts on webhook downtime; produces `admission_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| validating_admission | ACTIVE (Fail) / ABSENT (Ignore) | failurePolicy is the constitutional property |
| mutating_admission | ACTIVE (Fail) / ABSENT (Ignore) | Same failurePolicy analysis |
| policy_evaluation | ACTIVE (Fail) / ABSENT (Ignore) | OPA/Kyverno/CEL policy enforcement |
| webhook_governance | CRYSTALLIZED | Webhook config changes audited |
| supply_chain_enforcement | ACTIVE (Fail) / ABSENT (Ignore) | Cosign policy-controller |
