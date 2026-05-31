# FINDINGS: OPA Constitutional Analysis
*Wave 2 — System 6 · EAR ceiling: CRYSTALLIZED · Fingerprint: 03d6372bc582c267*

## Executive Finding
OPA is the canonical policy engine governance case. It demonstrates the ceiling that all three Wave 2 policy engines share: CRYSTALLIZED. Decision logging exists as a mechanism, is not enabled by default, and is structurally non-constitutive — OPA evaluates and returns a decision whether or not the log write succeeds.

## Primary Gap: Decision Log Non-Constitutivity
The decision log records what OPA decided. It does not govern whether OPA decides. This is the GCG three-condition conjunction exactly: N=2 (policy_package + decision_log), k=1 when log is enabled, k=0 when not. Gap form: NON_ACTIVATION when deployed without log config; ABSENCE when log explicitly disabled.

## Policy Version Gap
Even with logging enabled, the link between a specific decision and the exact policy version that produced it is fragile. Policy bundles activate with an ID but the decision log entry's policy version binding is advisory. An administrator can update a bundle without the decision log clearly reflecting which version of a rule was applied at evaluation time.

## Governance Technology Recursion
OPA is governance technology that has governance gaps in its own operation. The GCG framework applies to OPA itself. This is the Wave 2 insight: systems whose declared purpose is governance have EAR states that must be analyzed the same way as any other software system.


## Real-World Incident Mapping

**Finding: OPA decision log non-constitutivity is experienced as a debugging crisis.**

The security community has independently diagnosed the same problem CSoftA classifies structurally. OPA's own documentation confirms the CRYSTALLIZED finding: OPA evaluates and returns decisions whether or not any logging infrastructure is configured. If OPA starts with no policies loaded, it returns `undefined` to all queries — the operation completes whether or not governance is active.

Practitioners describe the operational consequence directly: without deep visibility into policy decisions, engineers face guesswork rather than insight. Debugging OPA in production without decision logs enabled is a documented pain point that has driven an entire ecosystem of observability tooling — tools that exist precisely because OPA's default deployment leaves no record of what it decided.

**The audit trail gap in practice:** The policy version binding gap in the decision log is operationally significant. When a policy bundle is updated and a previously-allowed request is suddenly denied, operators without policy version tracking in their decision log cannot determine which version of which rule changed the outcome. This is STRUCTURAL_NONLOCALITY recoverability expressed as an operational incident: the governance state cannot be reconstructed from OPA's own artifacts alone.

**The "undefined on startup" edge case** is a direct expression of the ABSENT classification: OPA deployed without a policy bundle loaded returns `undefined` to all queries. If the calling service treats `undefined` as `allow` (a common pattern), all governance is absent for that service until the bundle loads. This is not a CVE — it is documented behavior. Its constitutional classification is Layer Absence with gap magnitude equal to the entire declared governance stack.

**Governance technology recursion confirmed:** CSoftA applied to OPA reveals that governance technology has governance gaps in its own operation. The GCG three-condition conjunction applies to OPA itself: N declared (decision_log + policy_package), k < N when log is not configured, no non-participation record. The finding is structural, not configurational.

## The Add-On: `opa-governance-enforcer`

*T1657* — Sidecar and deployment gate enforcing OPA constitutional completeness. Validates --decision-log-path before allowing traffic; wraps decision endpoint to verify log entry before forwarding (making log write constitutive); produces policy_posture.json per bundle activation; blocks activations without version identifiers. fail_closed_on_log_error moves OPA toward ACTIVE.

## Summary
| Family | EAR State | Key gap |
|--------|-----------|---------|
| policy_evaluation | CRYSTALLIZED (ABSENT if no log) | decision_log non-constitutive |
| bundle_activation | CRYSTALLIZED | activation_receipt absent |
| policy_management | CRYSTALLIZED | no mandatory admin audit |
| data_write | CRYSTALLIZED | no mandatory data change receipt |
