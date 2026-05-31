# FINDINGS: Falco Constitutional Analysis
*Wave 5 — System 25 · kernel_module_load: ACTIVE · syscall_detection: CRYSTALLIZED · Fingerprint: `eeb233194100c6ab`*

## Executive Finding
Falco is the corpus's second meta-governance case after OpenTelemetry (Wave 4). It monitors runtime behavior and generates security alerts, but the governance of Falco's own detection decisions is CRYSTALLIZED. The security alert is generated after the governed event occurs — the event happens whether or not the alert is generated. This is CRYSTALLIZED by architecture: Falco observes and reports, but does not prevent or constitute.

The kernel module load is ACTIVE: if Falco cannot load its kernel module or eBPF probe, it fails to start — constitutive of monitoring availability. But this governs Falco's availability, not its detection decisions per event.

New constitutional concept: **the security alert as a governance receipt**. An alert records that a governed event occurred. But unlike a Stripe Event (which cannot be suppressed by the caller) or a SPIFFE SVID (which is constitutive of access), a Falco alert can be missed, dropped, delayed, or evaded. The alert follows the event rather than constituting it.

## The Alert Delivery Gap
Alert delivery is CRYSTALLIZED: Falco generates alerts and routes them to output sinks (stdout, file, webhook, gRPC), but delivery to the sink may fail. A dropped alert has no meta-alert recording that the drop occurred. This is the same meta-governance gap as OpenTelemetry's silent span drops — the governance evidence gap is itself ungoverned.

## Kernel Bypass: The Structural Evasion Gap
A container with `CAP_SYS_PTRACE` capability can attach to its own process and manipulate its syscall stream, potentially evading Falco's kernel-level detection. Falco's detection is based on what the kernel module observes — if the observed events are manipulated, the detection is incomplete. This is a structural BYPASS gap: the attacker has a declared capability (ptrace) that bypasses the governance layer.

## Real-World Incident Mapping
Container escape attacks targeting monitoring evasion: documented attack patterns specifically disable or evade Falco as a first step, precisely because its detection layer is CRYSTALLIZED — disabling alert delivery achieves monitoring absence with no meta-alert. Attackers who can delete Falco pods, exhaust Falco's output queue, or kill the Falco process achieve governance absence. The CRYSTALLIZED classification predicts exactly this attack pattern.

Falco rule bypass via namespace manipulation: attackers have exploited Falco rule conditions that check container namespaces — by creating containers in specific namespace configurations, rules that check `container.namespace` conditions can be made to not match. NON_ACTIVATION: the rule was present but the matching condition was insufficiently scoped.

The ptrace evasion is confirmed as a documented technique: security researchers have demonstrated that containers with elevated capabilities can manipulate their syscall stream to evade Falco's detection. The kernel bypass BYPASS gap is not theoretical.

## The Add-On: `falco-governance-auditor`
Meta-governance layer for Falco's own operation. Monitors Falco pod health and alert delivery queue depth; produces meta-alerts when Falco drops alerts or fails to deliver to sinks; validates rule version and hash on every reload; monitors for attempts to disable Falco (pod deletion, signal injection); produces `falco_posture.json` with detection coverage assessment and rule version history.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| syscall_detection | CRYSTALLIZED | Alert follows event; event occurs regardless |
| alert_delivery | CRYSTALLIZED | Delivery may fail; no meta-alert for drop |
| rule_management | CRYSTALLIZED | Rule changes not mandatorily receipted |
| kernel_module_load | **ACTIVE** | Constitutive of monitoring availability |
| container_monitoring | CRYSTALLIZED | Structural ptrace bypass exists |
