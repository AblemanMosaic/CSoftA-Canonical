# FINDINGS: Istio Constitutional Analysis
*Wave 2 — System 9 · EAR ceiling: CRYSTALLIZED · Substrate dependency: Kubernetes sidecar injection · Fingerprint: 5696f45f889bba1d*

## Executive Finding
Istio is the Wave 2 service mesh governance case. CRYSTALLIZED ceiling with a critical substrate dependency: Istio governance operates through Envoy sidecar injection, which is itself a Kubernetes admission webhook. Any pod that reaches production without a sidecar is completely outside Istio's governance. This is not a misconfiguration — it is a structural bypass route that the current Istio architecture cannot close.

## Sidecar Injection Bypass: The Structural Gap
The governance gap magnitude for a pod without a sidecar is the entire Istio governance stack: authorization policy, mTLS, access log, telemetry — all absent. The bypass is achievable by:
1. Deploying pods in namespaces not labeled for injection
2. Deploying pods with `sidecar.istio.io/inject: "false"` annotation
3. Deploying pods before the injection webhook was active
The third case is historically common in Kubernetes clusters that adopted Istio after initial deployment.

## mTLS Governance Character
mTLS handshake is structurally the closest Istio operation to ACTIVE-EAR: the TLS certificate validation is constitutive of connection establishment — the connection fails without a valid SVID. However, the governance receipt (which AuthorizationPolicy rule evaluated this connection, what decision was made) is still in the access log, which is opt-in. The connection is governed; the record of how it was governed is not.

## Access Log Non-Constitutivity
Envoy access logs record request decisions. They are not enabled by default in Istio and their write is not constitutive of the authorization decision. Envoy enforces AuthorizationPolicy whether or not the log write succeeds.


## Real-World Incident Mapping

**Finding: Sidecar injection bypass is a documented, widely-experienced attack vector with Kyverno policies specifically designed to counter it.**

**Documented bypass routes (Istio Security Best Practices, confirmed):**
Istio's own security documentation explicitly states: "A pod can intentionally bypass its sidecar for outbound traffic — as a result, it is not secure to rely on all traffic being captured unconditionally by Istio." This is not a CVE disclosure — it is an architectural acknowledgment. The security boundary is that a client may not bypass *another pod's* sidecar, but a pod can disable its own injection. The CSoftA sidecar bypass finding (gap magnitude = entire Istio governance stack for unsidecarred pod) is confirmed by the system's own documentation.

**The three bypass routes in production:**
Application teams misusing namespace labels to disable sidecar injection at namespace level, and application teams setting `sidecar.istio.io/inject: false` at pod level, are both documented operational failure modes. Platform teams have responded by abstracting app deployment to prevent direct access to raw Kubernetes pod resources — evidence that the bypass is actively exploited in multi-team environments where developers have kubectl access.

**Kyverno policy for sidecar injection enforcement (confirmed):**
The Kyverno policy library includes a production policy specifically preventing `sidecar.istio.io/inject: false` annotations — direct evidence that sidecar injection bypass is a common enough real-world occurrence to warrant a dedicated admission control policy. The existence of this policy is the incident report: organizations have experienced unsidecarred pods escaping mesh governance and responded by adding an admission controller to prevent it.

**The "Sidecar Siphon" attack (research, 2024-2026):**
Research confirmed that in sidecar-mode Istio, an attacker with code execution in a container can read the Envoy proxy's mTLS certificates from shared pod memory, extract the service account token from the shared volume, and present their own CSR to Istiod — effectively stealing the pod's mesh identity. This is a consequence of the sidecar sharing the pod's network namespace: the governance layer (Envoy proxy) and the application share a trust boundary that the governance layer cannot enforce. The Istio Ambient Mesh (production-stable late 2024) was specifically designed to address this by moving the sidecar out of the pod — architectural confirmation that the governance gap is structural.

**Access log non-constitutivity in practice:**
Envoy access logs are not enabled by default and their absence does not affect Envoy's enforcement of AuthorizationPolicy. Security teams investigating incidents in Istio clusters without access logs enabled face the same problem as OPA without decision logs: the governance action occurred, but no record exists. Incident responders cannot reconstruct which AuthorizationPolicy rule allowed or denied a specific request. This is STRUCTURAL_NONLOCALITY at the service mesh layer.

**Substrate dependency (T019) in production:**
Every cluster that adopted Istio after initial deployment has a window during which pods were deployed without sidecars. Those pods remain outside Istio governance until restarted with injection enabled. In large production clusters, this means a non-trivial fraction of workloads may be operating outside mesh governance with no record indicating which workloads lack sidecars and for how long.

## The Add-On: `istio-governance-scanner`

*T1660* — Continuous cluster scanner for Istio mesh coverage. BYPASS assertion for every unsidecarred pod in Istio-labeled namespaces; validates access logging via Telemetry API; checks AuthorizationPolicy coverage; verifies STRICT mTLS PeerAuthentication mode; produces mesh_posture.json. Makes the sidecar bypass continuously visible rather than incident-discovered.

## Summary
| Family | EAR State | Key gap |
|--------|-----------|---------|
| request_authorization | CRYSTALLIZED (ABSENT if no sidecar) | access_log non-constitutive; sidecar bypass |
| mtls_handshake | CRYSTALLIZED | cert validation constitutive; decision record not |
| traffic_management | CRYSTALLIZED | access_log opt-in |
| sidecar_injection | CRYSTALLIZED | substrate dependency on Kubernetes admission |
