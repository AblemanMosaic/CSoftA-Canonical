# FINDINGS: Linkerd Service Mesh Constitutional Analysis
*Wave 14 — System 67 · service_communication: ACTIVE · Fingerprint: `6d015915549c11ae`*

## Executive Finding
Linkerd provides the constitutional comparison to Istio (Wave 2, T1610). The primary governance distinction is injection mechanism and proxy implementation. Linkerd uses a Rust micro-proxy (linkerd2-proxy) injected via CNI plugin or initContainers — it does NOT rely on the Kubernetes admission webhook path for mTLS enforcement. Istio's governance ceiling is bounded by K8s admission governance (T1613) because mTLS depends on sidecar injection via admission webhook; Linkerd's mTLS is enforced independently of the admission webhook path.

`service_communication` between meshed pods is **ACTIVE**: mTLS is automatic, mandatory, and tied to the Kubernetes ServiceAccount identity via SPIFFE SVIDs. You cannot have a meshed service-to-service communication that is not mTLS-encrypted and ServiceAccount-authenticated. This is a stronger ACTIVE than Istio's permissive mode (which is CRYSTALLIZED by default).

The 2024 security audit (7ASecurity/OSTIF/CNCF) found no critical findings. Linkerd's total CVE count is 2 (resource exhaustion and HTTP/2 Rapid Reset) — a significantly lower attack surface than Istio, attributable to the Rust proxy's memory safety and smaller codebase.

## Linkerd vs Istio: Constitutional Comparison
| Property | Istio | Linkerd |
|---|---|---|
| Proxy language | C++ (Envoy) | Rust (linkerd2-proxy) |
| Injection mechanism | Admission webhook (K8s dependent) | CNI / initContainer |
| mTLS default | Permissive (CRYSTALLIZED) | Strict (ACTIVE for meshed) |
| Governance ceiling bounded by K8s admission? | Yes (T1613) | No |
| CVE count (corpus period) | Multiple | 2 |

## Real-World Incidents
CVE-2025-43915 (May 2025): proxy metrics resource exhaustion via crafted URLs — DoS, not a governance gap. Linkerd 2.19 (October 2025): post-quantum TLS (ML-KEM-768 / X25519 hybrid) — governance-forward evolution. The clean 2024 security audit validates the Rust proxy's architectural security advantage.

## The Add-On: `linkerd-governance-enforcer`
Mesh injection completeness auditor and AuthorizationPolicy validator. Validates all sensitive namespaces have Linkerd injection enabled; validates Server and HTTPRoute policies defined for critical services; validates cert-manager integration for certificate rotation; produces `linkerd_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| service_communication | **ACTIVE** | mTLS automatic + mandatory; no admission dependency |
| mtls_certificate | **ACTIVE** | Certificate issuance tied to ServiceAccount identity |
| authorization_policy | CRYSTALLIZED | MeshTLSAuthentication + HTTPRoute policies opt-in |
| ingress_governance | CRYSTALLIZED | External traffic not automatically meshed |
| mesh_observability | CRYSTALLIZED | Tap + Viz available; not enforcement |
