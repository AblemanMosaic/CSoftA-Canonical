# D3 Classification: Kubernetes

*CSoftA D3 Corpus Classification Protocol (T002)*
*Version: 1.0 — 2026-05-29*

---

## Commit Point

**Primary commit point:** API server persistence to etcd.

A Kubernetes operation commits when the API server writes the state
change to etcd. The admission chain (RBAC → mutating webhooks →
validating webhooks → PSS → etcd write) executes before the commit
point. The audit record is written as part of the admission pipeline.

**Commit point visibility:** MEDIUM. The audit log records before and
after the commit; the admission chain's intermediate decisions are
partially visible (RBAC reason field) and partially invisible (webhook
decisions not uniformly recorded).

---

## Recoverability Regime

**API server layer: COMPOSITIONAL**
Audit log + RBAC policies + admission webhook configs together describe
the governance topology. No single artifact contains the complete
governance trace.

**Node execution layer: STRUCTURAL_NONLOCALITY**
Container processes running on nodes are outside API server governance.
Node-level audit (auditd, Falco) is a separate system not integrated
into the Kubernetes governance chain.

**Control plane: COMPOSITIONAL**
etcd, kube-scheduler, kube-controller-manager each have their own
governance surfaces not unified with the API server audit chain.

---

## EAR State by Operation Family

| Operation Family    | EAR State    | Reason                                           |
|---------------------|--------------|--------------------------------------------------|
| pod_create          | CRYSTALLIZED | Audit records request; non-participation absent  |
| pod_privileged_create | CRYSTALLIZED | Same; PSS and admission typically absent         |
| secret_read         | CRYSTALLIZED | RBAC + audit; no additional layers applicable    |
| rbac_escalation     | CRYSTALLIZED | RBAC + audit; admission often absent             |
| workload_create     | CRYSTALLIZED | RBAC + audit; PSS and admission often absent     |

No operation family reaches ACTIVE-EAR. Kubernetes cannot produce a
complete governance participation receipt for any operation.

---

## Jurisdiction Boundaries

**JD-1: etcd (primary)**
- Location: Between API server and etcd
- Governance consequence: Direct etcd access bypasses all Kubernetes
  governance; etcd encryption is separate from admission governance
- Severity: CRITICAL — direct etcd access = unbounded bypass

**JD-2: Container runtime (containerd/CRI-O)**
- Location: Between kubelet and container runtime
- Governance consequence: Container runtime executes workloads;
  its internal behavior is outside Kubernetes governance
- Severity: HIGH — runtime vulnerabilities bypass namespace isolation

**JD-3: Admission webhooks (external)**
- Location: Between API server and webhook service
- Governance consequence: Webhook's internal decision logic is outside
  Kubernetes audit; webhook failures may silently allow requests
- Severity: MEDIUM — webhook failure modes affect governance completeness

**JD-4: Cloud provider (managed Kubernetes)**
- Location: Between cluster and cloud control plane (EKS, GKE, AKS)
- Governance consequence: Cloud provider manages control plane components;
  their governance is not integrated with cluster-level audit
- Severity: MEDIUM — cloud provider access is a separate JD

---

## Structural Observations

**Kubernetes is the GCG framework's origin system.**
The three core GCG instances (PCM-0333-023) are Kubernetes (TARGET R),
Docker (TARGET R), and SolarWinds Orion. This analysis cross-validates
the GCG codex against its primary grounding system.

**This analysis advances the GCG codex from UNVALIDATED to VALIDATED.**
Cross-validation confirms: N=5 for pod_create, k=2 in default config
(RBAC + audit), gap magnitude=3. The canonical structural gap
(admission, PSS, NetworkPolicy absent without record) is confirmed.

**The gap is configurable but the non-participation record is not.**
Deploying webhooks + PSS Restricted + NetworkPolicy closes the participation
gap. But Kubernetes has no mechanism to produce a per-operation record
of which layers participated vs. did not — even in a fully hardened
cluster. The CRYSTALLIZED-EAR ceiling is architectural.
