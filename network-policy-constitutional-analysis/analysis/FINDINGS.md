# FINDINGS: Kubernetes NetworkPolicy Constitutional Analysis
*Wave 7 — System 32 · EAR ceiling: CRYSTALLIZED · Default: ABSENT · Fingerprint: `2d0a562f1421f8df`*

## Executive Finding
Kubernetes NetworkPolicy is the network segmentation governance case. Default Kubernetes: all pods can reach all pods — ABSENT network governance. NetworkPolicy resources declare allowed traffic patterns, but enforcement requires a CNI plugin that implements the policy (Calico, Cilium, Weave, Antrea, etc.). Without a NetworkPolicy-capable CNI, NetworkPolicy objects exist as declarations but are completely unenforced — the same structural dependency as Istio sidecar injection (T1601).

Even with CNI enforcement, traffic decisions are made but not constitutively receipted per flow. A denied connection attempt produces no governance record by default — the deny happened but was not logged. Flow logging (Cilium Hubble, Calico flow logs) is opt-in and required to make the governance record queryable.

## The CNI Dependency Analogy (T019 Pattern)
NetworkPolicy's governance ceiling is bounded by the CNI plugin's own governance. A Calico or Cilium misconfiguration can invalidate all NetworkPolicy enforcement. This is the T019 substrate dependency pattern: NetworkPolicy governance is bounded by CNI governance, which is bounded by the Kubernetes node network configuration.

The constitutional finding: NetworkPolicy declares the governance intent, but the CNI is the execution layer. If the CNI is not installed, all policies are no-ops. If the CNI is installed but misconfigured, policies may be selectively enforced. The gap between the governance declaration (NetworkPolicy CRD) and the governance execution (CNI kernel-level enforcement) is the constitutional surface.

## Real-World Incident Mapping
Container escape and lateral movement within Kubernetes clusters is a well-documented attack pattern. Attackers who compromise one pod in a namespace without NetworkPolicy can reach any other pod in the cluster on any port. Security researchers have demonstrated complete cluster compromise starting from a single compromised pod in clusters without network segmentation.

CVE-2023-3955 and CVE-2023-3676 (Kubernetes node privilege escalation): these vulnerabilities allowed containers to escape to the host node. In a cluster with NetworkPolicy, the escaped container would still be subject to host-level networking; in a cluster without NetworkPolicy, lateral movement to any pod is trivially possible before the escape.

## The Add-On: `network-policy-governance-enforcer`
CNI enforcement validator and network segmentation auditor. Verifies CNI enforcement active; validates default-deny policies present in all non-system namespaces; enables flow logging; audits for pods without any NetworkPolicy coverage; produces `netpol_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| ingress_control | ABSENT / CRYSTALLIZED | CNI required; flow log opt-in |
| egress_control | ABSENT / CRYSTALLIZED | All-allow default; egress rarely restricted |
| policy_declaration | CRYSTALLIZED | RBAC-governed; no change receipt |
| namespace_isolation | ABSENT / CRYSTALLIZED | Default-deny requires explicit configuration |
| flow_audit | ABSENT / CRYSTALLIZED | Flow logging requires CNI support + config |
