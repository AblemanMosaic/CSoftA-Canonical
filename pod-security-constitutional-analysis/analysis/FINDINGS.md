# FINDINGS: Kubernetes Pod Security Admission Constitutional Analysis
*Wave 10 — System 50 · psa_enforce (labeled namespaces): ACTIVE · Default: ABSENT · Fingerprint: `1ba5f066ed462e1e`*

## Executive Finding
Pod Security Admission (PSA) is the final Kubernetes workload security governance primitive — it completes the K8s workload security layer alongside RBAC (T1742, who submits), admission controllers (T1748, what is valid), and PSA (what security profile workloads must comply with). PSA in `enforce` mode is ACTIVE: pods that violate the selected profile (privileged/baseline/restricted) cannot be created. Default Kubernetes: no namespace PSA labels = privileged profile = all pods admitted = ABSENT enforcement.

PSA `restricted` profile prevents the container escape vectors that have been exploited in documented attacks: privileged containers, hostPath mounts, hostNetwork, hostPID, hostIPC. These are not theoretical risks — they are the attack surfaces used in container escape CVEs.

## Profile Level Governance
PSA has three profiles — privileged (no restrictions), baseline (prevents known privilege escalations), restricted (hardened, deny-by-default security). The governance gap: choosing the right profile per namespace requires understanding which workloads run there. Most organizations run applications in `baseline` profiles because `restricted` requires explicit seccomp profiles and drops all capabilities. The profile level choice is CRYSTALLIZED: reviewed and labeled, but the review is not constitutive of correct profile selection.

## Real-World Incident Mapping
Container escape via privileged containers (multiple CVEs 2019-2025): CVE-2019-5736 (runc), CVE-2020-15257 (containerd), CVE-2022-0185 (Linux kernel via pod hostnamespace). PSA `restricted` profile prevents privileged container creation — would have blocked the attack vector for these CVEs. KENSAI cluster audit: many clusters run application workloads in namespaces without PSA labels — ABSENT enforcement for all pods. Red team assessments routinely find privileged pods in production namespaces that are not needed to be privileged.

## The Add-On: `pod-security-governance-enforcer`
Namespace PSA label auditor and profile recommendation engine. Validates all application namespaces have PSA labels; identifies namespaces running privileged workloads without justification; recommends profile upgrades (privileged→baseline→restricted); monitors for PSA violations in audit/warn mode; produces `psa_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| pod_admission | ABSENT (default) / ACTIVE (enforce labeled) | No namespace labels = ABSENT |
| privileged_restriction | ACTIVE (enforce) / ABSENT | Prevents privileged container creation |
| escape_prevention | ACTIVE (enforce) / ABSENT | Prevents hostPath/hostNetwork/hostPID |
| profile_governance | CRYSTALLIZED | Profile selection reviewed, not constitutive |
| seccomp_enforcement | ACTIVE (enforce restricted) / CRYSTALLIZED | Restricted profile requires seccomp |
