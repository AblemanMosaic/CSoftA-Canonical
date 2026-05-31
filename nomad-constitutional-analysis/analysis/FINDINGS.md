# FINDINGS: HashiCorp Nomad Constitutional Analysis
*Wave 15 — System 74 · EAR ceiling: CRYSTALLIZED · Fingerprint: `e8c3666122b4a1dc`*

## Executive Finding
Nomad is the Kubernetes alternative for multi-runtime workload orchestration, supporting containers, VMs, Java JARs, and raw executables in a single scheduler. Its governance model uses namespace-based HCL ACL policies (community) or Sentinel policies (enterprise) rather than K8s RBAC. The default configuration has ACL disabled — any agent can submit jobs without authentication.

CVE-2025-1296 (March 2025) introduces a particularly pointed constitutional finding: workload identity tokens and client secret tokens were exposed in audit logs. The governance receipt (the audit log) became the credential exposure surface. This is a new gap form: the audit evidence itself contains the credential material it was supposed to protect governance evidence about. The audit log is both the governance evidence AND the attack surface.

CVE-2025-4922 (June 2025): prefix-based ACL policy lookup leads to policy shadowing — a job matching the prefix of another policy's namespace may receive incorrect ACL policies. NON_ACTIVATION at the ACL policy lookup boundary. CVE-2024-12678: unredacted workload identity tokens in allocation metadata allow privilege escalation within namespace. CVE-2025-3744 (Enterprise): Sentinel policy override option bypasses mandatory sentinel policies.

The enterprise audit log follows the commercial governance paywalling pattern (T1784): structured audit logging for compliance requires Nomad Enterprise. Community edition has limited log output, not structured audit.

## The Add-On: `nomad-governance-enforcer`
ACL policy auditor and workload identity validator. Validates ACL enabled; validates TLS on all agent-to-server communication; validates namespace isolation configured; monitors for workload identity token exposure in logs; produces `nomad_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| job_submission | ABSENT (default) / CRYSTALLIZED (ACL) | Default: no ACL |
| job_execution | ABSENT (default) / CRYSTALLIZED (ACL) | CVE-2024-12678 workload token class |
| secret_access | CRYSTALLIZED | Vault integration via workload identity |
| acl_management | CRYSTALLIZED | CVE-2025-4922 ACL policy shadowing class |
| volume_management | CRYSTALLIZED | CVE-2024-10975 cross-namespace volume class |
