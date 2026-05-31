# FINDINGS: Kubernetes RBAC Constitutional Analysis
*Wave 9 — System 41 · api_authorization: ACTIVE · Fingerprint: `1c0f339a0fe10190`*

## Executive Finding
Kubernetes RBAC is the authorization governance engine for every Kubernetes API operation. Every governance mechanism in the corpus that touches Kubernetes — Argo CD (Wave 5), Argo Workflows (Wave 8), Tekton (Wave 9), NetworkPolicy (Wave 7), ingress-nginx (Wave 6) — depends on RBAC for its access control. RBAC is the authorization substrate: api_authorization is ACTIVE (RBAC policy evaluation is constitutive of every API request), but the policy content governance is CRYSTALLIZED at best and ABSENT in practice.

KENSAI research (2026): analysis of 12,000 production Kubernetes clusters found that 58% contain RBAC misconfigurations enabling privilege escalation to cluster-admin. Average time from initial pod compromise to cluster-admin using automated tools: 3.2 minutes. This is not a vulnerability in RBAC — it is a governance gap in how RBAC is configured and maintained.

## The Privilege Escalation Primitive Set
Five RBAC permissions are sufficient for cluster-admin escalation when granted to an attacker:
- `create clusterrolebindings` — bind any ClusterRole (including cluster-admin) to any subject
- `bind` verb on roles — bind a ClusterRole without needing those permissions yourself
- `escalate` verb on roles — create Roles with permissions the creator doesn't have
- `impersonate` verb — make API requests as any user or ServiceAccount
- `pods/exec create` in kube-system — exec into control plane pods, extract credentials

These are governance-of-governance verbs: they govern the RBAC system itself.

## Real-World Incident Mapping
KENSAI 2026 research: 23% of clusters have custom ClusterRoles with wildcard (`*`) verbs or resources. Clusters with wildcard read permissions exposed an average of 847 Kubernetes Secrets. MITRE ATT&CK T1098 (Account Manipulation): documented attacker technique for modifying RBAC bindings to maintain or escalate access. Sysdig 2025 usage report: machine identities outnumber humans 40,000 to 1 in cloud-native environments — every machine identity carries RBAC permissions most teams never review. Multiple red team assessments confirm that stale RoleBindings for decommissioned workloads persist indefinitely, providing persistent escalation paths.

## The Add-On: `rbac-governance-enforcer`
RBAC policy auditor and escalation path detector. Detects wildcard permissions; identifies escalation paths from any subject to cluster-admin; flags dangerous verbs (bind, escalate, impersonate); removes stale bindings for deleted ServiceAccounts; produces `rbac_posture.json` with per-subject escalation risk score.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| api_authorization | **ACTIVE** | RBAC constitutive of every API request |
| role_management | CRYSTALLIZED | Policy created; content not constitutively governed |
| binding_management | CRYSTALLIZED | Bindings created; scope often too broad |
| serviceaccount_governance | CRYSTALLIZED | SA tokens long-lived by default |
| rbac_audit | CRYSTALLIZED | Audit optional; escalation paths accumulate silently |
