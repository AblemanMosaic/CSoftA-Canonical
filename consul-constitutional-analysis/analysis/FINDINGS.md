# FINDINGS: Consul Constitutional Analysis
*Wave 3 — System 13 · Connect: ACTIVE · ACL (Enterprise): CRYSTALLIZED · Fingerprint: `64b81b25e1b19c94`*

## Executive Finding
Consul has the most complex governance profile in Wave 3. Its governance quality varies radically by feature tier and deployment type: Connect certificate issuance is ACTIVE (SVID constitutive, Consul implements SPIFFE), ACL authorization is CRYSTALLIZED in Enterprise and ABSENT in open source, and the audit log is an Enterprise-only feature entirely absent from the open-source version. The constitutional finding: open-source Consul's governance ceiling is ABSENT for most administrative operations.

## The Enterprise/OSS Constitutional Divide
The audit log in Consul is not a missing feature in the open-source version — it is a deliberate product boundary. Open-source Consul users have no structured audit log for ACL decisions, KV operations, or service registrations. This is not a configuration gap; it is an architectural gap that cannot be closed without the Enterprise license. The constitutional classification is ABSENT for audit_log in all open-source deployments, making open-source Consul's administrative operations ungoverned in the Wave 1/2 sense.

## Connect Certificate: ACTIVE (Same Pattern as SPIFFE/SPIRE)
Consul Connect implements the SPIFFE specification. Certificate issuance via the Connect CA is constitutive of mesh membership — a service cannot participate in the Connect mesh without a valid SVID. The SVID is the receipt. This is the same constitutional pattern as SPIFFE/SPIRE svid_issuance and reaches ACTIVE for the same reason.

## Real-World Incident Mapping
CVE-2020-13250: Consul ACL bypass via crafted JWT tokens — ACL enforcement was bypassed by constructing JWT tokens with specific claim structures. The constitutional finding: acl_policy was declared applicable and appeared active, but the policy evaluation logic had a scope boundary that was exploitable — the same NON_ACTIVATION pattern as Kyverno CVE-2023-34091.

## The Add-On: `consul-constitutional-auditor`

*T1664* — Proxy compensating for OSS Consul audit log absence. Sits in front of Consul HTTP API recording all ACL-bearing requests (closes product-boundary ABSENT gap); normalizes L7 intention paths before evaluation (CVE-2024-10005 class); validates SAN URI count on Connect CSRs (CVE-2022-40716 class); produces consul_posture.json distinguishing OSS (ABSENT) vs Enterprise (CRYSTALLIZED) for audit families.

## Summary
| Family | EAR State (OSS) | EAR State (Enterprise) |
|--------|----------------|----------------------|
| connect_certificate | **ACTIVE** | **ACTIVE** |
| acl_authorization | ABSENT | CRYSTALLIZED |
| service_registration | ABSENT | CRYSTALLIZED |
| intention_enforcement | CRYSTALLIZED | CRYSTALLIZED |
| kv_operation | ABSENT | CRYSTALLIZED |
