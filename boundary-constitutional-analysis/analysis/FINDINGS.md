# FINDINGS: Boundary Constitutional Analysis
*Wave 3 — System 15 · EAR ceiling: CRYSTALLIZED · Fingerprint: `fbb184dfbf411e82`*

## Executive Finding
HashiCorp Boundary is Wave 3's clearest CRYSTALLIZED case. Session authorization is CRYSTALLIZED: Boundary issues tokens, records sessions, and logs access events, but session establishment does not depend on the session record being durably written before access is granted — contrast with Teleport's strict recording mode. The distinction is precise and consequential: Boundary records what happened; Teleport (strict mode) requires the record to exist before the session proceeds.

## The Boundary/Teleport Constitutional Comparison
Boundary and Teleport solve the same problem (identity-based infrastructure access) with different constitutional commitments. Teleport's strict session recording is a governance prerequisite — the session does not exist without the recording. Boundary's session record is a governance artifact — the session exists regardless of whether the record is successfully written. This places Boundary at CRYSTALLIZED and Teleport (strict) at ACTIVE for the equivalent operation family.

## Vault Integration: Upstream Governance Inheritance
Boundary's credential brokering via Vault Credential Libraries inherits Vault's ACTIVE-EAR for the credential fetch. When Boundary brokers a dynamic database credential from Vault, Vault's audit log constitutively records the credential issuance. Boundary's own governance of the brokering operation is CRYSTALLIZED, but the combined governance quality includes Vault's ACTIVE receipt upstream. This is the same upstream governance inheritance pattern as External Secrets Operator syncing from Vault.

## Real-World Incident Mapping
Boundary CVE-2023-3462 (OIDC AMP bypass): under specific conditions, OIDC authentication could be bypassed allowing unauthenticated access. The auth_token layer appeared active; the oidc_token verification scope was insufficient for the specific flow. NON_ACTIVATION form — governance layer present but evaluation incomplete.

## The Add-On: `boundary-session-receipt-enforcer`

*T1666* — Session proxy moving Boundary governance toward constitutive. Binds session ID to expected TLS certificate hash (closes CVE-2024-1052 class); validates KMS encryption for credential writes (plaintext storage gap); verifies Vault connectivity before brokered sessions; produces boundary_session_posture.json with upstream governance inheritance per T1613. Moves Boundary toward Teleport strict model: receipt as prerequisite, not artifact.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| session_authorization | CRYSTALLIZED | Session record non-constitutive |
| credential_brokering | CRYSTALLIZED (Vault: ACTIVE upstream) | Vault governs fetch; Boundary governs brokering |
| user_authentication | CRYSTALLIZED | Auth token constitutive; audit opt-in |
| target_management | CRYSTALLIZED | No mandatory change audit |
