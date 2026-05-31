# FINDINGS: Teleport Constitutional Analysis
*Wave 3 — System 14 · session_establishment (strict): ACTIVE · certificate_issuance: ACTIVE · Fingerprint: `8e2bdb197bdfab08`*

## Executive Finding
Teleport is Wave 3's strongest governance case — the analog of Vault (Wave 1) and SPIFFE/SPIRE (Wave 2). Two operation families reach ACTIVE-EAR: certificate issuance (Teleport certificates are constitutive of access, same as SPIFFE SVIDs) and session establishment in strict recording mode (the session cannot be established if the recording backend is unavailable — the recording IS the governance receipt). Teleport's audit log is the most comprehensive structured access audit surface in the 15-system corpus.

## Why Session Establishment Is ACTIVE in Strict Mode
In Teleport's strict session recording mode, the session recording backend must be available before a session is established. If the recording backend is down, the session is not permitted — Teleport fails closed. The session recording is not a post-hoc log; it is a prerequisite for session establishment. This is the Vault pattern: the receipt write is constitutive of the operation. The session recording IS the receipt.

## Certificate Issuance: ACTIVE
Teleport short-lived certificates (typically 8-12 hours) are constitutive of resource access — no valid Teleport certificate means no access. The certificate encodes the user identity, roles, and access scope. Like SPIFFE SVIDs and cert-manager certificates, the credential is the receipt.

## The Strict vs Best-Effort Gap
The constitutional distinction between strict and best-effort recording is decisive. Best-effort recording means the session proceeds even if recording fails — governance is decoupled from the access event. Best-effort is CRYSTALLIZED. Strict is ACTIVE. The choice of recording mode is the single most important constitutional decision in a Teleport deployment.

## Real-World Incident Mapping
CVE-2024-9407 (Teleport): insufficient verification of JWT tokens in specific MFA flows allowed authentication bypass under specific conditions. The constitutional finding: user_authentication layer was declared and appeared active, but the verification scope was insufficient for one token type — NON_ACTIVATION at the authentication verification layer.

## The Add-On: `teleport-governance-enforcer`

*T1665* — Deployment gate enforcing strict session recording as prerequisite. BYPASS assertion for any cluster with best_effort or off recording; monitors certificate TTL; validates recording backend connectivity pre-session; monitors for CVE-2025-49825 class (SSH auth bypass); produces teleport_posture.json. Makes the strict/best_effort constitutional choice a hard gate — the single most important configuration decision in any Teleport deployment.

## Summary
| Family | EAR State (strict) | EAR State (best-effort) |
|--------|--------------------|------------------------|
| session_establishment | **ACTIVE** | CRYSTALLIZED |
| certificate_issuance | **ACTIVE** | **ACTIVE** |
| access_request | CRYSTALLIZED | CRYSTALLIZED |
| node_registration | CRYSTALLIZED | CRYSTALLIZED |
