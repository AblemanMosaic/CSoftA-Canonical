# FINDINGS: SPIFFE/SPIRE Constitutional Analysis
*Wave 2 — System 10 · EAR: ACTIVE (svid_issuance, svid_rotation) / CRYSTALLIZED (admin) · Fingerprint: 1f7ef578746a90db*

## Executive Finding
SPIFFE/SPIRE is Wave 2's strongest governance case — the analog of Vault in Wave 1. svid_issuance is ACTIVE-EAR: workload attestation is constitutive of SVID issuance. SPIRE cannot issue an SVID without completing the attestation plugin chain. The SVID itself is the governance receipt — it cryptographically encodes the attested identity (SPIFFE ID), validity period, and issuing authority.

## Why svid_issuance Is ACTIVE
The three-condition conjunction for ACTIVE-EAR holds: N is declared (workload_attestation + node_attestation + svid_receipt), k = N when attestation succeeds, and the receipt (the SVID) is constitutively bound to execution — the SVID cannot be issued without completing attestation, and receiving a valid SVID IS the receipt of successful governance.

## Short-Lived SVIDs as a Governance Mechanism
Default SVID TTL of 1 hour means workloads must re-attest every hour. This is not merely a security feature — it is a governance re-execution requirement. A workload that loses its attestation standing (deleted RegistrationEntry, policy change) will fail to rotate its SVID and lose access when the current SVID expires. Re-attestation is the governance loop that prevents stale identity from accumulating.

## The Remaining Gap: Attestation Decision Audit
The attestation process is constitutive but the structured record of which selector matched, which RegistrationEntry authorized the issuance, and what policy evaluated the workload is not in a separate mandatory receipt. SPIRE server logs capture this information at DEBUG level, but not as a structured, queryable governance receipt. This is the gap between ACTIVE (which svid_issuance achieves) and a fully structured governance receipt system.

## Administrative Operations Gap
RegistrationEntry management, node attestation, and bundle federation are CRYSTALLIZED: audit logging is available but opt-in. Administrative changes to SPIRE server configuration are not mandatorily receipted.

## Wave 2 Governance Spectrum
SPIFFE/SPIRE completes the Wave 2 arc: policy engines (OPA/Gatekeeper/Kyverno) are CRYSTALLIZED; service mesh (Istio) is CRYSTALLIZED with bypass risk; workload identity (SPIFFE/SPIRE) reaches ACTIVE for its core issuance operation. The pattern holds: systems designed around cryptographic authority — where the authority artifact IS the receipt — reach ACTIVE more naturally than systems designed around policy evaluation logging.


## Real-World Incident Mapping

**Finding: SPIFFE/SPIRE's ACTIVE-EAR classification is validated by the security community's own framing of what short-lived SVIDs achieve.**

**The Internet Archive breach (October 2024) — canonical contrast case:**
A GitLab authentication token hardcoded in a configuration file in December 2022 sat dormant, unrotated, and fully privileged for nearly two years. When attackers found it, they obtained persistent access — the damage window was bounded only by incident detection speed, not by any cryptographic property of the credential. This is the ABSENT-EAR classification for static secrets: no constitutive governance receipt, no expiry enforcing re-attestation, blast radius unbounded by design.

SPIFFE/SPIRE's ACTIVE classification is the structural fix: an SVID expiring within 60 minutes means an attacker who compromises a container obtains a credential with a bounded damage window. The damage window is bounded by cryptographic TTL, not by detection speed. The SVID receipt constitutively limits the blast radius — which is exactly the constitutional property that defines ACTIVE-EAR.

**Registration Entry governance gap confirmed:**
The security community independently identifies the same gap CSoftA classifies under administrative operations (CRYSTALLIZED): overly permissive workload selectors in Registration Entries can result in incorrect identity grants. Treat Registration Entries with the same rigor as IAM policies — least privilege, regular review, and alerting on unexpected changes. The governance gap is that RegistrationEntry creation and modification is not mandatorily receipted in a structured audit log. An administrator can create an overly permissive entry with no constitutive record of the authorization decision. This is NON_ACTIVATION: the audit_log layer is applicable and available, but not constitutive of the registration operation.

**SPIRE Server as a governance gap surface:**
The SPIRE Server is a single point of authority for all SVID issuance in a trust domain. High-availability deployment and health monitoring are described as non-optional operational requirements. An unavailable SPIRE Server prevents all new SVID issuance and renewal — the governance mechanism fails closed, which is constitutionally correct (the system refuses to operate ungoverned) but operationally demanding. This is the Vault parallel: both Vault and SPIRE fail closed on governance infrastructure failure, which is why both reach ACTIVE-EAR for their core operations.

**The attestation decision audit gap in production:**
Security practitioners confirm the gap CSoftA identified: SPIRE Server attestation logs capture which plugin was used and whether attestation succeeded, but the structured record of which selector matched, which RegistrationEntry authorized the issuance, and what the governance decision chain was is not available as a first-class queryable artifact. Post-incident reconstruction requires correlating SPIRE Server logs at DEBUG level with RegistrationEntry state — the same COMPOSITIONAL recoverability pattern that limits Kubernetes and Keycloak in Wave 1.

**Why SPIFFE/SPIRE reaches ACTIVE where policy engines do not:**
The security community's framing confirms the constitutional analysis: SPIFFE/SPIRE solves the static secret problem by making the credential itself the governance receipt. A policy engine decision log records what was decided; an SVID cryptographically encodes the governance decision in the credential. You cannot separate the SVID from its attestation provenance — they are the same artifact. This is why short-lived SVIDs bound blast radius: the governance receipt (the SVID) is constitutively bound to the governance event (attestation), and the governance event enforces re-execution on every renewal cycle.

## The Add-On: `spire-governance-enforcer`

*T1661* — SPIRE plugin closing administrative governance gaps. Wraps registration API for mandatory structured receipts on RegistrationEntry mutations; validates selector specificity; extends SVID issuance response with attestation receipt (which plugin, which selectors, which entry authorized); monitors entry modifications; produces spire_posture.json. Closes CRYSTALLIZED admin gap.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| svid_issuance | **ACTIVE** | Attestation constitutive; SVID is the receipt |
| svid_rotation | **ACTIVE** | Re-attestation constitutive |
| workload_registration | CRYSTALLIZED | Admin audit opt-in |
| node_attestation_op | CRYSTALLIZED | Attestation logged but opt-in |
| bundle_federation | CRYSTALLIZED | Bundle receipt exists; audit opt-in |
