# FINDINGS: cert-manager Constitutional Analysis
*Wave 3 — System 11 · certificate_issuance: ACTIVE · Fingerprint: `164cdec1a94bb5a6`*

## Executive Finding
cert-manager is Wave 3's first ACTIVE-EAR system. Certificate issuance and renewal are ACTIVE: the Certificate resource is constitutive of issuance — cert-manager cannot issue a certificate without creating/updating the Certificate CRD resource, and the Certificate resource IS the governance receipt. It encodes the issued certificate, expiry, issuing CA, and renewal schedule. This is the same constitutional pattern as SPIFFE/SPIRE svid_issuance: the credential is the receipt.

## Why Certificate Issuance Is ACTIVE
The Certificate resource is both the governance declaration (what certificate is needed) and the governance receipt (what certificate was issued). The resource cannot exist in the Ready state without a certificate having been issued. The certificate data, expiry, and issuer are all encoded in the resource status. You cannot separate the issued certificate from its governance record — they are the same Kubernetes object.

Automatic renewal (renewBefore threshold) is a governance re-execution requirement: like SPIFFE/SPIRE's 1-hour SVID TTL, cert-manager enforces re-issuance before expiry, preventing stale certificates from accumulating.

## Primary Gap: No Mandatory Audit Log
cert-manager produces no structured audit log of its own. Certificate issuance events appear in Kubernetes events (short retention) and in Kubernetes audit logs (if enabled), but cert-manager has no dedicated audit surface. An administrator cannot query "what certificates were issued in the last 30 days" from cert-manager alone.

## Substrate Dependency (T019)
cert-manager governance is bounded by Kubernetes admission governance. A ClusterIssuer misconfiguration that allows unauthorized certificate issuance is a governance gap at the Kubernetes RBAC layer, not at the cert-manager layer.

## Real-World Incident Mapping
cert-manager CVE-2022-4602 (ACME DNS-01 solver): a user could craft an ACME challenge response that caused cert-manager to resolve DNS entries outside the authorized scope, potentially issuing certificates for domains the user did not control. The constitutional finding: the issuer_verification layer was present but its scope was insufficiently bounded — N declared, k < N_correct, governance record showed success while the authorization was incomplete.

## The Add-On: `cert-manager-audit-bridge`

*T1662* — Continuous event consumer providing queryable audit history cert-manager lacks. Persists cert-manager events beyond Kubernetes event retention; maintains certificate_inventory (all valid certs with issuer, expiry, subject, renewal); alerts on failed renewals before expiry; validates ClusterIssuer scope (CVE-2022-4602 class); produces cert_posture.json. Closes the audit history queryability gap on an ACTIVE-EAR system.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| certificate_issuance | **ACTIVE** | Certificate resource IS the receipt |
| certificate_renewal | **ACTIVE** | Renewal constitutive, re-execution required |
| issuer_management | CRYSTALLIZED | No mandatory audit of issuer changes |
| certificate_signing_request | CRYSTALLIZED | CSR resource exists, no audit log |
