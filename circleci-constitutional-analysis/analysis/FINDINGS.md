# FINDINGS: CircleCI Constitutional Analysis
*Wave 16 — System 77 · EAR ceiling: CRYSTALLIZED · Fingerprint: `940a7eb305c2b1de`*

## Executive Finding
CircleCI is the most significant documented CI/CD security incident in the corpus. The January 2023 breach established the constitutional case for CI/CD secret store governance: an attacker compromised an engineer's laptop with malware, stole a 2FA-backed SSO session cookie (bypassing MFA entirely at the session layer), and used that session to exfiltrate all customer environment variables, OAuth tokens, and encryption keys from running processes. Encrypted at rest did not prevent key exfiltration because the attacker extracted encryption keys from a running process — the encryption was bypassed at the execution layer, not the storage layer.

The constitutional finding: **a SaaS CI/CD platform's secret store is a single breach point for all customer projects simultaneously**. Unlike self-hosted Jenkins (T1796) where configuration drift is an organizational problem, CircleCI's shared infrastructure means a platform-level compromise exposes every customer's secrets in one event. This is structurally inherent to the SaaS CI/CD model — it is not a misconfiguration.

OIDC federation (CircleCI 2022+): projects using OIDC ID tokens for cloud access no longer store long-lived cloud credentials in CircleCI — the breach would not yield persistent cloud access for OIDC-configured projects. This is the correct architectural response to the structural gap.

## The Add-On: `circleci-governance-enforcer`
OIDC adoption auditor and context scope validator. Validates OIDC configured for all cloud deployments; validates contexts scoped to minimum necessary projects; produces `circleci_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| pipeline_execution | CRYSTALLIZED | Auth always on; OIDC closes long-lived credential gap |
| secret_access | CRYSTALLIZED | Encrypted at rest; platform breach = single point |
| oidc_federation | CRYSTALLIZED | Short-lived tokens; 2023 breach class closed |
| context_management | CRYSTALLIZED | Shared context = shared blast radius |
| artifact_access | CRYSTALLIZED | Auth-gated; retention policy opt-in |
