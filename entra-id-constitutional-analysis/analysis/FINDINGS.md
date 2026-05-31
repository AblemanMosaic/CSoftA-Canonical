# FINDINGS: Microsoft Entra ID Constitutional Analysis
*Wave 11 — System 53 · modern_authentication (CAP+MFA): ACTIVE · Fingerprint: `a99ccf679a8fd267`*

## Executive Finding
Entra ID introduces the most important constitutional concept of Wave 11: split-path governance — the same identity policy is simultaneously ACTIVE for one authentication path and ABSENT for another, and the attacker chooses the path. Conditional Access Policies with MFA requirements produce ACTIVE governance for modern authentication (OAuth 2.0 / OIDC) — the token cannot be issued without MFA completing. Legacy authentication protocols (Basic Auth, NTLM, ESMTP AUTH) bypass Conditional Access entirely and reach Entra ID directly. Blocking legacy auth is a separate, explicit configuration step; it is not the default.

CVE-2025-55241 (CVSS 10.0, September 2025) is the most severe finding in the corpus from a governance evidence perspective: Actor tokens — undocumented legacy service-to-service tokens — could be used to impersonate any user in any Entra ID tenant globally. They bypass Conditional Access, bypass MFA, are valid for 24 hours and cannot be revoked, and generate **no logs in the target tenant**. This is the ABSENT governance evidence class combined with a BYPASS gap: the governance is absent not because it failed, but because the attack path was architecturally invisible to the governance layer.

## Split-Path Governance: A New Constitutional Concept
Previous corpus systems have single governance paths that are either ACTIVE, CRYSTALLIZED, or ABSENT. Entra ID introduces a system where two authentication paths coexist, one ACTIVE and one ABSENT, and the attacker selects which path to use. The CAP correctly governs modern authentication. The CAP has no visibility into legacy authentication. The entire security architecture is built on the modern path while the legacy path remains open.

This is constitutional because it is a property of the system's design, not a misconfiguration. The only resolution is blocking legacy authentication entirely — which requires auditing all existing legacy integrations first, a non-trivial operation for large enterprises.

## Real-World Incidents
Midnight Blizzard (APT29, 2023-2024): exploited legacy authentication to bypass MFA for initial access to Microsoft corporate environments. The breach that led to Microsoft executives' emails being compromised used a password spray against legacy auth endpoints that were exempt from MFA. This is the canonical split-path governance exploit. CVE-2025-55241 Actor token exploit: complete tenant impersonation with no log trail. Researcher Dirk-jan Mollema confirmed the vulnerability by building a proof of concept; Microsoft patched before public exploitation. Legacy API deprecation: Azure AD Graph API (graph.windows.net) deprecated September 2025; organizations dependent on it retained the attack surface until migration.

## The Add-On: `entra-id-governance-enforcer`
Legacy auth blocker and CAP compliance validator. Validates legacy auth blocked via CAP; validates MFA required for all users via CAP; validates PIM configured for privileged roles (no permanent Global Admin); monitors sign-in logs for legacy auth attempts; exports sign-in logs to external SIEM; produces `entra_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| modern_authentication | **ACTIVE** (with CAP+MFA) | Token cannot issue without MFA completing |
| legacy_authentication | ABSENT (default) | Bypasses CAP entirely; no MFA possible |
| privileged_role_assignment | CRYSTALLIZED | PIM optional; permanent Global Admin common |
| token_issuance | CRYSTALLIZED | Sign-in logs available; Actor tokens leave no logs |
| cross_tenant_access | CRYSTALLIZED | B2B policies configurable; CVE-2025-55241 class |
