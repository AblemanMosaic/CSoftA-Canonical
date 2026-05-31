# FINDINGS: Keycloak Constitutional Analysis

*Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*
*Version: 1.0 — 2026-05-29*
*EAR state: ACTIVE (token_introspection) / CRYSTALLIZED (auth, admin) / ABSENT (authz default)*
*Recoverability: LOCAL (token introspection) / COMPOSITIONAL (session lifecycle)*

---

## Executive Finding

Keycloak closes Wave 1 by demonstrating that identity governance can
reach ACTIVE-EAR for specific operation families — the only Wave 1 system
besides Vault to achieve this.

Token introspection is ACTIVE-EAR: the introspection response constitutively
embeds the governance receipt. Authentication and session management are
CRYSTALLIZED. Authorization Services — Keycloak's fine-grained policy
engine — are ABSENT in most deployments by default.

The central finding: Keycloak's governance quality is operation-family-dependent
in a way that requires explicit declaration per family. "Keycloak is an
identity provider" does not specify EAR state — token_introspection and
authorization_decision are in fundamentally different governance states
in the same deployment.

---

## Dimension 1: Authority (F-AUTH)

**Finding: F-AUTH LOW — authority explicitly declared via realm and client config**

Keycloak's authority model is explicit: realm configuration declares
authentication flows, required actions, brute force protection, and
session policies. Client configuration declares allowed scopes, protocol
mappers, and (optionally) authorization policies.

This is closer to Vault than to npm or Docker: authority is declared
in named configuration artifacts before operations execute.

**F-AUTH weakness:** Token scope grants are declared at client registration
time, but the runtime enforcement of scope restrictions at resource servers
depends on the resource server calling token introspection — Keycloak
cannot force resource servers to validate tokens. The authority declaration
exists; the authority enforcement is boundary-dependent.

---

## Dimension 2: Accountability (F-LINEAGE)

**Finding: Stratified by operation family**

| Operation Family       | EAR State    | Receipt quality                                      |
|------------------------|--------------|------------------------------------------------------|
| token_introspection    | ACTIVE       | Response IS the receipt; constitutive                |
| user_authentication    | CRYSTALLIZED | User events record login; not mandatory              |
| token_issuance         | CRYSTALLIZED | Token events record issuance; session gap            |
| token_refresh          | CRYSTALLIZED | Refresh events recorded; lifecycle not unified       |
| authorization_decision | ABSENT (default) | Not enabled in most deployments                |
| admin_operation        | CRYSTALLIZED | Admin events record changes; opt-in                  |

**The session lifecycle gap:** Keycloak creates sessions at login and
issues tokens referencing sessions. But the governance of session validity
re-evaluation at each token operation is not uniformly receipted. A token
issued against a valid session has no durable record of which realm policies
were re-evaluated at issuance time.

---

## Dimension 3: Governance (F-ADMIT)

**Finding: F-ADMIT LOW for core operations; ABSENT for authorization**

**GCG instances (default deployment, events enabled):**

| Operation Family       | Gap Form         | N | k | Gap | Absent                              |
|------------------------|------------------|---|---|-----|-------------------------------------|
| authorization_decision | ABSENCE          | 3 | 0 | 3   | authorization_services, realm_policy, admin_audit |
| token_refresh          | NON_ACTIVATION   | 4 | 3 | 1   | client_policy (not always present)  |

**No gap for token_introspection** when events enabled (T-GCG-03 confirmed).

**The authorization gap:** The most significant finding is that Keycloak's
most powerful governance mechanism — Authorization Services with fine-grained
RBAC/ABAC policies — is absent from most deployments. The gap magnitude
when authz services are enabled but not configured for a client is 3
(all three declared layers absent). This is the highest gap magnitude
in Keycloak outside of authorization_decision with authz disabled.

---

## Dimension 4: Configuration and Authority Binding

**Finding: STRUCTURAL SEPARATION for realm/client config**

Keycloak separates configuration (realm settings, client registration)
from authority evaluation (authentication flows, token validation,
authorization policy evaluation). This is genuine structural separation —
closer to Vault than to npm or Docker.

The gap: Authorization Services policies are defined separately from
the operations they govern. This is correct architectural separation,
but it creates a deployment problem: a client can be created without
authorization policies, and Keycloak will serve tokens for it without
enforcing any authorization beyond RBAC.

---

## Dimension 5: Resolution Cascade Opacity

**Finding: LOW for token introspection; MEDIUM for session lifecycle**

**Token introspection:** The introspection response is the complete
governance record. Any resource server that calls introspection can
reconstruct exactly what governance was applied. This is the lowest
opacity in the Wave 1 corpus for a single operation.

**Session lifecycle:** The chain from login → session creation → token
issuance → token refresh cannot be reconstructed from any single Keycloak
artifact. Admin events + user events together provide a partial reconstruction,
but the linkage between session governance state and token governance
decisions is not unified in a single queryable artifact.

---

## Dimension 6: Extension Surfaces (F-SCOPE)

**Finding: Governed extension model (SPI)**

Keycloak's Service Provider Interface (SPI) allows custom authenticators,
protocol mappers, event listeners, and authorization policies. SPIs are
deployed as JAR files and registered in realm configuration.

Extension classification: **Perimeter-governed** — SPIs must be registered
in realm configuration (explicit declaration) before they execute.
This is better governance than npm (ungoverned) and comparable to Docker
content trust.

**F-SCOPE weakness:** Custom SPIs execute with full Keycloak context and
are not independently audited by Keycloak's built-in event system.
A malicious SPI can read and modify token claims without generating
a governance event.

---

## Dimension 7: Authority Bypass

**Finding: Scoped bypasses — realm admin and service accounts**

| Bypass | Scope | Effect |
|--------|-------|--------|
| Realm admin via master realm | Realm-scoped | Full realm configuration access |
| Service account with admin role | Role-scoped | Admin API access |
| Direct database access | Unbounded | Bypasses all Keycloak governance |
| Expired session with cached token | Request-scoped | Token valid despite session termination |

Keycloak's bypasses are more scoped than Vault's root token or Docker's
--privileged. The expired-session/cached-token bypass is the most
operationally significant: if resource servers cache tokens without
calling introspection, Keycloak's governance is bypassed entirely.

---

## Dimension 8: Projection Divergence (F-PROJ)

**Finding: F-PROJ MODERATE — authorization capability vs authorization reality**

Keycloak's interface and documentation present it as a complete identity
and access management platform with authorization services. The reality:
most deployments use Keycloak as an authentication provider (OIDC) with
basic token issuance, without enabling the Authorization Services that
provide governance completeness.

The divergence is material for security architects who assume Keycloak's
authorization features are active by default.

---

## The Add-On: `keycloak-governance-enforcer`

*T1656* — Keycloak event listener SPI and resource server middleware. Writes structured receipts for every token issuance/introspection/revocation to durable backend; makes token introspection constitutive (blocks offline JWT validation); enforces session binding; monitors admin operations without MFA; produces keycloak_posture.json. Closes the offline JWT bypass gap.

## Summary

| Dimension              | Finding                                       | Severity |
|------------------------|-----------------------------------------------|----------|
| Authority              | Explicit realm/client declaration; LOW F-AUTH | LOW      |
| Accountability         | ACTIVE (introspection); CRYSTALLIZED (rest)   | LOW-MED  |
| Governance             | ABSENT for authz (default); LOW elsewhere     | MEDIUM   |
| Config-Authority       | Structural separation                         | LOW      |
| Resolution Opacity     | LOW (introspection); MEDIUM (session)         | LOW-MED  |
| Extension Surfaces     | Perimeter-governed SPI                        | LOW      |
| Authority Bypass       | Scoped; cached token risk                     | LOW-MED  |
| Projection Divergence  | Authz capability vs default deployment        | MEDIUM   |

**Constitutional verdict: Keycloak reaches ACTIVE-EAR for token introspection,
making it the Wave 1 identity governance reference case. Authorization Services
are the governance completeness path — enabling them advances all authorization
operation families from ABSENT to CRYSTALLIZED. The session lifecycle gap and
opt-in event logging are architectural constraints, not defects.**
