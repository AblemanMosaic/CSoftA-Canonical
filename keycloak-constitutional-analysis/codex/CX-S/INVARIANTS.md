# CX-S: Keycloak Constitutional Domain Invariants

*Keycloak Constitutional Analysis — CX:AES Codex*
*Inherits from: CSoftA Parent CX:AES Codex (T1574)*
*Version: 1.0*

---

## S-01: Token Introspection Is ACTIVE-EAR

Token introspection (`POST /protocol/openid-connect/token/introspect`)
is Keycloak's single ACTIVE-EAR operation. The response constitutively
embeds the governance decision: token validity, expiry, subject, scope,
and active status are returned in a structured receipt that IS the
authorization decision — not a record of it.

**What must hold:** token_introspection must be classified as ACTIVE-EAR
in any conforming analysis. It is the only Keycloak operation family
where the governance receipt is constitutive of the operation result.

**Contrast with Vault:** Vault's ACTIVE-EAR is on the server side
(audit log mandatory). Keycloak's ACTIVE-EAR is on the protocol side
(introspection response IS the receipt).

---

## S-02: Authorization Services Are ABSENT by Default

Keycloak Authorization Services (fine-grained authorization — UMA,
RBAC policies, ABAC policies) must be explicitly enabled per client.
Most Keycloak deployments do not enable them.

**What must hold:** authorization_decision must be classified as ABSENT
when Authorization Services are not enabled for the target client.
"Keycloak has authorization capabilities" does not satisfy this layer —
the capability must be active for the specific client being analyzed.

**When enabled:** Authorization Services provide CRYSTALLIZED-EAR —
policy evaluation occurs and results are structured, but the receipt
is in the PDP response, not in a mandatory audit record.

---

## S-03: User and Admin Events Are Opt-In (CRYSTALLIZED Ceiling)

Keycloak user events (login, token, logout) and admin events (realm
changes, user management) must be configured to persist. Default
Keycloak installations may have event logging disabled or with short
retention.

**What must hold:** Any EAR state claim for non-introspection operations
must declare whether event logging is enabled. With events disabled:
ABSENT. With events enabled: CRYSTALLIZED (events record outcomes;
they do not record which governance policies evaluated the operation).

---

## S-04: Session Lifecycle Has a Governance Gap

Keycloak sessions bridge authentication (login) and token issuance.
The session is created at login; tokens reference the session. However,
the governance of session validity checking during token operations
is not uniformly receipted.

**What must hold:** session_management must be distinguished from
realm_authentication. A valid session does not imply the session was
re-evaluated against realm policies at token issuance time — it implies
the session exists and has not expired. These are different governance
assertions.

---

## S-05: Realm Policies Are Always Evaluated on Authentication

Realm-level policies (brute force protection, required actions, session
limits) are evaluated on every authentication event. This distinguishes
realm_policy from authorization_services (optional) — realm_policy
participation is structural for the authentication path.

**What must hold:** realm_policy must appear in k(O,e) for all
user_authentication instances where the event type is LOGIN (not LOGIN_ERROR
due to policy rejection — rejection IS participation).

---

## S-06: Token Types Have Different Governance Profiles

Access tokens, refresh tokens, and ID tokens have different governance:
- Access tokens: validated at each resource server call (via introspection)
- Refresh tokens: validated only at refresh endpoint (less frequent)
- ID tokens: validated at client; no server-side introspection required

**What must hold:** Analysis must declare which token types are in scope.
Refresh token governance is weaker than access token governance because
the refresh endpoint is called less frequently and the token itself
has a longer lifetime with less frequent validation.
