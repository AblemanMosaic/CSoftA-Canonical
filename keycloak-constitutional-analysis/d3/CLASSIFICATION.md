# D3 Classification: Keycloak

*CSoftA D3 Corpus Classification Protocol (T002)*
*Version: 1.0 — 2026-05-29*

---

## Commit Point

**Primary commit point (token introspection):** Introspection response.
The governance decision is committed and receipted in the same operation.

**Primary commit point (authentication):** Session creation in Keycloak's
database after successful credential validation and flow completion.

**Primary commit point (admin operations):** Database write when realm
or user configuration changes are persisted.

---

## Recoverability Regime

**Token introspection: LOCAL**
The introspection endpoint returns a complete, self-contained governance
receipt. No external artifact required. Highest recoverability in Wave 1.

**Authentication/session: COMPOSITIONAL**
User events + realm configuration + session store together describe
the governance state. No single artifact is sufficient.

**Authorization decisions: STRUCTURAL_NONLOCALITY (when authz disabled)**
When Authorization Services are not enabled, authorization decisions
happen at resource servers with no Keycloak visibility.

---

## EAR State by Operation Family

| Operation Family       | EAR State     | Evidence                                       |
|------------------------|---------------|------------------------------------------------|
| token_introspection    | ACTIVE        | Response constitutes the receipt               |
| user_authentication    | CRYSTALLIZED  | User events record outcome; not mandatory      |
| token_issuance         | CRYSTALLIZED  | Token events record; session gap               |
| token_refresh          | CRYSTALLIZED  | Refresh events; client_policy often absent     |
| authorization_decision | ABSENT (default) | Not enabled in most deployments             |
| admin_operation        | CRYSTALLIZED  | Admin events record; opt-in                    |

---

## Jurisdiction Boundaries

**JD-1: Resource servers (primary)**
- Location: Between Keycloak and services consuming tokens
- Governance consequence: Keycloak cannot force resource servers to
  call introspection; if they cache tokens, Keycloak's governance is bypassed
- Severity: HIGH — offline token validation = no Keycloak visibility

**JD-2: External identity providers (IdP federation)**
- Location: Between Keycloak and upstream IdPs (LDAP, SAML, external OIDC)
- Governance consequence: Upstream authentication decisions are accepted
  without Keycloak independently re-evaluating them
- Severity: MEDIUM — federated identity brings external governance assumptions

**JD-3: Database (session/token store)**
- Location: Between Keycloak service and database
- Governance consequence: Database access bypasses all Keycloak governance
- Severity: HIGH — same as Vault storage backend

---

## Structural Observations

**Keycloak closes the Wave 1 arc.**
Wave 1 demonstrates governance across the spectrum: ACTIVE-EAR operations
exist in both Vault (mandatory server-side audit) and Keycloak (token
introspection protocol receipt). Both paths to ACTIVE-EAR require explicit
design; neither is automatic.

**Token introspection is the model for distributed governance receipting.**
Keycloak's introspection endpoint is the reference implementation for how
a centralized authority can provide ACTIVE-EAR semantics in a distributed
architecture: the receipt IS the protocol response, making governance
visible to any party that calls the endpoint.

**Authorization Services is the governance completeness path.**
Most Keycloak deployments use a fraction of available governance capability.
Enabling Authorization Services per client is the single highest-leverage
action for advancing from CRYSTALLIZED to CRYSTALLIZED-with-policy-receipt
for resource authorization decisions.
