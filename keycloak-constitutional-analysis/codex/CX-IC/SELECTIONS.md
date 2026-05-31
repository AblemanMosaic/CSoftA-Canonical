# CX-IC: Keycloak Selected Instance Configuration

*Keycloak Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## IC-01: N-Determination Strategy → DECLARED-N

**Rationale:** N(O) derived from Keycloak's documented security model.
Keycloak's operation families have heterogeneous N sizes (N=2 for
token_introspection through N=4 for user_authentication), making
DECLARED-N the most informative strategy for architectural review.

---

## IC-02: Authorization Services → ABSENT scope declaration

**Per CX-S S-02:** This analysis treats authorization_decision as ABSENT
for the canonical (default) deployment. Authorization Services analysis
is available as a CX-IC extension when explicitly enabled.

---

## IC-03: Event Logging → ENABLED (canonical instance)

**Rationale:** The canonical instance assumes event logging is configured.
This gives the most useful EAR state differentiation. Deployments
without event logging degrade all non-introspection families to ABSENT.

---

## IC-04: Token Types in Scope → All three (access, refresh, ID)

**Rationale:** Full scope for Wave 1 founding analysis. Refresh token
governance weakness (S-06) is documented as a finding.

---

## Instance Summary

| Dimension             | Selected Value       | Alternatives              |
|-----------------------|----------------------|---------------------------|
| N-determination       | DECLARED-N           | MINIMUM-N, PER-CONTEXT-N |
| Authz services        | ABSENT (not enabled) | CRYSTALLIZED when enabled |
| Event logging         | ENABLED              | ABSENT when disabled      |
| Token scope           | All types            | Access tokens only        |
