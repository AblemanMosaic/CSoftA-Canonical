# CX-C: Vault Configuration Manifold

*Vault Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## Scope

The configuration manifold defines the choices that may legitimately vary
across Vault constitutional analyses without violating the CX-S invariants.
Each dimension has admissible and inadmissible regions.

---

## CC-01: N-Determination Strategy

**Options:**
- `DECLARED-N`: Derive N(O) from Vault's official security documentation,
  architecture guides, and CIS Benchmark. Recommended for architectural review.
- `MINIMUM-N`: Count only the governance layers that are active in the
  specific deployment under analysis. Recommended for deployment audit.
- `PER-CONTEXT-N`: Compute N(O) per namespace, auth method, and operation
  path. Required for precise gap magnitude claims.

**Default:** `DECLARED-N` against Vault security model documentation
(HashiCorp Learn, Vault Architecture Guide, CIS Benchmark for Vault).

**Inadmissible:** Asserting N(O) without declaring which strategy was used.

---

## CC-02: Operation Families in Scope

**Full scope (all operation families):**
- Secret access (KV, PKI, database, transit, SSH, TOTP, ...)
- Auth method operations (login, token renewal, token revocation)
- Policy operations (policy read, policy write, policy delete)
- System operations (audit enable/disable, mount enable/disable, health)
- Root token operations (declared as bypass, not governed scope)

**Minimum scope (architectural review):**
- Secret read / secret write (KV v2)
- Token-based auth (AppRole or userpass)
- Audit device enable/disable

**Default:** Full scope where audit log is available; minimum scope
for static/architectural analysis only.

---

## CC-03: Evidence Standard

**Options:**
- `STATIC`: Analysis based on Vault configuration files, documentation,
  and architecture review only. No live cluster required.
- `RUNTIME`: Analysis based on Vault audit log from a live or test cluster.
  Required for k(O,e) assessment and ACTIVE-EAR claims.
- `BOTH`: Static analysis establishes N(O); runtime analysis measures k(O,e).

**Default:** `BOTH` for a complete analysis. `STATIC` is admissible for
architectural review with explicit scope declaration.

---

## CC-04: Audit Log Format

**Options:**
- `FILE`: Vault file audit device (JSON newline-delimited)
- `SYSLOG`: Vault syslog audit device
- `SOCKET`: Vault socket audit device

**Python implementation default:** `FILE` audit device (most common,
machine-readable JSON). Other formats require adapter extension.

---

## CC-05: Vault Edition in Scope

**Options:**
- `OSS`: Vault open-source. N(O) does not include Sentinel EGP/RGP or
  namespace governance layers.
- `ENTERPRISE`: Vault Enterprise. N(O) may include Sentinel policies,
  namespaces, MFA enforcement, and HSM integration as additional layers.

**Default:** `OSS`. Enterprise analysis requires explicit scope declaration
and additional CX-S invariant S-08 application.

---

## CC-06: Root Token Handling

**Options:**
- `EXCLUDE`: Root token operations excluded from governance analysis scope
  (declared scope boundary — correct for production governance assessment).
- `ENUMERATE`: Root token operations included in analysis scope as
  Layer Bypass instances only — not as governed operations.

**Default:** `ENUMERATE`. Root tokens must be counted as bypass events
to produce an accurate gap magnitude. `EXCLUDE` is admissible only with
explicit declaration that bypass scope is excluded.

---

## Inadmissible Directions

| Direction | Reason |
|-----------|--------|
| Claim ACTIVE-EAR without confirming audit device enabled and blocking | Violates S-02 |
| Assert N(O) = 1 (only RBAC/token auth) for a deployment with audit enabled | Undercounts N — audit layer not included |
| Claim governance completeness for root namespace when child namespaces are unanalyzed | Scope fragmentation (F-SCOPE) |
| Treat Vault OSS findings as applicable to Enterprise without namespace caveat | Violates S-08 |
