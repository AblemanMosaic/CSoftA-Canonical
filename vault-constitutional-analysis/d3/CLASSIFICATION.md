# D3 Classification: HashiCorp Vault

*CSoftA D3 Corpus Classification Protocol (T002)*
*Version: 1.0 — 2026-05-29*

---

## Commit Point

**Primary commit point:** Vault storage backend write.

A Vault operation is committed when the state change is durably written
to the storage backend. The API server processes the request, evaluates
policy, and writes to storage. The storage write is the point of no return.

**Commit point visibility:** HIGH. Vault's audit log records the request
before storage write (request entry) and after (response entry). The
commit point is externally observable.

**Commit point location:** Within the Vault process for Integrated Raft;
at the Consul or cloud storage boundary for external backends.

---

## Recoverability Regime

**Primary regime:** LOCAL (Integrated Raft) / COMPOSITIONAL (Consul) /
STRUCTURAL_NONLOCALITY (cloud storage)

**Integrated Raft (most common in modern deployments):**
- Recoverability is LOCAL. Vault controls the storage substrate.
- The complete governance trace τ = (EP, GR, ER) can be assembled
  from Vault's own artifacts: audit log + policy definitions + raft log.
- This is the strongest recoverability claim available in Vault.

**Consul backend:**
- Recoverability is COMPOSITIONAL. Vault and Consul share the governance
  surface but it is not unified under a single receipt chain.
- The storage layer produces its own events; aligning Vault audit log
  events with Consul KV events requires external correlation.

**Cloud storage (DynamoDB, S3, GCS):**
- Recoverability is STRUCTURAL_NONLOCALITY.
- The cloud storage provider is an external actor. What the provider
  does to Vault's data (access, replication, deletion) is outside
  Vault's constitutional visibility.
- Cloud provider access logs are separate artifacts not integrated
  into the Vault receipt chain.

**Recommendation:** Integrated Raft is the constitutionally preferred
deployment for governance-complete Vault installations.

---

## EAR State by Operation Family

| Operation Family     | EAR State    | Evidence                                              |
|----------------------|--------------|-------------------------------------------------------|
| secret_read          | ACTIVE*      | policyresults.grantingpolicies present when audit enabled + policy receipt present |
| secret_write         | ACTIVE*      | Same as secret_read                                   |
| auth_login           | CRYSTALLIZED | Audit records login attempt; no policy evaluation receipt pre-auth |
| token_create         | ACTIVE*      | Full policy evaluation and audit receipt              |
| policy_manage        | ACTIVE*      | Full policy evaluation and audit receipt              |
| sys_audit            | ACTIVE*      | Full policy evaluation; bootstrapping note below      |
| root_token_operation | ABSENT       | Root token bypasses policy evaluation layer entirely  |

*ACTIVE requires audit device enabled and configured as blocking device.
Without audit device: all families degrade to CRYSTALLIZED.

**Bootstrapping note for sys_audit:** Enabling the first audit device is
itself a sys_audit operation. If no audit device is enabled, this operation
cannot produce its own receipt. This is a known bootstrapping gap in Vault's
constitutional completeness — the first audit device enable is unreceipted.

---

## Jurisdiction Boundaries

**JD-1: Storage Backend (primary)**
- Location: Between Vault process and storage backend
- Governance consequence: What the storage backend does to Vault's data
  is not observable within Vault's receipt chain
- Severity: HIGH for cloud backends; LOW for Integrated Raft

**JD-2: Auth Method External Validator (when used)**
- Location: Between Vault and external auth validators (LDAP, OIDC
  provider, cloud IAM, Kubernetes API server)
- Governance consequence: The external validator's decision is accepted
  by Vault without independent witness of the validator's internal state
- Severity: MEDIUM — Vault receipts the outcome, not the external decision

**JD-3: Secret Engine External Backend (dynamic secrets)**
- Location: Between Vault and the target system for dynamic credentials
  (database, cloud IAM, Kubernetes)
- Governance consequence: The target system's acceptance of the dynamic
  credential is outside Vault's governance perimeter
- Severity: LOW for short-lived credentials; MEDIUM for long-lived

**JD-4: Vault Agent / Proxy (when deployed)**
- Location: Between client application and Vault API
- Governance consequence: Vault Agent performs caching and token renewal;
  these operations may not produce individual audit entries per client request
- Severity: MEDIUM — agent operations are partially receipted

---

## Structural Observations

**Vault is the SFA corpus reference implementation of strong governance.**
It is the only system in the 17-system corpus with mandatory-ledger receipt
tier (PCM-0113-010). Every permitted operation produces a structured record
including token identity, policy evaluation, and outcome.

**The root token is the singular constitutional weakness.** Every other
Vault governance mechanism is constitutionally complete or close to it.
The root token represents an unbounded Layer Bypass that exists at all
privilege levels. It cannot be disabled without breaking emergency recovery.
It should be treated as a declared scope exclusion in production governance
claims, not as an authorized governance path.

**Audit device bootstrapping is an unavoidable structural gap.** The first
audit device enable cannot receipt itself. This is documented, known, and
structural — not an implementation defect. Any constitutional analysis must
declare this gap explicitly.

**Vault Enterprise adds governance depth.** Sentinel EGP/RGP policies,
namespace isolation, and MFA enforcement are additional governance layers
that increase N(O) and decrease gap magnitude. Enterprise analysis must
declare which layers are active and include them in N(O).
