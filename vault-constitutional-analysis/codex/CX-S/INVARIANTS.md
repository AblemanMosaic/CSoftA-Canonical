# CX-S: Vault Constitutional Domain Invariants

*Vault Constitutional Analysis — CX:AES Codex*
*Inherits from: CSoftA Parent CX:AES Codex (T1574)*
*Version: 1.0*

---

## Scope

These invariants govern the structure of any conforming constitutional analysis
of HashiCorp Vault. They are domain physics: they do not prescribe configuration
choices, but they bound what can be claimed about Vault's governance structure.

---

## S-01: Authority Derives From Named Policy Paths

Every secret access, auth method operation, and system operation in Vault
must derive authority from a named policy path bound to the requesting token.

**What must hold:** Authority is explicit and declared. No operation may be
constitutionally authorized by execution path, runtime state, or implicit
capability alone.

**Diagnostic:** If authority for an operation cannot be traced to a specific
policy path in a specific policy document attached to a specific token,
that operation's authority is constitutionally undeclared (F-AUTH present).

**Exception:** Root token operations. Root token bypasses the policy system
entirely. This is declared as Layer Bypass (F-SCOPE, C-11) — not as
authorized governance. Root token operations are constitutionally inadmissible
for production governance claims (see S-04).

**Vault API surface:** `sys/policy/*`, `auth/token/create`,
`auth/token/lookup`, `policyresults.grantingpolicies` in audit log.

---

## S-02: Audit Device Is a Mandatory Governance Layer

For a Vault deployment to be governance-complete at the ACTIVE-EAR level,
at least one audit device must be enabled and configured as a blocking
device (not `log_raw=false` only).

**What must hold:** Vault's mandatory-ledger receipt tier (PCM-0113-010)
is only realized when an audit device is enabled. Without an audit device,
every operation is CRYSTALLIZED at best — the receipt mechanism exists
but is not activated.

**Diagnostic:** A Vault cluster with no enabled audit device has N(O) that
includes "audit log" as a declared governance layer, but k(O,e) does not
include it. This is a Layer Non-Activation GCG (C-09) for all operation
families that declare the audit device as applicable.

**Vault API surface:** `sys/audit` (list enabled audit devices).

---

## S-03: Policy Evaluation Must Be Receipted Per Operation

The `policyresults.grantingpolicies` field in the Vault audit log is the
primary evidence of policy participation. Any operation that produces an
audit record without `policyresults.grantingpolicies` (or with it empty
and no explicit deny record) indicates incomplete policy evaluation receipt.

**What must hold:** Every permitted operation must carry evidence of which
policy granted the permission. Silent permits (operation allowed, no policy
attribution) are F-ADMIT (admissibility record absent for policy layer).

**Diagnostic:** Parse audit log entries. Count entries where
`auth.token_policies` is non-empty but `auth.policy_results.allowed_policies`
is absent or empty. These are underreceipted operations.

---

## S-04: Root Token Is Layer Bypass, Not Authorized Governance

The Vault root token bypasses the policy evaluation layer entirely.
Root token operations are constitutionally classified as Layer Bypass (C-11):
the policy evaluation layer is declared applicable, it is present in the
architecture, but execution routes around it.

**What must hold:** Any analysis that counts root token operations as
"governed" is constitutionally inadmissible. Root token operations may
be necessary for initial setup, but they must be enumerated and classified
as bypass events, not governance events.

**Diagnostic:** Audit log entries where `auth.token_type = "service"` and
`auth.token_policies = ["root"]` are Layer Bypass instances.

---

## S-05: Storage Backend Is the Primary Jurisdiction Boundary

Vault's commit point is the storage backend (Integrated Raft, Consul,
cloud storage). The governance chain that Vault provides does not extend
into the storage backend. What the storage backend does to Vault's data
(encryption at rest, access controls, replication) is outside Vault's
constitutional visibility.

**What must hold:** Any recoverability claim for Vault must declare the
storage backend JD as the boundary. Vault's recoverability is LOCAL for
operations within the Vault governance perimeter; it is COMPOSITIONAL
or STRUCTURAL_NONLOCALITY once the storage backend JD is crossed.

**Diagnostic:** Vault Integrated Raft is LOCAL (Vault controls the
storage substrate). Consul backend is COMPOSITIONAL (Vault and Consul
share the governance surface but it is not unified). Cloud storage
(DynamoDB, S3, GCS) is STRUCTURAL_NONLOCALITY (external actor, no
independent governance witness).

---

## S-06: Auth Method Non-Participation Is Structurally Distinct From Auth Failure

When a request is rejected by Vault's auth method, that is a governance
outcome — not a GCG. When a request succeeds through an auth method that
does not produce a durable participation record, that is F-ADMIT.

**What must hold:** The analysis must distinguish:
- Auth method evaluated and denied (governance outcome — correct)
- Auth method evaluated and permitted with full receipt (governance complete)
- Auth method evaluated but no participation record produced (F-ADMIT)
- Auth method not activated for this operation (GCG — Layer Non-Activation)

**Diagnostic:** AppRole auth without audit device = Layer Non-Activation
for the audit layer. Token auth with audit device = ACTIVE-EAR.

---

## S-07: N(O) Varies By Deployment Configuration

Vault's N(O) is not fixed. It depends on:
- Which auth methods are enabled (determines auth governance layers)
- Whether audit device is enabled (determines receipt layer participation)
- Whether Sentinel EGP/RGP policies are active (Enterprise only —
  determines policy-engine governance layer count)
- Whether namespaces are in use (Enterprise only — affects scope)

**What must hold:** Every GCG assertion must state the N-determination
strategy used (DECLARED-N from Vault documentation, MINIMUM-N for
architectural review, or PER-CONTEXT-N for deployment-specific analysis)
and cite the governance declaration source.

---

## S-08: Vault Root Namespace vs Child Namespaces (Enterprise)

In Vault Enterprise, child namespaces have their own policy and auth
method contexts. N(O) for a child namespace operation may differ from
N(O) for a root namespace operation.

**What must hold:** Multi-namespace analyses must declare N(O) per
namespace context and note where namespace isolation creates JD-like
boundaries within Vault itself.

**Scope:** This invariant applies only to Vault Enterprise deployments.
Vault OSS analyses may note this as a declared scope boundary.

---

## Inadmissible Regions

The following analytical positions are inadmissible in a conforming
Vault constitutional analysis:

- Claiming a Vault deployment is governance-complete when no audit
  device is enabled (violates S-02)
- Counting root token operations as "governed" operations (violates S-04)
- Claiming LOCAL recoverability for a Vault deployment backed by
  cloud storage (violates S-05)
- Asserting N(O) without citing the N-determination strategy (violates S-07)
- Treating policy evaluation presence as equivalent to policy
  evaluation receipt (violates S-03)
