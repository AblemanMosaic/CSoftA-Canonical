# CSoftA Methodology

**Ableman Constitutional Systems** — ableman.research@gmail.com

---

Constitutional Software Analysis (CSoftA) applies a single question to every
operation in a software system: is the governance check *constitutive* of that
operation completing, or merely *parallel* to it?

A governance check that must complete before the operation proceeds — and whose
failure causes the operation to fail — is constitutive. It is load-bearing. The
operation cannot exist in a governed sense without it. A governance check that
runs alongside the operation, records what happened, or is optionally enabled
is parallel. It may be useful and correct, but it does not prevent the ungoverned
operation from completing.

This distinction produces the three-state EAR classification.

---

## Key Terms

**EAR — Execution Authorization Receipt.** The receipt that a governance
mechanism produces (or fails to produce) when an operation executes. The
three EAR states — ACTIVE, CRYSTALLIZED, ABSENT — classify whether that
receipt is constitutive of the operation completing, parallel to it, or
nonexistent.

**GCG — Governance Coverage Gap.** The gap between the governance layers
declared as applicable to an operation (N) and the layers that actually
participated in a specific execution (k). GCG = N − k. A gap of zero means
full coverage; a gap greater than zero means one or more declared layers did
not participate and left no record of their non-participation.

**N(O) — Declared governance layer set.** The set of governance layers that
*should* participate in governing operations of family O, according to the
system's architecture, documentation, and configuration. Determining N(O)
is called N-determination; it is the analyst's primary claim about what
governance the system is supposed to provide.

**k(O, e) — Realized governance layer set.** The set of governance layers
that *actually participated* in a specific execution instance e of operation
family O. The GCG for that execution is N(O) − k(O, e).

**Operation family.** A named class of operations that share a governance
surface. A single system has multiple operation families, each assessed
separately. Vault has `secret_read`, `auth_login`, `root_token_operation`,
and others — each with its own EAR state and gap profile.

**Convergence fingerprint.** A content-addressed hash of an analysis's
structural properties: EAR states, N(O) per family, gap forms, gap
distribution. Deterministic across runs. Two independent implementations
that reach the same classifications produce the same fingerprint.

**Gap forms.** The three structural forms a GCG can take: Layer
Non-Activation (the layer exists but did not activate for this execution),
Layer Absence (the layer does not exist for this operation family), and
Layer Bypass (the layer exists and is active but this execution routed
around it).

---

## EAR States

**ACTIVE** — the receipt is constitutive of operation completion. The governance
mechanism is not observing the operation; it is a prerequisite of the operation.
Remove the mechanism and the operation fails.

The canonical case is HashiCorp Vault with an audit device enabled. Vault's audit
device is fail-closed: if the audit device cannot write the receipt of a
`secret/read` operation, the operation fails. The governance receipt is not a
log entry written after the fact — it is part of the operation's completion
condition. This makes `secret_read` ACTIVE.

The defining property of ACTIVE: *two independent observers could construct the
complete authorization chain for every operation from the receipts alone.*

**CRYSTALLIZED** — governance mechanisms exist and are formally evaluated, but
the operation proceeds regardless of outcome. The receipt is parallel, not
constitutive. This is the governance-forward state: the infrastructure is present
but not yet mandatory.

The canonical case is GitHub Actions with OIDC cloud federation. When a workflow
requests an OIDC token for AWS access, the token exchange is governed — the token
identifies the workflow by repository, branch, and job context. But the workflow
proceeds whether or not the token exchange succeeds. The governance is evaluated
and receipted; it does not gate the workflow.

CRYSTALLIZED is where most production systems sit. It is not a failure — it is
the correctly identified state of systems where governance is specified and
implemented but not yet constitutive.

**ABSENT** — no governance mechanism exists for this operation family. The
operation completes and leaves no structured record that preserves truth about
who authorized it, what policy applied, or what happened.

The canonical case is default Elasticsearch: no authentication, no TLS, no audit
log. Any network-reachable client can read, write, and delete indices. ABSENT is
often the default state before governance is configured — it is the starting
point, not the endpoint.

---

## Operation Families

EAR state is assessed per *operation family*, not per system. An operation family
is a named class of operations that share a governance surface. Vault has
`secret_read`, `secret_write`, `auth_login`, `token_create`, `policy_manage`,
`sys_audit`, and `root_token_operation` as distinct families — each with its own
governance layers, its own EAR state, and its own gap profile.

This matters because a system's governance quality is not uniform. Vault is ACTIVE
for `secret_read` (audit device is fail-closed) and ABSENT for
`root_token_operation` (root token bypasses all governance mechanisms). Reporting
Vault as simply "ACTIVE" would be misleading. Reporting it as "ABSENT" because of
the root token would be equally misleading. The per-family classification captures
the actual structure.

---

## N-Determination

**N(O)** is the declared governance layer set for an operation family O — the set
of layers that *should* participate in governing that operation according to the
system's architecture and documentation.

**k(O, e)** is the realized set for a specific execution instance e — the layers
that *actually participated* in governing that operation when it ran.

The **Governance Coverage Gap (GCG)** is N(O) − k(O, e): the layers that
were declared but did not participate.

Each EAR adapter declares N(O) in its `GovernanceDeclaration` with one of three
determination strategies:

- **DECLARED-N**: N is read from the system's own documentation, architecture
  guides, and configuration surface. This is the standard strategy.
- **MINIMUM-N**: N is the smallest set consistent with the system's claims.
  Used when documentation is incomplete or contradictory.
- **PER-CONTEXT-N**: N varies by execution context (e.g., different governance
  applies to privileged vs standard containers).

N-determination must be idempotent: two independent calls to `collect_governance_layers()`
for the same operation family must return the same result. The gate tests verify this.

---

## Gap Forms

When k(O, e) < N(O), the gap takes one of three forms:

**NON_ACTIVATION** — the governance layer exists and is configured, but did not
activate for this execution instance. The mechanism is present; the trigger
condition was not met, or the mechanism has a scope boundary that excludes this
operation. *Example: Kubernetes audit log configured but not capturing this API
group. Example: Entra ID Conditional Access Policy that does not cover legacy
authentication paths.*

**ABSENCE** — the governance layer does not exist for this operation family.
There is no mechanism to govern this operation, not a misconfigured one.
*Example: npm lifecycle script execution has no governance layer in the npm
runtime. Example: Ansible CLI execution has no state model and therefore no
receipt.*

**BYPASS** — the governance layer exists and is active, but this operation
takes a path that circumvents it. The bypass may be intentional (root token,
`--privileged` flag) or exploitable (privilege escalation, CVE-class bypass).
*Example: Vault root token bypasses all policy evaluation. Example: Docker
`--privileged` disables seccomp, AppArmor, and capability restrictions.*

Gap magnitude is |N(O)| − |k(O, e)|: how many declared governance layers did
not participate.

---

## Convergence Fingerprints

Each EAR adapter analysis produces a **convergence fingerprint** via
`convergence_fingerprint(report)` in `gap_assertions.py`. The fingerprint is
a 16-character hex string derived from the SHA-256 hash of the analysis's
structural properties:

- EAR states per operation family
- N(O) declared governance layers per family
- Gap forms and gap patterns per family
- Total gap count and form distribution

The fingerprint deliberately excludes timestamps, request IDs, and
instance-specific evidence text. This makes it deterministic across runs:
two independent executions of the same adapter on the same code produce the
same fingerprint. Two conforming implementations that reach the same
classifications produce the same fingerprint — this is the convergence
property. A classification change — even a single family shifting from
CRYSTALLIZED to ABSENT — produces a different fingerprint.

Fingerprints serve two purposes. First, they are regression anchors: if an
adapter changes, the fingerprint changes, and the change is visible in
`governed_pytest.py` as a MISMATCH. Second, they are conformance checks:
a new implementation of the same system that produces the same fingerprint is
demonstrably convergent with the reference implementation.

The reference fingerprints for all 80 systems are recorded in
`governed_pytest.py`'s `KNOWN_FINGERPRINTS` table and in each system's
`FINDINGS.md`.

---

## Gate Tests

Every EAR adapter must pass a minimum of 9 gate tests across three categories
(the T1576 standard):

**Category 1 — GCG detection (3 tests)**

- T-GCG-01: Given an execution trace with a Layer Absence, the adapter produces
  a GCG assertion with the correct form.
- T-GCG-02: Given an execution trace with a Layer Bypass, the adapter produces
  a BYPASS assertion with gap magnitude > 0.
- T-GCG-03: Given a fully governed trace (all N layers participated), the adapter
  produces zero GCG assertions. No false positives.

**Category 2 — N-determination (3 tests)**

- T-ND-01: N-determination is idempotent — two independent calls return the same
  layer set.
- T-ND-02: The N-determination strategy (DECLARED-N, MINIMUM-N, PER-CONTEXT-N)
  is documented in the governance declaration.
- T-ND-03: N is documented with source citations — where the declared layer set
  was derived from.

**Category 3 — EAR state assessment (3 tests)**

- T-EAR-01: A configuration that enables the constitutive governance mechanism
  produces ACTIVE (or the correct ceiling for systems where ACTIVE requires
  specific conditions).
- T-EAR-02: A configuration without the constitutive mechanism produces
  CRYSTALLIZED or ABSENT as appropriate.
- T-EAR-03: Verifies a specific characteristic EAR property of the system —
  e.g., that no family reaches ACTIVE for a CRYSTALLIZED-ceiling system, or
  that a specific ACTIVE family correctly identifies the constitutive condition.

The gate tests verify internal consistency of the adapter's model, not the
correctness of the model against a live system. Correctness comes from the
analysis work documented in FINDINGS.md.

---

## Corpus inclusion criteria

Systems were selected to provide broad coverage of the production software
stack rather than to represent a statistical sample. Inclusion criteria:

**Deployment prevalence.** Systems in wide production use, where governance
properties affect a large number of real deployments.

**Governance surface diversity.** Systems spanning meaningfully different
governance architectures: secrets management, container runtime, service
mesh, CI/CD, identity, databases, supply chain, cloud infrastructure, ML
platforms, policy engines, messaging. Comparisons across categories are
more informative when categories are well-represented.

**EAR state range.** The corpus was built to include systems across the
full ACTIVE–CRYSTALLIZED–ABSENT spectrum, including systems where ACTIVE
is achievable and systems where it is architecturally impossible.

**Structural novelty.** Systems that introduced a new constitutional
concept (see [CONCEPTS.md](CONCEPTS.md)) were prioritized, as novel
findings contribute more to the methodology than confirmatory ones.

Corpus-relative claims ("only CI/CD system in corpus with constitutive
approval gate") are claims about this selection of 80 systems. They do not
assert universality across all software. The corpus makes no claim to be
exhaustive or representative of any broader population.

---

## What this methodology is not

**Not a scanner.** The adapters model governance architecture. They do not
run against live systems to detect misconfigurations in production environments.
Running an adapter against live audit data is possible where systems provide
APIs, but the primary output is a structural classification of what governance
is achievable, not a runtime posture assessment.

**Not a compliance checklist.** The EAR classification captures constitutional
properties — whether governance is constitutive of operations — not compliance
with any specific framework. A CRYSTALLIZED system may fully satisfy a compliance
requirement; an ACTIVE system may not. Compliance and constitutional governance
quality are different questions.

**Not a CVSS scorer.** CVEs appear in FINDINGS documents as evidence of where
gaps have been exploited, not as the primary finding. A system with no CVEs
can be constitutionally ungoverned; a system with multiple CVEs can be
constitutionally well-governed. The classification is architectural, not
vulnerability-count-based.

**Not per-deployment.** EAR states reflect the governance architecture of a
system at a reference configuration, documented in each adapter's
`GovernanceDeclaration`. Whether your specific deployment reaches ACTIVE depends
on your configuration. The adapter tells you what governance architecture
is achievable and what the ceiling is.

---

© Ableman Constitutional Systems — ableman.research@gmail.com  
Documentation: CC BY-ND 4.0 International
