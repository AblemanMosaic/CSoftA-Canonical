# Closing the Gap
## Governance Remediation Recommendations — CSoftA Corpus

*Ableman Constitutional Systems*  
*ableman.research@gmail.com*  
*https://github.com/AblemanMosaic/CSoftA-Canonical*

---

Most systems that claim governance do not fully govern. This document
identifies exactly where each gap is, what form it takes, and what closes
it — derived from the Constitutional Software Analysis (CSoftA) of 80
production systems.

**The ACTIVE standard:** a governed system is one where an operation cannot
complete without producing a receipt that binds that operation to its
authorizing principal. The receipt is not optional metadata appended after
the fact — it is constitutive of the operation. Most systems sit below this
standard by default. Most operators do not know they are below it.

**How to use this document:** Find your system. Read the current governance
state. The gap description names the structural property that limits
governance — not a CVE, not an opinion. Incidents are cited as confirmation,
not as the point. The vendor recommendation is directed at the vendor.
The "what closes it" section is directed at you.

Four gap forms appear throughout the corpus:

- **NON_ACTIVATION** — the governance mechanism exists, is not enabled by
  default, and produces no signal to the operator that it is absent.
- **BYPASS** — a specific path routes around an otherwise active governance
  layer, silently, often by design.
- **LAYER_ABSENCE** — no governance mechanism exists for this operation
  family at all, regardless of configuration.
- **PAYWALLED** — ACTIVE governance is architecturally available but gated
  behind a commercial license, making the gap a purchasing decision.

Entries are grouped by what kind of response the gap requires. Reference
T-ids point to the CSoftA corpus for full analysis.

Questions or engagements: **ableman.research@gmail.com**

---

## Part I — Configuration Gates
*One operation separates CRYSTALLIZED from ACTIVE. No architectural change
required. The gap is deployment, not design.*

---

### HashiCorp Vault

**Current state:** ACTIVE (with audit device) / CRYSTALLIZED (default)

**The gap:** Vault ships with auditing disabled by default. No audit device
is configured during `vault operator init`, and there is no startup warning,
UI banner, or persistent signal on `vault status` that the cluster is
ungoverned. Operators routinely believe governance is active because the
capability exists. HashiCorp's own best practices documentation opens with:
"Enable at least one audit device immediately after initialization." The
initialization process does not enforce this. Until an audit device is
configured, every secret read, policy evaluation, and token issuance
completes without a governance receipt.

**What closes it:** Require audit device configuration as a prerequisite for
production-readiness. A deployment gate validates `sys/audit` for enabled
devices before the cluster is declared production. A signed bypass declaration
is required for any root token operation. `governance_posture.json` is
produced for CI/CD gating. (T1652)

**Vendor recommendation:** Make audit device configuration a required step
in `vault operator init`. Surface a persistent warning on every `vault status`
and UI view until at least one audit device is enabled.

**Gap form:** NON_ACTIVATION (audit_device) + BYPASS (root_token)

---

### PostgreSQL

**Current state:** ACTIVE (with pgaudit) / ABSENT (default)

**The gap:** Default PostgreSQL produces no structured, queryable record of
which principal executed which query. ACTIVE governance requires installing
and configuring the pgaudit extension — adding it to `shared_preload_libraries`
and setting logging classes. Production clusters frequently run without it,
creating silent NON_ACTIVATION. Row-level security has a secondary gap:
multiple CVEs demonstrate policy bypass via cached query plans across roles.
This gap was material in the 2025 US Treasury breach where query-level
reconstruction was unavailable to incident responders. (T1675)

**What closes it:** Gate cluster production-readiness on pgaudit being
installed and configured. Validate `shared_preload_libraries` includes
pgaudit, validate logging class covers DDL/DML/role changes, monitor for
RLS policy bypass patterns via cached plan reuse. (corpus add-on)

**Vendor recommendation:** Ship pgaudit as a bundled extension enabled by
default, or surface a clear warning during `initdb` and `pg_ctl start` when
no audit extension is active.

**Gap form:** NON_ACTIVATION (query_audit)

---

### OPA (Open Policy Agent)

**Current state:** CRYSTALLIZED (decision log non-constitutive)

**The gap:** OPA evaluates policy and returns a decision whether or not the
decision log write succeeds. `--decision-log-path` is not required to start
OPA — decision logging is opt-in and structurally non-constitutive. An OPA
deployment without decision logging produces no queryable audit trail of
policy evaluations. The governance record is decoupled from the governance
event. Confirmed in production: OPA policy misconfiguration contributed to
unauthorized data access in a documented 2024 breach; no decision log was
available to reconstruct which evaluations permitted the access. (T1604)

**What closes it:** Validate `--decision-log-path` before OPA serves traffic.
Wrap the decision endpoint to verify log write before forwarding the decision,
making the log write constitutive. Block bundle activations without version
identifiers. (T1657)

**Vendor recommendation:** Make `--decision-log-path` required in production
mode. Surface a warning when OPA starts without decision logging configured.

**Gap form:** NON_ACTIVATION (decision_log)

---

### Apache Kafka

**Current state:** ACTIVE (broker mTLS) / ABSENT (all data operations, default)

**The gap:** Default Kafka ships with ACLs disabled
(`allow.everyone.if.no.acl.found=true`) and no structured audit log. No
receipt binds a produced message to its publishing principal. The single
ACTIVE surface — broker mTLS — governs access to the broker but not what
is produced or consumed once connected. This is the largest governance gap
relative to operational significance in the corpus: Kafka processes trillions
of messages per day in production and has ABSENT governance for all data
operations out of the box. Three named production breaches confirm the gap
form directly. (T1673)

**What closes it:** Gate deployment on ACL configuration — ABSENT assertion
if `allow.everyone.if.no.acl.found=true`. Enforce mTLS for all broker
connections. Wrap AdminClient to produce structured receipts for ACL changes.
Monitor producer/consumer operations against ACL declarations. (corpus add-on)

**Vendor recommendation:** Change `allow.everyone.if.no.acl.found` default
to `false`. Require explicit ACL bootstrap before broker accepts connections.

**Gap form:** NON_ACTIVATION (acl_enforcement) + LAYER_ABSENCE (audit_log)

---

### GitHub Actions

**Current state:** ACTIVE (OIDC cloud federation) / ABSENT (action supply chain, default)

**The gap:** Actions referenced by mutable version tags
(`uses: actions/checkout@v4`) can be retroactively modified to point to
malicious code without any workflow change. The governance gap is structural:
the workflow file has not changed, the audit record shows no modification,
but the code that executes has been silently replaced. SHA pinning closes
this with a single-character change per action reference and is almost never
applied by default. CVE-2025-30066 confirmed this at scale across 23,000+
repositories. (T1691)

**What closes it:** Scan all workflow files for unpinned action references —
ABSENT assertion per unpinned reference. Validate `permissions` blocks
declared and minimal. Detect `pull_request_target` without head SHA pinning.
Monitor OIDC federation configuration. (corpus add-on)

**Vendor recommendation:** Surface a repository-level warning for workflows
containing unpinned action references. Consider making SHA pinning the
default for newly created workflows.

**Gap form:** LAYER_ABSENCE (action_provenance, default)

---

### Entra ID (Azure Active Directory)

**Current state:** ACTIVE (modern auth with CAP+MFA) / ABSENT (legacy auth paths)

**The gap:** The same identity policy is simultaneously ACTIVE for one
authentication path and ABSENT for another — and the attacker chooses the
path. Conditional Access Policies with MFA produce ACTIVE governance for
OAuth 2.0 / OIDC. Legacy authentication protocols (Basic Auth, NTLM,
ESMTP AUTH) bypass Conditional Access entirely. Blocking legacy auth is an
explicit, non-default configuration step. This split-path architecture
produces a governance gap that exists by default in every new Entra ID
tenant. CVE-2025-55241 (CVSS 10.0) added an architectural amplifier:
undocumented Actor tokens could impersonate any user globally, bypass
Conditional Access and MFA, and generate no logs in the target tenant.
(corpus analysis)

**What closes it:** Block legacy auth via Conditional Access Policy. Require
MFA for all users via CAP. Configure PIM for privileged roles — no permanent
Global Admin assignments. Export sign-in logs to external SIEM; default
Entra ID log retention is 30 days. (corpus add-on)

**Vendor recommendation:** Make legacy authentication blocking the default
for new tenants. Surface a persistent tenant-level warning when legacy auth
paths are enabled.

**Gap form:** BYPASS (legacy_auth_path) + NON_ACTIVATION (log_export)

---

### Jenkins

**Current state:** CRYSTALLIZED (all families) — with configuration drift degradation

**The gap:** Jenkins introduces a governance gap form not present in
cloud-native CI/CD: configuration drift as governance degradation. Long-lived
installations accumulate it continuously. The most directly exploitable
form: global credentials in the Jenkins credential store are accessible to
any user with Job/Execute permission regardless of which job they are
executing. A credential declared for one purpose is reachable by any
principal with execute rights — no scope boundary enforced by default.
Compound this with plugin lag and the governance posture of a Jenkins
instance deployed in 2019 is structurally different from one deployed today,
even with identical initial configuration. (corpus analysis)

**What closes it:** Validate Matrix Authorization configured. Validate
Audit Trail plugin active. Validate credentials scoped to specific
folders/jobs — no global credentials accessible to all principals. Validate
plugin versions within security-patch window. Produce drift score per job.
(corpus add-on)

**Vendor recommendation:** Make credential folder scoping the default
configuration mode. Require explicit authorization for global credential
access rather than permitting it by default.

**Gap form:** NON_ACTIVATION (credential_scope) + NON_ACTIVATION (audit_trail)

---

## Part II — Architectural Changes Required
*The gap is structural. No single configuration operation closes it.
A compensating layer is required. We state the realistic governance
ceiling alongside the remediation.*

---

### Kubernetes

**Current state:** CRYSTALLIZED (all families — audit opt-in, non-participation unrecorded)

**The gap:** Kubernetes is a continuously executing governance machine that
cannot provide a unified explanation of how governance was applied to any
specific operation. Audit logging is opt-in. Non-participation by declared
governance layers is unrecorded. The gap between declared governance (N
layers) and realized governance (k layers per pod) is invisible without
additional instrumentation. Default pod creation touches RBAC but not Pod
Security Standards, not NetworkPolicy, not admission controllers — unless
each is explicitly configured per namespace. The gap is architectural:
Kubernetes was designed to be extensible, not to produce unified governance
receipts per operation. (T1655)

**What closes it:** Deploy an operator that computes k/N per pod
continuously — the ratio of realized governance participation to declared
governance layers. Gate on audit logging policy level. Enforce Pod Security
Standards at the namespace level. Monitor RBAC drift. Produce
`k8s_posture.json` per namespace. (T1655)

**Realistic ceiling:** CRYSTALLIZED. The compensating layer makes the gap
visible and measured rather than silent — it raises the floor, not the
ceiling.

**Vendor recommendation:** Make audit logging non-optional in production
clusters. Record non-participation events explicitly — when a declared
governance layer did not evaluate a specific admission request, that absence
should appear in the audit record.

**Gap form:** NON_ACTIVATION (audit_log) + NON_ACTIVATION (admission_controllers,
PSS, network_policy — all per-pod, all opt-in)

---

### AWS CloudTrail

**Current state:** CRYSTALLIZED (all families — governance substrate is revocable)

**The gap:** CloudTrail is the governance-of-governance layer for the
entire AWS corpus. Every receipt in the AWS stack — IAM authorization,
S3 data events, KMS operations, Identity Center sessions — depends on
CloudTrail being enabled. Any principal with `cloudtrail:StopLogging`
permission can disable it. This is MITRE ATT&CK T1562.008 — the first
step in every documented AWS compromise. The structural property that
makes CloudTrail CRYSTALLIZED rather than ACTIVE: the audit substrate of
a system that can be unilaterally disabled by a sufficiently privileged
principal is categorically different from one that cannot be. (T1727)

**What closes it:** Alert immediately on StopLogging/DeleteTrail — treat
them as breach indicators, not administrative operations. Validate
multi-region trail and data events for sensitive buckets. Enforce log
file validation. Lock the log storage bucket against modification via
S3 Object Lock. (corpus add-on)

**Realistic ceiling:** CRYSTALLIZED. Making StopLogging an immediate
alert converts a silent bypass into a detectable one. It does not make
CloudTrail structurally un-disableable.

**Vendor recommendation:** Require explicit re-authorization (separate
IAM policy, MFA, or approval workflow) for StopLogging and DeleteTrail.
Consider requiring a service control policy exception at the organization
level for these operations.

**Gap form:** BYPASS (StopLogging — always available to sufficiently
privileged principal)

---

### Docker

**Current state:** CRYSTALLIZED (standard containers) / ABSENT (--privileged, interior, build)

**The gap:** Docker demonstrates boundary governance without interior
governance — the structural pattern where controls concentrate at the
perimeter and disappear inside. The `--privileged` flag disables seccomp,
AppArmor, and capability restrictions simultaneously with no receipt
recording which layers were bypassed or why. This is a Layer Bypass with
gap magnitude 3 — the highest in the corpus for a single flag. Interior
container execution and Dockerfile RUN instructions have no governance
layer by design. (T1654)

**What closes it:** Deploy a governance-aware proxy between Docker clients
and the daemon. Intercept `--privileged` — require a signed bypass
justification receipt before allowing. Enforce seccomp profiles and
capability dropping for standard containers. Monitor privileged status
drift. (T1654)

**Realistic ceiling:** Interior execution governance requires a separate
architectural layer (Falco/Tetragon for syscall visibility). The proxy
makes the bypass declared and receipted rather than silent — it does not
govern what happens inside the container.

**Gap form:** BYPASS (--privileged, gap magnitude 3) + LAYER_ABSENCE
(interior_execution, build_execution)

---

### Elasticsearch

**Current state:** CRYSTALLIZED (with security enabled) / ABSENT (default dev mode)

**The gap:** Elasticsearch occupies a structurally distinct position in
the governance stack: it is the evidence layer — where audit logs, SIEM
events, and governance receipts from other systems are stored and queried.
A governance gap in the evidence store is not equivalent to a governance
gap in an application: it retroactively degrades the governance posture
of every system feeding into it. An attacker who can write to an
ungoverned Elasticsearch index can modify or delete the governance evidence
for Vault, CloudTrail, and every other system whose receipts are stored
there. Default single-node dev mode disables all security. This produced
years of publicly accessible instances exposing not just application data
but the governance records of other systems. (corpus analysis)

**What closes it:** Validate authentication and TLS enabled before
accepting external data. Validate audit logging configured. Validate RBAC
roles follow least-privilege. Monitor for unauthenticated access patterns.
Alert on bulk document access from unusual principals. (corpus add-on)

**Realistic ceiling:** CRYSTALLIZED. The compensating layer hardens the
default and makes access patterns visible.

**Vendor recommendation:** Remove the dev-mode security bypass from
production distributions. Default-enabled security for all deployment
modes — the current default has caused documented harm at scale.

**Gap form:** LAYER_ABSENCE (authentication, TLS — default dev mode) +
NON_ACTIVATION (audit_log)

---

### Active Directory / Kerberos

**Current state:** CRYSTALLIZED (Event 4769 logged) — with protocol-inherent bypass

**The gap:** Kerberoasting is not a misconfiguration. It is a consequence
of how Kerberos tickets work at the protocol level. Any authenticated
domain user can request a service ticket for any SPN. The KDC cannot
distinguish a legitimate from a malicious request — both produce Event
4769. The attacker takes the encrypted ticket offline and cracks the
password at arbitrary computing power, entirely outside the governance
perimeter. The governance evidence is present; it is structurally
insufficient to detect the attack. No configuration change to Active
Directory closes this gap. (corpus analysis)

**What closes it:** Eliminate the attack surface rather than detect it
post-fact. Deploy group Managed Service Accounts (gMSAs) for all SPNs —
240-character random passwords rotated automatically, offline cracking
computationally infeasible. Enforce AES-only Kerberos (disable RC4).
Monitor Event 4769 for anomalous patterns. Validate no accounts hold
DS-Replication permissions outside declared domain controllers. (corpus
add-on)

**Realistic ceiling:** CRYSTALLIZED. Protocol-level gaps require
protocol-level remediation, not detection. gMSA deployment shrinks the
attack surface structurally.

**Gap form:** BYPASS (protocol-inherent — Kerberos SPN ticket issuance
is identical for legitimate and malicious requestors)

---

### npm

**Current state:** ABSENT (lifecycle scripts) / CRYSTALLIZED (install with lockfile)

**The gap:** npm lifecycle scripts (`preinstall`, `postinstall`, `prepare`)
execute arbitrary code during package installation with full process
privileges and no governance receipt. The executing principal, script
content, and outcome produce no structured record. A structurally distinct
second surface: module-load-time execution — code that runs when `require()`
or `import` resolves a module, before application code executes. Both
surfaces operate without a governance layer by design, not by configuration
omission, and both have been exploited repeatedly in documented supply
chain attacks. (T1653, T1580, T1581)

**What closes it:** Pre-install hook intercepting lifecycle script
execution — records package name, version, script content hash, outcome.
Optionally sandboxes scripts. CI/CD gate validates hashes against allowlist
before install completes. Wrap `require()` to record module-load-time
execution events. (T1653)

**Vendor recommendation:** Default to `--ignore-scripts`, requiring
explicit opt-in for lifecycle script execution. Surface a per-package
warning for any package declaring lifecycle scripts. Provenance attestation
(PEP 740 equivalent) as a first-class install-time check.

**Gap form:** LAYER_ABSENCE (lifecycle_governance) + LAYER_ABSENCE
(module_load_governance)

---

## Part III — Vendor Decisions
*The gap is a commercial or architectural decision by the vendor.
No operator configuration closes it. We state this directly.*

---

### MongoDB

**Current state:** ACTIVE (Enterprise Audit) / ABSENT (Community Edition default)

**The gap:** MongoDB Enterprise Audit — ACTIVE structured governance for
document operations — requires a commercial license. MongoDB Community
Edition, the dominant global deployment form, defaults to ABSENT structured
audit: no queryable record of which principal read or wrote which document.
Unlike PostgreSQL where the ACTIVE path (pgaudit) is open-source, MongoDB
gates its governance path behind commercial licensing. The consequence is
a market incentive to leave governance absent: organizations using Community
Edition must pay for governance or operate without it. MongoBleed
(CVE-2025-14847, December 2025) confirmed the cost of the absent floor:
87,000+ vulnerable instances, no authentication, no TLS, no audit log —
the three governance prerequisites simultaneously absent in the default
configuration. (corpus analysis)

**What closes it (operator):** Enforce authentication and TLS regardless
of edition. Validate RBAC roles follow least-privilege. Detect
MongoBleed-class configurations. For Community Edition, accept that ACTIVE
query governance requires third-party tooling. (corpus add-on)

**Vendor recommendation:** Open-source audit logging. Authentication and
TLS should be enabled by default in all editions. The governance gap
created by commercial paywalling of audit has produced documented,
large-scale incidents in Community Edition deployments. The cost is borne
by your users, not by MongoDB, Inc.

**Gap form:** PAYWALLED (Enterprise Audit) + LAYER_ABSENCE (authentication,
TLS — default Community Edition)

---

### MySQL

**Current state:** ACTIVE (Enterprise Audit) / ABSENT (Community Edition default)

**The gap:** MySQL Enterprise Audit — ACTIVE structured query governance —
is only available in MySQL Enterprise Edition (commercial license). MySQL
Community Edition has only `general_log` (high performance impact, not
structured, disabled by default) or no query audit. This is not a
configuration gap. It is a purchasing decision. The ACTIVE governance
architecture exists and works. It is commercially gated by Oracle.
Community Edition is the dominant global deployment form — the gap
affects the majority of MySQL installations. (corpus analysis)

**What closes it (operator):** For Enterprise Edition: validate Enterprise
Audit configured, TLS required for all connections. For Community Edition:
enable `general_log` as a fallback, accepting performance impact and
reduced structure. Evaluate MariaDB Audit Plugin for some deployments.
(corpus add-on)

**Vendor recommendation:** Make structured audit logging available in
Community Edition. The current model creates a direct market incentive to
operate without governance — the cost of that incentive is borne by
Community Edition users and the organizations they operate within, not
by Oracle.

**Gap form:** PAYWALLED (Enterprise Audit)

---

## Consulting Engagement

These recommendations are derived from the CSoftA methodology — a
systematic framework for classifying governance completeness across
software systems. The gap forms above are not assessments of whether
your deployment is secure in a conventional sense. They are structural
findings about whether your system is architecturally capable of knowing
what happened, to whom, under whose authorization, when something goes
wrong.

Implementing these recommendations requires understanding which gap form
applies to your specific deployment configuration, which operation families
are in scope for your risk model, and what governance floor your
organization actually needs versus what it currently has.

We offer that assessment.

**Contact:** ableman.research@gmail.com  
**Corpus:** https://github.com/AblemanMosaic/CSoftA-Canonical  
**Methodology:** https://doi.org/10.5281/zenodo.20472195

---

*This document covers 15 of 80 analyzed systems. Full corpus available
at the repository above. CSoftA analyses for all 80 systems include
structured gap classifications, incident validations, and add-on
specifications.*

*Version 1.0 — 2026-05-31 · Living document, updated from corpus*  
*© Ableman Constitutional Systems*  
*CC BY-ND 4.0 International — https://creativecommons.org/licenses/by-nd/4.0/*
