# Constitutional Concepts

**Ableman Constitutional Systems** — ableman.research@gmail.com

---

17 constitutional concepts emerged from analyzing 80 production software systems.
Each names a structural property of governance that recurs across systems and was
not captured by the prior vocabulary of ACTIVE / CRYSTALLIZED / ABSENT alone.

They are ordered by introduction: the first four emerged from Waves 1–10, the
remaining thirteen from Waves 11–16 as the corpus expanded into enterprise
middleware, ML platforms, identity, and legacy infrastructure.

---

## Foundational Concepts (Waves 1–10)

---

### Compile-Time ACTIVE-EAR (T1640)

**Introduced by:** Rust / Cargo

The borrow checker is constitutive of compilation completing. A Rust program
that violates memory safety rules cannot compile — the compiled binary cannot
exist if the borrow checker did not pass. This is the only case in the 80-system
corpus where ACTIVE governance operates at compile time rather than runtime.

The constitutional significance is the enforcement layer: all other ACTIVE cases
in the corpus operate at runtime (audit device, OIDC token exchange, mTLS
handshake, eBPF hook). Rust's ACTIVE enforcement operates before execution
exists. The governance receipt is the compiled binary itself.

The `unsafe` block is the declared bypass: a Rust program can opt out of borrow
checker enforcement by explicitly marking a block `unsafe`. This is a BYPASS with
a declared, scope-limited form — the bypass requires a governance declaration
(`unsafe`) and is visible in the source. Supply chain governance remains ABSENT
regardless of memory safety.

---

### IaC State File as Governance Receipt (T1684)

**Introduced by:** Terraform / OpenTofu

The Terraform state file is a governance receipt with a property not found in any
other receipt class in the corpus: it can silently diverge from governed reality.

Every other receipt in the corpus is either accurate or absent. A CloudTrail event
accurately records what happened or does not exist. A Vault audit log entry is
correct or is not written. The Terraform state file can be present, structurally
valid, non-empty, and substantively wrong — when infrastructure is modified
outside the IaC system, the state file records the last known state, not the
current state, with no gap assertion and no signal that the divergence occurred.

This is classified as STRUCTURAL_NONLOCALITY: the governance gap is not visible
from within the governance system itself.

---

### CI/CD Supply Chain as Governance Surface (T1702)

**Introduced by:** GitHub Actions

Third-party actions referenced by mutable tags (`uses: actions/checkout@v4`) are
supply chain attack surfaces. An action referenced by tag can be silently replaced
with malicious code after the tag was pinned — the workflow definition is
unchanged, but the code it executes is not. The `tj-actions/changed-files` attack
(2025, ~23,000 repositories affected) is the canonical case.

The constitutional finding generalizes: wherever a CI/CD system references
external code by a mutable identifier, the governance of what executes is ABSENT.
Pinning to a commit hash (`uses: actions/checkout@11bd71901bbe...`) is CRYSTALLIZED:
same bytes every time, but no provenance verification. Admission gate enforcement
(Cosign policy-controller requiring signed artifacts) is the only ACTIVE closure.

---

### Security Alert as Governance Receipt (T1683)

**Introduced by:** Falco / GuardDuty

Security detection systems — Falco, GuardDuty, Prometheus alerting — produce
receipts for events that have already occurred. The alert is evidence of a
completed operation, not a check that governed the operation completing. This
makes detection systems structurally CRYSTALLIZED for their detection families:
the event occurs, then the alert fires.

This is the correct classification, not a deficiency. Detection systems serve a
different constitutional role than admission systems: they provide governance
evidence after the fact, enabling audit, forensics, and response. The governance
receipt is parallel to the governed operation, not constitutive of it.

Falco's `kernel_module_load` is ACTIVE because loading Falco's kernel module is
constitutive of Falco's monitoring capability — not because detection itself is
ACTIVE. The distinction is between what Falco does (CRYSTALLIZED) and what Falco
requires to function (ACTIVE).

---

## Extended Concepts (Waves 11–16)

---

### Governance Evidence Storage Layer (T1782)

**Introduced by:** Elasticsearch

When the system that stores governance receipts from other systems is itself
ungoverned, all stored governance evidence is simultaneously accessible and
modifiable by any attacker who can reach it. One gap in the evidence storage
system compromises the governance evidence of every system whose receipts land
there.

Default Elasticsearch ships with no authentication, no TLS, and no audit log —
meaning the most common audit log storage backend is simultaneously the system
with no governance of its own contents. CVE-2025-37731 (PKI realm authentication
bypass) demonstrates that even when authentication is configured, scope boundary
gaps at the storage layer can retroactively undermine ACTIVE governance upstream.

The full meta-governance stack in an enterprise deployment runs four layers deep:
evidence generated (CloudTrail, OTel) → evidence collected (Falco, Prometheus) →
evidence stored (Elasticsearch) → evidence analyzed (Splunk, Grafana). A gap at
any layer compromises all layers above it.

---

### Split-Path Governance (T1783)

**Introduced by:** Microsoft Entra ID

The same identity policy is simultaneously ACTIVE on one authentication path and
ABSENT on another. The attacker selects the path, defeating the policy without
exploiting a vulnerability.

Entra ID Conditional Access Policies with MFA enforcement are ACTIVE for modern
authentication (OAuth 2.0 / OIDC): the token cannot be issued without MFA
completing. The same policies do not apply to legacy authentication (Basic Auth,
NTLM): these paths bypass Conditional Access entirely. Midnight Blizzard exploited
this to bypass MFA for initial Microsoft corporate access.

CVE-2025-55241 (CVSS 10.0, September 2025) extends the finding: Actor tokens
bypass Conditional Access, bypass MFA, and generate no logs in the target tenant —
the BYPASS and ABSENT governance properties occur simultaneously.

Split-path governance is constitutionally distinct from most gap forms in the
corpus: it is not that governance is absent across the board, nor that it failed
to activate — it is that two governance regimes coexist with incompatible
properties, and the attacker-controlled choice of path determines which applies.

---

### Commercial Governance Paywalling (T1784)

**Introduced by:** MySQL, MongoDB, Nomad, Consul

ACTIVE governance exists and is technically available but is gated behind a
commercial license. This is the only gap class in the 80-system corpus where
closing the gap requires a purchasing decision, not a configuration decision.

MySQL Enterprise Audit provides ACTIVE structured query governance. MySQL
Community Edition provides no structured audit path — not CRYSTALLIZED-by-default
but genuinely ABSENT. MongoDB Enterprise Audit is ACTIVE for document operations;
MongoDB Community Edition is ABSENT by default. Nomad Enterprise includes an audit
log; Nomad Community does not.

The constitutional implication is sharper than it appears: compliance frameworks
that require database audit logging may be formally satisfied with CRYSTALLIZED
controls (general_log in MySQL Community, connection logging) while ACTIVE
governance — the kind that records what was queried, by whom, on what data — is
gated behind expensive licensing. The gap between what the framework requires and
what is achievable without additional spending is a financial boundary, not a
technical one.

---

### Configuration Drift as Governance Gap (T1791)

**Introduced by:** Jenkins

Long-lived self-hosted installations accumulate governance degradation
continuously over their operational lifetime. A Jenkins instance correctly
configured on day one degrades over years: stale jobs accumulate unused
credentials, plugins lag security patches, RBAC configurations grow organically
without review, global credential stores expand to cover new projects without
scope restriction.

This is the first system in the 80-system corpus where governance quality is
*dynamically degrading* rather than statically determined by configuration.
Every other system in the corpus has a fixed governance quality at a reference
configuration: configure the audit device and Vault is ACTIVE; disable it and
it is CRYSTALLIZED. Jenkins is different: even with the correct initial
configuration, governance quality moves toward ABSENT as a function of time and
operational activity without active maintenance.

The remediation direction — systematic periodic audit of credential stores,
plugin versions, and RBAC configurations — is structurally different from
"configure this setting." It requires ongoing operational governance, not a
one-time configuration act.

---

### Stateless IaC (T1792)

**Introduced by:** Ansible

Imperative configuration management with no persistent state model produces ABSENT
governance receipt by architectural design, not misconfiguration.

Terraform's governance gap (T1684) is a state file that can diverge from reality —
the receipt exists but can be inaccurate. Ansible's governance gap is different:
no state file exists by design. Each playbook execution is fresh imperative
execution against the current system state. There is no persistent record of what
the last execution produced, no convergence proof, and no structural basis for a
governance receipt.

AWX / Ansible Tower adds CRYSTALLIZED governance on top — it records what playbooks
ran, when, and with what result. But the underlying model remains stateless: the
receipt is a record of execution, not a record of state. A host modified outside
Ansible produces no receipt, no drift detection, and no gap assertion.

The IaC governance spectrum that emerges from the corpus:
Ansible (stateless, ABSENT) → Puppet (convergence report, CRYSTALLIZED) →
Terraform (state file, CRYSTALLIZED with drift gap) →
Pulumi (state + CrossGuard policy, ACTIVE for policy) →
Crossplane (K8s-native reconciliation, ACTIVE continuously).

---

### Kernel-Time Enforcement (T1793)

**Introduced by:** Cilium / Tetragon

eBPF LSM (Linux Security Module) hooks evaluate and enforce policy within the
Linux kernel before system calls complete — constitutive enforcement below the
container runtime, below the container escape boundary, below all userspace
bypass paths.

Kernel-time enforcement eliminates the TOCTOU (time-of-check-time-of-use) gap
present in userspace enforcement: the evaluation occurs synchronously in-kernel,
not via a userspace agent that could be killed, bypassed, or evaded. It cannot
be bypassed via privileged containers, admission webhook failure, container
runtime vulnerabilities, or process signals.

The XZ Utils backdoor (CVE-2024-3094) is the canonical demonstration: Tetragon
detected anomalous sshd process chains at kernel level before CVE disclosure and
before the attack method was known to the security community. Behavioral detection
without prior knowledge of the attack — the receipt was constitutive of detecting
the anomaly, not a log entry produced after exploitation.

This extends the governance enforcement hierarchy established elsewhere in the
corpus: post-hoc log < admission gate ACTIVE < kernel-time enforcement ACTIVE.

---

### Relationship Tuple Store as Governance Surface (T1794)

**Introduced by:** OpenFGA (Zanzibar model)

Relationship-based access control (ReBAC) derives permissions from a graph of
relationships stored as tuples: `user:alice member group:eng`, `group:eng viewer
document:x` → alice has viewer on document:x. The primary governance surface
is not the authorization check (which OpenFGA evaluates correctly) — it is the
tuple store that encodes the relationships.

If tuple write governance is ABSENT — if any authenticated user can write tuples
that grant permissions — the entire authorization model is undermined via data
writes. A correctly functioning authorization check on incorrect data produces
incorrect authorization decisions.

This is a new governance surface not present in RBAC or policy-based systems:
those systems derive permissions from role assignments or policy documents, which
are typically governed as configuration. ReBAC derives permissions from data,
which has different governance requirements. The tuple store must be governed as
a security-critical data store, not just as application data.

---

### Protocol-Inherent Bypass (T1801)

**Introduced by:** Active Directory / Kerberos

Kerberoasting exploits the correct operation of the Kerberos protocol. Any
authenticated domain user can request service tickets from the KDC. The KDC
responds normally — it cannot distinguish a Kerberoasting request from a
legitimate service ticket request. Service tickets are encrypted with the service
account's password hash, which is extractable from the ticket and offline-crackable.

This is not a vulnerability. It is not a misconfiguration. It is how Kerberos
was designed, and it has been documented as an attack technique since 2014.

The constitutional distinction from all other bypass forms in the corpus: prior
bypasses exploit design flaws (`--privileged`, `failurePolicy:Ignore`) or
misconfigurations (legacy authentication not blocked). Kerberoasting exploits
correct protocol behavior. The bypass cannot be made ACTIVE without replacing
the Kerberos protocol. gMSAs (Group Managed Service Accounts with 120-character
auto-rotating passwords) make offline cracking computationally infeasible but
do not eliminate the structural exposure: any domain user can still request
tickets and attempt to crack them.

The Ascension Health breach (May 2024, 140 hospitals disrupted) is the canonical
case. The governance ceiling for Active Directory Kerberos is CRYSTALLIZED.

---

### SIEM as Target (T1802)

**Introduced by:** Splunk

The SIEM is simultaneously the governance evidence store and a high-value
escalation target with elevated runtime privileges. Compromising it achieves
three things at once: read access to all indexed security events from every
monitored system, ability to create false detections or suppress real ones,
and elevated privilege escalation via the SIEM's own runtime context.

CVE-2026-20140 (February 2026, DLL hijacking → SYSTEM on Splunk Enterprise
Windows) demonstrates all three simultaneously. The Universal Forwarder
compounds the finding: an attacker with access to `inputs.conf` on any monitored
host can selectively suppress their own activity from the SIEM — governance
evidence goes ABSENT for that source with no central alarm.

This extends the governance evidence meta-layer concept (T1782, Elasticsearch)
with the addition that the SIEM holds elevated privileges the storage layer does
not. The meta-governance stack consequence: compromise of the analysis layer
(SIEM) yields more than compromise of the storage layer alone.

---

### Supply Chain Middle Layer (T1803)

**Introduced by:** Docker Hub / OCI Registry

The container registry sits between build-time provenance and admission-time
enforcement. Mutable tags (`image:latest`) are not a security boundary: an
attacker with push access can silently re-point any tag to different content
without triggering a governance event. Digest pins (`image@sha256:...`) are
CRYSTALLIZED — same bytes every time — but provide no provenance verification.

The Trivy scanner compromise (March 2026) is the canonical case: the `:latest`
tag for a widely-used security scanning image was re-pointed to malicious content.
Organizations that trusted the tag had the correct tag and the wrong image.

The supply chain triangle that emerges from the corpus:
Build-time (Packer, T1704): ABSENT provenance by default →
Registry-time (Docker Hub, T1803): ABSENT for mutable tags, CRYSTALLIZED for
digest pins →
Admission-time (Cosign + policy-controller, T1739): ACTIVE when configured.

The admission gate is the only constitutional closure for registry-layer gaps.
A correctly configured policy-controller verifying Cosign signatures makes
unsigned images constitutively inadmissible, closing the gap at the deployment
boundary regardless of what happened at build or registry time.

---

### Model Deployment Governance Gap (T1810)

**Introduced by:** MLflow, Kubeflow

No constitutive governance receipt exists for the decision to put a model version
into production in most ML platforms. The governance question for code deployment
is settled infrastructure: commit signatures, CI pipeline receipts, test gate
results, approval workflows with audit trails. The equivalent question for model
deployment — what is the governance receipt for authorizing `fraud-detector-v2`
for production serving — has no equivalent settled infrastructure.

MLflow tracks what models exist and what experiments produced them. It does not
require a receipted authorization decision for production promotion. Kubeflow
inherits K8s RBAC governance but adds no ML-specific governance of the promotion
decision.

CVE-2025-15379 (March 2026, command injection via `python_env.yaml` in model
artifacts) extends the finding: the model artifact itself is an execution surface.
A malicious model file can achieve RCE on any system that deploys it. The model
registry becomes a supply chain attack vector — the same constitutional class as
npm package injection, applied to model artifacts.

This is a domain maturity gap, not a fixable default. The tooling ecosystem for
constitutive model deployment governance does not yet exist in standardized form.

---

### Visualization Layer as Credential Store (T1811)

**Introduced by:** Grafana

The observability frontend stores credentials for every backend it queries:
Prometheus URLs, CloudWatch access keys, Elasticsearch passwords, Azure Monitor
credentials, Postgres connection strings. Compromising Grafana achieves two things
simultaneously: read access to all observability data from every monitored system,
and the credentials to access every backend directly.

This is the third meta-governance layer identified in the corpus, extending
Elasticsearch (T1782, storage layer) and Splunk (T1802, analysis layer): the
visualization/alerting frontend holds the keys to all backends. The attack value
of Grafana access exceeds the value of access to any individual backend it queries,
because Grafana holds the credentials for all of them.

CVE-2025-3260 (dashboard API authentication bypass) and CVE-2024-1442 (data source
wildcard UID granting access to all data source credentials) demonstrate that this
surface has a recurring vulnerability class — each new API path Grafana adds is a
potential scope boundary gap.

The meta-governance stack at completion: evidence generated (CloudTrail, OTel) →
evidence collected (Falco, Prometheus) → evidence stored (Elasticsearch) →
evidence analyzed (Splunk) → evidence visualized (Grafana). Each layer is
simultaneously the governance surface and a target whose compromise propagates
downward through the stack.

---

### Third-Party Governance Custody (T1818)

**Introduced by:** Weights & Biases (W&B), commercial ML platforms

Governance evidence held by a party the organization cannot unilaterally control.
W&B, Comet, Neptune, and similar commercial ML tracking platforms hold experiment
metadata, model versions, run lineage, and deployment records externally to the
organization.

The constitutional comparison to Certificate Transparency logs is instructive.
CT logs (T1779) are constitutively external: Certificate Authorities must submit
to them, browsers verify them, and no single organization controls the arrangement.
The custody is enforced by protocol. W&B custody is voluntarily external: the
organization chooses this arrangement. If W&B has a service outage, the governance
evidence is unavailable. If W&B changes terms of service, the evidence access
changes. If W&B is acquired, the custody transfers. None of these risks exist
for CT logs because the custody arrangement is not modifiable by either party.

The concept is not limited to ML platforms. It applies to any governance evidence
held in SaaS systems: audit logs in cloud-only SIEM products, configuration history
in SaaS IaC platforms, code review audit trails in hosted source control. The
voluntary vs constitutive distinction determines how robust the governance evidence
custody is.

---

*© Ableman Constitutional Systems — ableman.research@gmail.com*  
*Documentation: CC BY-ND 4.0 International*
