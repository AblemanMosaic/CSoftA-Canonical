# CX-S: Docker Constitutional Domain Invariants

*Docker Constitutional Analysis — CX:AES Codex*
*Inherits from: CSoftA Parent CX:AES Codex (T1574)*
*Version: 1.0*

---

## S-01: Boundary Governance Exists; Interior Governance Is Absent

Docker applies governance at the container boundary (seccomp syscall
filtering, AppArmor MAC, capability restrictions, namespace isolation).
Governance of process execution inside the container does not exist.

**What must hold:** Any analysis must distinguish boundary governance
(CRYSTALLIZED-EAR at best) from interior governance (ABSENT). Claiming
Docker containers are "governed" without specifying which boundary is
constitutionally inadmissible.

**Structural consequence:** The container boundary is a JD boundary
within the analysis scope. What happens inside is outside Docker's
constitutional visibility.

---

## S-02: --privileged Is Layer Bypass, Not Accepted Governance

`--privileged` disables seccomp, AppArmor, and capability restrictions
simultaneously. It is a Layer Bypass (GCG form C-11): the layers exist
in the architecture, are active for standard containers, and are
explicitly routed around by this flag.

**What must hold:** --privileged containers must be classified as
Layer Bypass instances. "Common in CI/CD" does not negate the GCG —
prevalence of bypass is not governance. (PCM-0333-200 Pitfall 1.)

**GCG codex canonical case:** PCM-0333-136 T-D.1 and PCM-0333-201
both treat --privileged as the Docker Layer Bypass reference instance.

---

## S-03: N(O) Is Equal for Standard and Privileged Families

The declared applicable layer set N(O) for `container_run_privileged`
is identical to N(O) for `container_run_standard`. The bypass claim
requires that the same layers are declared applicable — the gap is
in k(O,e), not in N(O).

**What must hold:** Any analysis that gives --privileged containers a
lower N(O) is inadmissible. The governance declaration applies equally;
the bypass is what differs.

---

## S-04: No Per-Operation Receipt Exists for Container Operations

Docker does not produce a per-operation structured receipt for container
runs. The daemon log records Docker's internal operations; the container
runtime logs record container lifecycle events; neither constitutes an
EAR for the governance decision that produced the container's security
configuration.

**What must hold:** Docker's recoverability is STRUCTURAL_NONLOCALITY
for interior execution, COMPOSITIONAL for daemon-level events.
No LOCAL recoverability claim is admissible for Docker container governance.

---

## S-05: seccomp=unconfined Is Non-Activation, Not Absence

`seccomp=unconfined` explicitly disables seccomp for a container that
would otherwise have it active. This is Layer Non-Activation (C-09):
the layer exists in the architecture and is active by default; this
execution context explicitly deactivates it.

**Contrast with npm:** npm's `lifecycle_governance` absence is Layer
Absence (C-10) because the layer was never part of the architecture.
Docker's `seccomp=unconfined` is Non-Activation because the layer exists
and was deliberately suppressed.

---

## S-06: Build-Run Authority Disconnect Is an Open Question

The Docker Dockerfile `USER` directive declares the intended runtime user,
but `docker run --user <override>` can supersede it at runtime. Whether
this constitutes Layer Bypass (Dockerfile USER as governance declaration
for runtime) or a distinct GSBG structure is declared as an open question
in the GCG codex (PCM-0333-208 OQ-03, unresolved in RC v1.6).

**What must hold:** Any analysis that resolves OQ-03 must declare the
resolution and its rationale. Treating the Dockerfile USER directive as
a governance declaration and runtime --user as bypass is an admissible
interpretation; it must be declared as a CX-IC selection.

---

## S-07: Kernel Is the Primary Jurisdiction Boundary

Docker's governance mechanisms (seccomp, capabilities, namespaces) operate
as filters between the container process and the kernel. The kernel itself
is outside Docker's governance perimeter. Kernel exploits that bypass
namespace isolation represent a JD boundary Docker cannot govern.

**What must hold:** Any recoverability or governance completeness claim
must declare the kernel JD as the terminal boundary.
