# D3 Classification: Docker

*CSoftA D3 Corpus Classification Protocol (T002)*
*Version: 1.0 — 2026-05-29*

---

## Commit Point

**Primary commit point:** Container start (daemon creates namespaces and
applies security configuration).

The security posture of a container is established at `docker run` /
container start. The cgroup configuration, namespace creation, seccomp
profile application, and AppArmor label assignment all occur at this moment.
This is the commit point for boundary governance.

**No commit point for interior execution:** Processes running inside a
container have no Docker-level commit point. Their operations are committed
at the kernel level only.

---

## Recoverability Regime

**Daemon-level: COMPOSITIONAL**
Docker's daemon log + docker inspect together describe the container's
declared security configuration. The full governance trace requires both.

**Interior execution: STRUCTURAL_NONLOCALITY**
Process execution inside a container is not receipted by Docker.
The governance trace cannot be assembled from Docker's own artifacts.

**Build-time: STRUCTURAL_NONLOCALITY**
`docker build` executes RUN instructions with no structured receipt.

---

## EAR State by Operation Family

| Operation Family              | EAR State    | Evidence                                        |
|-------------------------------|--------------|------------------------------------------------|
| container_run_standard        | CRYSTALLIZED | Security config applied; no per-run receipt    |
| container_run_privileged      | ABSENT       | Governance layers bypassed; no bypass receipt  |
| container_interior_execution  | ABSENT       | No governance layer for interior processes     |
| image_build                   | ABSENT       | RUN instructions ungoverned                    |

---

## Jurisdiction Boundaries

**JD-1: OS Kernel (primary)**
- Location: Between container process and kernel syscall interface
- Governance consequence: seccomp/capabilities operate here;
  kernel exploits bypass all Docker governance
- Severity: HIGH — kernel escapes break all boundary governance

**JD-2: Container filesystem (image)**
- Location: Between image layers and running container
- Governance consequence: Image contents are not verified at runtime
  (unless Docker Content Trust is enabled — opt-in)
- Severity: MEDIUM — supply chain risk

**JD-3: Docker daemon (host daemon)**
- Location: Between docker CLI and Docker daemon
- Governance consequence: Daemon operates with root privileges;
  access to Docker socket = root equivalent
- Severity: HIGH — Docker socket access is a privileged JD

---

## Structural Observations

**Docker is the SFA corpus reference implementation of boundary governance.**
It demonstrates that genuine governance can exist at a well-defined perimeter
without extending into the interior. This is structurally different from
both Vault (complete boundary + interior) and npm (neither).

**--privileged is the canonical Layer Bypass in the GCG codex.**
PCM-0333-136 T-D.1, PCM-0333-199, and PCM-0333-201 all use --privileged
as the primary example. Gap magnitude = 3 (seccomp, AppArmor, capabilities).

**Docker Content Trust (DCT) is an underused governance layer.**
When enabled, image pulls verify cryptographic signatures. DCT is the
path toward CRYSTALLIZED-EAR for image provenance — currently ABSENT by default.

**The interior execution gap is structural and intentional.**
Docker's design places process governance inside the container's own
responsibility (via the containerized application's own security posture).
This is a design choice, not an oversight. The constitutional analysis
names it as ABSENT and declares the JD explicitly.
