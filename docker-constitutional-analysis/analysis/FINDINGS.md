# FINDINGS: Docker Constitutional Analysis

*Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*
*Version: 1.0 — 2026-05-29*
*EAR state: CRYSTALLIZED (standard) / ABSENT (--privileged, interior, build)*
*Recoverability: COMPOSITIONAL (daemon) / STRUCTURAL_NONLOCALITY (interior)*

---

## Executive Finding

Docker demonstrates boundary governance without interior governance —
the structural pattern that concentrates at perimeters and disappears inside.

Docker's boundary mechanisms (seccomp, AppArmor, capabilities, namespaces)
are constitutionally real: they exist, they activate by default, and they
reduce the attack surface. They are CRYSTALLIZED-EAR: governance mechanisms
that function without producing per-operation receipts.

The interior of a running container — process execution, file system access,
network activity after namespace establishment — has no governance and no
receipt. This is ABSENT-EAR.

The `--privileged` flag is the canonical Layer Bypass: three of five declared
governance layers (seccomp, AppArmor, capabilities) are simultaneously
disabled with no record of the bypass. Gap magnitude = 3.

---

## Dimension 1: Authority (F-AUTH)

**Finding: F-AUTH PRESENT — authority from runtime flags**

Docker container authority is derived from runtime configuration, not
from a declared authority specification surface.

`docker run --privileged`, `--cap-add`, `--security-opt seccomp=unconfined`
each modify the container's authority implicitly through execution flags.
There is no Docker equivalent of Vault's policy system: no named document
declaring what a container is permitted to do before it runs.

The `securityContext` in Kubernetes (when used with Docker as runtime)
introduces a governance layer — but this is Kubernetes governance over
Docker, not Docker governance over itself.

**Classification:** F-AUTH PRESENT, accidental entanglement.
Runtime flags = authority grants, no prior declaration.

---

## Dimension 2: Accountability (F-LINEAGE)

**Finding: F-LINEAGE PRESENT — no container execution receipt**

Docker does not produce a structured receipt of governance decisions
per container run. The daemon log records lifecycle events; it does not
record: which governance layers evaluated the container configuration,
what the evaluation produced, or what the realized security posture was.

`docker inspect` provides the security configuration as a snapshot;
it is not a receipt of the governance decision that produced that config.

**EAR states:**
- container_run_standard: CRYSTALLIZED (config visible, no governance receipt)
- container_run_privileged: ABSENT (bypass not receipted)
- container_interior_execution: ABSENT
- image_build: ABSENT

---

## Dimension 3: Governance (F-ADMIT)

**Finding: F-ADMIT PRESENT for bypass and interior; LOW for standard boundary**

**GCG instances identified:**

| Operation Family              | Gap Form         | N(O) | k(O,e) | Absent                              |
|-------------------------------|------------------|------|--------|-------------------------------------|
| container_run_privileged      | BYPASS           | 5    | 2      | seccomp, apparmor, capabilities     |
| container_run_standard (no seccomp) | NON_ACTIVATION | 5 | 4   | seccomp (unconfined)               |
| container_interior_execution  | ABSENCE          | 2    | 0      | interior_execution, audit_log       |
| image_build                   | ABSENCE          | 1    | 0      | audit_log                           |

**The --privileged bypass** is the primary finding: gap magnitude 3,
the highest bypass magnitude in the corpus after npm (which has no
governance baseline at all).

**Standard container with defaults:** gap magnitude ~0. This is the
strongest case for Docker governance — the default seccomp profile
blocks ~44 syscalls, AppArmor applies a default profile, capabilities
are reduced. This is genuine boundary governance.

---

## Dimension 4: Configuration and Authority Binding

**Finding: ACCIDENTAL ENTANGLEMENT for boundary flags**

`--privileged`, `--cap-add SYS_ADMIN`, `--security-opt seccomp=unconfined`
are configuration flags that simultaneously configure behavior AND grant
authority. There is no separation between the configuration surface
and the authority surface for boundary governance.

Contrast: Kubernetes PodSecurityContext separates the configuration
(what the pod requests) from the governance evaluation (whether PSS/PSP
permits it). Docker has no such separation.

---

## Dimension 5: Resolution Cascade Opacity

**Finding: TOTAL for --privileged; LOW for standard inspectable containers**

For `docker inspect`-visible containers: the security configuration is
externally readable. The governance decision chain (who ran with what
flags, when, why) is not.

For --privileged containers: no record of which layers were bypassed
exists in the container's inspect output (Privileged=true is the only
indicator) or in the daemon log.

---

## Dimension 6: Extension Surfaces (F-SCOPE)

**Finding: UNGOVERNED for build-time execution**

`Dockerfile RUN` instructions execute arbitrary commands during build.
No governance layer constrains this execution. Build context is fully
ungoverned — equivalent to npm postinstall in scope.

Container runtime: the extension surface is the container process itself.
From Docker's perspective, once a container is running, its internal
process execution is outside Docker's governance scope.

---

## Dimension 7: Authority Bypass

**Finding: PROCESS-SCOPED bypass (--privileged)**

| Bypass | Scope | Effect |
|--------|-------|--------|
| --privileged | Process-scoped (this container) | Disables seccomp, AppArmor, capability restrictions |
| --cap-add ALL | Process-scoped | Grants all capabilities |
| --security-opt seccomp=unconfined | Process-scoped | Disables syscall filtering only |
| --pid=host | Process-scoped | Shares host PID namespace |
| --network=host | Process-scoped | Bypasses network namespace |

Docker's bypass scope is process-scoped (better than Vault root token's
unbounded scope). The bypass is per-container, not system-wide. However,
within the container's execution context, --privileged is effectively
unbounded — the container can escape namespace isolation through
kernel exploits.

---

## Dimension 8: Projection Divergence (F-PROJ)

**Finding: F-PROJ MODERATE**

Docker's interface presents containers as isolated, governed execution
environments. The actual governance posture depends entirely on which
flags were passed, with no governance baseline enforced by the daemon.

The divergence is moderate (not as severe as npm) because:
- Standard containers DO have meaningful boundary governance
- `docker inspect` reveals the actual security configuration
- The divergence is knowable from inspect output

The divergence is real because:
- Users assume containers are more isolated than they are
- --privileged is a common flag that most users understand as
  "security disabled" but not as a specific Layer Bypass with gap magnitude 3
- Interior execution is completely ungoverned with no visual indication

---

## The Add-On: `docker-governance-proxy`

*T1654* — Governance-aware proxy between Docker clients and daemon. Intercepts --privileged flag use (BYPASS gap assertion); requires signed bypass justification receipt; enforces seccomp profiles and capability dropping; monitors privileged status drift; produces docker_posture.json. Makes the --privileged bypass declared and receipted rather than silent.

## Summary

| Dimension              | Finding                                    | Severity |
|------------------------|--------------------------------------------|----------|
| Authority              | F-AUTH PRESENT — flag-derived              | MEDIUM   |
| Accountability         | CRYSTALLIZED boundary; ABSENT interior     | MEDIUM   |
| Governance             | Boundary real; --privileged BYPASS (mag 3) | MEDIUM   |
| Config-Authority       | Accidental entanglement                    | MEDIUM   |
| Resolution Opacity     | LOW for inspect; TOTAL for --privileged    | MEDIUM   |
| Extension Surfaces     | Build ungoverned; interior ungoverned      | HIGH     |
| Authority Bypass       | Process-scoped --privileged               | MEDIUM   |
| Projection Divergence  | MODERATE                                   | MEDIUM   |

**Constitutional verdict: Docker provides genuine boundary governance for
standard containers. --privileged is a Layer Bypass with magnitude 3 and
must be enumerated and recorded. Interior execution is constitutionally
ungoverned by design. Recoverability is COMPOSITIONAL at daemon level.**
