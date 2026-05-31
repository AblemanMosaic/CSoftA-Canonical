# CX-IC: Docker Selected Instance Configuration

*Docker Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

---

## IC-01: N-Determination Strategy → DECLARED-N

**Rationale:** N(O) derived from Docker's documented security model
and CIS Docker Benchmark v1.6. Standard container N=5; same N applies
to --privileged (S-03 invariant).

---

## IC-02: Operation Families in Scope → Full (4 families)

container_run_standard, container_run_privileged,
container_interior_execution, image_build.

**Rationale:** All four are necessary to capture the boundary/interior
governance distinction and the full bypass profile.

---

## IC-03: Evidence Standard → STATIC (docker inspect)

`docker inspect` JSON provides the security configuration for each
container. No daemon instrumentation required for the primary findings.
Interior execution ABSENT finding is structural — not runtime-measurable.

---

## IC-04: Build-Run Authority Disconnect (OQ-03) → NOT RESOLVED

OQ-03 (Dockerfile USER vs runtime --user) is declared as unresolved
per GCG codex PCM-0333-208. This analysis does not resolve it.
Future analysis may treat runtime --user override as Layer Bypass
with explicit IC declaration.

---

## IC-05: Kernel JD Treatment → Declared boundary, not analyzed

The kernel JD (S-07) is declared as the terminal boundary.
Kernel-level container escape vulnerabilities are outside scope.
Scope boundary declared: Docker daemon-level governance only.

---

## Instance Summary

| Dimension              | Selected Value      | Alternatives              |
|------------------------|---------------------|---------------------------|
| N-determination        | DECLARED-N          | MINIMUM-N, PER-CONTEXT-N |
| Scope                  | Full (4 families)   | Standard-only             |
| Evidence               | STATIC              | RUNTIME with daemon trace |
| OQ-03 resolution       | UNRESOLVED          | Bypass interpretation     |
| Kernel JD              | Declared boundary   | In-scope kernel analysis  |
