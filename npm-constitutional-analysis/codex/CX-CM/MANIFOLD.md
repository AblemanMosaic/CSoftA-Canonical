# CX-CM: npm Configuration Manifold

*npm Constitutional Analysis — CX:AES Codex*
*Version: 1.0*

The admissible variation space for npm constitutional analysis.
CX-CM defines what may vary; CX-IC records what was selected.

---

## CC-01: N-Determination Strategy

**Options:**
- `DECLARED-N`: N(O) derived from npm documentation and supply chain
  security standards (SLSA, OpenSSF Scorecard). Declares lifecycle_governance
  and audit_surface as applicable even though npm never implemented them —
  because a constitutionally complete package manager must provide them.
- `MINIMUM-N`: Count only layers that actually exist in npm's architecture.
  With MINIMUM-N, lifecycle_script_execution has N(O) = 0, which obscures
  the finding that governance is required but absent.
- `PER-CONTEXT-N`: Varies N(O) by SLSA level the project targets.

**Default:** DECLARED-N. MINIMUM-N is inadmissible for lifecycle analysis
because it erases the gap by definition.

---

## CC-02: Analytical Scope

**Options:**
- `FULL`: All four operation families (lifecycle, install, publish, resolution)
- `LIFECYCLE_ONLY`: Focus on lifecycle_script_execution (primary finding)
- `INSTALL_ONLY`: Focus on dependency_install and resolution

**Default:** FULL for founding analysis.

---

## CC-03: Evidence Standard

**Options:**
- `STATIC`: Analysis of package.json + lockfile only. No live npm run.
- `RUNTIME`: Instrumented npm install with process tracing.
- `BOTH`: Static for N(O); runtime for k(O,e).

**Default:** STATIC. npm's primary finding (absent governance) is
detectable statically — the absence of a lifecycle governance layer
is a structural property, not a runtime measurement.

---

## CC-04: Dependency Depth

**Options:**
- `DIRECT_ONLY`: Only packages in package.json dependencies
- `FULL_TREE`: All packages in package-lock.json (including transitive)
- `CONFIGURABLE`: Depth limit as parameter

**Default:** FULL_TREE (cap at 50 packages for performance).
Transitive dependencies are where supply chain attacks enter.

---

## CC-05: Lockfile Treatment

**Options:**
- `REQUIRED`: Analysis fails if no lockfile present
- `OPTIONAL`: Absence recorded as gap, analysis continues
- `GENERATE`: Run npm install --package-lock-only to generate

**Default:** OPTIONAL. Lockfile absence is itself a governance finding
(F-LINEAGE, lockfile_integrity ABSENT).
