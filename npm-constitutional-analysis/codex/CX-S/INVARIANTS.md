# CX-S: npm Constitutional Domain Invariants

*npm Constitutional Analysis — CX:AES Codex*
*Inherits from: CSoftA Parent CX:AES Codex (T1574)*
*Version: 1.0*

---

## S-01: Lifecycle Script Execution Is Pre-Governance Capability

npm lifecycle scripts (preinstall, postinstall, prepare, prepublishOnly, etc.)
execute arbitrary code with the installing user's full privileges. This
capability exists entirely outside any declared governance scope.

**What must hold:** Any analysis that treats lifecycle script execution
as "governed" is constitutionally inadmissible. There is no lifecycle
governance layer in npm's architecture. The gap is not Non-Activation
(layer present but not activated) — it is Absence (layer never exists).

**Form:** F-SCOPE (scope fragmentation) + GCG Form: ABSENCE.

**The GCG codex classification (PCM-0333-195):** This is an instance
of "O-36 adjacency at build scripts" — the capability-grant boundary
where declared scope ends and execution begins, with no governance bridge.

---

## S-02: Lockfile Integrity Is Partial Receipt Only

The `integrity` field in `package-lock.json` provides a sha512 hash of
the downloaded tarball. This constitutes partial receipt for the
dependency_install operation family: it verifies what was downloaded
matches a declared hash, but it does not receipt what executed during
installation (lifecycle scripts, build steps, side effects).

**What must hold:** lockfile_integrity provides N(O) ≥ 1 for the
dependency_install family but does not satisfy audit_surface.
A locked install is CRYSTALLIZED-EAR, not ACTIVE-EAR.

**Inadmissible claim:** "npm with lockfile is governance-complete."
The lockfile governs artifact integrity, not execution behavior.

---

## S-03: No Audit Surface Exists for Install Operations

npm does not produce a structured record of what executed during
`npm install`. There is no equivalent to Vault's audit log — no record
of which lifecycle scripts ran, what they executed, what system state
they modified, or what network connections they made.

**What must hold:** Any recoverability claim for npm install operations
must declare STRUCTURAL_NONLOCALITY — the execution chain cannot be
reconstructed from npm's own artifacts.

**Evidence:** `npm install` produces lock file changes and `node_modules/`
but no execution receipt. The npm debug log (`~/.npm/_logs/`) captures
npm's internal operations but not the executed script content or effects.

---

## S-04: Registry Authentication Governs Publishing, Not Installing

npm's registry authentication (`npm login`, `.npmrc` tokens) governs
who can publish packages. It does not govern who installs them or what
the installed packages execute.

**What must hold:** registry_auth is a valid governance layer for the
package_publish operation family. It is NOT a governance layer for
the dependency_install or lifecycle_script_execution families — consumers
install packages regardless of publisher authentication state.

---

## S-05: Semver Range Resolution Is Governance-Incomplete Without Lockfile

`npm install` without a lockfile resolves semver ranges at install time,
potentially installing different versions across environments. This is
a dependency_resolution GCG: the governance declaration (the semver range
in package.json) does not fully specify the installed artifact.

**What must hold:** Any analysis of npm dependency governance must
declare whether a lockfile is present. Without a lockfile, N(O) for
dependency_resolution cannot be satisfied by any realized k.

---

## S-06: Provenance Attestation Is CRYSTALLIZED

npm `--provenance` (available since npm 9.5.0) produces a SLSA
provenance attestation linking a published package to its source
repository and build environment. This is an ACTIVE-EAR mechanism
for the package_publish operation family — when used.

**What must hold:** `--provenance` is opt-in and not the default.
A package published without provenance is CRYSTALLIZED at best for
the provenance_attestation layer.

**Forward-looking:** npm provenance is the path from CRYSTALLIZED to
ACTIVE-EAR for the publish operation family. An analysis must declare
whether provenance was used and classify accordingly.

---

## S-07: Module-Load-Time Execution Is a Second Independent ABSENT-EAR Surface

npm has two structurally independent ungoverned execution surfaces.
The CSoftA analysis must declare BOTH and treat them separately.
Conflating them understates the governance gap and produces incorrect
tool recommendations.

**Surface 1 — Install-time (lifecycle scripts):**
Trigger: `npm install` / `npm ci`. Source: `package.json` scripts block.
Detectable by: static analysis of package.json + lockfile before install.
Canonical attacks: Shai-Hulud (Sept 2025), Axios (March 2026), qix compromise.

**Surface 2 — Module-load-time (require()/import evaluation):**
Trigger: application code calls `require()` or `import()`.
Mechanism: top-level IIFE in CommonJS module; top-level await in ES module;
dynamic `require()` calls in module body.
Source: module source files in `node_modules/`.
Detectable by: AST analysis of module source files; NOT by preinstall/postinstall scanning.
Canonical attack: node-ipc (May 2026) — IIFE appended after `module.exports`,
fires the first time any application calls `require('node-ipc')`.

**What must hold:** Any conforming CSoftA npm analysis must include
`module_load_execution` as a declared operation family with `module_load_governance`
and `audit_surface` as its declared layers (both ABSENT). A tool or analysis
that only scans preinstall/postinstall hooks is constitutionally incomplete —
it covers Surface 1 but leaves Surface 2 entirely undetected. T1580, T1581.

---

## Inadmissible Regions

- Claiming npm lifecycle script execution is governed in any form (violates S-01)
- Claiming lockfile_integrity alone satisfies audit_surface (violates S-02)
- Asserting LOCAL recoverability for npm install operations (violates S-03)
- Treating registry_auth as a governance layer for install operations (violates S-04)
- Claiming an npm analysis is complete when it covers only lifecycle scripts
  and omits module-load-time execution (violates S-07)
