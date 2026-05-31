# D3 Classification: npm

*CSoftA D3 Corpus Classification Protocol (T002)*
*Version: 1.0 — 2026-05-29*

---

## Commit Point

**Primary commit point:** Package tarball extraction to `node_modules/`

The npm install operation commits when the package contents are written
to disk. There is no pre-commit evaluation that can be witnessed from
outside the npm process.

**For lifecycle scripts:** No commit point is defined. Lifecycle scripts
have no transaction boundary — they execute and produce effects with no
rollback mechanism and no receipt.

**Commit point visibility:** LOW for lifecycle execution; MEDIUM for
dependency resolution (lockfile records the resolution outcome).

---

## Recoverability Regime

**Regime: STRUCTURAL_NONLOCALITY**

The npm install execution chain crosses multiple jurisdiction boundaries
with no unified witness:

1. Registry (downloads happen at registry; npm does not independently
   verify the registry's operation)
2. npm process itself (execution of lifecycle scripts is not receipted)
3. User filesystem (effects of lifecycle scripts are not tracked)
4. Network (lifecycle scripts may make arbitrary network requests)

The governance trace τ = (EP, GR, ER) cannot be assembled from npm's
own artifacts for lifecycle operations. For pure dependency resolution
with lockfile, the regime is COMPOSITIONAL (lockfile + registry metadata
together describe the resolved state).

---

## EAR State by Operation Family

| Operation Family          | EAR State    | Evidence                                    |
|---------------------------|--------------|---------------------------------------------|
| lifecycle_script_execution | ABSENT      | No lifecycle governance layer in architecture |
| dependency_install (lockfile) | CRYSTALLIZED | Lockfile integrity check; no execution receipt |
| dependency_install (no lockfile) | ABSENT  | No lockfile, no integrity, no receipt      |
| dependency_resolution (lockfile) | CRYSTALLIZED | Semver locked; no execution audit      |
| package_publish (--provenance) | CRYSTALLIZED | Provenance attestation exists; not default |
| package_publish (default)  | ABSENT       | No provenance, registry auth only          |

---

## Jurisdiction Boundaries

**JD-1: npm registry (primary)**
- Location: Between npm client and registry.npmjs.org
- Governance consequence: Registry serves packages; registry's security
  controls (malware scanning, ownership verification) are not part of
  npm's own governance chain
- Severity: HIGH — supply chain attacks enter here

**JD-2: Lifecycle script process (critical)**
- Location: Between npm process and child process executing lifecycle script
- Governance consequence: Child process has full user privilege with no
  governance constraint from npm
- Severity: CRITICAL — this is the primary F-SCOPE gap

**JD-3: Operating system (always)**
- Location: Between lifecycle script and kernel
- Governance consequence: Kernel enforces process isolation but not
  script-level governance
- Severity: MEDIUM — OS provides containment but not npm-level governance

---

## Structural Observations

**npm is the SFA corpus reference implementation of absent governance.**
It is the deliberate contrast case to Vault — demonstrating the floor
of the governance spectrum. Where Vault has mandatory receipts, explicit
authority, and structured policy evaluation, npm has none of these for
its primary execution surface (lifecycle scripts).

**The absence is structural, not accidental.** npm was designed for
developer ergonomics. Lifecycle scripts were added to enable flexible
build tooling. The governance gap is a consequence of this design
philosophy, not a bug.

**`--ignore-scripts` is not remediation.** Suppressing scripts without
a declared policy for when suppression is appropriate exchanges one
ungoverned state for another.

**The path to governance completeness requires architectural change:**
a governed lifecycle model would require a separate authorization surface
for lifecycle scripts, capability declarations, and mandatory execution
receipts. This is a different package manager, not a patched npm.
