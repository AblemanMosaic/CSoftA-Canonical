# FINDINGS: npm Constitutional Analysis

*Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*
*Version: 1.0 — 2026-05-29*
*EAR state: ABSENT (lifecycle) / CRYSTALLIZED (install with lockfile)*
*Recoverability: STRUCTURAL_NONLOCALITY*

---

## Executive Finding

npm demonstrates the structural floor of the governance spectrum.

It is the weakest governance case in the 17-system SFA corpus — the
deliberate contrast case to Vault. The revised analysis finds:

**Two structurally independent ABSENT-EAR execution surfaces** (T1581):
Surface 1 (install-time lifecycle scripts) and Surface 2 (module-load-time
require()/import evaluation). These have different triggers, different
detection profiles, and different remediation requirements. Every prior
npm security analysis that addresses only lifecycle hooks is constitutionally
incomplete — it leaves Surface 2 entirely undetected.

**One structurally absent governance layer** (lifecycle_governance)
that does not exist anywhere in npm's architecture, making every
package with a lifecycle script a pre-governance capability exercise.

**A second structurally absent governance layer** (module_load_governance)
that does not exist anywhere in npm, Node.js, or the CommonJS/ESM module
system, making every installed module a potential load-time execution site.

**STRUCTURAL_NONLOCALITY recoverability** — npm install and module load
operations cannot be reconstructed from npm's own artifacts.

The findings are not implementation defects. They are structural properties
of npm's design philosophy: maximize developer ergonomics, defer governance
to the operator. The consequence is that two independent arbitrary code
execution surfaces exist with no governance and no receipt in the most
widely deployed software packaging system in the world.

---

## Dimension 1: Authority (F-AUTH)

**Finding: F-AUTH PRESENT — authority emerges from execution**

npm has no authority specification surface. Lifecycle scripts run because
they exist in `package.json`. There is no prior declaration of what a
script is permitted to do, no authority chain evaluated before execution,
no governance layer that validates the script's scope.

Authority is fully implementation-derived:
- Presence in `scripts` block = authority to execute
- Installed as a dependency = authority to run postinstall scripts
- User privilege at time of `npm install` = effective authority scope

This is the canonical F-AUTH finding. Compare to Vault (F-AUTH ABSENT):
Vault requires named policy paths; npm requires only package presence.

---

## Dimension 2: Accountability (F-LINEAGE)

**Finding: F-LINEAGE PRESENT — no install receipt surface**

npm produces no structured record of what executed during `npm install`.
The execution chain — dependency resolution → tarball download → tarball
extraction → lifecycle script execution → system effects — leaves no
unified receipt.

What npm does produce:
- `package-lock.json` — records what was resolved (not what executed)
- `node_modules/` — the result (not the process)
- npm debug log — npm's internal operations (not script effects)

The lifecycle script execution gap is total: no record of what script
ran, what it did, what files it modified, what network requests it made.

**EAR states:**
- lifecycle_script_execution: ABSENT
- dependency_install (no lockfile): ABSENT
- dependency_install (with lockfile): CRYSTALLIZED (hash verified, execution not receipted)
- package_publish (with provenance): CRYSTALLIZED

---

## Dimension 3: Governance (F-ADMIT)

**Finding: F-ADMIT PRESENT (structural) — lifecycle governance layer absent**

The F-ADMIT finding for npm is structurally deeper than for most systems:
this is not a case where a governance layer exists but was not activated
(Non-Activation). The lifecycle governance layer does not exist in npm's
architecture at all.

**GCG instances identified:**

| Operation Family         | Gap Form | N(O)                                          | k(O,e) | Absent |
|--------------------------|----------|-----------------------------------------------|--------|--------|
| lifecycle_script_execution | ABSENCE | lifecycle_governance, audit_surface           | []     | both   |
| module_load_execution    | ABSENCE  | module_load_governance, audit_surface         | []     | both   |
| dependency_install (no lockfile) | ABSENCE | registry_auth, lockfile_integrity, audit_surface | [] | all |
| dependency_install (lockfile) | NON_ACTIVATION | registry_auth, lockfile_integrity, audit_surface | [lockfile_integrity] | 2/3 |
| package_publish (no provenance) | NON_ACTIVATION | registry_auth, provenance_attestation, audit_surface | [registry_auth] | 2/3 |

**Critical distinction — module_load_execution vs lifecycle_script_execution:**

These are two independent ABSENT-EAR surfaces, not the same gap in two forms.

Lifecycle scripts are detectable before installation by scanning package.json
and the lockfile — every major supply chain scanner does this. The node-ipc
attack (May 2026) demonstrated that Surface 2 is entirely invisible to this
approach: the malicious IIFE was appended after `module.exports` and fired
unconditionally the first time any application called `require('node-ipc')`.
This is not a variant of the lifecycle script problem — it is a structurally
different attack surface with a different detection requirement (AST analysis
of installed module source, not package metadata).

**Total npm gap magnitude at canonical level: 5 ABSENCE assertions** across
two execution surfaces, covering both install-time and runtime ungoverned execution.

---

## Dimension 4: Configuration and Authority Binding

**Finding: ACCIDENTAL ENTANGLEMENT**

The presence of a `scripts` entry in `package.json` IS the authority grant.
Configuration and authority are not separated — they are the same artifact.
Adding `"postinstall": "node setup.js"` to package.json simultaneously
configures the build behavior AND grants authority to execute arbitrary code.

This is the canonical accidental entanglement case (PCM-0113-013):
there is no structural separation between configuration surface and
authority surface. Contrast with Vault (structural separation) and
PostgreSQL (structural separation).

---

## Dimension 5: Resolution Cascade Opacity

**Finding: TOTAL opacity for lifecycle execution**

npm provides zero resolution chain visibility for lifecycle script execution.
An operator running `npm install` cannot observe:
- which lifecycle scripts ran
- in what order
- what system effects they produced
- whether they succeeded or failed (unless the process exited non-zero)

For dependency resolution (with lockfile): LOW opacity. The lockfile
records what was resolved; the hash verifies the download.

For lifecycle execution: HIGH opacity. No visibility mechanism exists.

---

## Dimension 6: Extension Surfaces (F-SCOPE)

**Finding: TWO INDEPENDENT UNGOVERNED extension surfaces (REVISED — T1580, T1581)**

**Surface 1 — Install-time lifecycle scripts:**
npm lifecycle scripts are the canonical ungoverned install-time execution surface
in the SFA corpus (PCM-0113-014). Unlike Deno (perimeter-governed modules)
or Vault (governed plugin API), npm provides no boundary on what lifecycle
scripts can execute. Extension classification: **UNGOVERNED**.

**Surface 2 — Module-load-time execution:**
Node.js evaluates every top-level statement in a CommonJS module on load.
This creates a second, structurally independent ungoverned execution surface:
any code at module top-level executes the moment the module is required.
Canonical attack: node-ipc (May 2026) — an IIFE appended after `module.exports`
fires unconditionally on `require('node-ipc')` with no governance layer and no receipt.

This surface is **invisible to preinstall/postinstall scanners** — the entire
class of tools that address Surface 1 provides zero coverage for Surface 2.

**Combined F-SCOPE assessment:** Two ungoverned execution surfaces.
The lockfile integrity layer covers artifact integrity (what was downloaded)
but not execution behavior (what runs when that downloaded code is loaded).
Both surfaces are ABSENT-EAR with gap magnitude 2 each.

---

## Dimension 7: Authority Bypass

**Finding: No bypass — the base case IS ungoverned**

npm has no bypass mechanism to enumerate because there is no governance
to bypass. The concept of an authority bypass requires a governance
baseline that execution routes around; npm has no such baseline for
lifecycle scripts.

This is the structural inversion of the bypass analysis: rather than
cataloging bypasses, the analysis catalogs the baseline governance
that does not exist.

**What exists instead of governance:** the `--ignore-scripts` flag
suppresses lifecycle script execution. This is a consumer-side option,
not a governance mechanism — it trades one ungoverned state (scripts
run without oversight) for another (scripts suppressed without declared
policy for when suppression is appropriate).

---

## Dimension 8: Projection Divergence (F-PROJ)

**Finding: F-PROJ HIGH — interface conceals execution scope**

npm's interface presents as a dependency management tool: "install
your project's dependencies." The execution scope includes arbitrary
code execution with user privileges.

This divergence is the highest in the corpus for a commonly-used
developer tool. Every developer who runs `npm install` on a project
with lifecycle scripts is executing arbitrary code they did not
explicitly authorize — and npm's interface does not surface this.

The `npm audit` command partially addresses this by reporting known
vulnerabilities, but does not address the governance structure problem:
the issue is not that specific packages are malicious, but that the
execution model makes it impossible to distinguish malicious from benign.

---

## The Add-On: `npm-constitutional-audit`

*T1653* — Pre-install hook and CI/CD gate intercepting both ungoverned npm execution surfaces (Surface 1: lifecycle scripts; Surface 2: module-load-time execution). Records lifecycle hook execution with package name, version, script content, SHA256; optionally sandboxes scripts; validates hashes against allowlist; wraps require() to record module-load-time execution; produces npm_posture.json.

## Summary

| Dimension              | Finding                                   | Severity |
|------------------------|-------------------------------------------|----------|
| Authority              | F-AUTH PRESENT — execution-derived        | HIGH     |
| Accountability         | F-LINEAGE PRESENT — no install or load receipt | HIGH |
| Governance             | TWO ABSENT surfaces: lifecycle + module-load | HIGH  |
| Configuration-Authority| Accidental entanglement                   | HIGH     |
| Resolution Opacity     | TOTAL for both execution surfaces         | HIGH     |
| Extension Surfaces     | TWO INDEPENDENT UNGOVERNED surfaces       | HIGH     |
| Authority Bypass       | No bypass — no governance baseline        | N/A      |
| Projection Divergence  | F-PROJ HIGH — interface conceals scope    | HIGH     |

**Constitutional verdict: npm has two structurally independent ungoverned execution
surfaces — install-time lifecycle scripts (Surface 1) and module-load-time evaluation
(Surface 2, T1580). Every tool that scans only lifecycle hooks is constitutionally
incomplete. Neither surface can be governed without architectural change.
The lockfile governs what was downloaded; nothing governs what executes when
downloaded code runs.**

---

## Constitutional Path Forward

A constitutionally governed npm-equivalent would require:
1. Explicit lifecycle script authorization surface (separate from `scripts` block)
2. Per-script capability declarations (network, filesystem scope)
3. Mandatory execution receipt per lifecycle invocation
4. Lockfile as mandatory governance artifact (currently opt-in)
5. Provenance attestation as default for publish operations

This is the content of the CX:AES codex for a constitutionally governed
package manager — not a description of npm as it exists, but a
specification anyone can implement.
