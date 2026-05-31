# FINDINGS: PyPI / pip Constitutional Analysis
*Wave 11 — System 52 · EAR ceiling: CRYSTALLIZED · Fingerprint: `242663985440d6b5`*

## Executive Finding
PyPI is the Python supply chain governance case, extending the npm (Wave 1) analysis with two critical new findings. First: PEP 740 Trusted Publishing + Sigstore attestations are in CRYSTALLIZED-forward state — attestations cryptographically bind packages to their build provenance, but pip/uv do not yet verify attestations during install. The governance evidence exists and is publicly auditable; the governance enforcement at the installation boundary does not yet exist.

Second, and more important: the Mini Shai-Hulud campaign (September 2025–May 2026, CVE-2026-45321) achieved a critical first — 84 malicious TanStack package versions were published carrying valid SLSA Build Level 3 provenance attestations. The signing mechanism was ACTIVE (constitutively signing every published package); the policy being signed was corrupted. This is the T1777 second-order governance gap applied to supply chain provenance: ACTIVE signing of malicious packages produces ACTIVE wrong attestations.

## Mini Shai-Hulud: The Policy Correctness Gap at Supply Chain Scale
TeamPCP (also tracked as UNC6780) compromised CI/CD pipelines, injected malicious code, and published packages through the legitimate GitHub Actions workflow — thus triggering Trusted Publishing and receiving valid Sigstore attestations. The attestations correctly recorded: "this package was published via workflow X from repository Y." The policy they expressed was correct. The code the workflow ran was malicious. The attestation mechanism had no visibility into whether the workflow itself had been compromised.

Constitutional finding: SLSA L3 provenance attests the build process integrity, not the build environment integrity. A compromised build cache that injects malicious code during the build process can produce artifacts with valid L3 attestations. This is the same second-order gap as T1777 (OPA policy correctness) applied to supply chain: the governance mechanism correctly enforces the declared policy; the declared policy reflects a compromised state.

## Real-World Incidents
Ultralytics compromise (December 2024): GitHub Actions cache poisoning injected cryptominer into YOLO package with ~80 million monthly downloads. Thousands downloaded malware before detection. PyPI Trusted Publishing attestations confirmed the package was published via the legitimate GitHub Actions workflow — which is accurate; the workflow was compromised. PyPI phishing campaign (July 2025): maintainers targeted with credential harvesting via lookalike domain (pypj.org). 512,847 new malicious packages identified on PyPI in 2024 — 156% year-over-year increase.

## The Add-On: `pypi-governance-enforcer`
Attestation verification enforcer and dependency integrity monitor. Configures pip/uv to require PEP 740 attestation verification; validates Trusted Publishing configured for all owned packages; monitors Sigstore transparency log for owned package names; alerts on packages published outside expected workflows; produces `pypi_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| package_install | ABSENT (default) | pip does not verify attestations at install |
| package_publish | CRYSTALLIZED | Trusted Publishing available; not mandatory |
| provenance_attestation | CRYSTALLIZED | Sigstore records; not verified at install |
| maintainer_authentication | CRYSTALLIZED | MFA available; required only for PyPI.org |
| dependency_resolution | ABSENT | Transitive deps have no attestation enforcement |
