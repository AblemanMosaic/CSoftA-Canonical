# FINDINGS: Docker Hub / OCI Registry Constitutional Analysis
*Wave 13 — System 62 · EAR ceiling: CRYSTALLIZED · Fingerprint: `ec55c46d91bffa7d`*

## Executive Finding
Docker Hub / OCI registries are the supply chain middle layer between image build (Packer, Wave 7, T1719) and image admission (Cosign, Wave 8, T1739). This analysis completes the supply chain triangle: build-time provenance gap (Packer) → registry-time governance gap (Docker Hub) → admission-time closure (Cosign). The registry layer is structurally ABSENT for image provenance when mutable tags are used — the constitutional finding is confirmed by the Trivy scanner compromise of March 2026.

Trivy scanner supply chain compromise (March 2026): an attacker re-pointed the `:latest` tag on the official Trivy container image on Docker Hub to malicious content multiple times. Organizations pulling `aquasec/trivy:latest` unknowingly ran compromised security scanner versions. Docker's post-incident advisory confirmed: mutable tags are not a security boundary; digest pinning provides immutability but not provenance verification; DHI (Docker Hardened Images) with SLSA L3 provenance would have made this class of attack impossible.

The constitutional finding: digest pinning moves `image_pull` from ABSENT to CRYSTALLIZED (same bytes every time) but does not reach ACTIVE (no provenance verification). Only the combination of digest pinning + Cosign signature verification + Cosign admission controller (failurePolicy:Fail) achieves ACTIVE — the registry layer alone cannot reach ACTIVE.

## Real-World Incidents
Trivy scanner compromise (March 2026): `:latest` tag re-pointed multiple times to malicious Docker Hub content. Security teams running Trivy in CI pipelines unknowingly executed compromised scanner. Cryptomining supply chain abuse on Docker Hub (Flare, December 2025): multiple cryptomining campaigns distributed malicious container images at scale via Docker Hub. Docker Hub accounts compromised via phishing/credential theft; malicious images published as official-looking repositories. Docker Hardened Images (DHI, December 2025): Apache 2.0 open-source release of SLSA L3 + SBOM + VEX + Cosign signed images addressing the registry-layer governance gap.

## The Add-On: `docker-hub-governance-enforcer`
Registry pull governance validator. Validates all production image pulls use digest references; validates Cosign signatures verified at pull/admission; validates DHI or equivalent signed provenance for base images; produces `registry_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| image_pull (mutable tag) | ABSENT | :latest can be silently re-pointed (Trivy class) |
| image_pull (digest pin) | CRYSTALLIZED | Same bytes; no provenance verification |
| image_push | CRYSTALLIZED | Auth required; no mandatory signing |
| tag_mutation | ABSENT | Tag re-pointing produces no governance event |
| provenance_verification | CRYSTALLIZED | Cosign verify available; not mandatory at registry |
