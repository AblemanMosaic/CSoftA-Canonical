# FINDINGS: HashiCorp Packer Constitutional Analysis
*Wave 7 — System 31 · EAR ceiling: CRYSTALLIZED · Fingerprint: `27c3c185a592e465`*

## Executive Finding
HashiCorp Packer is the image build governance case — the system that produces the machine images, AMIs, and container base images that all other infrastructure runs on. Packer produces build logs (CRYSTALLIZED) and records image checksums, but provides no mandatory governance receipt binding the output artifact to the declared build configuration, input sources, and build environment. Image signing (Cosign, AWS AMI signing) and SLSA provenance attestation are opt-in. No Packer family reaches ACTIVE.

The constitutional significance: images are the foundational artifact of cloud-native infrastructure. An image with unknown provenance may have been built from a compromised base, with unauthorized modifications, or by an unauthorized principal. The governance gap at the image build layer is upstream of every container, VM, and cloud workload in the system.

## Image Provenance: ABSENT by Default
A Packer build produces: build logs, an image artifact with a checksum, and optionally a published artifact ID. None of these constitute a binding receipt that can answer: "Was this image built from exactly these sources, by this principal, in this build environment, at this time?" SLSA provenance attests this for build pipelines, but SLSA integration with Packer is opt-in and requires additional tooling.

## Real-World Incident Mapping
SolarWinds build system compromise (2020): attackers compromised the build pipeline to inject malicious code into software artifacts. The build system produced signed artifacts — the signature was valid. But the governance gap was at the build environment level: no receipt existed proving the build environment was unmodified when the artifact was produced. SLSA provenance would have detected the build environment compromise because the provenance attestation would have come from a trusted builder (GitHub Actions SLSA, etc.) rather than the compromised build system.

XZ Utils backdoor (April 2024): malicious code was introduced through the source control layer before the build step. SLSA provenance for the build step would not have prevented this — it would have attested that the build was performed correctly from the compromised source. This confirms: image build governance must include base image provenance, source commit provenance, and build environment attestation to fully govern the artifact. Each is a separate governance layer, and each is opt-in in Packer.

## The Add-On: `packer-governance-enforcer`
SLSA-L3 governance gate for Packer builds. Requires SLSA provenance attestation as prerequisite for artifact publication; validates base image digest pinned; enforces image signing (Cosign); generates SBOM for built images; records build lineage in HCP Packer Registry; produces `packer_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| image_build | CRYSTALLIZED | Log + checksum exist; provenance opt-in |
| base_image_pull | CRYSTALLIZED | Base image digest recorded; provenance opt-in |
| image_publication | CRYSTALLIZED | Signing opt-in |
| build_registry | CRYSTALLIZED | HCP Registry commercial feature |
| sbom_generation | CRYSTALLIZED | SBOM generation opt-in |
