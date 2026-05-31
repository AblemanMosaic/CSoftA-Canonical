# FINDINGS: Rust Ownership Model / cargo Constitutional Analysis
*Wave 4 — System 19 · memory_safety_compilation: ACTIVE · Fingerprint: `c86c6d145f7be4ae`*

## Executive Finding
Rust introduces a constitutional concept not found in any previous system: compile-time ACTIVE-EAR. The Rust borrow checker is constitutive of compilation — a program containing memory safety violations cannot compile. The compiler is the Governor, ownership and borrowing rules are the policy, and the successfully compiled binary is the governance receipt. Safety governance is not a runtime check or an audit log entry; it is a prerequisite for the artifact to exist.

This extends the credential-as-receipt pattern to a new dimension: the compiled binary IS the receipt of compile-time safety governance. You cannot have the artifact without the governance completing successfully.

The critical distinction: memory safety is ACTIVE at compile time; supply chain safety is CRYSTALLIZED at build time. These two properties are fully independent. A Rust program can be memory-safe (borrow checker passed) while using a supply chain crate that is compromised, malicious, or contains known vulnerabilities.

## Unsafe Blocks: Declared Bypass
`unsafe` in Rust is the constitutionally correct mechanism for declared bypass. The unsafe block is explicitly named in source code — it is not a silent bypass. The borrow checker is suspended within the unsafe block, but the suspension is visible, auditable, and subject to code review. This is closer to the constitutional ideal for bypass than any other bypass mechanism in the corpus: the bypass is declared, localized, and minimized.

The governance gap: unsafe code cannot be validated by the borrow checker — it must be validated by human review and external tools (Miri, clippy). The governance surface shifts from compiler-enforced to human-enforced, which is CRYSTALLIZED.

## Supply Chain: The Critical Gap
cargo resolves crates from crates.io with SHA256 checksum verification (recorded in Cargo.lock). But checksum verification confirms that you received what crates.io published — it does not confirm that what crates.io published is what the author intended, that the build was reproducible, or that the crate is free of known vulnerabilities. The supply chain is CRYSTALLIZED: cargo_audit provides vulnerability scanning but is opt-in; SLSA provenance attestation is opt-in; reproducible builds are opt-in.

## Real-World Incident Mapping
XZ Utils backdoor (2024): a sophisticated social engineering attack compromised the maintainer of xz-utils and introduced a malicious backdoor into the source code, which was then published to package repositories. The constitutional finding: any language's package ecosystem faces this threat. Rust's borrow checker would not have prevented this — it governs memory safety at compile time, not supply chain integrity. cargo_audit would have detected the CVE after publication; SLSA provenance would have detected the build-provenance discrepancy. The supply chain gap in Rust/cargo is the same gap that XZ exploited.

Rust memory safety guarantee: when a Rust crate reports CVE-level vulnerabilities, they are overwhelmingly logic errors, cryptographic implementation errors, or supply chain issues — not buffer overflows, use-after-free, or memory corruption. The borrow checker's ACTIVE-EAR classification is validated by the CVE distribution: memory safety CVEs are near-zero in safe Rust.

## The Add-On: `cargo-constitutional-gate`

A CI/CD enforcement layer that makes supply chain and unsafe governance constitutive at build time. (1) Runs `cargo audit` as mandatory gate — build fails on any RUSTSEC advisory; exemptions require explicit signed acknowledgment. (2) Runs `cargo geiger` producing unsafe usage report — blocks builds where unsafe exceeds configured thresholds or where new unsafe appears without review approval. (3) Verifies SLSA provenance for direct dependencies where attestations are available — gap assertions for dependencies without provenance. (4) Generates `supply_chain_posture.json` per build: dependency tree hash, RUSTSEC count, unsafe count, provenance coverage. (5) Enforces `cargo deny` for license compliance and banned crates. Closes the supply chain gap orthogonally to the compile-time memory safety ACTIVE: the gate enforces at build time what the borrow checker cannot enforce.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| memory_safety_compilation | **ACTIVE** | Compile-time ACTIVE-EAR — binary IS the receipt |
| unsafe_block_usage | CRYSTALLIZED | Declared bypass — visible, auditable, localized |
| dependency_resolution | CRYSTALLIZED | Checksums verified; provenance opt-in |
| supply_chain_verification | CRYSTALLIZED | cargo_audit opt-in; SLSA opt-in |
| binary_publication | CRYSTALLIZED | crates.io receipt; no mandatory provenance |
