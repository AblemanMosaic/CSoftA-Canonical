"""
ear_adapter_rust_cargo.py — Rust Ownership Model / cargo EAR Adapter
Wave 4 — System 19. Formally verified safety via type system.

Key finding: Rust is the corpus's formally verified safety case and introduces
a new constitutional concept: compile-time ACTIVE-EAR. The Rust borrow checker
is constitutive of compilation — a program with memory safety violations cannot
compile. The compiler is the Governor, ownership rules are the policy, and the
type-checked binary is the receipt. Safety governance is not a runtime check;
it is a compile-time prerequisite.
cargo supply chain: CRYSTALLIZED (crates.io packages have checksums but no
mandatory provenance verification). cargo audit provides gap analysis.
The distinction: memory safety is ACTIVE at compile time; supply chain
safety is CRYSTALLIZED at build time.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE="ACTIVE"; CRYSTALLIZED="CRYSTALLIZED"; ABSENT="ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION="NON_ACTIVATION"; ABSENCE="ABSENCE"; BYPASS="BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; rust_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    borrow_check_passed: bool; type_check_passed: bool
    unsafe_used: bool; audit_clean: bool
    crate_checksum_verified: bool; provenance_verified: bool
    error: str | None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

RUST_OPERATION_FAMILIES = [
    OperationFamily("memory_safety_compilation",
        "Compile Rust code with borrow checker enforcement",
        ["borrow_checker","type_system","ownership_receipt"], "compile"),
    OperationFamily("unsafe_block_usage",
        "Compile code containing unsafe blocks",
        ["borrow_checker","unsafe_declaration","type_system"], "unsafe"),
    OperationFamily("dependency_resolution",
        "Resolve and download crate dependencies via cargo",
        ["cargo_lock","crate_checksum","cargo_audit"], "deps"),
    OperationFamily("supply_chain_verification",
        "Verify dependency provenance and known vulnerabilities",
        ["cargo_lock","crate_checksum","cargo_audit","provenance_attestation"], "supply"),
    OperationFamily("binary_publication",
        "Publish crate to crates.io",
        ["crate_checksum","cargo_publish_receipt","crates_io_registry"], "publish"),
]

RUST_GOVERNANCE_LAYERS = {
    "borrow_checker": GovernanceLayer("borrow_checker",
        "Rust borrow checker — constitutive of compilation", "rustc error[E...]"),
    "type_system": GovernanceLayer("type_system",
        "Rust type system — memory safety guarantee", "rustc type check"),
    "ownership_receipt": GovernanceLayer("ownership_receipt",
        "Successfully compiled binary — IS the receipt of safety governance", "binary"),
    "unsafe_declaration": GovernanceLayer("unsafe_declaration",
        "Explicit unsafe block — declared bypass of borrow checker", "unsafe{}"),
    "cargo_lock": GovernanceLayer("cargo_lock",
        "Cargo.lock file pinning exact dependency versions", "Cargo.lock"),
    "crate_checksum": GovernanceLayer("crate_checksum",
        "SHA256 checksum of downloaded crate verified against crates.io", "checksum"),
    "cargo_audit": GovernanceLayer("cargo_audit",
        "cargo audit scan against RustSec advisory database", None, is_optional=True),
    "provenance_attestation": GovernanceLayer("provenance_attestation",
        "SLSA provenance attestation for crate build", None, is_optional=True),
    "cargo_publish_receipt": GovernanceLayer("cargo_publish_receipt",
        "crates.io publication receipt with version and checksum", "version"),
    "crates_io_registry": GovernanceLayer("crates_io_registry",
        "crates.io registry entry for published crate", "name"),
}

class RustCargoEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "Rust Reference + Rustonomicon + cargo Documentation + "
            "RustSec Advisory Database + SLSA Supply Chain Levels"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) from Rust/cargo architecture. memory_safety_compilation N=3. "
            "memory_safety_compilation: ACTIVE — borrow checker is constitutive "
            "of compilation. Program with memory safety violations cannot compile. "
            "The compiled binary IS the receipt of safety governance. "
            "New constitutional concept: compile-time ACTIVE-EAR. "
            "Governor=compiler, policy=ownership rules, receipt=type-checked binary. "
            "unsafe_block_usage: CRYSTALLIZED — unsafe is a declared bypass, "
            "explicitly named, but borrow checker is suspended within unsafe blocks. "
            "dependency_resolution: CRYSTALLIZED — Cargo.lock + checksums exist, "
            "provenance verification is opt-in (cargo audit, SLSA attestation). "
            "Supply chain is the governance gap: memory safety is ACTIVE, "
            "supply chain safety is CRYSTALLIZED."
        ),
    )

    def __init__(self, unsafe_used: bool=False,
                 cargo_audit_enabled: bool=False,
                 provenance_attestation: bool=False):
        self._unsafe = unsafe_used
        self._audit = cargo_audit_enabled
        self._provenance = provenance_attestation

    def collect_operation_families(self): return RUST_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [RUST_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in RUST_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            borrow_check_passed=(not self._unsafe),
            type_check_passed=True,
            unsafe_used=self._unsafe,
            audit_clean=self._audit,
            crate_checksum_verified=True,
            provenance_verified=self._provenance,
            error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in RUST_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "borrow_checker" in fam.declared_layers and inst.borrow_check_passed:
            k.append("borrow_checker")
        if "type_system" in fam.declared_layers and inst.type_check_passed:
            k.append("type_system")
        if "ownership_receipt" in fam.declared_layers and inst.borrow_check_passed:
            k.append("ownership_receipt")
        if "unsafe_declaration" in fam.declared_layers and inst.unsafe_used:
            k.append("unsafe_declaration")
        if "cargo_lock" in fam.declared_layers:
            k.append("cargo_lock")
        if "crate_checksum" in fam.declared_layers and inst.crate_checksum_verified:
            k.append("crate_checksum")
        if "cargo_audit" in fam.declared_layers and self._audit:
            k.append("cargo_audit")
        if "provenance_attestation" in fam.declared_layers and self._provenance:
            k.append("provenance_attestation")
        if "cargo_publish_receipt" in fam.declared_layers:
            k.append("cargo_publish_receipt")
        if "crates_io_registry" in fam.declared_layers:
            k.append("crates_io_registry")
        return k

    def assess_ear_state(self, op_family):
        # memory_safety_compilation: ACTIVE — borrow checker is constitutive
        if op_family.name == "memory_safety_compilation":
            return EARState.ACTIVE
        # unsafe_block_usage: CRYSTALLIZED (declared bypass)
        if op_family.name == "unsafe_block_usage":
            return EARState.CRYSTALLIZED
        # supply chain: CRYSTALLIZED (checksums exist, provenance opt-in)
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
