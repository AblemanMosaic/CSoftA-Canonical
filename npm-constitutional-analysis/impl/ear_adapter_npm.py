"""
ear_adapter_npm.py — npm EAR Adapter

Implements the EARAdapter interface for npm.
Static analyzer: reads package.json, package-lock.json, and
optionally node_modules/.package-lock.json to produce
operation families, governance layer assessment, and EAR states.

Unlike Vault (runtime log reader), npm has no audit surface to read.
The absence IS the finding.

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
Implements: GCG Codex C-01 through C-04 (Phase A) for npm
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ── Re-export types used by gcg_analyzer ────────────────────────────────────

class EARState(Enum):
    ACTIVE       = "ACTIVE"
    CRYSTALLIZED = "CRYSTALLIZED"
    ABSENT       = "ABSENT"


class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"
    ABSENCE        = "ABSENCE"
    BYPASS         = "BYPASS"


@dataclass
class OperationFamily:
    name:               str
    description:        str
    declared_layers:    list[str]
    npm_scope:          str   # 'install' | 'publish' | 'lifecycle' | 'registry'


@dataclass
class GovernanceLayer:
    name:        str
    description: str
    evidence_field: str | None = None
    is_optional: bool = False


@dataclass
class ExecutionInstance:
    """
    For npm, an execution instance is a static observable unit:
    a declared lifecycle script, a dependency, or a registry operation.
    There is no runtime audit log — the instance is derived from
    package metadata.
    """
    operation_family:  str
    package_name:      str
    package_version:   str
    script_name:       str | None   # e.g. 'postinstall', 'preinstall'
    script_body:       str | None   # the actual script content
    has_lockfile_entry: bool
    has_integrity_hash: bool
    has_provenance:     bool
    is_direct_dep:      bool
    request_id:         str         # synthetic: 'pkg:name@version:script'
    timestamp:          str = ""
    raw:               dict = field(default_factory=dict)


@dataclass
class GovernanceDeclaration:
    source:      str
    strategy:    str
    description: str


# ── npm governance layer registry ─────────────────────────────────────────────

NPM_GOVERNANCE_LAYERS = {
    "registry_auth": GovernanceLayer(
        name="registry_auth",
        description="npm registry authentication — verifies publisher identity",
        evidence_field="npm-signature or provenance attestation",
    ),
    "lockfile_integrity": GovernanceLayer(
        name="lockfile_integrity",
        description="package-lock.json integrity hash — verifies installed package matches declared",
        evidence_field="package-lock.json integrity field (sha512)",
    ),
    "lifecycle_governance": GovernanceLayer(
        name="lifecycle_governance",
        description="Governance over lifecycle script execution (preinstall/postinstall/etc.)",
        evidence_field=None,   # ABSENT — this layer does not exist in npm
        is_optional=False,
    ),
    "module_load_governance": GovernanceLayer(
        name="module_load_governance",
        description=(
            "Governance over module-load-time code execution (require()/import IIFEs, "
            "top-level await, dynamic require). Structurally distinct from lifecycle "
            "governance — fires at application runtime, not at install time. "
            "Does not exist in npm, Node.js, or the CommonJS module system. T1580."
        ),
        evidence_field=None,   # ABSENT — this layer does not exist anywhere in npm/Node.js
        is_optional=False,
    ),
    "provenance_attestation": GovernanceLayer(
        name="provenance_attestation",
        description="SLSA provenance attestation linking artifact to build source",
        evidence_field="npm publish --provenance attestation",
        is_optional=True,
    ),
    "audit_surface": GovernanceLayer(
        name="audit_surface",
        description="Structured record of what executed during install (scripts, side effects)",
        evidence_field=None,   # ABSENT — npm produces no install execution receipt
        is_optional=False,
    ),
}

# ── npm operation family registry ────────────────────────────────────────────

NPM_OPERATION_FAMILIES: list[OperationFamily] = [
    OperationFamily(
        name="dependency_install",
        description="Install a declared dependency from the registry",
        declared_layers=["registry_auth", "lockfile_integrity", "audit_surface"],
        npm_scope="install",
    ),
    OperationFamily(
        name="lifecycle_script_execution",
        description="Execute preinstall/postinstall/prepare/prepublish lifecycle scripts",
        declared_layers=["lifecycle_governance", "audit_surface"],
        npm_scope="lifecycle",
    ),
    OperationFamily(
        name="module_load_execution",
        description=(
            "Code execution triggered at module load time (require()/import), "
            "distinct from lifecycle scripts. Fires when application code loads a "
            "module — not during npm install. Canonical: node-ipc IIFE payload "
            "(2026-05-14) — invisible to preinstall/postinstall scanners. "
            "T1580: structurally independent ABSENT-EAR surface."
        ),
        declared_layers=["module_load_governance", "audit_surface"],
        npm_scope="runtime",
    ),
    OperationFamily(
        name="package_publish",
        description="Publish a package to the npm registry",
        declared_layers=["registry_auth", "provenance_attestation", "audit_surface"],
        npm_scope="publish",
    ),
    OperationFamily(
        name="dependency_resolution",
        description="Resolve semver ranges to concrete versions",
        declared_layers=["lockfile_integrity", "audit_surface"],
        npm_scope="install",
    ),
]


# ── npm EAR Adapter ───────────────────────────────────────────────────────────

class NpmEARAdapter:
    """
    EAR Adapter for npm.

    Static analyzer — reads package.json + package-lock.json.
    No runtime log exists; the ABSENCE of receipt surface is the primary finding.
    """

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "npm Documentation + SLSA Supply Chain Security Framework + "
            "OpenSSF Scorecard + npm Security Advisories"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) derived from npm's documented security model and "
            "supply chain security standards. "
            "lifecycle_governance is declared as an applicable layer because "
            "a constitutionally complete package manager MUST govern "
            "lifecycle script execution — npm's absence of this layer is "
            "the primary F-SCOPE finding. "
            "audit_surface is declared applicable because every governance "
            "system must receipt what it executes — npm's absence is F-LINEAGE."
        ),
    )

    def __init__(
        self,
        package_json_path: str | None = None,
        lockfile_path: str | None = None,
        package_json_data: dict | None = None,
        lockfile_data: dict | None = None,
    ):
        self._pkg_path      = package_json_path
        self._lock_path     = lockfile_path
        self._pkg_data      = package_json_data
        self._lock_data     = lockfile_data
        self._loaded        = False

    def load(self) -> None:
        if self._loaded:
            return
        if self._pkg_path and self._pkg_data is None:
            try:
                self._pkg_data = json.loads(Path(self._pkg_path).read_text())
            except Exception:
                self._pkg_data = {}
        if self._lock_path and self._lock_data is None:
            try:
                self._lock_data = json.loads(Path(self._lock_path).read_text())
            except Exception:
                self._lock_data = {}
        self._loaded = True

    # ── C-01: Operation families ──────────────────────────────────────────

    def collect_operation_families(self) -> list[OperationFamily]:
        return NPM_OPERATION_FAMILIES

    # ── C-02: Governance layers ───────────────────────────────────────────

    def collect_governance_layers(
        self, op_family: OperationFamily
    ) -> list[GovernanceLayer]:
        return [
            NPM_GOVERNANCE_LAYERS[name]
            for name in op_family.declared_layers
            if name in NPM_GOVERNANCE_LAYERS
        ]

    # ── C-03: Execution instances ─────────────────────────────────────────

    def collect_executions(
        self, op_family: OperationFamily
    ) -> list[ExecutionInstance]:
        """
        For npm, execution instances are derived from package metadata.
        No runtime log exists.
        """
        self.load()
        instances = []

        if op_family.name == "lifecycle_script_execution":
            instances.extend(self._extract_lifecycle_instances())
        elif op_family.name == "dependency_install":
            instances.extend(self._extract_dependency_instances())
        elif op_family.name == "dependency_resolution":
            instances.extend(self._extract_resolution_instances())
        elif op_family.name == "package_publish":
            instances.extend(self._extract_publish_instances())
        elif op_family.name == "module_load_execution":
            instances.extend(self._extract_module_load_instances())

        return instances

    def _extract_module_load_instances(self) -> list[ExecutionInstance]:
        """
        Extract module-load-time execution instances from node_modules.

        Detects patterns that execute at require()/import time rather than
        install time. These are invisible to preinstall/postinstall scanners.

        Patterns detected (static AST heuristics via source scan):
        1. IIFE at module top level: (function(){...})() or (() => {...})()
        2. Top-level dynamic require() with non-literal argument
        3. process.exit(), child_process, net, http in top-level scope
        4. eval() or Function() constructor at module level

        Canonical: node-ipc 2026-05-14 — IIFE appended after module.exports,
        fires unconditionally on require('node-ipc'). T1580.
        """
        import re, os
        self.load()
        instances = []

        # Patterns that indicate load-time execution risk
        SUSPICIOUS_PATTERNS = [
            (r'^\s*\((?:function\s*\(|async\s+function\s*\(|\()', 'top_level_iife'),
            (r'^\s*\(\s*async\s*\(', 'top_level_async_iife'),
            (r'require\s*\(\s*[^\'"][^\)]*\)', 'dynamic_require'),
            (r'(?:child_process|exec|spawn|execSync)\s*\(', 'process_spawn'),
            (r'eval\s*\(|new\s+Function\s*\(', 'eval_usage'),
            (r'process\.env\.[A-Z_]{4,}', 'env_access'),
        ]

        # Scan node_modules if lockfile available
        node_modules_path = None
        if self._lock_path:
            nm = str(self._lock_path).replace('package-lock.json', 'node_modules')
            if os.path.isdir(nm):
                node_modules_path = nm

        scanned = 0
        if node_modules_path:
            for root, dirs, files in os.walk(node_modules_path):
                # Skip nested node_modules and .bin
                dirs[:] = [d for d in dirs
                           if d not in ('node_modules', '.bin', '.cache')]
                for fname in files:
                    if not fname.endswith(('.js', '.cjs', '.mjs')):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'r', errors='replace') as f:
                            content = f.read(8192)  # scan first 8KB
                    except OSError:
                        continue

                    scanned += 1
                    if scanned > 500:  # cap scan depth
                        break

                    hits = []
                    for line_no, line in enumerate(content.splitlines(), 1):
                        for pattern, label in SUSPICIOUS_PATTERNS:
                            if re.search(pattern, line):
                                hits.append(f'{label}:line{line_no}')
                                break

                    if hits:
                        pkg_name = root.replace(node_modules_path, '').strip('/\\').split('/')[0]
                        instances.append(ExecutionInstance(
                            operation_family="module_load_execution",
                            package_name=pkg_name,
                            package_version="(from lockfile)",
                            script_name=fname,
                            script_body=f"patterns={hits[:3]}",
                            has_lockfile_entry=True,
                            has_integrity_hash=False,
                            has_provenance=False,
                            is_direct_dep=False,
                            request_id=f"module_load:{pkg_name}:{fname}",
                            raw={"patterns": hits, "file": fpath},
                        ))
                if scanned > 500:
                    break

        # If no node_modules to scan, return one structural synthetic instance
        # to ensure the operation family always has a GCG assertion
        if not instances:
            instances.append(ExecutionInstance(
                operation_family="module_load_execution",
                package_name="(all installed modules)",
                package_version="(structural)",
                script_name=None,
                script_body=None,
                has_lockfile_entry=bool(self._lock_data),
                has_integrity_hash=False,
                has_provenance=False,
                is_direct_dep=False,
                request_id="module_load:structural",
                raw={
                    "finding": (
                        "module_load_governance layer ABSENT — Node.js CommonJS/ESM "
                        "module evaluation is ungoverned. Any installed module can "
                        "execute arbitrary code at require()/import time with no "
                        "governance layer and no receipt. T1580."
                    )
                },
            ))
        return instances

    def _extract_lifecycle_instances(self) -> list[ExecutionInstance]:
        """Extract lifecycle script instances from package.json scripts."""
        if not self._pkg_data:
            return []

        lifecycle_hooks = [
            "preinstall", "install", "postinstall",
            "preuninstall", "uninstall", "postuninstall",
            "prepublish", "prepare", "prepublishOnly",
            "prepack", "pack", "postpack",
            "preversion", "version", "postversion",
        ]

        instances = []
        scripts = self._pkg_data.get("scripts", {})
        pkg_name = self._pkg_data.get("name", "unknown")
        pkg_ver  = self._pkg_data.get("version", "unknown")

        for hook in lifecycle_hooks:
            if hook in scripts:
                body = scripts[hook]
                instances.append(ExecutionInstance(
                    operation_family="lifecycle_script_execution",
                    package_name=pkg_name,
                    package_version=pkg_ver,
                    script_name=hook,
                    script_body=body,
                    has_lockfile_entry=False,  # lifecycle scripts have no lock entry
                    has_integrity_hash=False,
                    has_provenance=False,
                    is_direct_dep=True,
                    request_id=f"lifecycle:{pkg_name}@{pkg_ver}:{hook}",
                    raw={"hook": hook, "body": body},
                ))

        # Also scan dependencies for their lifecycle scripts (via lockfile)
        if self._lock_data:
            packages = self._lock_data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if not pkg_path or pkg_path == "":
                    continue
                dep_scripts = pkg_info.get("scripts", {})
                for hook in lifecycle_hooks:
                    if hook in dep_scripts:
                        dep_name = pkg_path.replace("node_modules/", "")
                        dep_ver  = pkg_info.get("version", "unknown")
                        instances.append(ExecutionInstance(
                            operation_family="lifecycle_script_execution",
                            package_name=dep_name,
                            package_version=dep_ver,
                            script_name=hook,
                            script_body=dep_scripts[hook],
                            has_lockfile_entry=True,
                            has_integrity_hash=bool(pkg_info.get("integrity")),
                            has_provenance=False,
                            is_direct_dep=False,
                            request_id=f"lifecycle:{dep_name}@{dep_ver}:{hook}",
                            raw={"hook": hook, "body": dep_scripts[hook],
                                 "lockfile_path": pkg_path},
                        ))

        return instances

    def _extract_dependency_instances(self) -> list[ExecutionInstance]:
        """Extract dependency install instances from lockfile."""
        self.load()
        if not self._lock_data:
            # No lockfile — this is itself an F-ADMIT finding
            # Return a synthetic instance representing the absent lockfile
            return [ExecutionInstance(
                operation_family="dependency_install",
                package_name="(all dependencies)",
                package_version="(unknown — no lockfile)",
                script_name=None,
                script_body=None,
                has_lockfile_entry=False,
                has_integrity_hash=False,
                has_provenance=False,
                is_direct_dep=True,
                request_id="no-lockfile",
                raw={"finding": "no package-lock.json found"},
            )]

        instances = []
        packages = self._lock_data.get("packages", {})
        for pkg_path, pkg_info in list(packages.items())[:50]:  # cap at 50
            if not pkg_path or pkg_path == "":
                continue
            dep_name = pkg_path.replace("node_modules/", "")
            dep_ver  = pkg_info.get("version", "unknown")
            is_direct = dep_name in (self._pkg_data or {}).get("dependencies", {}) or \
                        dep_name in (self._pkg_data or {}).get("devDependencies", {})

            instances.append(ExecutionInstance(
                operation_family="dependency_install",
                package_name=dep_name,
                package_version=dep_ver,
                script_name=None,
                script_body=None,
                has_lockfile_entry=True,
                has_integrity_hash=bool(pkg_info.get("integrity")),
                has_provenance=bool(pkg_info.get("attestations")),
                is_direct_dep=is_direct,
                request_id=f"dep:{dep_name}@{dep_ver}",
                raw=pkg_info,
            ))
        return instances

    def _extract_resolution_instances(self) -> list[ExecutionInstance]:
        """Check whether semver resolution is locked (lockfile present + integrity)."""
        self.load()
        if not self._lock_data:
            return [ExecutionInstance(
                operation_family="dependency_resolution",
                package_name="(all)",
                package_version="(semver range — unresolved)",
                script_name=None, script_body=None,
                has_lockfile_entry=False,
                has_integrity_hash=False,
                has_provenance=False,
                is_direct_dep=True,
                request_id="resolution:no-lockfile",
                raw={"finding": "semver resolution not locked"},
            )]
        return []  # lockfile present = resolution is locked (no gap)

    def _extract_publish_instances(self) -> list[ExecutionInstance]:
        """Synthetic publish instance from package.json metadata."""
        self.load()
        if not self._pkg_data:
            return []
        name = self._pkg_data.get("name", "unknown")
        ver  = self._pkg_data.get("version", "unknown")
        return [ExecutionInstance(
            operation_family="package_publish",
            package_name=name,
            package_version=ver,
            script_name=None, script_body=None,
            has_lockfile_entry=False,
            has_integrity_hash=False,
            has_provenance=bool(self._pkg_data.get("provenance")),
            is_direct_dep=True,
            request_id=f"publish:{name}@{ver}",
            raw={"name": name, "version": ver},
        )]

    # ── EAR state assessment ──────────────────────────────────────────────

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """
        Assess EAR state for npm operation families.
        npm's primary EAR state is ABSENT for lifecycle and audit surfaces.
        """
        if op_family.name == "lifecycle_script_execution":
            # No lifecycle governance layer exists anywhere in npm.
            # Scripts run with user privileges. No record produced.
            return EARState.ABSENT

        if op_family.name == "module_load_execution":
            # Module-load-time execution governance does not exist in Node.js.
            # require()/import evaluates all top-level code unconditionally.
            # This is structurally ABSENT — no mechanism in the npm/Node.js
            # architecture can govern or receipt this execution surface. T1580.
            return EARState.ABSENT

        if op_family.name == "dependency_install":
            # audit_surface is ABSENT (no install receipt)
            # lockfile_integrity is CRYSTALLIZED (exists if lockfile present)
            self.load()
            if self._lock_data:
                return EARState.CRYSTALLIZED  # lockfile provides partial receipt
            return EARState.ABSENT

        if op_family.name == "dependency_resolution":
            self.load()
            if self._lock_data:
                return EARState.CRYSTALLIZED
            return EARState.ABSENT

        if op_family.name == "package_publish":
            # Provenance attestation is CRYSTALLIZED (infrastructure exists,
            # requires --provenance flag, not default)
            return EARState.CRYSTALLIZED

        return EARState.ABSENT

    def get_governance_declaration(self) -> GovernanceDeclaration:
        return self.GOVERNANCE_DECLARATION

    def summary(self) -> dict:
        self.load()
        families = self.collect_operation_families()
        lifecycle = self.collect_executions(
            next(f for f in families if f.name == "lifecycle_script_execution")
        )
        return {
            "package_name":         (self._pkg_data or {}).get("name", "unknown"),
            "has_lockfile":         self._lock_data is not None,
            "lifecycle_scripts":    len(lifecycle),
            "operation_families":   [f.name for f in families],
            "ear_states": {
                f.name: self.assess_ear_state(f).value
                for f in families
            },
        }
