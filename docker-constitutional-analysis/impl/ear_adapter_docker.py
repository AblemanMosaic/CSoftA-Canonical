"""
ear_adapter_docker.py — Docker EAR Adapter

Implements the EARAdapter interface for Docker (Moby/Docker Engine).
Primary evidence source: `docker inspect` JSON output.
Secondary: daemon.json configuration, seccomp profile presence.

Docker's primary finding: boundary governance (seccomp, AppArmor,
capability restrictions) is CRYSTALLIZED; interior execution is ABSENT.
--privileged is the canonical Layer Bypass.

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
GCG Codex Binding 3: Container Security Architecture (PCM-0333-197..201)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ── Enumerations ─────────────────────────────────────────────────────────────

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
    docker_scope:       str   # 'run' | 'build' | 'exec' | 'daemon'


@dataclass
class GovernanceLayer:
    name:        str
    description: str
    inspect_field: str | None = None  # path in docker inspect JSON
    is_optional: bool = False


@dataclass
class ExecutionInstance:
    """
    For Docker, an execution instance is derived from docker inspect output.
    One instance = one container configuration.
    """
    operation_family:       str
    container_id:           str
    container_name:         str
    image:                  str
    privileged:             bool
    seccomp_profile:        str | None   # 'default', path, or None (absent)
    apparmor_profile:       str | None   # 'docker-default', 'unconfined', or None
    capabilities_added:     list[str]
    capabilities_dropped:   list[str]
    read_only_rootfs:       bool
    user:                   str          # e.g. '0' (root), '1000', ''
    network_mode:           str          # 'bridge', 'host', 'none', etc.
    pid_mode:               str          # '' (default), 'host'
    ipc_mode:               str          # 'private', 'host', 'shareable'
    has_audit_log:          bool         # Docker daemon audit logging present
    request_id:             str
    timestamp:              str = ""
    raw:                    dict = field(default_factory=dict)


@dataclass
class GovernanceDeclaration:
    source:      str
    strategy:    str
    description: str


# ── Docker governance layer registry ──────────────────────────────────────────

DOCKER_GOVERNANCE_LAYERS = {
    "seccomp": GovernanceLayer(
        name="seccomp",
        description="Seccomp syscall filtering — restricts available syscalls",
        inspect_field="HostConfig.SecurityOpt",
    ),
    "apparmor": GovernanceLayer(
        name="apparmor",
        description="AppArmor/SELinux MAC — mandatory access control profile",
        inspect_field="HostConfig.SecurityOpt",
    ),
    "capabilities": GovernanceLayer(
        name="capabilities",
        description="Linux capability restrictions — limits root-equivalent powers",
        inspect_field="HostConfig.CapDrop",
    ),
    "namespace_isolation": GovernanceLayer(
        name="namespace_isolation",
        description="Linux namespaces — PID, net, mount, UTS, IPC isolation",
        inspect_field="HostConfig.NetworkMode",
    ),
    "cgroups": GovernanceLayer(
        name="cgroups",
        description="Control groups — resource limits and accounting",
        inspect_field="HostConfig.Resources",
    ),
    "user_namespace": GovernanceLayer(
        name="user_namespace",
        description="User namespace — UID/GID remapping",
        inspect_field="HostConfig.UsernsMode",
        is_optional=True,
    ),
    "audit_log": GovernanceLayer(
        name="audit_log",
        description="Docker daemon audit logging (via auditd or daemon log)",
        inspect_field=None,
        is_optional=False,
    ),
    "interior_execution": GovernanceLayer(
        name="interior_execution",
        description="Governance over processes executing inside the container",
        inspect_field=None,
        is_optional=False,
    ),
}


# ── Docker operation family registry ──────────────────────────────────────────

DOCKER_OPERATION_FAMILIES: list[OperationFamily] = [
    OperationFamily(
        name="container_run_standard",
        description="Run a container with default/standard flags (no --privileged)",
        declared_layers=["seccomp", "apparmor", "capabilities",
                         "namespace_isolation", "cgroups"],
        docker_scope="run",
    ),
    OperationFamily(
        name="container_run_privileged",
        description="Run a container with --privileged flag (Layer Bypass)",
        declared_layers=["seccomp", "apparmor", "capabilities",
                         "namespace_isolation", "cgroups"],
        docker_scope="run",
    ),
    OperationFamily(
        name="container_interior_execution",
        description="Process execution inside a running container",
        declared_layers=["interior_execution", "audit_log"],
        docker_scope="exec",
    ),
    OperationFamily(
        name="image_build",
        description="Build an image from Dockerfile",
        declared_layers=["audit_log"],
        docker_scope="build",
    ),
]


# ── Docker EAR Adapter ────────────────────────────────────────────────────────

class DockerEARAdapter:
    """
    EAR Adapter for Docker.

    Primary input: docker inspect JSON (list of container inspect objects).
    Secondary: daemon.json path for audit configuration.

    For testing without a live daemon: pass inspect_data directly.
    """

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "Docker Security Documentation + CIS Docker Benchmark v1.6 + "
            "Docker Engine Hardening Guide"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) derived from Docker's documented security model. "
            "Standard container: N=5 (seccomp, apparmor, capabilities, "
            "namespace_isolation, cgroups). "
            "--privileged container: N declared=5 but execution bypasses 3. "
            "Interior execution: N=2 (interior_execution, audit_log) both ABSENT."
        ),
    )

    def __init__(
        self,
        inspect_data: list[dict] | None = None,
        inspect_json_path: str | None = None,
        daemon_json_path: str | None = None,
        audit_log_enabled: bool | None = None,
    ):
        self._inspect_data    = inspect_data
        self._inspect_path    = inspect_json_path
        self._daemon_path     = daemon_json_path
        self._audit_enabled   = audit_log_enabled
        self._daemon_config   = {}
        self._loaded          = False

    def load(self) -> None:
        if self._loaded:
            return
        if self._inspect_path and self._inspect_data is None:
            try:
                raw = Path(self._inspect_path).read_text()
                self._inspect_data = json.loads(raw)
            except Exception:
                self._inspect_data = []
        if self._daemon_path:
            try:
                self._daemon_config = json.loads(
                    Path(self._daemon_path).read_text()
                )
            except Exception:
                self._daemon_config = {}
        self._loaded = True

    # ── C-01: Operation families ──────────────────────────────────────────

    def collect_operation_families(self) -> list[OperationFamily]:
        return DOCKER_OPERATION_FAMILIES

    # ── C-02: Governance layers ───────────────────────────────────────────

    def collect_governance_layers(
        self, op_family: OperationFamily
    ) -> list[GovernanceLayer]:
        return [
            DOCKER_GOVERNANCE_LAYERS[name]
            for name in op_family.declared_layers
            if name in DOCKER_GOVERNANCE_LAYERS
        ]

    # ── C-03: Execution instances ─────────────────────────────────────────

    def collect_executions(
        self, op_family: OperationFamily
    ) -> list[ExecutionInstance]:
        self.load()
        if not self._inspect_data:
            return []

        instances = []
        for container in self._inspect_data:
            inst = self._parse_container(container)
            if inst is None:
                continue

            if op_family.name == "container_run_privileged":
                if not inst.privileged:
                    continue
            elif op_family.name == "container_run_standard":
                if inst.privileged:
                    continue
            elif op_family.name in ("container_interior_execution", "image_build"):
                # Synthetic: one instance per adapter (structural finding)
                return [ExecutionInstance(
                    operation_family=op_family.name,
                    container_id="(all containers)",
                    container_name="(structural)",
                    image="(any)",
                    privileged=False,
                    seccomp_profile=None,
                    apparmor_profile=None,
                    capabilities_added=[],
                    capabilities_dropped=[],
                    read_only_rootfs=False,
                    user="",
                    network_mode="",
                    pid_mode="",
                    ipc_mode="",
                    has_audit_log=self._audit_enabled is True,
                    request_id=f"structural:{op_family.name}",
                    raw={},
                )]

            instances.append(inst)
        return instances

    def _parse_container(self, container: dict) -> ExecutionInstance | None:
        """Parse docker inspect output for one container."""
        try:
            hc      = container.get("HostConfig", {})
            config  = container.get("Config", {})
            state   = container.get("State", {})
            cid     = container.get("Id", "")[:12]
            name    = (container.get("Name", "") or "").lstrip("/")
            image   = config.get("Image", "")

            privileged = bool(hc.get("Privileged", False))

            # Seccomp profile
            sec_opts = hc.get("SecurityOpt") or []
            seccomp  = None
            apparmor = None
            for opt in sec_opts:
                if "seccomp" in opt.lower():
                    if "unconfined" in opt.lower():
                        seccomp = "unconfined"
                    elif "=" in opt:
                        seccomp = opt.split("=", 1)[1]
                    else:
                        seccomp = "custom"
                elif "apparmor" in opt.lower():
                    apparmor = opt.split("=", 1)[-1] if "=" in opt else "docker-default"

            # Default seccomp: Docker applies default profile unless explicitly unconfined
            if seccomp is None and not privileged:
                seccomp = "default"
            elif privileged:
                seccomp = None  # --privileged disables seccomp

            # AppArmor default
            if apparmor is None and not privileged:
                apparmor = "docker-default"
            elif privileged:
                apparmor = None

            caps_add  = hc.get("CapAdd")  or []
            caps_drop = hc.get("CapDrop") or []
            if privileged:
                caps_add  = ["ALL"]
                caps_drop = []

            return ExecutionInstance(
                operation_family="container_run_privileged" if privileged
                                 else "container_run_standard",
                container_id=cid,
                container_name=name,
                image=image,
                privileged=privileged,
                seccomp_profile=seccomp,
                apparmor_profile=apparmor,
                capabilities_added=caps_add,
                capabilities_dropped=caps_drop,
                read_only_rootfs=bool(hc.get("ReadonlyRootfs", False)),
                user=config.get("User", ""),
                network_mode=hc.get("NetworkMode", "default"),
                pid_mode=hc.get("PidMode", ""),
                ipc_mode=hc.get("IpcMode", "private"),
                has_audit_log=self._audit_enabled is True,
                request_id=f"container:{cid}:{name}",
                raw=container,
            )
        except Exception:
            return None

    # ── EAR state ─────────────────────────────────────────────────────────

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """
        Docker EAR state per operation family.

        container_run_standard: CRYSTALLIZED
          (seccomp/AppArmor/capabilities exist and default-on,
           but no per-operation receipt is produced)
        container_run_privileged: ABSENT
          (bypasses all governance layers; no receipt of bypass)
        container_interior_execution: ABSENT
          (no governance or receipt for process execution inside container)
        image_build: ABSENT
          (build-time execution not receipted)
        """
        if op_family.name == "container_run_standard":
            return EARState.CRYSTALLIZED

        if op_family.name == "container_run_privileged":
            return EARState.ABSENT

        if op_family.name == "container_interior_execution":
            return EARState.ABSENT

        if op_family.name == "image_build":
            return EARState.ABSENT

        return EARState.ABSENT

    # ── k(O,e) assessment ────────────────────────────────────────────────

    def assess_k(self, inst: ExecutionInstance) -> list[str]:
        """
        Assess which governance layers actually participated for this instance.
        """
        k = []

        if inst.privileged:
            # --privileged: only namespace isolation and cgroups survive
            k.append("namespace_isolation")  # namespaces still exist
            k.append("cgroups")              # cgroups still active
            # seccomp, apparmor, capabilities: bypassed
            return k

        # Standard container
        if inst.seccomp_profile and inst.seccomp_profile not in ("unconfined", ""):
            k.append("seccomp")
        if inst.apparmor_profile and inst.apparmor_profile not in ("unconfined", ""):
            k.append("apparmor")
        if inst.capabilities_dropped:  # some caps dropped = participation
            k.append("capabilities")
        elif "ALL" not in inst.capabilities_added:
            # Default Docker drops a subset of caps even without explicit CapDrop
            k.append("capabilities")  # default cap restriction counts
        k.append("namespace_isolation")  # always active for standard containers
        k.append("cgroups")             # always active

        if inst.has_audit_log:
            k.append("audit_log")

        return k

    def get_governance_declaration(self) -> GovernanceDeclaration:
        return self.GOVERNANCE_DECLARATION

    def summary(self) -> dict:
        self.load()
        families   = self.collect_operation_families()
        all_insts  = []
        for f in families:
            all_insts.extend(self.collect_executions(f))
        privileged = sum(1 for i in all_insts if i.privileged)
        return {
            "total_containers":  len(all_insts),
            "privileged":        privileged,
            "audit_enabled":     self._audit_enabled,
            "ear_states": {f.name: self.assess_ear_state(f).value for f in families},
        }
