"""
ear_adapter_redis.py — Redis EAR Adapter
Wave 7 — System 34. In-memory data store governance.

Key finding: Redis is the corpus's in-memory data store governance case.
No authentication by default (pre-Redis 6 had no AUTH; Redis 6+ introduced
ACLs but requirepass is still empty by default in many deployments).
No audit log. No TLS by default. 57% of cloud environments have Redis deployed;
60,000+ instances have no authentication configured (Wiz Research, 2025).
CVE-2025-49844 (RediShell, CVSS 10.0): 13-year-old use-after-free in Lua scripting
engine, achieves host-level RCE. Affects all Redis versions since 2012.
CVE-2022-0543 (Lua sandbox escape, CVSS 10.0): previously exploited by
P2PInfect worm targeting unauthenticated Redis instances.
The ABSENT default configuration combined with CVSS 10.0 vulnerabilities in
the default-enabled Lua scripting feature makes Redis a high-priority lateral
movement target in compromised environments.
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
    name: str; description: str; declared_layers: list[str]; redis_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    auth_verified: bool; tls_enabled: bool; audit_logged: bool
    acl_applied: bool; lua_restricted: bool
    command: str|None; key: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

REDIS_OPERATION_FAMILIES = [
    OperationFamily("data_read",
        "Read key-value data from Redis",
        ["auth_control","acl_policy","audit_log","tls_transport"], "read"),
    OperationFamily("data_write",
        "Write key-value data to Redis",
        ["auth_control","acl_policy","audit_log","tls_transport"], "write"),
    OperationFamily("lua_execution",
        "Execute Lua script via EVAL/EVALSHA",
        ["auth_control","acl_policy","lua_scope","audit_log"], "lua"),
    OperationFamily("admin_command",
        "Execute admin command (CONFIG, DEBUG, SLAVEOF, etc.)",
        ["auth_control","acl_policy","audit_log","protected_mode"], "admin"),
    OperationFamily("pubsub_operation",
        "Publish or subscribe to Redis pub/sub channel",
        ["auth_control","acl_policy","audit_log"], "pubsub"),
]

REDIS_GOVERNANCE_LAYERS = {
    "auth_control": GovernanceLayer("auth_control",
        "Authentication (requirepass or ACL) — empty by default", "requirepass"),
    "acl_policy": GovernanceLayer("acl_policy",
        "ACL rules controlling command and key access (Redis 6+)", "ACL"),
    "audit_log": GovernanceLayer("audit_log",
        "Redis audit log — not built-in; requires external proxy or module", None),
    "tls_transport": GovernanceLayer("tls_transport",
        "TLS encryption for client connections — opt-in", "tls-port"),
    "lua_scope": GovernanceLayer("lua_scope",
        "Lua scripting scope restrictions (disable/restrict EVAL)", None),
    "protected_mode": GovernanceLayer("protected_mode",
        "Protected mode — blocks unauthenticated access from non-loopback", "protected-mode"),
}

class RedisEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="Redis Documentation + Redis ACL docs + CVE-2025-49844 advisory + P2PInfect analysis",
        strategy="DECLARED-N",
        description=(
            "N(O) from Redis architecture. data_read N=4. "
            "ABSENT by default: requirepass empty, no ACL, no TLS, no audit log. "
            "Protected mode blocks cross-network unauthenticated access in default config "
            "but is bypassed by any valid bind address configuration. "
            "57% of cloud environments have Redis deployed; 60,000+ instances publicly "
            "exposed without authentication (Wiz Research, October 2025). "
            "CVE-2025-49844 (RediShell, CVSS 10.0): Lua use-after-free, all versions since 2012. "
            "CVE-2022-0543 (CVSS 10.0): Lua sandbox escape exploited by P2PInfect worm. "
            "Lua scripting is enabled by default — two CVSS 10.0 vulnerabilities in this surface. "
            "No Redis family reaches ACTIVE in standard deployment."
        ),
    )
    def __init__(self, auth_enabled: bool=False, acl_enabled: bool=False,
                 tls_enabled: bool=False, lua_restricted: bool=False,
                 audit_log_enabled: bool=False):
        self._auth = auth_enabled
        self._acl = acl_enabled
        self._tls = tls_enabled
        self._lua = lua_restricted
        self._audit = audit_log_enabled

    def collect_operation_families(self): return REDIS_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [REDIS_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in REDIS_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            auth_verified=self._auth, tls_enabled=self._tls,
            audit_logged=self._audit, acl_applied=self._acl,
            lua_restricted=self._lua, command=None, key=None,
            decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in REDIS_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "auth_control" in fam.declared_layers and self._auth: k.append("auth_control")
        if "acl_policy" in fam.declared_layers and self._acl: k.append("acl_policy")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "tls_transport" in fam.declared_layers and self._tls: k.append("tls_transport")
        if "lua_scope" in fam.declared_layers and self._lua: k.append("lua_scope")
        if "protected_mode" in fam.declared_layers: k.append("protected_mode")
        return k
    def assess_ear_state(self, op_family):
        if not self._auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
