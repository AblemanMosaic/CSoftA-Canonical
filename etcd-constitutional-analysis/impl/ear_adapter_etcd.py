"""
ear_adapter_etcd.py — etcd EAR Adapter
Wave 6 — System 27. Kubernetes cluster backing store.

Key finding: etcd is the substrate-of-the-substrate. Every Kubernetes
governance mechanism (RBAC, admission controllers, Secrets) ultimately
stores its state in etcd. etcd's own governance surface is CRYSTALLIZED:
encryption at rest is opt-in (EncryptionConfiguration, not default),
etcd has no audit log of its own, and peer authentication via mTLS is
the only constitutive governance layer. etcd access bypasses Kubernetes
RBAC entirely — direct etcd access reads all Secrets, all RBAC policies,
all resource definitions without any Kubernetes admission control.
This is the constitutional significance: etcd is the substrate that all
Kubernetes governance depends on, yet etcd governance is weaker than
the Kubernetes governance it supports.
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
    name: str; description: str; declared_layers: list[str]; etcd_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str|None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    mtls_verified: bool; encryption_at_rest: bool; audit_logged: bool
    peer_authenticated: bool; key: str|None
    decision: str|None; error: str|None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ETCD_OPERATION_FAMILIES = [
    OperationFamily("key_read",
        "Read key-value from etcd store",
        ["peer_mtls","encryption_at_rest","audit_log"], "read"),
    OperationFamily("key_write",
        "Write key-value to etcd store",
        ["peer_mtls","encryption_at_rest","audit_log"], "write"),
    OperationFamily("peer_authentication",
        "Authenticate etcd peer/client connection via mTLS",
        ["peer_mtls","peer_cert"], "peer"),
    OperationFamily("snapshot_backup",
        "Create etcd snapshot backup",
        ["peer_mtls","encryption_at_rest","backup_encryption"], "backup"),
    OperationFamily("member_management",
        "Add/remove etcd cluster member",
        ["peer_mtls","audit_log"], "member"),
]

ETCD_GOVERNANCE_LAYERS = {
    "peer_mtls": GovernanceLayer("peer_mtls",
        "Mutual TLS authentication for all client and peer connections", "--peer-client-cert-auth"),
    "encryption_at_rest": GovernanceLayer("encryption_at_rest",
        "Encryption at rest via EncryptionConfiguration — opt-in, not default", "EncryptionConfiguration"),
    "audit_log": GovernanceLayer("audit_log",
        "etcd audit log — not built-in; must use external logging", None),
    "peer_cert": GovernanceLayer("peer_cert",
        "Peer certificate — IS the authentication receipt for peer connections", "--peer-cert-file"),
    "backup_encryption": GovernanceLayer("backup_encryption",
        "Encryption of snapshot backups", None, is_optional=True),
}

class EtcdEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="etcd Documentation + Kubernetes etcd security guide + CIS Kubernetes Benchmark",
        strategy="DECLARED-N",
        description=(
            "N(O) from etcd architecture. key_read N=3. "
            "peer_authentication: ACTIVE — mTLS is constitutive of connection. "
            "key_read/write: CRYSTALLIZED with mTLS; ABSENT without. "
            "Encryption at rest: opt-in (EncryptionConfiguration) — "
            "Kubernetes Secrets stored as plaintext base64 by default. "
            "No native etcd audit log — external log aggregation required. "
            "Critical constitutional significance: direct etcd access bypasses "
            "all Kubernetes RBAC and admission control — "
            "etcd is the substrate whose governance is weaker than "
            "the Kubernetes governance layer built on top of it."
        ),
    )
    def __init__(self, mtls_enabled: bool=True, encryption_at_rest: bool=False,
                 audit_log_enabled: bool=False, backup_encrypted: bool=False):
        self._mtls = mtls_enabled
        self._enc = encryption_at_rest
        self._audit = audit_log_enabled
        self._backup_enc = backup_encrypted

    def collect_operation_families(self): return ETCD_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ETCD_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ETCD_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            mtls_verified=self._mtls, encryption_at_rest=self._enc,
            audit_logged=self._audit, peer_authenticated=self._mtls,
            key=None, decision=None, error=None, raw={},
        )]
    def assess_k(self, inst):
        k=[]
        fam=next((f for f in ETCD_OPERATION_FAMILIES if f.name==inst.operation_family),None)
        if not fam: return k
        if "peer_mtls" in fam.declared_layers and inst.mtls_verified: k.append("peer_mtls")
        if "encryption_at_rest" in fam.declared_layers and self._enc: k.append("encryption_at_rest")
        if "audit_log" in fam.declared_layers and self._audit: k.append("audit_log")
        if "peer_cert" in fam.declared_layers and self._mtls: k.append("peer_cert")
        if "backup_encryption" in fam.declared_layers and self._backup_enc: k.append("backup_encryption")
        return k
    def assess_ear_state(self, op_family):
        if op_family.name == "peer_authentication" and self._mtls: return EARState.ACTIVE
        if not self._mtls: return EARState.ABSENT
        return EARState.CRYSTALLIZED
    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
