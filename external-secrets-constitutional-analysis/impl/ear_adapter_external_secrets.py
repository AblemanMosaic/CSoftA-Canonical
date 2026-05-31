"""
ear_adapter_external_secrets.py — External Secrets Operator EAR Adapter
Wave 3 — System 12. Kubernetes operator syncing secrets from external stores.

Key finding: CRYSTALLIZED ceiling. ExternalSecret CRD records sync status
but secret sync is not constitutive of the ExternalSecret resource — the
operator may sync successfully or fail, the CRD records outcome not receipt.
The external secret store (Vault, AWS SM, etc.) has its own EAR state that
is upstream of external-secrets-operator's governance.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

class EARState(Enum):
    ACTIVE = "ACTIVE"; CRYSTALLIZED = "CRYSTALLIZED"; ABSENT = "ABSENT"

class GCGForm(Enum):
    NON_ACTIVATION = "NON_ACTIVATION"; ABSENCE = "ABSENCE"; BYPASS = "BYPASS"

@dataclass
class OperationFamily:
    name: str; description: str; declared_layers: list[str]; eso_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None = None; is_optional: bool = False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    external_secret_synced: bool; store_auth_verified: bool
    secret_written: bool; sync_status_recorded: bool
    store_type: str; namespace: str
    error: str | None; raw: dict = field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

ESO_OPERATION_FAMILIES = [
    OperationFamily("secret_sync",
        "Sync secret from external store to Kubernetes Secret",
        ["external_secret_resource", "store_auth", "secret_write", "sync_status"], "sync"),
    OperationFamily("store_authentication",
        "Authenticate to external secret store (Vault, AWS SM, GCP SM, etc.)",
        ["secret_store_resource", "store_auth", "auth_receipt"], "auth"),
    OperationFamily("secret_rotation",
        "Detect and sync rotated secret from external store",
        ["external_secret_resource", "store_auth", "secret_write"], "rotation"),
    OperationFamily("push_secret",
        "Push Kubernetes Secret to external store",
        ["push_secret_resource", "store_auth", "sync_status"], "push"),
]

ESO_GOVERNANCE_LAYERS = {
    "external_secret_resource": GovernanceLayer("external_secret_resource",
        "ExternalSecret CRD declaring external secret reference", "spec.dataFrom"),
    "store_auth": GovernanceLayer("store_auth",
        "Authentication to external secret store", "spec.secretStoreRef"),
    "secret_write": GovernanceLayer("secret_write",
        "Kubernetes Secret written with synced data", "spec.target.name"),
    "sync_status": GovernanceLayer("sync_status",
        "Sync status on ExternalSecret .status.conditions", "status.conditions"),
    "secret_store_resource": GovernanceLayer("secret_store_resource",
        "SecretStore/ClusterSecretStore CRD declaring store connection", "spec.provider"),
    "auth_receipt": GovernanceLayer("auth_receipt",
        "Authentication receipt from external store", None, is_optional=True),
    "push_secret_resource": GovernanceLayer("push_secret_resource",
        "PushSecret CRD declaring push target", "spec.secretStoreRefs"),
}

class ExternalSecretsEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="External Secrets Operator Documentation + ESO GitHub + SecretStore API spec",
        strategy="DECLARED-N",
        description=(
            "N(O) from ESO architecture. secret_sync N=4. "
            "CRYSTALLIZED ceiling: sync status on ExternalSecret records outcome "
            "but secret sync is not constitutive of ExternalSecret existence. "
            "The external secret store's own EAR state is upstream of ESO governance. "
            "If syncing from Vault: Vault's ACTIVE-EAR governs the fetch; "
            "ESO's own governance of the sync operation is CRYSTALLIZED."
        ),
    )

    def __init__(self, store_type: str = "vault",
                 sync_status_enabled: bool = True, store_auth_configured: bool = True):
        self._store = store_type
        self._sync_status = sync_status_enabled
        self._store_auth = store_auth_configured

    def collect_operation_families(self): return ESO_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [ESO_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in ESO_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            external_secret_synced=(op_family.name in ("secret_sync","secret_rotation")),
            store_auth_verified=self._store_auth,
            secret_written=(op_family.name in ("secret_sync","secret_rotation")),
            sync_status_recorded=self._sync_status,
            store_type=self._store, namespace="default", error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in ESO_OPERATION_FAMILIES if f.name == inst.operation_family), None)
        if not fam: return k
        if "external_secret_resource" in fam.declared_layers:
            k.append("external_secret_resource")
        if "store_auth" in fam.declared_layers and inst.store_auth_verified:
            k.append("store_auth")
        if "secret_write" in fam.declared_layers and inst.secret_written:
            k.append("secret_write")
        if "sync_status" in fam.declared_layers and inst.sync_status_recorded:
            k.append("sync_status")
        if "secret_store_resource" in fam.declared_layers:
            k.append("secret_store_resource")
        if "push_secret_resource" in fam.declared_layers:
            k.append("push_secret_resource")
        return k

    def assess_ear_state(self, op_family):
        # No ESO operation reaches ACTIVE — sync status is not constitutive
        if not self._store_auth: return EARState.ABSENT
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
