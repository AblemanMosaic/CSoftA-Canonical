"""
ear_adapter_vault.py — Vault EAR Adapter

Implements the EARAdapter interface for HashiCorp Vault.
Reads Vault audit log (file audit device, JSON newline-delimited).
Extracts operation families, governance layer participation, and
assesses EAR state per operation family.

Conforms to: CSoftA Python Reference Implementation Skeleton (T1575)
Implements: GCG Codex C-01 through C-04 (Phase A) for Vault
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator


# ── Enumerations ─────────────────────────────────────────────────────────────

class EARState(Enum):
    """EAR state per operation family. T1573."""
    ACTIVE       = "ACTIVE"        # receipt constitutive of execution
    CRYSTALLIZED = "CRYSTALLIZED"  # receipt mechanism exists, not mandatory
    ABSENT       = "ABSENT"        # no receipt surface


class GCGForm(Enum):
    """GCG form classification. GCG Codex C-09/C-10/C-11."""
    NON_ACTIVATION = "NON_ACTIVATION"  # layer present, not activated in context
    ABSENCE        = "ABSENCE"         # layer not deployed in this environment
    BYPASS         = "BYPASS"          # execution path routes around layer


# ── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class OperationFamily:
    """GCG Codex C-01: class of operations sharing same declared governance layer set."""
    name:               str
    description:        str
    declared_layers:    list[str]        # C-05: N(O) — declared layer names
    vault_path_pattern: str              # regex matching audit log request paths


@dataclass
class GovernanceLayer:
    """GCG Codex C-02: distinct mechanism that evaluates, constrains, or records."""
    name:        str
    description: str
    audit_field: str | None = None       # field in audit log indicating participation
    is_optional: bool       = False      # can be absent without violating invariants


@dataclass
class ExecutionInstance:
    """GCG Codex C-03: single occurrence of an operation at a specific time."""
    operation_family:    str
    timestamp:           str
    request_id:          str
    request_path:        str
    request_operation:   str
    token_type:          str
    token_policies:      list[str]
    granting_policies:   list[str]        # policyresults.grantingpolicies
    auth_type:           str
    response_code:       int | None
    raw:                 dict             # original audit log entry


@dataclass
class GovernanceDeclaration:
    """GCG Codex C-04: explicit or conventional specification of applicable layers."""
    source:      str                      # e.g. 'Vault Architecture Guide v1.13'
    strategy:    str                      # DECLARED-N / MINIMUM-N / PER-CONTEXT-N
    description: str


# ── Vault governance layer registry ──────────────────────────────────────────

VAULT_GOVERNANCE_LAYERS = {
    "token_auth": GovernanceLayer(
        name="token_auth",
        description="Token authentication — verifies token validity and type",
        audit_field="auth.client_token",
    ),
    "policy_evaluation": GovernanceLayer(
        name="policy_evaluation",
        description="Policy engine — evaluates token policies against request path/operation",
        audit_field="auth.policy_results.allowed_policies",
    ),
    "audit_device": GovernanceLayer(
        name="audit_device",
        description="Audit device — produces durable receipt of every operation",
        audit_field=None,  # presence is structural, not per-entry
        is_optional=False,  # S-02: mandatory for ACTIVE-EAR
    ),
    "mfa": GovernanceLayer(
        name="mfa",
        description="Multi-Factor Authentication enforcement (if configured)",
        audit_field="auth.mfa_requirement",
        is_optional=True,
    ),
    "sentinel_egp": GovernanceLayer(
        name="sentinel_egp",
        description="Sentinel Endpoint Governing Policies (Vault Enterprise only)",
        audit_field="auth.policy_results.granting_policies",
        is_optional=True,
    ),
}


# ── Vault operation family registry ──────────────────────────────────────────

VAULT_OPERATION_FAMILIES: list[OperationFamily] = [
    OperationFamily(
        name="secret_read",
        description="Read a secret from a secrets engine (KV v1/v2, PKI, database, etc.)",
        declared_layers=["token_auth", "policy_evaluation", "audit_device"],
        vault_path_pattern=r"^(secret|kv|pki|database|ssh|totp|transit)/",
    ),
    OperationFamily(
        name="secret_write",
        description="Write or create a secret in a secrets engine",
        declared_layers=["token_auth", "policy_evaluation", "audit_device"],
        vault_path_pattern=r"^(secret|kv|pki|database|ssh|totp|transit)/",
    ),
    OperationFamily(
        name="auth_login",
        description="Authenticate via an auth method to obtain a token",
        declared_layers=["audit_device"],  # pre-auth: no token_auth or policy yet
        vault_path_pattern=r"^auth/[^/]+/login",
    ),
    OperationFamily(
        name="token_create",
        description="Create a new token (token auth method operations)",
        declared_layers=["token_auth", "policy_evaluation", "audit_device"],
        vault_path_pattern=r"^auth/token/(create|lookup|renew|revoke)",
    ),
    OperationFamily(
        name="policy_manage",
        description="Create, read, update, or delete policies",
        declared_layers=["token_auth", "policy_evaluation", "audit_device"],
        vault_path_pattern=r"^sys/policy",
    ),
    OperationFamily(
        name="sys_audit",
        description="Enable, disable, or list audit devices",
        declared_layers=["token_auth", "policy_evaluation", "audit_device"],
        vault_path_pattern=r"^sys/audit",
    ),
    OperationFamily(
        name="root_token_operation",
        description="Operations performed with root token — Layer Bypass form",
        declared_layers=["token_auth", "policy_evaluation", "audit_device"],
        vault_path_pattern=r".*",  # matches all — filtered by token type
    ),
]


# ── EAR Adapter ──────────────────────────────────────────────────────────────

class VaultEARAdapter:
    """
    EAR Adapter for HashiCorp Vault.

    Reads Vault file audit device (JSON newline-delimited).
    Implements GCG Codex Phase A (C-01..C-04) for Vault.
    """

    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source="HashiCorp Vault Architecture Guide + CIS Benchmark for Vault",
        strategy="DECLARED-N",
        description=(
            "N(O) derived from Vault's documented security model. "
            "Core layers for authenticated operations: token_auth, "
            "policy_evaluation, audit_device. "
            "auth_login has reduced N (pre-auth). "
            "Root token operations are declared Layer Bypass."
        ),
    )

    def __init__(self, audit_log_path: str | None = None,
                 audit_log_lines: list[str] | None = None,
                 audit_device_enabled: bool | None = None):
        """
        Parameters
        ----------
        audit_log_path : path to Vault file audit device log
        audit_log_lines : pre-loaded log lines (for testing)
        audit_device_enabled : override for structural audit device presence
        """
        self._log_path             = audit_log_path
        self._log_lines            = audit_log_lines
        self._audit_device_enabled = audit_device_enabled
        self._entries: list[dict]  = []
        self._loaded               = False

    # ── Loading ───────────────────────────────────────────────────────────

    def load(self) -> None:
        """Parse audit log entries from file or pre-loaded lines."""
        if self._loaded:
            return

        lines: list[str] = []
        if self._log_lines is not None:
            lines = self._log_lines
        elif self._log_path:
            lines = Path(self._log_path).read_text().splitlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if entry.get("type") == "request":
                    self._entries.append(entry)
            except json.JSONDecodeError:
                continue

        self._loaded = True

    # ── C-01: Operation families ──────────────────────────────────────────

    def collect_operation_families(self) -> list[OperationFamily]:
        """Return the declared Vault operation families. GCG C-01."""
        return VAULT_OPERATION_FAMILIES

    # ── C-02: Governance layers ───────────────────────────────────────────

    def collect_governance_layers(
        self, op_family: OperationFamily
    ) -> list[GovernanceLayer]:
        """Return the governance layers declared for this operation family. GCG C-02."""
        return [
            VAULT_GOVERNANCE_LAYERS[name]
            for name in op_family.declared_layers
            if name in VAULT_GOVERNANCE_LAYERS
        ]

    # ── C-03: Execution instances ─────────────────────────────────────────

    def collect_executions(
        self, op_family: OperationFamily
    ) -> list[ExecutionInstance]:
        """
        Extract execution instances for an operation family from audit log.
        GCG C-03.
        """
        self.load()
        instances = []

        for entry in self._entries:
            req  = entry.get("request", {})
            auth = entry.get("auth", {}) or {}
            resp = entry.get("response", {}) or {}

            path      = req.get("path", "")
            operation = req.get("operation", "")

            # Root token check (bypass classifier)
            is_root = (auth.get("token_type") == "service" and
                       "root" in (auth.get("policies") or []))

            # Match operation family
            if op_family.name == "root_token_operation":
                if not is_root:
                    continue
            elif not re.match(op_family.vault_path_pattern, path):
                continue
            elif is_root and op_family.name != "root_token_operation":
                # Root token ops: only classify as root_token_operation
                continue

            # Filter by operation type for read/write families
            if op_family.name == "secret_read" and operation not in ("read",):
                continue
            if op_family.name == "secret_write" and operation not in ("create", "update", "patch"):
                continue

            granting = []
            pr = auth.get("policy_results") or {}
            if isinstance(pr, dict):
                granting = pr.get("granting_policies") or []
                if isinstance(granting, list):
                    granting = [
                        (p.get("name") if isinstance(p, dict) else p)
                        for p in granting
                    ]

            instances.append(ExecutionInstance(
                operation_family=op_family.name,
                timestamp=entry.get("time", ""),
                request_id=req.get("id", ""),
                request_path=path,
                request_operation=operation,
                token_type=auth.get("token_type", ""),
                token_policies=auth.get("policies") or [],
                granting_policies=[p for p in granting if p],
                auth_type=auth.get("display_name", ""),
                response_code=resp.get("data", {}).get("http_status_code") if resp else None,
                raw=entry,
            ))

        return instances

    # ── EAR state assessment ──────────────────────────────────────────────

    def assess_ear_state(self, op_family: OperationFamily) -> EARState:
        """
        Assess EAR state for an operation family. T1573.

        ACTIVE:       audit device enabled AND operations in this family
                      produce audit entries with policy evaluation receipts
        CRYSTALLIZED: audit device enabled but policy evaluation receipt
                      absent for some instances, OR audit device exists
                      in architecture but not confirmed enabled
        ABSENT:       no audit device, no policy evaluation receipt surface
        """
        # Structural check: is audit device enabled?
        if self._audit_device_enabled is False:
            return EARState.CRYSTALLIZED  # mechanism known, not activated

        self.load()

        if op_family.name == "root_token_operation":
            # Root token bypasses policy evaluation — always ABSENT for that layer
            return EARState.ABSENT

        if op_family.name == "auth_login":
            # Pre-auth: no token_auth or policy_evaluation yet
            # Only audit device layer applies — CRYSTALLIZED unless audit confirmed
            if self._audit_device_enabled is True and len(self._entries) > 0:
                return EARState.CRYSTALLIZED  # audit records login but no policy receipt
            return EARState.CRYSTALLIZED

        instances = self.collect_executions(op_family)
        if not instances:
            # No executions observed — cannot confirm ACTIVE; fallback to CRYSTALLIZED
            # if audit device known enabled, else ABSENT
            if self._audit_device_enabled is True:
                return EARState.CRYSTALLIZED
            return EARState.ABSENT

        # Check if any instances have granting_policies (policy evaluation receipt)
        receipted = [i for i in instances if i.granting_policies]
        unreceipted = [i for i in instances if not i.granting_policies]

        if len(receipted) == len(instances):
            # All instances have policy evaluation receipts
            return EARState.ACTIVE
        elif len(receipted) > 0:
            # Some have receipts — CRYSTALLIZED (partial)
            return EARState.CRYSTALLIZED
        else:
            # No policy receipts found
            return EARState.ABSENT

    # ── Governance declaration ────────────────────────────────────────────

    def get_governance_declaration(self) -> GovernanceDeclaration:
        """Return the governance declaration for N-determination. GCG C-04."""
        return self.GOVERNANCE_DECLARATION

    # ── Summary ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return a summary of the adapter's view of the Vault deployment."""
        self.load()
        families = self.collect_operation_families()
        return {
            "total_audit_entries":   len(self._entries),
            "audit_device_enabled":  self._audit_device_enabled,
            "operation_families":    [f.name for f in families],
            "ear_states": {
                f.name: self.assess_ear_state(f).value
                for f in families
            },
            "governance_declaration": {
                "source":   self.GOVERNANCE_DECLARATION.source,
                "strategy": self.GOVERNANCE_DECLARATION.strategy,
            },
        }
