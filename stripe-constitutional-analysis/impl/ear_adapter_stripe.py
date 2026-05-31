"""
ear_adapter_stripe.py — Stripe API EAR Adapter
Wave 4 — System 17. Financial transaction platform.

Key finding: Stripe is the corpus's strongest ACTIVE-EAR system for
financial operations. Every charge, payment_intent, refund, and webhook
produces a mandatory Event object that cannot be suppressed by the API caller.
The Event IS the receipt — it is immutable, assigned by Stripe, and not
deletable by the API caller. This is the most complete implementation
of the credential-as-receipt pattern in the corpus: the receipt is
issued by a party (Stripe) that is independent of the transaction parties.
PCI-DSS compliance mandates this receipt architecture — Stripe's ACTIVE
status is constitutionally required by its regulatory environment.
Webhook delivery has gaps: webhook events may fail delivery (CRYSTALLIZED).
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
    name: str; description: str; declared_layers: list[str]; stripe_scope: str

@dataclass
class GovernanceLayer:
    name: str; description: str; evidence_field: str | None=None; is_optional: bool=False

@dataclass
class ExecutionInstance:
    operation_family: str; request_id: str; timestamp: str
    event_created: bool; idempotency_key_used: bool
    webhook_delivered: bool; pci_logged: bool
    amount: int; currency: str
    status: str | None; error: str | None; raw: dict=field(default_factory=dict)

@dataclass
class GovernanceDeclaration:
    source: str; strategy: str; description: str

STRIPE_OPERATION_FAMILIES = [
    OperationFamily("charge_creation",
        "Create a charge or payment_intent",
        ["stripe_event","idempotency_key","payment_receipt","pci_log"], "charge"),
    OperationFamily("refund_creation",
        "Issue a refund on a charge",
        ["stripe_event","idempotency_key","refund_receipt","pci_log"], "refund"),
    OperationFamily("webhook_delivery",
        "Deliver event notification to merchant endpoint",
        ["stripe_event","webhook_signature","delivery_log"], "webhook"),
    OperationFamily("dispute_resolution",
        "Process chargeback or dispute",
        ["stripe_event","dispute_evidence","pci_log"], "dispute"),
    OperationFamily("api_key_operation",
        "Create/revoke API key or restricted key",
        ["stripe_event","audit_log"], "key"),
]

STRIPE_GOVERNANCE_LAYERS = {
    "stripe_event": GovernanceLayer("stripe_event",
        "Stripe Event object — immutable, mandatory, not deletable by caller",
        "id"),
    "idempotency_key": GovernanceLayer("idempotency_key",
        "Idempotency key preventing duplicate charge creation",
        "Idempotency-Key", is_optional=True),
    "payment_receipt": GovernanceLayer("payment_receipt",
        "Payment confirmation receipt with charge ID and amount", "charge.id"),
    "pci_log": GovernanceLayer("pci_log",
        "PCI-DSS mandated transaction log", "created"),
    "refund_receipt": GovernanceLayer("refund_receipt",
        "Refund confirmation with original charge reference", "refund.id"),
    "webhook_signature": GovernanceLayer("webhook_signature",
        "Stripe-Signature header for webhook authenticity verification",
        "Stripe-Signature"),
    "delivery_log": GovernanceLayer("delivery_log",
        "Webhook delivery attempt log", "pending_webhooks"),
    "dispute_evidence": GovernanceLayer("dispute_evidence",
        "Dispute evidence submission record", "dispute.id"),
    "audit_log": GovernanceLayer("audit_log",
        "Stripe Dashboard audit log for API key operations", None),
}

class StripeAPIEARAdapter:
    GOVERNANCE_DECLARATION = GovernanceDeclaration(
        source=(
            "Stripe API Documentation + Stripe Events documentation + "
            "PCI DSS v4.0 Requirements + Stripe Security Whitepaper"
        ),
        strategy="DECLARED-N",
        description=(
            "N(O) from Stripe API architecture. charge_creation N=4. "
            "ACTIVE across all transaction families: Stripe Event object is "
            "mandatory, immutable, and not deletable by the API caller. "
            "The Event IS the governance receipt — issued by Stripe independently "
            "of the transaction parties. PCI-DSS compliance requires this architecture. "
            "Strongest ACTIVE case in the corpus: receipt independence from caller. "
            "Webhook delivery: CRYSTALLIZED — delivery may fail, retry logic exists "
            "but delivery is not constitutive of charge creation. "
            "Idempotency key: not mandatory but strongly recommended — "
            "absence creates gap for duplicate charge scenarios."
        ),
    )

    def __init__(self, idempotency_keys_used: bool=True,
                 webhook_configured: bool=True):
        self._idempotency = idempotency_keys_used
        self._webhook = webhook_configured

    def collect_operation_families(self): return STRIPE_OPERATION_FAMILIES
    def collect_governance_layers(self, op_family):
        return [STRIPE_GOVERNANCE_LAYERS[n] for n in op_family.declared_layers
                if n in STRIPE_GOVERNANCE_LAYERS]
    def collect_executions(self, op_family):
        return [ExecutionInstance(
            operation_family=op_family.name,
            request_id=f"synthetic:{op_family.name}", timestamp="",
            event_created=True,
            idempotency_key_used=self._idempotency,
            webhook_delivered=self._webhook,
            pci_logged=True,
            amount=1000, currency="usd",
            status="succeeded", error=None, raw={},
        )]

    def assess_k(self, inst):
        k = []
        fam = next((f for f in STRIPE_OPERATION_FAMILIES if f.name==inst.operation_family), None)
        if not fam: return k
        if "stripe_event" in fam.declared_layers and inst.event_created:
            k.append("stripe_event")
        if "idempotency_key" in fam.declared_layers and inst.idempotency_key_used:
            k.append("idempotency_key")
        if "payment_receipt" in fam.declared_layers and inst.event_created:
            k.append("payment_receipt")
        if "pci_log" in fam.declared_layers and inst.pci_logged:
            k.append("pci_log")
        if "refund_receipt" in fam.declared_layers and inst.event_created:
            k.append("refund_receipt")
        if "webhook_signature" in fam.declared_layers and self._webhook:
            k.append("webhook_signature")
        if "delivery_log" in fam.declared_layers and self._webhook:
            k.append("delivery_log")
        if "dispute_evidence" in fam.declared_layers:
            k.append("dispute_evidence")
        if "audit_log" in fam.declared_layers:
            k.append("audit_log")
        return k

    def assess_ear_state(self, op_family):
        # All transaction families: ACTIVE — Event is mandatory and immutable
        if op_family.name in ("charge_creation","refund_creation",
                              "dispute_resolution","api_key_operation"):
            return EARState.ACTIVE
        # Webhook delivery: CRYSTALLIZED — delivery may fail
        if op_family.name == "webhook_delivery":
            return EARState.CRYSTALLIZED if self._webhook else EARState.ABSENT
        return EARState.CRYSTALLIZED

    def get_governance_declaration(self): return self.GOVERNANCE_DECLARATION
