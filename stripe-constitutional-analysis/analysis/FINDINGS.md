# FINDINGS: Stripe API Constitutional Analysis
*Wave 4 — System 17 · All transaction families: ACTIVE · webhook_delivery: CRYSTALLIZED · Fingerprint: `96b1e45d66e84c35`*

## Executive Finding
Stripe is the corpus's strongest ACTIVE-EAR system and introduces a new constitutional property not seen in any previous system: receipt independence from the caller. Every Stripe charge, refund, dispute, and API key operation produces a mandatory Event object that the API caller cannot suppress, modify, or delete. The Event is issued by Stripe — a party independent of both the merchant and the customer. The receipt is governed by a third party, not by the principal performing the operation.

This is constitutionally more robust than Vault's audit log (which can be disabled by a sufficiently privileged operator) and more robust than SPIFFE/SPIRE SVIDs (which are controlled by the SPIRE Server, itself part of the governed infrastructure). Stripe's Event objects are governed by Stripe as a platform — an entity whose interests are structurally aligned with maintaining the integrity of the receipt.

## PCI-DSS as Constitutional Mandate
Stripe's ACTIVE classification is not incidental — it is required by regulatory environment. PCI-DSS mandates audit trails for all cardholder data operations. The Event architecture is the structural implementation of PCI-DSS Requirement 10 (track and monitor all access). This is the corpus's first example of regulatory mandate driving ACTIVE-EAR status.

## Primary Gap: Idempotency Keys Not Mandatory
Idempotency keys prevent duplicate charge creation — a caller who sends the same charge request twice with an idempotency key gets one charge; without it, they may get two. The key is strongly recommended but not required. A merchant who does not use idempotency keys has a governance gap: duplicate charges may occur with no structural prevention, only after-the-fact detection from the Event log.

## Webhook Delivery Gap
Webhooks are CRYSTALLIZED: Stripe generates Events and attempts delivery to the merchant's endpoint, but delivery may fail. The Event exists regardless of webhook delivery success, but the merchant's own systems may not receive the notification. The governance record (Stripe Event) is complete; the merchant's reaction to governance events is CRYSTALLIZED.

## Real-World Incident Mapping
Stripe API misuse (various): fraudulent charges using stolen card details produce Stripe Events — the Event is the constitutive record that fraud investigations use. The ACTIVE classification means every fraudulent transaction is receipted regardless of whether the attacker wants it to be. This is the constitutional value of receipt independence: the fraudulent actor cannot suppress the receipt.

Webhook signature verification bypass: merchants who do not validate the Stripe-Signature header on webhook events accept potentially forged webhook deliveries. This is the NON_ACTIVATION form for webhook_signature — the layer is declared and available but not evaluated by the recipient.

## The Add-On: `stripe-governance-enforcer`

A merchant-side SDK wrapper and webhook validator enforcing constitutional completeness for Stripe integrations. (1) Wraps the Stripe API client to require idempotency keys on all charge and refund calls — raises `MissingIdempotencyKeyError` rather than allowing non-idempotent requests. (2) Implements constitutive webhook signature verification — events rejected before reaching business logic if `Stripe-Signature` absent or invalid; timing-safe comparison enforced. (3) Maintains persistent Event log from the Stripe Events API, providing the queryable administrative audit trail the Dashboard UI lacks. (4) Reconciles merchant-side processed events against Stripe's Event list — detects delivery gaps. (5) Validates idempotency key uniqueness per operation type. Note: Stripe is the corpus's first merchant-side add-on — all previous add-ons are operator-side or platform-side, reflecting that Stripe's ACTIVE architecture means the gap is entirely on the merchant side.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| charge_creation | **ACTIVE** | Event mandatory, immutable, caller-independent |
| refund_creation | **ACTIVE** | Refund Event references original charge |
| dispute_resolution | **ACTIVE** | Dispute Event constitutive of chargeback |
| api_key_operation | **ACTIVE** | Key events in Dashboard audit log |
| webhook_delivery | CRYSTALLIZED | Delivery may fail; Event exists regardless |
