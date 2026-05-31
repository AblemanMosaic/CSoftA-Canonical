# FINDINGS: Weights & Biases (W&B) Constitutional Analysis
*Wave 15 — System 72 · EAR ceiling: CRYSTALLIZED · Fingerprint: `2ac122a96584c313`*

## Executive Finding
W&B introduces the most constitutionally novel finding of Wave 15: third-party governance custody. W&B, Comet, Neptune, and similar commercial ML tracking platforms are custody holders for organizational governance evidence — they store experiment metadata, model versions, run lineage, and deployment records externally to the organization.

The constitutional question is not whether W&B has good security controls (it does — RBAC, SSO, audit log for enterprise tier). The question is: what is the sovereignty model for governance evidence? If W&B has a service outage, organizational ML governance evidence is unavailable. If W&B changes terms of service, exports become subject to their policies. If W&B is acquired, the governance evidence custody transfers. These are constitutional properties of the third-party custody model that are independent of W&B's security posture.

Constitutional comparison to Certificate Transparency logs (T1779): CT logs are constitutively external — CAs must submit to them, browsers verify them, and no single organization controls them. W&B governance evidence is voluntarily external — the organization chooses this custody arrangement. CT logs are more constitutionally robust because the custody arrangement cannot be changed by either party; W&B custody can be changed by either party.

Audit log: enterprise tier only — commercial governance paywalling analog (T1784). Audit log availability for governance requires purchasing enterprise tier.

## The Add-On: `wandb-governance-enforcer`
Governance evidence sovereignty checker. Validates organizational data exportability configured; validates SSO/SAML configured; validates audit log enabled (enterprise tier); validates RBAC teams configured; produces `wandb_posture.json` with custody risk assessment.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| run_logging | CRYSTALLIZED | Auth + RBAC; external custody; audit enterprise-only |
| artifact_registry | CRYSTALLIZED | Lineage tracked; external custody |
| model_promotion | CRYSTALLIZED | Approval workflow enterprise-only |
| data_access | CRYSTALLIZED | RBAC governs; external custody |
| governance_export | CRYSTALLIZED | Export configurable; sovereignty opt-in |
