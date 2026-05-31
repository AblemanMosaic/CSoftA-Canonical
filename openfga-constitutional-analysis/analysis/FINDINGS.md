# FINDINGS: OpenFGA / Zanzibar Constitutional Analysis
*Wave 12 — System 60 · EAR ceiling: CRYSTALLIZED · Fingerprint: `489ef9f8b9fb468b`*

## Executive Finding
OpenFGA implements the Google Zanzibar relationship-based access control (ReBAC) model — the authorization paradigm distinct from all existing corpus systems. K8s RBAC (T1742) assigns permissions to roles; OPA (T1762) evaluates declarative policies; OpenFGA derives permissions from relationship graphs (user:alice is member of group:eng; group:eng has viewer on document:x). The authorization architecture is fundamentally different from both.

The governance receipt for an OpenFGA authorization check is the check API response (allowed/denied) — CRYSTALLIZED when audit logging is configured. But the primary constitutional surface is not the check itself: it is the tuple store — the data structure that encodes relationships from which permissions are derived. Who can write tuples is the governance question. If tuple write is ABSENT governance, the entire authorization model is undermined regardless of how well the check API is governed.

## Relationship Tuple Store as Governance Surface: A New Constitutional Concept
Previous authorization systems in the corpus have governance surfaces over policies (OPA), roles (RBAC), or tokens (SPIFFE). OpenFGA introduces a new governance surface: the relationship data that determines permissions. A tuple written to OpenFGA saying "user:attacker is admin of organization:acme" grants admin access — not via policy misconfiguration, but via a data write. Governing tuple writes is therefore the primary governance requirement for ReBAC systems.

Authorization model versioning: OpenFGA authorization models are immutable once written — each model has an authorization_model_id that cannot be modified. This is ACTIVE in a narrow sense: the model receipt (the model ID) is constitutively bound to the authorization decisions it governs. You cannot retroactively change what a model_id means.

## Real-World Incidents
OpenFGA is relatively new (CNCF sandbox 2022, incubating 2023) with limited public CVE history. The primary documented governance gaps are in enterprise deployments: tuple write governance absent in early integrations, allowing application bugs to escalate privileges via incorrect tuple writes. The Google Zanzibar paper (2019) documents the lessons from governing a relationship store at Google scale — tuple write governance, consistency model selection, and audit trail completeness are the production governance lessons.

## The Add-On: `openfga-governance-enforcer`
Tuple write governance enforcer and model audit tool. Validates authentication required for all API operations; validates tuple write operations logged; validates model versioning in use; validates tuple write authorizations follow least-privilege; produces `openfga_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| authorization_check | CRYSTALLIZED | Check receipt exists; audit log opt-in |
| tuple_write | CRYSTALLIZED | Primary governance surface; audit opt-in |
| tuple_read | CRYSTALLIZED | Read access to relationship data |
| model_management | CRYSTALLIZED | Model immutable (ACTIVE receipt for model ID) |
| store_governance | CRYSTALLIZED | Store-level RBAC for multi-tenancy |
