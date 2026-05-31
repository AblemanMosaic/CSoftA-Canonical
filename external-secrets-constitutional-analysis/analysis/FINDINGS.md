# FINDINGS: External Secrets Operator Constitutional Analysis
*Wave 3 — System 12 · EAR ceiling: CRYSTALLIZED · Fingerprint: `470814a27d6395e5`*

## Executive Finding
External Secrets Operator (ESO) is Wave 3's clearest CRYSTALLIZED case and introduces a new constitutional concept: upstream governance inheritance. When ESO syncs secrets from Vault, Vault's ACTIVE-EAR governs the fetch at the source. ESO's own governance of the sync operation is CRYSTALLIZED. The combined governance quality of an ESO deployment is the minimum of ESO's own EAR state and the upstream store's EAR state.

## The Upstream Governance Inheritance Finding
ESO's architecture makes it a governance relay: it authenticates to an external store, fetches secrets, and writes them to Kubernetes Secrets. The governance quality of the fetch is determined by the upstream store, not by ESO. Syncing from Vault means Vault's audit log is the constitutive receipt for the secret fetch. Syncing from a plaintext file means no receipt exists upstream. ESO's sync status records that a sync occurred but not what governance was applied to the fetch at the source.

## Primary Gap: Sync Status Non-Constitutivity
The ExternalSecret `.status.conditions` records sync outcomes but sync is not constitutive of the ExternalSecret resource. ESO may fail to write sync status under resource pressure without affecting the secret sync operation. The governance record is decoupled from the governance event — the same pattern as Kyverno's PolicyReport.

## Real-World Incident Mapping
ESO CVE-2024-45041: a path traversal vulnerability allowed users to access secrets outside their authorized namespace scope via crafted SecretStore references. The constitutional finding: store_auth was present and declared, but the scope boundary of the authorization was not enforced — the governance layer evaluated authentication but not authorization scope. This is the Gap form NON_ACTIVATION at the scope boundary layer.

## The Add-On: `eso-governance-monitor`

*T1663* — Complementary operator enforcing scope boundaries and monitoring sync freshness. Validates SecretStore namespace scope (CVE-2024-45041 class); monitors sync status freshness with configurable threshold; validates upstream store connectivity and detects upstream rotation/revocation since last sync; produces eso_posture.json including upstream store EAR state per T1613. Makes sync staleness a monitored governance property.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| secret_sync | CRYSTALLIZED | Sync status non-constitutive; upstream store governs fetch |
| store_authentication | CRYSTALLIZED | Auth receipt opt-in |
| secret_rotation | CRYSTALLIZED | Rotation detection not real-time |
| push_secret | CRYSTALLIZED | Push status non-constitutive |
