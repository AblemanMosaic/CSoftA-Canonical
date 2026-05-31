# FINDINGS: MySQL / MariaDB Constitutional Analysis
*Wave 11 — System 55 · query_execution (Enterprise Audit): ACTIVE · OSS default: ABSENT · Fingerprint: `469d8705994d8200`*

## Executive Finding
MySQL confirms the PostgreSQL pattern (Wave 5, T1670) with one critical constitutional addition: the ACTIVE governance path is paywalled. PostgreSQL + pgaudit achieves ACTIVE query governance via an open-source extension. MySQL Enterprise Audit — which provides ACTIVE structured query governance — is only available in MySQL Enterprise Edition (commercial license). MySQL Community Edition, the dominant deployment form globally, has only `general_log` (high performance impact, not structured, not default) or no query audit at all. The governance gap is not merely a configuration choice — it is a purchasing decision.

This introduces a new constitutional concept: commercial governance paywalling — the ACTIVE governance architecture exists and is technically available, but is gated behind a commercial license rather than configuration.

## Commercial Governance Paywalling: A New Constitutional Concept
The previous corpus contains two ACTIVE-via-extension cases: PostgreSQL (pgaudit, open-source) and Rust (borrow checker, built-in). MySQL adds a third case: ACTIVE-via-commercial-license. The constitutional implication is different from both: organizations that deploy MySQL Community Edition for cost reasons may genuinely have no ACTIVE query governance path available without changing their software procurement. The governance gap is real, documented, and architecturally locked behind a paywall.

This is the only system in the corpus where ACTIVE governance requires spending money on a different license. It has direct regulatory implications: compliance frameworks that require audit logging of database queries (PCI DSS, SOX, HIPAA) may be met on paper with general_log while the query audit is CRYSTALLIZED at best — or may require expensive Enterprise licensing to achieve the ACTIVE governance those frameworks implicitly expect.

## Real-World Incidents
CVE-2026-3494 (MariaDB server audit plugin / Aurora MySQL, March 2026): SQL statements prefixed with `--` or `#` comments bypass the server_audit_events filter when DDL/DML/DCL filtering is configured. The audit plugin is present and configured; the SQL parser that drives the filter has a comment-handling gap that allows any filtered statement to evade logging by prepending a comment. NON_ACTIVATION at the audit filter parsing boundary — same evasion class as CloudTrail log padding (T1727) but at the database audit layer. Affects Aurora MySQL 2.x, 3.x, and 8.4.x — deployed at AWS scale. CVE-2025-21540: Oracle MySQL Server auth bypass — low-privileged attacker with network access can compromise MySQL Server.

## The Add-On: `mysql-governance-enforcer`
Audit configuration validator and query governance enforcer. Validates Enterprise Audit configured if EE deployment; validates general_log enabled as fallback for CE deployments; validates TLS required for all connections; validates comment-evasion mitigation (CVE-2026-3494 class); produces `mysql_posture.json` with governance tier assessment.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| query_execution | **ACTIVE** (EE only) / ABSENT (CE default) | Commercial paywall on ACTIVE governance |
| ddl_operation | **ACTIVE** (EE only) / ABSENT (CE default) | Same paywall applies |
| privilege_grant | **ACTIVE** (EE only) / ABSENT (CE default) | Privilege changes ungoverned in CE |
| connection_establishment | CRYSTALLIZED | Auth evaluated; TLS opt-in |
| stored_procedure_exec | **ACTIVE** (EE only) / ABSENT (CE default) | Procedure execution ungoverned in CE |
