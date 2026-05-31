# FINDINGS: MongoDB Constitutional Analysis
*Wave 12 — System 56 · document_write (Enterprise Audit): ACTIVE · Default: ABSENT · Fingerprint: `5640fc726ccdeb0b`*

## Executive Finding
MongoDB confirms the default ABSENT pattern for document databases and extends the commercial governance paywalling concept introduced by MySQL (Wave 11, System 55): MongoDB Enterprise Audit — which provides ACTIVE structured governance for document operations — requires a commercial license. MongoDB Community Edition defaults to ABSENT structured audit. Unlike PostgreSQL where pgaudit is open-source, both MongoDB and MySQL gate their ACTIVE governance path behind commercial licensing.

CVE-2025-14847 "MongoBleed" (December 2025, actively exploited within 3 days of PoC release): unauthenticated memory leak via malformed zlib-compressed wire protocol messages. 87,000+ vulnerable servers worldwide. No authentication required. Attackers could extract cleartext credentials, authentication tokens, and sensitive data directly from server heap memory. This is distinct from the standard ABSENT default governance gap — it is a protocol-layer vulnerability that bypasses the authentication layer entirely, extracting governance evidence (credentials, tokens) directly from memory.

## New Constitutional Finding: Protocol-Layer Bypass
MongoBleed represents a gap form not previously expressed at this layer: the network wire protocol itself becomes an extraction surface when compression is enabled. The attack does not bypass governance policies — it extracts data from the server's memory before governance is evaluated. This is structurally upstream of all authentication, RBAC, and audit governance.

## Real-World Incidents
CVE-2025-14847 actively exploited starting December 29, 2025: Rapid7 confirmed fully functional PoC; widespread scanning via Shodan-discovered instances. Affected versions spanning MongoDB 4.4 through 8.2. Community edition deployments with default configurations (auth disabled until 7.x in some configurations) combined with MongoBleed created zero-authentication memory extraction. Historic MongoDB default-open exposure: the corpus of publicly accessible MongoDB instances from 2015–2024 constitutes the largest documented ABSENT default governance pattern in enterprise databases — millions of records exposed across healthcare, finance, and government.

## The Add-On: `mongodb-governance-enforcer`
Authentication enforcer and Enterprise Audit validator. Validates auth enabled; validates TLS on all connections; validates RBAC roles follow least-privilege; detects MongoBleed-class configurations (zlib with unauthenticated access); produces `mongodb_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| document_write | **ACTIVE** (Enterprise) / ABSENT (Community) | Commercial governance paywall |
| document_read | **ACTIVE** (Enterprise) / ABSENT (Community) | Same paywall |
| collection_management | **ACTIVE** (Enterprise) / ABSENT (Community) | DDL ungoverned in CE |
| change_stream | CRYSTALLIZED | Oplog-backed; requires Enterprise for audit use |
| user_management | **ACTIVE** (Enterprise) / ABSENT (Community) | Privilege changes ungoverned in CE |
