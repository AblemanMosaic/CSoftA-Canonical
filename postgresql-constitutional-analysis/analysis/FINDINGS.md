# FINDINGS: PostgreSQL Constitutional Analysis
*Wave 5 — System 23 · query_execution (pgaudit): ACTIVE · Default: ABSENT · Fingerprint: `b46ea1c6353462f1`*

## Executive Finding
PostgreSQL is the corpus's relational database case and introduces a governance property shared with Rust: the ACTIVE-EAR path requires an extension (pgaudit) rather than a core feature. When pgaudit is installed and configured, query execution is ACTIVE — queries cannot complete without being logged, and pgaudit is constitutive of query execution in the sense that it intercepts the query executor before results are returned. But pgaudit is an extension: it must be explicitly installed, added to `shared_preload_libraries`, and configured. Default PostgreSQL has ABSENT structured query governance.

Row-level security (RLS) is CRYSTALLIZED: policies are declared and enforced, but multiple CVEs demonstrate policy bypass via query planning — the policy evaluation logic has scope boundaries that are exploitable through cached query plans, optimizer statistics, and table inheritance.

## pgaudit as the Extension-ACTIVE Pattern
pgaudit's architectural position is constitutionally significant: it hooks into the PostgreSQL executor at the executor_run stage, before results are returned to the client. This makes it constitutive rather than post-hoc — the audit record is written during execution, not after. If pgaudit fails to write its log entry, it raises an error. This is the fail-closed pattern: governance failure prevents operation completion.

The constitutional gap: pgaudit is not in the default installation. An organization that installs PostgreSQL and begins using it without explicitly configuring pgaudit is running ABSENT governance for all query operations. There is no audit, no governance record, and nothing in the default installation that prevents this gap from existing indefinitely.

## Real-World Incident Mapping
CVE-2025-1094 (SQL injection → RCE, exploited in BeyondTrust/US Treasury breach, January 2025): a SQL injection flaw in PostgreSQL's `COPY TO PROGRAM` feature allowed unauthenticated remote code execution. The flaw was chained with CVE-2024-12356 (BeyondTrust zero-day) to compromise BeyondTrust's Remote Support SaaS and subsequently the US Treasury Department's workstations. The constitutional finding: the query execution governance layer (pgaudit) would have recorded the malicious query — but pgaudit was not present to be exploited. The ABSENT governance gap means the malicious query execution left no structured receipt. Post-incident reconstruction required correlating PostgreSQL logs (unstructured) with BeyondTrust application logs and network forensics.

CVE-2023-2455 (RLS cached plan bypass): row-level security policies were not applied correctly when a query plan was cached under one role and reused under a different role. The `rls_policy` layer was declared and appeared active, but the policy evaluation was bypassed by the query planner's caching behavior. NON_ACTIVATION at the policy evaluation reuse boundary.

CVE-2025-8713 (August 2025, optimizer statistics leakage, PostgreSQL 13-17): PostgreSQL optimizer statistics allowed a user to craft a leaky operator that bypassed view ACLs and row security policies in partitioning and table inheritance hierarchies, exposing histograms and most-common-values lists. This is the third time this vulnerability class has appeared — CVE-2017-7484 and CVE-2019-10130 both intended to close it. The constitutional finding: rls_policy was declared and evaluated, but the statistics pathway was outside the RLS enforcement boundary — a structural bypass through a data pathway the policy system did not govern. Fixed in PostgreSQL 17.6/16.10/15.14/14.19/13.22. CVE-2025-8714 (August 2025, pg_dump arbitrary code execution via untrusted data, CVSS 8.8): malicious superusers on origin servers could inject psql meta-commands into pg_dump output, executing as the OS account performing restoration. The backup/restore pathway was outside the normal query governance scope — NON_ACTIVATION at the backup execution boundary.

## The Add-On: `postgresql-constitutional-gate`
pgaudit deployment enforcer and RLS validation tool. Validates pgaudit is installed and configured before declaring a PostgreSQL cluster production-ready; enforces `shared_preload_libraries` includes pgaudit; validates pgaudit logging class covers DDL, DML, and role changes; monitors for RLS policy bypass patterns (cached plan reuse across roles); produces `pg_posture.json` with per-database governance assessment.

## Summary
| Family | EAR State (pgaudit) | EAR State (default) |
|--------|---------------------|---------------------|
| query_execution | **ACTIVE** | ABSENT |
| ddl_operation | **ACTIVE** | ABSENT |
| role_management | **ACTIVE** | ABSENT |
| connection_establishment | CRYSTALLIZED | CRYSTALLIZED |
| rls_enforcement | CRYSTALLIZED | CRYSTALLIZED |
