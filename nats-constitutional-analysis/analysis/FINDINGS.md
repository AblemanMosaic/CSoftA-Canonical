# FINDINGS: NATS Messaging Constitutional Analysis
*Wave 14 — System 66 · EAR ceiling: CRYSTALLIZED · Fingerprint: `0ecc36c4791e3bdb`*

## Executive Finding
NATS uses an Operator/Account/User JWT hierarchy for multi-tenant governance. The primary constitutional surface is account isolation: the guarantee that subjects published in Account A are not visible in Account B. The default NATS configuration ships with no authentication — any TCP client on port 4222 can publish and subscribe to any subject. The governance model is opt-in, not opt-out.

CVE-2025-30215 (April 2025): JetStream management APIs exposed a cross-account scope boundary — a user with JetStream admin rights in Account A could delete streams in Account B by sending requests to `$JS.API.STREAM.DELETE.<name>` because the management subject namespace was not fully scoped per account. This is NON_ACTIVATION at the account isolation scope boundary for JetStream management operations. Any user in any account could destroy JetStream assets in any other account in the same cluster.

CVE-2023-47090: when only the system account is configured with an explicit operator/account block, an implicit `$G` (global) user is created that provides unauthenticated access. NON_ACTIVATION at the configuration interpretation boundary — the administrator's intent (require authentication) was not matched by the system's behavior with that specific configuration.

## Account Isolation as Primary Governance Surface
NATS account isolation is the architectural abstraction that enables multi-tenant messaging without per-message encryption. When account isolation is complete, Account A subscribers cannot receive Account B publications even if they know the subject name. CVE-2025-30215 demonstrates that this isolation had a gap at the JetStream management plane — the data plane was isolated but the management plane was not fully scoped.

## The Add-On: `nats-governance-enforcer`
Account isolation validator and JetStream scope auditor. Validates JWT+NKey authentication configured; validates TLS on all connections; validates JetStream account scope restrictions; monitors for cross-account subject access patterns; produces `nats_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| message_publish | ABSENT (default) / CRYSTALLIZED (JWT+NKey) | Default: no auth, any TCP client |
| message_subscribe | ABSENT (default) / CRYSTALLIZED (JWT+NKey) | Same as publish |
| jetstream_management | CRYSTALLIZED | CVE-2025-30215 scope gap patched |
| jetstream_message | CRYSTALLIZED | Ack policy configurable; ABSENT for fire-and-forget |
| account_management | CRYSTALLIZED | Operator JWT governs account hierarchy |
