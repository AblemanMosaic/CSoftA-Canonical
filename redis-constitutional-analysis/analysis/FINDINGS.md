# FINDINGS: Redis Constitutional Analysis
*Wave 7 — System 34 · EAR ceiling: CRYSTALLIZED · Default: ABSENT · Fingerprint: `8cee438b696c3e4e`*

## Executive Finding
Redis is the corpus's in-memory data store governance case. No authentication by default, no audit log, no TLS, and two CVSS 10.0 vulnerabilities in the Lua scripting engine that is enabled by default. 57% of cloud environments have Redis deployed; 60,000 internet-exposed instances have no authentication configured (Wiz Research, October 2025). Redis is the corpus's clearest confirmation that the default configuration gap produces measurable, large-scale harm.

The constitutional significance of Lua scripting: Redis supports Lua scripting via EVAL and EVALSHA, enabled by default. CVE-2022-0543 (CVSS 10.0) and CVE-2025-49844 (CVSS 10.0, RediShell) are both Lua sandbox escape vulnerabilities that achieve host-level RCE. A feature enabled by default contains two separate CVSS 10.0 vulnerabilities. An unauthenticated Redis instance with default Lua scripting enabled is trivially exploitable for host compromise.

## Default Authentication Gap
Pre-Redis 6: no authentication at all (requirepass directive is empty by default). Redis 6+: ACL system introduced, but requirepass remains empty by default in many distributions and deployment configurations. Protected mode blocks cross-network unauthenticated access when no bind address is configured, but any explicit bind configuration disables protected mode. The ABSENT classification is confirmed by 60,000 internet-exposed unauthenticated instances.

## Real-World Incident Mapping
CVE-2025-49844 (RediShell, CVSS 10.0, October 2025, Wiz Research): use-after-free in Redis Lua scripting engine, achieves host-level RCE. Exists in all Redis versions since 2012. 330,000+ Redis instances exposed on internet; 60,000 without authentication. The vulnerable code path was introduced over 13 years before discovery — ABSENT authentication governance means this vulnerability was exploitable by anyone who could reach the Redis port.

CVE-2022-0543 (CVSS 10.0, Lua sandbox escape): previously exploited by the P2PInfect worm targeting Redis instances on both Windows and Linux. Palo Alto Unit 42 described it as "highly potent." The worm spread through unauthenticated Redis instances and installed cryptomining software. The P2PInfect campaign confirmed that ABSENT authentication enables worm propagation at scale.

## The Add-On: `redis-constitutional-enforcer`
Authentication enforcement gate and Lua restriction tool. Validates requirepass set or ACL configured; enforces TLS for client connections; restricts EVAL/EVALSHA to ACL-permitted users; configures bind to private interface only; produces `redis_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| data_read | ABSENT (default) / CRYSTALLIZED | No auth, no audit log by default |
| data_write | ABSENT (default) / CRYSTALLIZED | Two CVSS 10.0 Lua vulns in default config |
| lua_execution | ABSENT (default) / CRYSTALLIZED | Default-enabled feature with CVSS 10.0 vulns |
| admin_command | ABSENT (default) / CRYSTALLIZED | CONFIG/DEBUG unrestricted without ACL |
| pubsub_operation | ABSENT (default) / CRYSTALLIZED | No channel access control by default |
