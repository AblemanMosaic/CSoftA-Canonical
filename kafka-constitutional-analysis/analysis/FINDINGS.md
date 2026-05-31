# FINDINGS: Apache Kafka Constitutional Analysis
*Wave 5 — System 21 · broker_auth (mTLS): ACTIVE · All data ops default: ABSENT · Fingerprint: `7ef198eee84b42bc`*

## Executive Finding
Apache Kafka is the corpus's largest governance gap relative to operational significance. Kafka processes trillions of messages per day in production deployments — and its default configuration has ABSENT governance for all data operations. ACLs are disabled by default (`allow.everyone.if.no.acl.found=true`). The audit log is not structured, not enabled by default, and not queryable as a governance artifact. A producer publishing a message to a topic in a default Kafka deployment produces no receipt binding that message to the publishing principal.

The single ACTIVE surface is broker mTLS authentication: when `ssl.client.auth=required`, the TLS handshake is constitutive of the broker connection — a client without a valid certificate cannot connect. This governs access to the broker. It does not govern what is produced or consumed once connected.

## Primary Gap: No Mandatory Produce/Consume Receipt
Kafka's offset mechanism (the producer offset, the consumer group commit) records where messages are in the log, not who produced or consumed them with what authorization. The offset receipt is a positional record, not a governance receipt. It cannot be used to reconstruct "which principal produced this message under which ACL."

## ACL Default Gap
The `allow.everyone.if.no.acl.found=true` default means Kafka permits all operations when no ACLs are configured. A new Kafka cluster with no ACL configuration is fully open. The gap is not that ACLs are misconfigured — it is that the secure configuration requires deliberate opt-in action, and the default is permissive.

## Real-World Incident Mapping
The Kafka default ABSENT gap is not theoretical — it is confirmed by a recurring pattern of named production breaches directly attributable to unauthenticated brokers.

Cartlow.com (January 2026, 3 million users): an open, unauthenticated Kafka broker streamed real-time internal messages including two-factor authentication codes, SMS notifications, and gift card redemption links. Personal data including names, phone numbers, email addresses, IP addresses, and MD5-hashed session tokens was exposed continuously. The constitutional finding: the broker was deployed with `allow.everyone.if.no.acl.found=true` (the default) — ABSENT governance for all produce/consume operations. Every message produced was constitutively ungoverned.

AI companion apps Chattee Chat and GiMe Chat (October 2025, 400,000+ users): an unprotected Kafka broker exposed 43 million private messages and 600,000 media files in real time, including purchase records and authentication tokens. The broker was indexed by internet search engines, making discovery trivial. ABSENT authentication and ABSENT ACLs — the default deployment state.

Huddle01 video call app (October 2025, 621,000+ log entries): Kafka broker left open without authentication or encryption, exposing crypto wallet addresses, session activity, and call participation data for the previous 13 days. ABSENT governance throughout.

These three incidents in a single six-month window share a single constitutional cause: the default Kafka configuration has `allow.everyone.if.no.acl.found=true`. Every organization that deployed Kafka without deliberate security configuration produced this outcome.

CVE-2024-31141 (Apache Kafka privilege escalation): ACL scope boundary insufficiently bounded for cluster-level operations — acl_authorization present, k < N, NON_ACTIVATION at cluster permission scope.

CVE-2025-27817/27818/27819 (SASL JNDI RCE chain): SASL JAAS configuration allowed JNDI lookups → remote code execution. An attacker with AlterConfigs permission could exploit this. ACL governance CRYSTALLIZED (permission evaluated) while the scope of the granted permission contained an exploitable execution surface. Patched in Kafka 3.4.0/3.9.1.

## The Add-On: `kafka-constitutional-enforcer`
A deployment gate and runtime monitor enforcing Kafka constitutional completeness. Validates ACL configuration (ABSENT assertion if `allow.everyone.if.no.acl.found=true`); enforces mTLS as required for all broker connections; wraps Kafka AdminClient to produce structured receipts for ACL changes; monitors producer/consumer operations against ACL declarations for undeclared access patterns; produces `kafka_posture.json` per cluster.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| produce | ABSENT (default) / CRYSTALLIZED (ACL+audit) | No mandatory produce receipt |
| consume | ABSENT (default) / CRYSTALLIZED (ACL+audit) | No mandatory consume receipt |
| topic_management | ABSENT (default) / CRYSTALLIZED | ACL opt-in |
| acl_management | ABSENT (default) / CRYSTALLIZED | No ACL change audit |
| broker_auth | **ACTIVE** (mTLS required) | TLS constitutive of connection |
