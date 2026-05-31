# FINDINGS: RabbitMQ Constitutional Analysis
*Wave 15 — System 75 · EAR ceiling: CRYSTALLIZED · Fingerprint: `380c0c3e76db24e5`*

## Executive Finding
RabbitMQ provides the constitutional comparison to Kafka (Wave 5, T1671) and NATS (Wave 14, T1812) for the message broker governance space. The vhost model is the primary isolation boundary: each virtual host has its own exchanges, queues, and bindings, and user permissions are granted per-user-per-vhost. This is structurally similar to Kafka's per-topic ACL model and NATS's account isolation model — all three have the same fundamental constitutional property: publish/subscribe authorization is CRYSTALLIZED (evaluated but not constitutive), and message content governance is ABSENT by default.

CVE-2025-50200 (June 2025) introduces the credential-in-audit-log pattern: basic authentication headers are logged in base64-encoded plaintext in RabbitMQ audit logs. This is the same constitutional form as Nomad CVE-2025-1296 (wave 15): the audit receipt contains the credential it should be protecting. Across two different systems in the same wave, we see the same gap form — the audit log as credential exposure surface.

The HTTP API queue deletion permission bypass (November 2024 advisory) is the direct analog of CVE-2024-6678 in GitLab CI (Wave 11): an API endpoint that should verify `configure` permission does not, allowing deletion of queues the user shouldn't be able to delete. NON_ACTIVATION at the HTTP API permission check boundary.

CVE-2022-37026 (Erlang/OTP CVSS 9.8): authentication bypass via Erlang TLS auth — a runtime dependency vulnerability that constitutes a BYPASS at the TLS authentication layer. RabbitMQ inherits Erlang/OTP CVEs because its runtime is Erlang.

## The Add-On: `rabbitmq-governance-enforcer`
vhost permission auditor and TLS configuration validator. Validates TLS on AMQP connections; validates per-vhost user permissions follow least-privilege; validates management UI credentials rotated; monitors for HTTP API permission anomalies; produces `rabbitmq_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| message_publish | CRYSTALLIZED | Auth + vhost isolation + permission check |
| message_consume | CRYSTALLIZED | Same as publish; message content ungoverned |
| queue_management | CRYSTALLIZED | CVE-2024-GHSA delete permission bypass class |
| vhost_management | CRYSTALLIZED | Management audit opt-in |
| shovel_federation | CRYSTALLIZED | Cross-broker credential governance opt-in |
