# FINDINGS: etcd Constitutional Analysis
*Wave 6 — System 27 · peer_authentication (mTLS): ACTIVE · key operations: ABSENT without mTLS · Fingerprint: `ae087f82bc081d32`*

## Executive Finding
etcd is the substrate-of-the-substrate. Every Kubernetes governance mechanism — RBAC policies, Secrets, admission controller configurations, ServiceAccount tokens — is stored in etcd. etcd's own governance surface is weaker than the Kubernetes governance layer built on top of it.

Peer and client authentication via mTLS is ACTIVE: a connection without a valid certificate cannot be established. This governs access to etcd. But encryption at rest is opt-in (EncryptionConfiguration), etcd has no native audit log, and — most critically — direct etcd access bypasses Kubernetes RBAC and admission controllers entirely. An attacker with direct etcd access can read every Secret in every namespace, modify RBAC policies, and alter any resource definition without any Kubernetes admission control intercepting the operation.

## The Substrate Bypass Finding
This is the constitutional inversion of the T019 substrate dependency pattern (Gatekeeper bounded by Kubernetes). Here: Kubernetes governance is bounded by etcd governance. Every Kubernetes security control depends on etcd storing its configuration correctly. A compromised etcd server — or etcd configured with weak authentication — collapses all Kubernetes governance above it.

Kubernetes Secrets are stored in etcd as base64-encoded plaintext by default. Without EncryptionConfiguration, a `etcdctl get /registry/secrets/default/my-secret` with etcd credentials reads the secret directly, bypassing all Kubernetes RBAC.

## Real-World Incident Mapping
Shodan scanning confirms thousands of etcd instances exposed to the public internet with no authentication — the default mTLS disabled state. Researchers have reported finding credentials, Kubernetes cluster configurations, and application secrets from publicly exposed etcd instances. The ABSENT classification for unauthenticated etcd directly maps to these exposures.

CVE-2023-32082 (etcd leaky comparison, CVSS 3.1): etcd did not perform a bounds check during lease lookup, allowing a partial comparison to succeed, potentially returning incorrect data. The constitutional finding: the peer_mtls layer was present but the data integrity of the returned value was insufficiently validated — NON_ACTIVATION at the data integrity boundary.

The 2019 etcd public exposure research (Potaroo/SySS): researchers scanned for publicly accessible etcd instances and found hundreds of clusters exposing Kubernetes secrets, including credentials for cloud providers, database passwords, and SSH keys. All from the ABSENT mTLS configuration gap.

## The Add-On: `etcd-constitutional-enforcer`
Validates etcd security configuration as prerequisite for Kubernetes cluster governance. Verifies mTLS enabled (--peer-client-cert-auth=true, --client-cert-auth=true); validates EncryptionConfiguration present for Secrets and ConfigMaps; checks etcd not bound to 0.0.0.0 without firewall; verifies backup encryption; produces `etcd_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| key_read | ABSENT / CRYSTALLIZED | No native audit log; ABSENT without mTLS |
| key_write | ABSENT / CRYSTALLIZED | Encryption at rest opt-in |
| peer_authentication | **ACTIVE** | mTLS constitutive of connection |
| snapshot_backup | CRYSTALLIZED | Backup encryption opt-in |
| member_management | ABSENT / CRYSTALLIZED | No audit log; ABSENT without mTLS |
