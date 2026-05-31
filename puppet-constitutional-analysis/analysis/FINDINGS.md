# FINDINGS: Puppet Configuration Management Constitutional Analysis
*Wave 16 — System 79 · EAR ceiling: CRYSTALLIZED · Fingerprint: `87094f8d62dce447`*

## Executive Finding
Puppet occupies a specific position in the IaC governance spectrum introduced earlier in the corpus. The full spectrum now runs: Ansible (stateless/ABSENT receipt, T1797) < Puppet (catalog/CRYSTALLIZED convergence receipt) < Terraform (state/ABSENT drift gap, T1671) < Pulumi (state + CrossGuard ACTIVE policy, T1808) < Crossplane (K8s-native/ACTIVE continuous reconciliation, T1726). Puppet is the first step above Ansible's ABSENT: the Puppet catalog produces a convergence report per node per run, providing a CRYSTALLIZED receipt for what changed on each node.

However, Puppet's RBAC is enterprise-only (same commercial governance paywalling pattern as MySQL T1784 and Nomad T1822). Community Puppet has no access control for who can request catalogs or modify node classifications. The catalog injection attack — where an attacker performs MITM on the Puppet Server and injects a malicious catalog — is mitigated by catalog signing (opt-in).

Puppet is increasingly legacy in the corpus era (Kubernetes/Terraform-native shops) but remains widely deployed for bare-metal and VM configuration management.

## The Add-On: `puppet-governance-enforcer`
Catalog signing enforcer and node classification auditor. Validates TLS client certificate auth configured; validates catalog signing enabled (prevents MITM injection); validates Puppet Enterprise RBAC if available; produces `puppet_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| catalog_compilation | CRYSTALLIZED | TLS client cert auth; RBAC enterprise-only |
| catalog_application | CRYSTALLIZED | Convergence report always produced (extends T1797) |
| hiera_lookup | CRYSTALLIZED | Secrets in Hiera; no mandatory encryption |
| node_classification | CRYSTALLIZED | RBAC enterprise paywall T1784 |
| code_deployment | CRYSTALLIZED | r10k/CD4PE; code signing opt-in |
