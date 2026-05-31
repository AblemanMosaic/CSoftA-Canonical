# FINDINGS: cert-manager ACME Constitutional Analysis
*Wave 10 — System 47 · cert_issuance: ACTIVE · cert_renewal: ACTIVE · Fingerprint: `be6105890fe8f56f`*

## Executive Finding
cert-manager ACME is the TLS certificate lifecycle governance case, extending the Wave 3 cert-manager analysis (T1662) to the ACME protocol integration with Let's Encrypt. Certificate issuance is ACTIVE: a valid TLS certificate is constitutive of HTTPS connections — an expired or revoked certificate prevents all client connections. Certificate renewal automation is also ACTIVE: cert-manager renews certificates before expiry without operator intervention, preventing service outages.

Certificate Transparency (CT) logs provide a CRYSTALLIZED public record: every TLS certificate issued for a domain is recorded in CT logs, making certificate misissuance detectable. CT monitoring is opt-in but provides the governance evidence for detecting unauthorized certificates for owned domains.

## DNS-01 Solver RBAC Gap
When using DNS-01 challenges for wildcard certificates, cert-manager needs write access to DNS records to complete the ACME challenge. The solver's cloud provider credentials (Route53, Cloudflare, etc.) must be scoped to the specific DNS zone — overly broad DNS zone permissions give cert-manager write access beyond what is needed for challenge completion. This is the same credential scope gap seen elsewhere in the corpus: the functional requirement (DNS write) is correctly scoped in principle but often granted too broadly in practice.

## Real-World Incident Mapping
Let's Encrypt certificate misissuance incidents (2017, 2020): Let's Encrypt issued certificates to incorrect domains due to CAA checking bugs. CT logs detected these within hours. The CT monitoring CRYSTALLIZED finding: misissuance is detectable, not preventable, via CT.

cert-manager certificate expiry outages: multiple production incidents where cert-manager's renewal process failed silently (DNS-01 solver credentials expired, webhook connectivity lost) causing certificates to expire. The ACTIVE renewal classification is conditional on cert-manager being healthy — a cert-manager outage converts ACTIVE to ABSENT for certificate lifecycle governance.

## The Add-On: `cert-manager-governance-enforcer`
CT monitoring, solver scope auditor, and renewal health monitor. Validates CT monitoring configured; validates DNS solver credentials scoped to specific zones; monitors cert-manager renewal health; alerts on certificates within 7 days of expiry; produces `certmgr_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| cert_issuance | **ACTIVE** | Certificate constitutive of TLS connection |
| cert_renewal | **ACTIVE** | Automated renewal prevents expiry |
| challenge_completion | CRYSTALLIZED | DNS-01 solver RBAC scope gap |
| cert_revocation | CRYSTALLIZED | CT logs detect misissuance post-hoc |
| account_governance | CRYSTALLIZED | ACME account key in K8s Secret |
