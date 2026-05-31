# FINDINGS: Helm Constitutional Analysis
*Wave 7 — System 35 · EAR ceiling: CRYSTALLIZED · chart_pull (default): ABSENT · Fingerprint: `77e8b9f8025abca0`*

## Executive Finding
Helm is the Kubernetes deployment packaging governance case. Helm packages (charts) deploy arbitrary Kubernetes resources with the deploying principal's RBAC permissions. Chart provenance verification is opt-in and rarely used in practice. The Helm release record (stored as a Kubernetes Secret) provides a CRYSTALLIZED audit trail of deployments. No Helm family reaches ACTIVE.

The supply chain gap is the constitutional finding: Helm chart repositories can be compromised, chart maintainers' credentials can be stolen, and malicious charts can be published without any structural mechanism to prevent deployment. Organizations that do not verify chart provenance are executing arbitrary code from external repositories with cluster-wide permissions.

## Helm Values Governance Gap
Helm values frequently contain sensitive credentials: database passwords, API keys, TLS certificates. By default, these are stored in Kubernetes Secrets as base64-encoded values. The Helm `--dry-run` output may print sensitive values in plain text (CVE-2019-25210). Helm hooks execute with the deploying principal's ServiceAccount permissions, which may be cluster-admin in many environments.

## Real-World Incident Mapping
SUSE Fleet CVE-2024-52284: Helm chart values containing sensitive credentials were stored inside BundleDeployment resources in plain text, exposing them to any user with GET or LIST permissions on BundleDeployment resources. The values_governance layer was ABSENT — credentials in Helm values without encryption were visible to any cluster user with the right RBAC permissions.

CVE-2024-25620 (Helm path traversal, CVSS 6.4): a chart with a relative path in Chart.yaml's name field could be saved outside its expected directory. Chart name validation was insufficient — the same annotation content validation gap class as ingress-nginx (CVE-2023-5044 analog: insufficient input validation in the chart processing path).

CVE-2019-25210 (--dry-run secret disclosure): the `--dry-run` flag displayed Helm values of secrets in output, potentially exposing sensitive credentials in CI/CD logs. Confirmed by researchers who scanned public CI/CD logs and found Helm-deployed credentials.

Malicious Helm chart supply chain: chart repositories have been discovered hosting malicious charts designed to deploy cryptominers, exfiltrate credentials, or establish persistence. Organizations using chart repositories without provenance verification are exposed to this attack class.

## The Add-On: `helm-governance-enforcer`
Chart provenance gate and values security enforcer. Requires Cosign chart signature verification before install; validates no sensitive values in Helm values (should use external-secrets); enforces hook RBAC least-privilege; monitors release history for unauthorized changes; produces `helm_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| chart_install | CRYSTALLIZED | Release record exists; provenance opt-in |
| chart_upgrade | CRYSTALLIZED | Upgrade history in K8s Secrets |
| hook_execution | CRYSTALLIZED | Hooks run with deployer's RBAC permissions |
| chart_pull | ABSENT (default) | No provenance verification by default |
| secret_management | CRYSTALLIZED | Values stored in K8s Secrets; plaintext risk |
