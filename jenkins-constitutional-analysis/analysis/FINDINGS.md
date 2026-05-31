# FINDINGS: Jenkins Constitutional Analysis
*Wave 12 — System 57 · EAR ceiling: CRYSTALLIZED · Fingerprint: `a54d8a0510e96c75`*

## Executive Finding
Jenkins is the most widely deployed self-hosted CI/CD system globally by installation count, and it introduces a constitutional concept not present in GitHub Actions (ephemeral cloud) or Tekton (K8s-native declarative): configuration drift as governance gap. Long-lived Jenkins installations accumulate governance degradation continuously — stale jobs accumulate unused credentials, plugins lag security patches, and RBAC configurations grow organically without review. The governance posture of a Jenkins instance deployed in 2019 is structurally different from one deployed today, even with identical initial configuration.

The credential scope gap is the most directly exploitable: global credentials in the Jenkins credential store are accessible to any user with Job/Execute permission, regardless of which job they're executing. This is the same principal scope boundary issue as Argo CD CVE-2025-55190 (T1674) applied to CI/CD credential access — a credential declared for one purpose is accessible to any principal with execute permission.

## Configuration Drift as Governance Gap
Jenkins accumulates governance debt over its operational lifetime. A new Jenkins instance with Matrix Authorization configured, Audit Trail enabled, and credentials properly scoped is CRYSTALLIZED. The same instance three years later, after multiple team changes, plugin updates, new jobs added, and credentials accumulated, may have ABSENT governance for specific operations if unchecked access patterns have developed. The governance gap is temporal as well as configurational — it grows over time.

This is a new constitutional property: most analyzed systems have static governance quality determined by configuration. Jenkins has dynamic governance quality that degrades over operational lifetime without active maintenance.

## Real-World Incidents
Codecov breach (2021): attacker modified a bash script distributed via CI/CD pipeline, accessed by thousands of Jenkins and other CI/CD pipelines. Credentials exfiltrated from CI environments using the pipeline's own access rights. CircleCI breach (2023): internal secrets compromised, affecting customer pipeline credentials. Both demonstrate the CI/CD credential store as a high-value target — the constitutional finding that all credentials in the Jenkins credential store are accessible to any job with Execute permission directly enables this class of attack.

## The Add-On: `jenkins-governance-enforcer`
Configuration drift detector and credential scope enforcer. Validates Matrix Authorization configured; validates Audit Trail plugin active; validates credentials scoped to specific folders/jobs (not global); validates plugin versions within security-patch window; produces `jenkins_posture.json` with drift score per job.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| build_execution | CRYSTALLIZED | Matrix Auth + Audit Trail; config drift accumulates |
| credential_access | CRYSTALLIZED | Global credentials accessible to all Execute users |
| job_configuration | CRYSTALLIZED | JCasC opt-in; config drift unchecked without it |
| plugin_management | CRYSTALLIZED | Plugin signing enforced from Update Center only |
| admin_configuration | CRYSTALLIZED | Audit Trail opt-in; admin changes ungoverned by default |
