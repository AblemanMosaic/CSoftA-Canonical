# FINDINGS: Terraform / OpenTofu Constitutional Analysis
*Wave 5 — System 24 · state_management (remote+lock): ACTIVE · OSS default: ABSENT · Fingerprint: `37eb7ab8ad539c35`*

## Executive Finding
Terraform introduces the IaC governance surface — the state file as governance receipt. The Terraform state file records what infrastructure Terraform has deployed, but it is a CRYSTALLIZED receipt: it records what Terraform knows about, not what actually exists. State drift — infrastructure modified outside Terraform — produces no state update and no gap assertion. The state file may be completely correct and completely wrong simultaneously about the actual state of the infrastructure.

State management with a remote backend and locking reaches ACTIVE: the state lock acquisition is constitutive of state modification — Terraform cannot modify state without acquiring the lock, and the lock acquisition produces a receipt. This is the corpus's first infrastructure governance ACTIVE case.

## The Plan/Apply Split
The plan/apply split creates a governance gap that no other system in the corpus shares: the governance declaration (the plan) and the governance execution (the apply) are temporally and operationally separated. Between `terraform plan` and `terraform apply`, the infrastructure state may have changed, another operator may have run a competing plan, or the plan may have been approved for a different state than what apply will encounter. The plan receipt is a governance declaration for a state that may not exist at apply time.

## State Drift: The Canonical IaC Gap
Resources created, modified, or deleted outside Terraform produce no governance record. The state file silently diverges from reality with no gap assertion. Organizations discover drift retrospectively — during the next `terraform plan` run — often after significant manual changes have accumulated. The constitutional classification: STRUCTURAL_NONLOCALITY — the governance state cannot be reconstructed from the state file alone when external modifications exist.

Sensitive values in state: Terraform state files may contain sensitive values (database passwords, private keys, API tokens) in plaintext if not using external secret backends (Vault). This is a data governance gap specific to the state file architecture.

## Real-World Incident Mapping
Terraform state file exposure (multiple incidents, 2023-2025): organizations storing Terraform state in S3 buckets without encryption or access controls have experienced state file exposure, leaking infrastructure topology, resource IDs, and sensitive values stored in state. The constitutional finding: the state_file layer was present (state existed) but the governance of the state file itself was ABSENT — no receipt for who accessed the state, no encryption of sensitive values.

Terraform state manipulation attacks: a privileged attacker with write access to a remote state backend can acquire the lock legitimately and apply malicious state changes — the state_management ACTIVE classification prevents concurrent modification but not authorized malicious modification, the same apex bypass pattern as AWS IAM root.

Cloudflare breach (November 2023, nation-state attacker): a threat actor used stolen credentials from the Okta breach to access Cloudflare's internal systems. Among the 76 source code repositories accessed, Cloudflare specifically noted: "The 76 source code repositories were almost all related to how backups work, how the global network is configured and managed, how identity works at Cloudflare, remote access, and our use of Terraform and Kubernetes." The Terraform repositories exposed infrastructure topology, access control architecture, and network configuration — exactly the content of a Terraform state file. The constitutional finding: Terraform repository access = infrastructure topology disclosure, confirming that IaC artifacts are high-value targets.

Auth0 credentials exposed in Terraform state (January 2025, UK government Ministry of Justice Cloud Platform): Auth0 credentials were committed in an infrastructure repository containing Terraform state, exposed when the security team was notified. The incident was declared within two hours. The constitutional finding: sensitive values written to Terraform state in plaintext — the state_file layer present, secret_backend absent, credentials in cleartext in the state artifact.

CVE-2025-25291 (Terraform Enterprise SSO account takeover): a flaw in Terraform Enterprise's SSO implementation allowed account takeover without valid credentials. Authentication bypass in the governance layer protecting state access — BYPASS form.

Multiple Terraform provider CVEs (AWS, GCP, Azure providers, 2022-2025): database passwords, private keys, and API tokens written to state in plaintext across providers. The secret_management layer is CRYSTALLIZED at best — encryption available but not default in OSS Terraform.

## The Add-On: `terraform-governance-enforcer`
State file security gate and drift monitor. Enforces remote backend with encryption and state locking; validates plan approval before apply (Terraform Cloud gate or custom approval workflow); monitors for state drift via scheduled `terraform plan -refresh-only`; alerts on sensitive values detected in state without encryption; produces `tf_posture.json` per workspace.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| apply_operation | CRYSTALLIZED | State drift not receipted; plan/apply split gap |
| plan_operation | CRYSTALLIZED | Plan receipt exists; may not match apply-time state |
| state_management | **ACTIVE** (remote+lock) | Lock constitutive of state modification |
| drift_detection | CRYSTALLIZED | Scheduled, not continuous |
| secret_management | ABSENT (OSS) | Sensitive values in plaintext state |
