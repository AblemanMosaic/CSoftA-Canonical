# FINDINGS: GitHub Actions Constitutional Analysis
*Wave 6 — System 26 · cloud_federation (OIDC): ACTIVE · action_consumption (default): ABSENT · Fingerprint: `4b595e5b832d0a05`*

## Executive Finding
GitHub Actions is the corpus's canonical CI/CD governance case. The platform introduces two distinct governance surfaces with opposite constitutional classifications. Cloud federation via OIDC tokens is ACTIVE: the OIDC token is constitutive of cloud provider access — without a valid token, the workflow cannot access AWS, GCP, or Azure. Third-party action supply chain governance is ABSENT by default: actions referenced by mutable version tags can be retroactively modified to point to malicious code without any workflow configuration change.

The defining incident — CVE-2025-30066 (tj-actions/changed-files, March 2025) — confirmed this gap at scale: a compromised PAT was used to retroactively modify all version tags of a widely-used GitHub Action to point to a malicious commit that dumped CI/CD runner memory, exposing secrets in workflow logs. Over 23,000 repositories were affected. The initial target was Coinbase.

## Third-Party Action Supply Chain: ABSENT by Default
When a workflow references `uses: actions/checkout@v4`, the `v4` tag is a mutable pointer. The action owner can update what `v4` points to at any time. When a workflow references `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`, that SHA256 commit hash is immutable — it cannot be changed after the commit exists. Hash pinning moves action_consumption from ABSENT to CRYSTALLIZED. Without hash pinning, every workflow update of the referenced tag is a potential governance change with no receipt.

## Workflow Permissions: Broad GITHUB_TOKEN Default
The `GITHUB_TOKEN` is automatically provisioned with write permissions to the repository and read permissions to organization packages by default. A workflow that does not declare a `permissions` block runs with this broad scope. A compromised or malicious third-party action can use the broad GITHUB_TOKEN to push commits, create releases, or access secrets without any additional authentication. Declaring `permissions: {}` with only the needed scopes is the governance mechanism — and it is opt-in.

## Real-World Incident Mapping
CVE-2025-30066 (tj-actions/changed-files, CVSS 8.6, March 2025): the supply chain attack initially targeted Coinbase, then expanded to 23,000+ repositories. Attackers compromised a GitHub PAT belonging to the `@tj-actions-bot` account, used it to push a malicious commit, and retroactively updated all version tags to reference it. The malicious payload dumped CI/CD runner memory, printing secrets (AWS keys, GitHub PATs, npm tokens, private RSA keys) directly to workflow logs. Organizations using public repositories had their secrets exposed publicly. Linked to CVE-2025-30154 (reviewdog/actions-setup compromise), indicating a coordinated multi-action campaign.

Ultralytics YOLO supply chain attack (December 2024): attackers used a crafted pull request with a branch name containing injection characters to execute malicious code in GitHub Actions workflows triggered by `pull_request_target`. The branch name became an injection vector — the workflow_permissions gap allowed the runner to publish malicious packages to PyPI. 60 million PyPI downloads affected.

PostHog Shai Hulud v2 campaign (November 2025): attackers used `pull_request_target` workflow misconfiguration to inject malicious scripts through a brief pull request, stealing credentials and publishing malicious packages. Same vulnerability class as Ultralytics.

Script injection is a documented constitutional gap class: when untrusted data (PR titles, branch names, issue bodies) flows into workflow expressions like `${{ github.event.pull_request.title }}`, it can inject shell commands. This is the workflow_permissions NON_ACTIVATION form — the permissions boundary is set but the input validation is absent.

## The Add-On: `github-actions-governance-enforcer`
A repository governance gate enforcing constitutional completeness for GitHub Actions. Scans all workflow files for unpinned action references (ABSENT assertion per unpinned action); validates permissions blocks declared and minimal; monitors OIDC federation configuration; detects pull_request_target without head SHA pinning; produces `gha_posture.json` per repository.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| workflow_execution | CRYSTALLIZED | Run log not constitutive; permissions opt-in |
| secret_access | CRYSTALLIZED | Secrets scoped but token broad by default |
| cloud_federation | **ACTIVE** (OIDC) | OIDC token constitutive of cloud access |
| action_consumption | ABSENT (default) | Tags mutable; CVE-2025-30066 confirmed |
| artifact_publication | CRYSTALLIZED | Provenance opt-in (SLSA) |
