# FINDINGS: AWS Lambda Constitutional Analysis
*Wave 15 — System 73 · aws_api_call: ACTIVE (IAM T1629 carries) · Fingerprint: `f95380dbab83348d`*

## Executive Finding
AWS Lambda introduces serverless execution as a new governance model. The key constitutional finding: AWS API calls made by Lambda functions are ACTIVE — IAM evaluation is constitutive of every AWS SDK call (T1629 carries to Lambda). But Lambda introduces two new governance gaps not present in container-based compute:

First, the layer supply chain gap: Lambda Layers are versioned packages of code/libraries that functions reference. Layers from other accounts can be shared. A function referencing a public layer has ABSENT provenance governance — no mandatory signature verification, no attestation requirement. The same supply chain governance gap as npm, PyPI, and GitHub Actions actions, applied to serverless function dependencies.

Second, internal execution governance: Lambda's internal function execution is ABSENT governance. CloudWatch Logs capture function stdout/stderr (CRYSTALLIZED), but there is no governance receipt for what happens inside the function before it makes external API calls. An attacker who injects code that reads environment variables and exfiltrates them via direct HTTP (not through AWS SDKs) leaves no trace in CloudTrail — the exfiltration bypasses the ACTIVE IAM governance layer by avoiding AWS SDKs entirely.

## IAM Execution Role as Primary Attack Target
The execution role is the most security-sensitive Lambda configuration. A function with `s3:*` permissions can read or delete all S3 buckets. A function with `iam:*` can escalate to any privilege in the account. Overly permissive execution roles are the primary attack amplifier: once a function is compromised (via injection, dependency confusion, or SSJI), the execution role determines the blast radius.

## Real-World Incidents
CVE-2025-55182 (React2Shell, SSJI in Lambda-hosted Next.js): no shell spawning possible (read-only FS, Webpack-wrapped require), but Server-Side JavaScript Injection achieves credential extraction from Lambda environment variables, including AWS IAM temporary credentials. The attack trades RCE for credential theft — in a cloud environment, credentials may be more valuable than shell access. Overly permissive execution roles: repeatedly documented as the root cause of Lambda-related cloud account compromises.

## The Add-On: `lambda-governance-enforcer`
Execution role least-privilege auditor and layer provenance validator. Validates execution role follows least-privilege; validates layers referenced by version ARN (not :latest); validates Secrets Manager used instead of environment variables for sensitive values; produces `lambda_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| function_invocation | CRYSTALLIZED | IAM resource policy + CloudWatch |
| aws_api_call | **ACTIVE** | IAM always evaluated; T1629 carries to serverless |
| layer_consumption | CRYSTALLIZED | Layer provenance ABSENT; version pin = CRYSTALLIZED |
| environment_variable | CRYSTALLIZED | KMS encryption opt-in; Secrets Manager CRYSTALLIZED |
| vpc_execution | CRYSTALLIZED | Network isolation available; not default |
