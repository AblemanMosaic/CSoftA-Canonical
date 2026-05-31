# FINDINGS: AWS IAM Constitutional Analysis
*Wave 4 — System 16 · api_call_authorization: ACTIVE (CloudTrail required) · credential_issuance: ACTIVE · Fingerprint: `aa255556e281d862`*

## Executive Finding
AWS IAM is the corpus's canonical large-scale IAM case. CloudTrail provides ACTIVE-EAR for API authorization and credential issuance when properly configured (all regions, log file validation, management events). The STS temporary credential is the credential-as-receipt pattern at cloud scale: short-lived, scoped to a role, encoding the principal and permissions. Two operation families reach ACTIVE.

Critical structural gap: the root account can delete CloudTrail logs and disable CloudTrail entirely. No IAM-native protection prevents a sufficiently privileged actor from eliminating the governance record. root_operation is CRYSTALLIZED even with full CloudTrail — the governance mechanism can be destroyed by the apex of the trust hierarchy. This is the canonical apex bypass finding.

## Primary Gap: CloudTrail Not Default
CloudTrail is not enabled by default for all regions on new AWS accounts. Organizations that have not explicitly enabled CloudTrail with log file validation and all-region coverage are operating with ABSENT governance for all IAM operations. The gap is architectural: IAM has no built-in mandatory audit that survives root account compromise.

## Secondary Gap: Policy Evaluation Not Separately Receipted
IAM evaluates complex policy chains (identity policies, resource policies, permission boundaries, SCPs, session policies) to produce an Allow/Deny decision. CloudTrail records the API call outcome but not the full policy evaluation trace — which policy contributed to the decision, why a Deny won, which SCP overrode a resource policy. The governance record shows what was decided, not how the decision was made.

## Real-World Incident Mapping
Capital One breach (2019): SSRF vulnerability in a WAF allowed a compromised EC2 instance's IAM role to access S3 buckets. The IAM role had excessive permissions. CloudTrail recorded the S3 access, but the permissions existed for months before the breach — the governance record existed but was not monitored. The constitutional finding: CRYSTALLIZED governance (record exists, not constitutively acted upon) at the monitoring layer, combined with NON_ACTIVATION at the permission scope layer (role declared with permissions; access not reviewed for appropriateness).

AWS root account MFA bypass attacks: attackers who obtain root credentials can disable CloudTrail, delete logs, and create new administrator IAM users while removing all records of the activity. The root_operation CRYSTALLIZED classification is confirmed: the governance mechanism is not constitutive for root — it can be eliminated by the actor it is supposed to govern.

## The Add-On: `aws-iam-governance-enforcer`

A continuous compliance operator that enforces CloudTrail completeness and monitors for apex bypass attempts. Validates CloudTrail configuration across all regions (ABSENT gap assertion for uncovered regions), monitors CloudTrail disable/delete events in real time (BYPASS gap assertion), validates SCP coverage against CloudTrail modification, monitors root account activity with context classification, and produces `iam_governance_posture.json` per account. Implements the governance recommendation that CloudTrail completeness is a prerequisite for ACTIVE-EAR status, not a best-practice recommendation.

## Summary
| Family | EAR State | Key finding |
|--------|-----------|-------------|
| api_call_authorization | **ACTIVE** (CloudTrail required) | ABSENT without CloudTrail |
| credential_issuance | **ACTIVE** | STS token is credential-as-receipt |
| policy_management | ACTIVE (CloudTrail) | Policy changes recorded |
| access_analyzer | CRYSTALLIZED | Findings advisory, not constitutive |
| root_operation | CRYSTALLIZED | Root can delete logs — apex bypass |
