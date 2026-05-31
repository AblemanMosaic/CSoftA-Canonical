# FINDINGS: AWS S3 Constitutional Analysis
*Wave 6 — System 29 · object_lock (COMPLIANCE): ACTIVE · Default: ABSENT for audit · Fingerprint: `ea5f14a05d5c0d4d`*

## Executive Finding
AWS S3 is the corpus's canonical data storage governance case and the single most documented source of large-scale data breaches in the corpus. Server access logging, CloudTrail data events, server-side encryption, versioning, and Block Public Access are all opt-in. A new S3 bucket in a new account has ABSENT audit governance by default.

S3 Object Lock in COMPLIANCE mode is ACTIVE: objects cannot be deleted or modified by anyone — including the bucket owner, account root, and AWS support — during the lock period. This is constitutive immutability: the immutability constraint cannot be overridden by any principal within the AWS account. This makes Object Lock the corpus's canonical ACTIVE-EAR storage governance case.

## The Public Bucket Default Gap
New S3 buckets inherit their public access settings from account-level settings. While AWS has progressively tightened defaults (Block Public Access was made the account-level default for new accounts in 2023), legacy accounts and explicitly configured buckets may still have public access enabled. The public_access ABSENT classification expresses this: without Block Public Access, there is no structural mechanism preventing a bucket from being accidentally made public through bucket policy or ACL misconfiguration.

## CloudTrail Data Events: Opt-In by Default
S3 management events (bucket creation, deletion, policy changes) are logged by CloudTrail by default. S3 data events (GetObject, PutObject, DeleteObject) are NOT logged by default — they must be explicitly enabled at additional cost. This means that in the vast majority of production S3 deployments, the governance record for individual object access is ABSENT. Organizations know that buckets exist and policies were set; they do not know what objects were accessed by whom.

## Real-World Incident Mapping
Capital One breach (2019, 100+ million records): as noted in the AWS IAM analysis (T1635), the S3 access was recorded by CloudTrail — but only because Capital One had enabled CloudTrail data events. Most organizations would not have this record. The governance gap for S3 data access is confirmed by the specific configuration that was required to detect it.

Numerous misconfigured public bucket exposures (2018-2025, ongoing): S3 bucket misconfiguration is the most frequently reported cloud security incident category. Notable incidents include Twitch source code exposure (2021, 128GB), Microsoft Power Apps exposed data (2021, 38 million records), Toyota telematics data exposure (2023, 2.15 million customers). All share the same constitutional cause: access_control was configured insufficiently, no governance receipt existed for the access before discovery.

GhostToken vulnerability (GCP, 2023) cross-reference: cloud storage governance gaps are not S3-specific — but S3 is the highest-volume case in the corpus because of its market penetration.

## The Add-On: `s3-constitutional-enforcer`
S3 bucket security gate and continuous monitor. Validates server access logging enabled; validates CloudTrail data events for sensitive buckets; enforces encryption at rest; validates Block Public Access enabled; scans for public access ACLs; alerts on bucket policy changes; produces `s3_posture.json` per bucket.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| object_read | ABSENT (default) / CRYSTALLIZED | Server logging + CloudTrail data events both opt-in |
| object_write | ABSENT (default) / CRYSTALLIZED | Encryption + versioning opt-in |
| bucket_policy_management | CRYSTALLIZED | Management events in CloudTrail by default |
| object_lock | **ACTIVE** (COMPLIANCE) | Constitutive immutability — no override |
| public_access | ABSENT (no BPA) | Public access possible without BPA |
