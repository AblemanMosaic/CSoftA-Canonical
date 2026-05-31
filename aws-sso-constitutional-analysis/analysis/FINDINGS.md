# FINDINGS: AWS IAM Identity Center (SSO) Constitutional Analysis
*Wave 7 — System 33 · session_credential_issuance: ACTIVE · Fingerprint: `0dd4a41ce52c82a7`*

## Executive Finding
AWS IAM Identity Center (formerly AWS SSO) extends the AWS IAM analysis (Wave 4) to the federated identity layer. Session credential issuance is ACTIVE: temporary credentials are constitutive of account access, and CloudTrail records the issuance. The credential-as-receipt pattern applies at the federation layer just as it does for direct IAM (T1630).

The critical gap not present in direct IAM: the IdP compromise propagation chain. When the identity provider (Okta, Azure AD, Microsoft Entra) is compromised, all federated identities across all AWS accounts linked to Identity Center are compromised. This is upstream governance inheritance (T1613) at the identity layer: Identity Center's governance quality is bounded by the IdP's governance quality. A CRYSTALLIZED IdP with a compromised token produces ACTIVE temporary AWS credentials with real access.

## IdP as Upstream Governance Boundary
Identity Center trusts the IdP's SAML assertions. A compromised IdP can issue assertions for any user or group, giving attackers valid Identity Center sessions with whatever permission sets those principals hold. The permission set assignments exist and are enforced — the governance mechanism is present — but the assertions driving those assignments are from a compromised source. This is NON_ACTIVATION at the federation trust boundary: the SAML assertion was evaluated and accepted, but the claim was false.

## Real-World Incident Mapping
Okta breach (October 2023): threat actors gained access to Okta's support system and used it to access customer support tickets, stealing session tokens for authenticated support engineers. Organizations using Okta as their IdP for AWS Identity Center were exposed to the risk of attackers using stolen Okta sessions to generate valid AWS temporary credentials. The constitutional finding: Identity Center's session_credential_issuance was ACTIVE (correctly issued credentials), but the upstream Okta governance was CRYSTALLIZED (session tokens were compromised), producing valid AWS access from a compromised identity.

Lapsus$ group attacks (2022): systematically targeted identity providers and SSO systems to generate valid cloud access tokens. Compromising the IdP layer gave attackers access to all downstream cloud accounts federated through the IdP. The upstream governance inheritance finding (T1613) is confirmed: the combined governance quality of IdP+Identity Center is min(IdP, Identity Center).

## The Add-On: `aws-sso-governance-enforcer`
Identity Center governance gate. Validates CloudTrail enabled for SSO events; requires MFA via IdP; validates permission sets reviewed against least-privilege principle; monitors IdP sync freshness; alerts on new account assignments; produces `sso_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| federated_login | CRYSTALLIZED | IdP compromise propagates; CloudTrail records |
| permission_set_assignment | CRYSTALLIZED | Assignment exists; scope may be overly broad |
| session_credential_issuance | **ACTIVE** | Temp creds constitutive; CloudTrail records |
| idp_synchronization | CRYSTALLIZED | Sync staleness gap; group membership delay |
| permission_set_management | CRYSTALLIZED | Changes audited; content not reviewed |
