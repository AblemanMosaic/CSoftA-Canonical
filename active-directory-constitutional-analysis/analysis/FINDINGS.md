# FINDINGS: Active Directory Constitutional Analysis
*Wave 13 — System 64 · EAR ceiling: CRYSTALLIZED · Fingerprint: `3f4ad40fd8dc2c3c`*

## Executive Finding
Active Directory is the identity substrate for the majority of enterprise organizations globally, and it introduces the most important constitutional concept of Wave 13: the protocol-inherent bypass — a gap that exists because the protocol itself exposes the governance credential in the normal authentication flow, not because of misconfiguration.

Kerberoasting exploits how Kerberos tickets work: when any authenticated domain user requests a service ticket for an SPN, the KDC returns a ticket encrypted with the service account's password hash. This is normal protocol behavior — the KDC cannot distinguish a legitimate from a malicious request. The attacker takes the encrypted ticket offline and cracks the password at will. No alert is generated that distinguishes this from legitimate service ticket requests; Event 4769 is generated for both. The governance evidence is CRYSTALLIZED (Event 4769 logged) but the protocol design makes the bypass inherent.

This is constitutionally different from all other BYPASS gaps in the corpus. Previous BYPASS gaps are design flaws or misconfigurations: `--privileged` bypasses Docker namespaces (T1578), Redis unauthenticated (Wave 7), failurePolicy:Ignore bypasses admission webhooks (T1778). Kerberoasting is not a flaw — it is how Kerberos was designed. The governance gap cannot be eliminated without replacing the protocol; it can only be mitigated (gMSAs with 120-char auto-rotating passwords make offline cracking computationally infeasible).

## Real-World Incidents
Ascension Health ransomware breach (May 2024): Kerberoasting of service accounts with RC4 encryption allowed attackers to crack credentials. Domain controller compromise led to ransomware deployment across 140 hospitals, disrupting patient care for weeks. US Senator Ron Wyden pressed FTC to investigate Microsoft over Kerberoasting defaults (September 2025). IBM X-Force 2025: 30% of all 2024 intrusions involved stolen or abused credentials; Kerberoasting is a primary credential theft vector. DCSync attack surface: any account with DS-Replication-Get-Changes-All permission can replicate all password hashes from DC — BYPASS at replication governance, also protocol-inherent when over-permissioned.

## The Add-On: `active-directory-governance-enforcer`
Kerberoasting detection and SPN governance tool. Identifies all service accounts with SPNs; validates gMSAs deployed for all SPNs; validates AES-only Kerberos (RC4 disabled); monitors Event 4769 for anomalous SPN request patterns; validates no accounts hold DS-Replication permissions; produces `ad_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| kerberos_authentication | CRYSTALLIZED | Event 4769 logged; attacker requests indistinguishable |
| service_ticket_request | CRYSTALLIZED | Protocol-inherent bypass; gMSAs mitigate but not eliminate |
| privileged_access | CRYSTALLIZED | Admin audit available; tiered admin opt-in |
| group_policy_application | CRYSTALLIZED | GPO changes logged; change governance opt-in |
| replication_governance | CRYSTALLIZED | DCSync detectable; permission control is the mitigation |
