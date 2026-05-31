# CSoftA System Catalog

**Ableman Constitutional Systems** — ableman.research@gmail.com

Full index of all 80 analyzed systems. For methodology see
[METHODOLOGY.md](METHODOLOGY.md). For named concepts see
[CONCEPTS.md](CONCEPTS.md).

`†` — ACTIVE requires a commercial license.


| System | Category | EAR Ceiling | Key Finding |
|--------|----------|-------------|-------------|
| active-directory | Identity | CRYSTALLIZED | Kerberoasting is a protocol-inherent bypass — cannot be configured away |
| ansible | IaC | CRYSTALLIZED | Stateless IaC: ABSENT receipt is architectural, not a fixable default |
| argo-workflows | CI/CD | CRYSTALLIZED | Service account scope gap enables cross-namespace privilege escalation |
| argocd | CI/CD | CRYSTALLIZED | Git commit IS the governance declaration; sync receipt is CRYSTALLIZED |
| aws-codepipeline | CI/CD | ACTIVE | approval_gate ACTIVE; only CI/CD system in corpus with constitutive approval gate; full AWS backstop |
| aws-config | Cloud | CRYSTALLIZED | Drift detected after it occurs; CRYSTALLIZED complement to CloudTrail |
| aws-guardduty | Cloud | CRYSTALLIZED | Threat detection is post-hoc; detector can be disabled |
| aws-iam | Cloud | ACTIVE | IAM evaluation constitutive of every AWS API call; root can delete logs |
| aws-kms | Cloud | CRYSTALLIZED | Codefinger ransomware exploited BYOK key governance gap |
| aws-lambda | Cloud | ACTIVE | aws_api_call ACTIVE (IAM carries to serverless); layer supply chain ABSENT |
| aws-s3 | Cloud | ACTIVE | object_lock ACTIVE; default public access gap is the most frequently reported cloud security incident category |
| aws-secrets-manager | Secrets | CRYSTALLIZED | Auto-rotation ACTIVE-adjacent; depends on CloudTrail and KMS chain |
| aws-sso | Identity | ACTIVE | session_credential_issuance ACTIVE; IdP compromise propagates upstream |
| boundary | Access | CRYSTALLIZED | Session recording CRYSTALLIZED; Vault upstream governs all credentials |
| ceph | Storage | CRYSTALLIZED | CephX mandatory auth; distributed storage backend for OpenShift/OpenStack |
| cert-manager | PKI | ACTIVE | cert_issuance ACTIVE — certificate is the governance receipt |
| cert-manager-acme | PKI | ACTIVE | cert_issuance ACTIVE via ACME; CT log is the public misissuance record |
| cilium | Network/Security | ACTIVE | Kernel-time enforcement: eBPF LSM hooks below container runtime |
| circleci | CI/CD | CRYSTALLIZED | 2023 breach: encrypted-at-rest bypassed via running-process key extraction |
| cloudtrail | Cloud | CRYSTALLIZED | Governance-of-governance: StopLogging disables all AWS receipt governance at once |
| consul | Service Mesh | ACTIVE | connect_certificate ACTIVE; audit log enterprise-only paywall |
| cosign | Supply Chain | ACTIVE | policy_enforcement ACTIVE: unsigned images constitutively blocked at admission |
| crossplane | IaC | ACTIVE | drift_reconciliation ACTIVE: closes Terraform state drift gap |
| docker | Container | CRYSTALLIZED | --privileged is Layer Bypass magnitude 3; container interior ABSENT |
| docker-hub | Supply Chain | CRYSTALLIZED | Mutable tags are not a security boundary; the registry is the supply chain middle layer |
| elasticsearch | Observability | CRYSTALLIZED | Default ABSENT; one gap in this layer exposes all stored governance evidence |
| entra-id | Identity | ACTIVE | Split-path: modern_auth ACTIVE, legacy_auth ABSENT simultaneously |
| etcd | K8s | ACTIVE | peer_authentication ACTIVE; direct etcd access bypasses all K8s RBAC |
| external-secrets | Secrets | CRYSTALLIZED | CRYSTALLIZED relay in front of ACTIVE source; upstream governs |
| falco | Security | ACTIVE | kernel_module_load ACTIVE; detection itself is post-hoc CRYSTALLIZED |
| gatekeeper | K8s | CRYSTALLIZED | failurePolicy:Fail = ACTIVE; failurePolicy:Ignore = ABSENT — one field |
| gcp-iam | Cloud | CRYSTALLIZED | Admin Activity always on; Data Access logs ABSENT by default |
| github-actions | CI/CD | ACTIVE | cloud_federation ACTIVE via OIDC; mutable action tags ABSENT supply chain |
| gitlab-ci | CI/CD | CRYSTALLIZED | CI_JOB_TOKEN scope broader than declared; CVE-2024-6678 CVSS 9.9 |
| grafana | Observability | CRYSTALLIZED | Visualization layer as credential store; compromise yields all backend credentials |
| helm | K8s | CRYSTALLIZED | Chart provenance verification rarely used in practice |
| istio | Service Mesh | CRYSTALLIZED | Governance ceiling bounded by K8s admission; mTLS permissive by default |
| jaeger | Observability | CRYSTALLIZED | Default ABSENT auth; PII in trace spans is ungoverned |
| jenkins | CI/CD | CRYSTALLIZED | Configuration drift degrades governance continuously over operational lifetime |
| k8s-admission | K8s | ACTIVE | failurePolicy:Fail = ACTIVE; the constitutional closure for K8s supply chain |
| k8s-rbac | K8s | ACTIVE | api_authorization ACTIVE — constitutive of every K8s API request |
| kafka | Messaging | ACTIVE | broker_auth ACTIVE with mTLS; default configuration ships with no ACL — all data operations ABSENT |
| keycloak | Identity | ACTIVE | token_introspection ACTIVE; authorization_decision ABSENT by default |
| kubeflow | ML | CRYSTALLIZED | Model promotion ABSENT by default; K8s governance bounds ML governance ceiling |
| kubernetes | K8s | CRYSTALLIZED | Multi-layer governance cascade; default cluster is effectively ungoverned |
| kyverno | K8s | CRYSTALLIZED | CRYSTALLIZED ceiling; image_verification is the strongest governance path Kyverno supports |
| linkerd | Service Mesh | ACTIVE | service_communication ACTIVE; mTLS mandatory without admission webhook dependency |
| minio | Storage | CRYSTALLIZED | Self-hosted S3 without AWS backstop; Evil MinIO binary replacement (CISA KEV) |
| mlflow | ML | CRYSTALLIZED | No constitutive receipt for the decision to put a model version into production |
| mongodb | Database | ACTIVE† | Enterprise Audit ACTIVE behind commercial paywall; MongoBleed 87k+ vulnerable |
| mysql | Database | ACTIVE† | Enterprise Audit ACTIVE behind commercial paywall; CVE-2026-3494 audit bypass |
| nats | Messaging | CRYSTALLIZED | Default ABSENT; CVE-2025-30215 cross-account JetStream management |
| network-policy | Network | CRYSTALLIZED | Default K8s is all-allow; NetworkPolicy+CNI required for any segmentation |
| nginx | Network | ACTIVE | tls_termination ACTIVE; IngressNightmare CVE-2025-1974 CVSS 9.8 |
| nomad | Orchestration | CRYSTALLIZED | Default ACL disabled; enterprise audit paywall; CVE-2025-1296 token-in-audit-log |
| npm | Supply Chain | CRYSTALLIZED | Two structurally independent ABSENT surfaces: lifecycle scripts and module-load-time |
| opa | Policy | CRYSTALLIZED | Decision log CRYSTALLIZED — policy evaluation is not constitutively receipted |
| opa-engine | Policy | ACTIVE | policy_evaluation ACTIVE; policy content correctness gap applies |
| openfga | AuthZ | CRYSTALLIZED | Tuple write governance is the primary gap in ReBAC authorization |
| opentelemetry | Observability | CRYSTALLIZED | Observability pipeline has its own governance gaps — meta-governance case |
| packer | Supply Chain | CRYSTALLIZED | Image build provenance ABSENT by default; supply chain gap at artifact origin |
| pod-security | K8s | ACTIVE | enforce mode ACTIVE; prevents container escape vectors constitutively |
| postgresql | Database | ACTIVE | pgaudit makes query_execution ACTIVE; extension is ABSENT by default installation |
| prometheus | Observability | CRYSTALLIZED | No authentication by default; governs governance data with governance gaps |
| pulumi | IaC | ACTIVE | CrossGuard policy_enforcement ACTIVE; completes the IaC governance spectrum |
| puppet | IaC | CRYSTALLIZED | Convergence report CRYSTALLIZED; RBAC paywall; sits above Ansible in IaC spectrum |
| pypi | Supply Chain | CRYSTALLIZED | pip does not verify attestations; Mini Shai-Hulud: valid SLSA L3 packages compromised |
| rabbitmq | Messaging | CRYSTALLIZED | vhost isolation CRYSTALLIZED; CVE-2025-50200 auth header logged in plaintext |
| redis | Database | CRYSTALLIZED | Default ABSENT; two CVSS 10.0 vulnerabilities in default Lua engine |
| rust-cargo | Language | ACTIVE | Compile-time ACTIVE: borrow checker is constitutive of compilation completing |
| spiffe | Identity | ACTIVE | svid_issuance ACTIVE — the SVID is the governance receipt |
| splunk | Observability | CRYSTALLIZED | SIEM as target: compromise yields evidence access, suppression, and escalation |
| stripe | Payments | ACTIVE | charge_creation ACTIVE — Stripe Event is mandatory, immutable, caller-independent |
| tekton | CI/CD | ACTIVE | result_attestation ACTIVE via Chains; K8s-native SLSA provenance |
| teleport | Access | ACTIVE | session_establishment ACTIVE with strict recording; certificate ACTIVE |
| terraform | IaC | ACTIVE | state_management ACTIVE with remote lock; state drift ABSENT gap persists |
| triton | ML | CRYSTALLIZED | AI inference: outputs not constitutively bound to the governed model state |
| vault | Secrets | ACTIVE | secret_read ACTIVE — audit device failure causes the operation to fail |
| wandb | ML | CRYSTALLIZED | Third-party governance custody: evidence sovereignty depends on W&B availability |
| workload-identity | Identity | ACTIVE | credential_exchange ACTIVE: OIDC token constitutive of cloud credential issuance |


---

© Ableman Constitutional Systems — ableman.research@gmail.com  
Documentation: CC BY-ND 4.0 International
