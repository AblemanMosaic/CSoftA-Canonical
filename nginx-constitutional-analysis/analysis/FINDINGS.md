# FINDINGS: Nginx / ingress-nginx Constitutional Analysis
*Wave 6 — System 28 · tls_termination: ACTIVE · ingress_admission (default): ABSENT · Fingerprint: `0f57a566e45289e5`*

## Executive Finding
Nginx / ingress-nginx is the network boundary governance case. Every HTTP/HTTPS request to a Kubernetes workload passes through ingress-nginx. TLS termination is ACTIVE: the TLS certificate is constitutive of the HTTPS connection — the connection cannot be established without the certificate and private key. Request access logging is CRYSTALLIZED. Ingress annotation governance is the critical gap: the admission webhook validates Ingress objects, but annotation scope boundaries have produced CVSS 9.8 vulnerabilities.

CVE-2025-1974 (IngressNightmare, CVSS 9.8, March 2025) is the most severe CVE in the Wave 6 corpus: an unauthenticated attacker with access to the pod network could achieve remote code execution on the ingress controller pod, which in default installations has cluster-wide access to all Secrets. Wiz Research found 43% of cloud environments vulnerable, with 6,500+ clusters identified including Fortune 500 companies.

## The Annotation Injection Gap
ingress-nginx processes Ingress annotations to generate NGINX configuration. Annotations like `nginx.ingress.kubernetes.io/configuration-snippet` and `nginx.ingress.kubernetes.io/auth-tls-match-cn` allow injecting arbitrary NGINX directives. In the CVE-2025-1974 family, the annotation validation was insufficient: a crafted Ingress object sent directly to the admission webhook (bypassing Kubernetes API RBAC) could inject NGINX configuration that caused the NGINX validator to execute arbitrary code.

The constitutional finding: annotation_validation layer was declared applicable in the admission webhook, but the scope boundary of what constituted valid annotation content was insufficiently bounded — NON_ACTIVATION at the annotation content scope boundary.

## Real-World Incident Mapping
CVE-2025-1974 (IngressNightmare, CVSS 9.8, March 2025, Wiz Research): unauthenticated RCE via admission webhook annotation injection. Any pod on the cluster network could exploit this without Kubernetes API credentials. In default installations, the ingress controller runs with a ServiceAccount that has cluster-wide Secret read access — full cluster Secret disclosure. Affects all ingress-nginx versions before 1.11.5 / 1.12.1. PoC exploit publicly available.

CVE-2025-1098 and CVE-2025-24514 (CVSS 8.8): companion annotation injection vulnerabilities in the same IngressNightmare family. auth-url and auth-tls-match-cn annotations allowed configuration injection resulting in RCE and secret disclosure.

CVE-2023-5044 (nginx.ingress.kubernetes.io/permanent-redirect annotation injection, CVSS 8.8): the permanent-redirect annotation allowed arbitrary NGINX directive injection. Users with Ingress creation permission could leverage this to expose Secrets or achieve code execution in the controller. The same annotation injection gap class as CVE-2025-1974, predating it by two years — the constitutional finding is structural, not incidental.

The pattern across three years: annotation governance is the systematic vulnerability surface for ingress-nginx. Every CVE in this family expresses the same constitutional gap — annotation content validation scope insufficiently bounded.

## The Add-On: `ingress-nginx-governance-enforcer`
Admission webhook validation layer enforcing annotation scope boundaries. Validates annotation allowlist (blocks configuration-snippet unless explicitly authorized); validates auth-tls-match-cn content against declared pattern; monitors admission webhook exposure to pod network; verifies annotation validation enabled; produces `nginx_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| request_proxying | CRYSTALLIZED | Access log records; not constitutive |
| tls_termination | **ACTIVE** | Certificate constitutive of HTTPS |
| ingress_admission | ABSENT / CRYSTALLIZED | CVE-2025-1974 class; annotation scope NON_ACTIVATION |
| annotation_processing | CRYSTALLIZED | Validation present but scope boundaries insufficient |
| config_reload | CRYSTALLIZED | Config changes not mandatorily receipted |
