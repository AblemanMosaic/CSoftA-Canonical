# Keycloak Constitutional Analysis

*A Constitutional Software Analysis (CSoftA) by Ableman Constitutional Systems*

---

This repository contains the Keycloak constitutional analysis —
the Wave 1 identity governance case and the second system (after Vault)
to demonstrate ACTIVE-EAR governance in the Wave 1 corpus.

---

## What This Analysis Finds

Keycloak's token introspection endpoint is ACTIVE-EAR: the introspection
response constitutively embeds the governance receipt. Authentication
and session lifecycle are CRYSTALLIZED. Keycloak Authorization Services
— the fine-grained policy engine — are ABSENT in most default deployments.

The architecture demonstrates two paths to ACTIVE-EAR in Wave 1:
Vault achieves it through mandatory server-side audit.
Keycloak achieves it through protocol-level receipt embedding.

---

## Constitutional Profile

| Dimension              | Finding                                      |
|------------------------|----------------------------------------------|
| Authority              | Explicit realm/client declaration            |
| Accountability         | ACTIVE (introspection); CRYSTALLIZED (rest)  |
| Governance             | ABSENT for authz by default; LOW elsewhere   |
| Configuration-Authority| Structural separation                        |
| Resolution Opacity     | LOW (introspection); MEDIUM (session)        |
| Extension Surfaces     | Perimeter-governed SPI                       |
| Authority Bypass       | Scoped; cached token risk                    |
| Projection Divergence  | Authz capability vs default deployment       |

**EAR State:**
- `token_introspection`: **ACTIVE** ← only Wave 1 operation besides Vault ACTIVE
- `user_authentication`: **CRYSTALLIZED**
- `authorization_decision`: **ABSENT** (default) / CRYSTALLIZED (when enabled)
- `admin_operation`: **CRYSTALLIZED**

**Recoverability:** LOCAL (introspection) / COMPOSITIONAL (session/admin)

---

## Wave 1 Completion

Wave 1: Vault → npm → Docker → Kubernetes → **Keycloak**

Wave 1 demonstrates the complete governance spectrum:

| System | ACTIVE-EAR | CRYSTALLIZED | ABSENT |
|--------|-----------|--------------|--------|
| Vault | secret_read, token_create, policy_manage | auth_login | root_token |
| npm | — | dep_install (lockfile) | lifecycle, install (no lock) |
| Docker | — | container_run_standard | --privileged, interior, build |
| Kubernetes | — | all families | — (with audit) |
| Keycloak | token_introspection | auth, admin, token | authz (default) |

---

## Python Reference Implementation

```bash
python3 impl/tests/test_gate_suite.py

# Analyze a Keycloak deployment
python3 -c "
import requests
from impl.ear_adapter_keycloak import KeycloakEARAdapter
from impl.gcg_analyzer import GCGAnalyzer
from impl.gap_assertions import write_receipt

# Fetch events from Keycloak Admin API
# (requires admin credentials)
base = 'https://your-keycloak/auth/admin/realms/master'
headers = {'Authorization': 'Bearer <admin_token>'}
user_events  = requests.get(f'{base}/events', headers=headers).json()
admin_events = requests.get(f'{base}/admin-events', headers=headers).json()

adapter = KeycloakEARAdapter(
    user_events=user_events,
    admin_events=admin_events,
    authz_services_enabled=False,  # set True if enabled
    user_events_enabled=True,
    admin_events_enabled=True,
)
report = GCGAnalyzer().analyze(adapter, target_system='Keycloak')
fp = write_receipt(report, 'keycloak_gcg_report.json')
print(f'Gaps: {report.total_gaps_found}, Fingerprint: {fp}')
"
```

**Convergence fingerprint:** `85c7340ecd34f3ed`

---

## License

Documentation: CC BY-ND 4.0 International · Code: Apache License 2.0
