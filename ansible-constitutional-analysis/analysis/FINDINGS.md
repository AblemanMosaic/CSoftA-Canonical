# FINDINGS: Ansible Constitutional Analysis
*Wave 12 — System 58 · EAR ceiling: CRYSTALLIZED (AWX) / ABSENT (CLI) · Fingerprint: `2dc25cf8769ed24e`*

## Executive Finding
Ansible introduces the most architecturally distinct constitutional concept of Wave 12: stateless IaC — imperative execution with no persistent state model produces ABSENT governance receipt by architectural design, not by misconfiguration. This extends T1684 (Terraform state file as governance receipt) by revealing the boundary case: Terraform has a state file that can drift from reality; Ansible has no state at all. Every playbook execution is a fresh imperative operation against current host state with no persistent record of what was applied, what changed, or what the pre-execution state was.

The constitutional distinction from Terraform: Terraform's ABSENT drift governance is a limitation of the state model (external modifications produce no state update). Ansible's ABSENT governance receipt is inherent to the execution model — there is no state to update because there is no state. The architecture does not produce a governance receipt; it produces a console log. The console log is not a governance receipt under the EAR taxonomy.

## Stateless IaC: A New Constitutional Concept
The stateless IaC gap cannot be closed by configuration within the Ansible model. It requires opting into a different execution layer (AWX/Tower) that adds state management and audit on top of Ansible's stateless core. AWX transforms Ansible from ABSENT to CRYSTALLIZED — it provides job execution records, approval workflows, RBAC, and structured output. But AWX is infrastructure that must be deployed and maintained; it is not a configuration option within Ansible itself.

This is the first system in the corpus where ABSENT governance is the correct constitutional classification for the architecture, not a misconfiguration. The stateless IaC model is intentional — it enables idempotent imperative execution without the state management overhead of Terraform or Crossplane.

## Real-World Incidents
Multiple documented incidents of Ansible playbooks executing without audit trail, making post-incident reconstruction impossible. Ansible role supply chain gap (analogous to npm/PyPI): Galaxy roles installed without signature verification — same ABSENT provenance pattern as package registries. SSH key management gap: Ansible often runs with broad SSH key access to target hosts; the governance of which hosts Ansible can reach is frequently ABSENT in community deployments.

## The Add-On: `ansible-governance-enforcer`
AWX enforcement gate and execution audit wrapper. Validates AWX/Tower managing all playbook execution; validates Ansible Vault encrypting all sensitive variables; validates Galaxy role pinning with checksums; produces `ansible_posture.json` with governance tier assessment.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| playbook_execution | ABSENT (CLI) / CRYSTALLIZED (AWX) | Stateless — no receipt by architecture |
| task_execution | ABSENT (CLI) / CRYSTALLIZED (AWX) | Individual task ABSENT in CLI model |
| secret_access | CRYSTALLIZED | Ansible Vault encrypts at rest; no access receipt |
| inventory_management | ABSENT (CLI) / CRYSTALLIZED (AWX) | Inventory changes ungoverned in CLI |
| role_execution | ABSENT (CLI) / CRYSTALLIZED (AWX) | Role provenance ungoverned in CLI |
