# FINDINGS: Cilium / Tetragon eBPF Constitutional Analysis
*Wave 12 — System 59 · syscall_enforcement (Tetragon enforce): ACTIVE · Fingerprint: `1c3d880d7a780cb0`*

## Executive Finding
Cilium/Tetragon introduces the strongest enforcement architecture in the corpus: kernel-time enforcement — policy evaluated and enforced within the Linux kernel via eBPF LSM hooks before system calls complete. This is a new ACTIVE class that extends T1640 (compile-time ACTIVE via Rust) with a runtime analog: the governance receipt is constitutive of system call completion, not a post-hoc record.

The constitutional significance is specific: kernel-time enforcement cannot be bypassed via privileged containers (PSA enforce prevents admission of privileged containers but cannot retroactively block syscalls from containers that gained privilege post-admission), cannot be bypassed via admission controller failure (failurePolicy:Ignore is not a concept at the eBPF LSM layer), and cannot be bypassed via container runtime vulnerabilities (eBPF operates below the container runtime in the Linux kernel).

## Kernel-Time Enforcement: A New Constitutional Concept
T1739 (Cosign admission gate) identified admission-gate ACTIVE as the constitutional backstop for supply chain governance. Cilium/Tetragon identifies a layer below admission: kernel-time enforcement governs runtime behavior after containers are admitted. The governance hierarchy from weakest to strongest:

1. Post-hoc log (Falco CRYSTALLIZED): alert follows event; event occurs regardless
2. Admission gate (Cosign ACTIVE): prevents admission; does not govern runtime
3. Kernel-time enforcement (Tetragon ACTIVE): governs runtime syscalls in-kernel; no TOCTOU gap

The XZ Utils backdoor (CVE-2024-3094, March 2024): Tetragon users observed anomalous sshd process execution chains — a backdoored sshd spawning unexpected child processes — at the kernel level before the CVE was publicly disclosed. Kernel-time observability detected behavioral anomaly from the execution pattern, not from a known CVE signature.

## Real-World Incidents
XZ Utils backdoor (CVE-2024-3094): Tetragon detected anomalous process chains at kernel level before CVE disclosure — behavioral detection without signature matching. Log4Shell (CVE-2021-44228): Tetragon would detect the JNDI outbound network connection from the Java process at the kernel network layer, independent of whether the Java application logging was governed. Container escape techniques: all known container escape techniques that operate via syscalls are detectable and blockable at the Tetragon layer — the escape attempt itself triggers the policy, not the post-escape activity.

## The Add-On: `cilium-governance-enforcer`
Tetragon policy validator and enforcement mode auditor. Validates Tetragon deployed and enforcement policies active; validates NetworkPolicy enforced via Cilium eBPF dataplane; validates Hubble observability configured; validates TracingPolicies cover critical syscall families; produces `cilium_posture.json`.

## Summary
| Family | EAR State | Character |
|--------|-----------|-----------|
| syscall_enforcement | **ACTIVE** (Tetragon enforce) | Kernel-time — cannot bypass via container privesc |
| network_enforcement | **ACTIVE** (Cilium eBPF) | eBPF dataplane — packet-level, below iptables |
| process_execution | **ACTIVE** (Tetragon enforce) | execve hook constitutive of process start |
| file_access | **ACTIVE** (Tetragon enforce) | file open hook constitutive of file access |
| network_observability | CRYSTALLIZED | Hubble observes; does not enforce |
