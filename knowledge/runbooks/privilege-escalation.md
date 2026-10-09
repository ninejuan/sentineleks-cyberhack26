# Runbook: Privilege Escalation

- runbook_id: privilege-escalation
- mitre: T1068 Exploitation for Privilege Escalation
- default_severity: P1
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker inside a container gains root privileges, either by exploiting a setuid-style syscall path or by running in a container already configured with excessive capabilities. This is frequently the step immediately before a container escape, so SEKS treats it with the same urgency: contain the pod first, let an operator judge whether the host itself needs attention.

## Detection signals

### GuardDuty

- `PrivilegeEscalation:EKS/PrivilegedContainer` - privilege escalation attempt from a privileged container.
- `PrivilegeEscalation:EKS/AnomalousBehavior` - behavior pattern inconsistent with the workload's baseline.
- `Execution:EKS/ExecInPod` - `kubectl exec` against a running pod, often used to launch the escalation attempt interactively.

### Falco

- No rule in `kubernetes/falco/values.yaml` is currently scoped specifically to setuid/setresuid privilege escalation. The closest related custom rule, `Binary modified in running container`, catches a common follow-on step (dropping a modified binary into `/bin` or `/usr/bin` after gaining elevated write access) and should be checked as corroborating evidence, but it is not a direct privilege-escalation detector. Do not cite a dedicated Falco privilege-escalation rule name; none exists yet.

### Tetragon

- `detect-privilege-escalation` (`kubernetes/tetragon/tracing-policies.yaml`) - kprobe on the `__x64_sys_setuid` syscall, posting an event whenever a process calls `setuid(0)`. This is the primary sensor for this threat.

### Network indicators

- Not applicable. Privilege escalation is a local, in-container syscall event; it has no inherent network signature until it leads to a container escape or lateral movement.

## Correlation and severity

Default severity is P1 on a single `detect-privilege-escalation` hit, consistent with the response policy's P1 definition for privilege escalation.

If GuardDuty's `PrivilegeEscalation:EKS/PrivilegedContainer` or `AnomalousBehavior` also fires against the same pod within the 10-minute window, that is 2 distinct sensor types, reinforcing P1 with high confidence. If the follow-on `Binary modified in running container` Falco rule also fires on the same pod in that window, treat it as a third corroborating signal of successful escalation (the attacker now has write access to system binary paths), even though it is not a purpose-built privilege-escalation rule.

Noisy-rule down-weighting applies to `detect-privilege-escalation` if it fires on 5 or more distinct workloads in 24 hours; this can happen with legitimate init containers or package managers that call `setuid(0)` as part of normal startup. Down-weighting adjusts the severity score only; forensics still run on every individual finding.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` - forensic snapshot before any destructive step; required precondition for everything below.
2. `capture_hubble_flows(namespace, pod_name)` - capture any network activity coincident with the escalation attempt.
3. `collect_tetragon_timeline(pod_uid)` - pull the `setuid(0)` kprobe event and surrounding process activity in sequence.
4. `collect_audit_events(namespace, pod_name)` - correlate `kubectl exec` events from the Kubernetes audit log against `Execution:EKS/ExecInPod`.
5. `collect_live_pod_forensics(namespace, pod_name, profile="process_snapshot")` - record the process tree and current UID/GID state.
6. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` - arms the pre-deployed Tetragon SIGKILL policy on this pod's outbound connections.
7. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` - selects only the compromised pod; prevents the now-root process from using the pod's network identity for lateral movement.
8. `delete_pod(namespace, pod_name)` - removes the escalated-privilege container.
9. `patch_deployment(namespace, deployment_name, replicas=0)` - scale down only if the Deployment's pod template itself grants the capabilities that enabled escalation (for example, `CAP_SYS_ADMIN`), pending a corrected manifest.

### Human follow-up (not automated)

- Audit the pod's ServiceAccount RBAC bindings for excessive permissions that let the escalated process reach the Kubernetes API; RBAC changes are human-only under this policy.
- Review the Deployment's `securityContext` and `capabilities` list before redeploying.

## Approval card

- What: Contain and remove the pod where root privilege escalation was detected; forensics first, then network isolation, then pod deletion.
- Impact: The pod is terminated and replaced by its Deployment. RBAC and capability configuration are not changed by this automated plan.
- Rollback: Remove the `security.incident/compromised` label and delete the `seks-isolate-<pod>` CiliumNetworkPolicy once the replacement pod is confirmed to run as non-root.

## Rollback

1. Confirm the new pod created by the Deployment runs with the expected non-root UID and no `setuid(0)` events in a fresh observation window.
2. Remove the `security.incident/compromised=true` label from any surviving pod, disarming the Tetragon SIGKILL policy.
3. Delete the `seks-isolate-<pod>` CiliumNetworkPolicy.
4. If `patch_deployment(replicas=0)` was used, scale the Deployment back to its pre-incident replica count only after the pod template's capabilities have been corrected.
5. Rollback is never automatic; an operator confirms resolution before any rollback step runs.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass, even if escalation is suspected to precede a container escape.
- Do not leave `endpointSelector` empty in the CiliumNetworkPolicy; an empty selector isolates the entire namespace.
- Do not add a `toEntities: world` or equivalent `0.0.0.0/0` egress allow rule to the isolation policy.
- Do not take any action against a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not cite a Falco rule name specific to privilege escalation in Slack messages or citations; the only related custom rule (`Binary modified in running container`) detects a follow-on symptom, not the escalation syscall itself.
- Do not recommend an RBAC change (such as removing a ClusterRoleBinding) as an automated step; there is no such tool on the EKS MCP server, and RBAC changes remain human-only.

## References

- https://attack.mitre.org/techniques/T1068/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
