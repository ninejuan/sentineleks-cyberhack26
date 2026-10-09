# Runbook: Container Escape

- runbook_id: container-escape
- mitre: T1611 Escape to Host
- default_severity: P1
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker breaks out of a container's isolation boundary and reaches the underlying host node, typically through a privileged container, a hostPath mount, or a namespace-unshare primitive like `nsenter`. A successful escape compromises every container scheduled on that node and the node itself, so detection must assume the worst and contain the pod immediately while leaving node-level judgment to a human operator.

## Detection signals

### GuardDuty

- `PrivilegeEscalation:EKS/PrivilegedContainer` - privileged container used to attempt an escape.
- `PrivilegeEscalation:EKS/ContainerMounts` - access to a sensitive host path after a hostPath mount.
- `Execution:EKS/HostAssumption` - container accessing the host process namespace.
- `Impact:EKS/MaliciousIPCaller` - connection to a known-malicious IP from the host after escape.

### Falco

- `Container escape via nsenter` (`kubernetes/falco/values.yaml`) - fires on `spawned_process` where `proc.name = nsenter`. Priority `CRITICAL`, tagged `mitre_privilege_escalation`, `T1611`.

### Tetragon

- `detect-container-escape` (`kubernetes/tetragon/tracing-policies.yaml`) - kprobe on the `__x64_sys_unshare` syscall, posting an event on every invocation. `unshare` is the primitive behind most namespace-escape techniques, so this policy fires earlier in the attack chain than the Falco `nsenter` rule, which only catches the follow-on tool.

### Network indicators

- Outbound connection from the host network namespace to an IP not seen in that node's baseline traffic (surfaced via `Impact:EKS/MaliciousIPCaller`).
- Access to the Docker or containerd socket (`/var/run/docker.sock`, `/run/containerd/containerd.sock`) from inside a container, visible in `collect_live_pod_forensics` filesystem triage.

## Correlation and severity

Default severity is P1 regardless of correlation, because any confirmed escape vector (privileged container plus `unshare` or `nsenter`) is treated as likely host compromise under the response policy's P1 definition.

If Tetragon's `detect-container-escape` fires and Falco's `Container escape via nsenter` fires against the same pod within the 10-minute window, that is 2 distinct sensor types and reinforces the P1 classification with high confidence. If GuardDuty also reports `PrivilegeEscalation:EKS/ContainerMounts` or `Execution:EKS/HostAssumption` in the same window, all 3 sensor types have correlated, which is the clearest possible signal that the escape succeeded rather than merely being attempted.

Noisy-rule down-weighting applies to `detect-container-escape` if it fires on 5 or more distinct workloads in 24 hours (for example, a CI runner that legitimately calls `unshare`), but down-weighting only adjusts the severity score; it never skips forensics on an individual finding.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` - forensic snapshot before any destructive step; required precondition for everything below.
2. `capture_hubble_flows(namespace, pod_name)` - capture any post-escape network activity visible from the pod's network identity.
3. `collect_tetragon_timeline(pod_uid)` - pull the `unshare` and any subsequent kprobe events in sequence.
4. `collect_audit_events(namespace, pod_name)` - correlate the pod's creation and exec history from the Kubernetes audit log.
5. `collect_live_pod_forensics(namespace, pod_name, profile="filesystem_triage")` - record mount points, socket access, and host-path exposure.
6. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` - arms the pre-deployed Tetragon SIGKILL policy on this pod's outbound connections.
7. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` - selects only the compromised pod; this stops the pod's own traffic but does not and cannot contain the node.
8. `delete_pod(namespace, pod_name)` - removes the escaped container from the node.
9. `patch_deployment(namespace, deployment_name, replicas=0)` - scale down if the Deployment's pod template itself is the escape vector (for example, a hardcoded `privileged: true`), pending a corrected manifest.

### Human follow-up (not automated)

- Node investigation and remediation (`cordon_node`, `drain_node`, instance replacement) is human-only break-glass; the Remediation Agent never calls these tools.
- Credential rotation for any Secret or ServiceAccount token that was live on the node during the suspected escape window, since a successful host-level compromise may have exposed every credential on that node.

## Approval card

- What: Contain and remove the escaping pod; forensics first, then network isolation, then pod deletion. Node-level action is explicitly out of scope for automation.
- Impact: The pod is terminated and replaced by its Deployment. The host node itself is not touched by this automated plan and must be assessed separately by an operator.
- Rollback: Remove the `security.incident/compromised` label and delete the `seks-isolate-<pod>` CiliumNetworkPolicy only after an operator confirms the node is clean or has been replaced.

## Rollback

1. Do not roll back any containment step until a human operator has independently assessed whether the host node requires replacement.
2. Remove the `security.incident/compromised=true` label from any surviving pod, disarming the Tetragon SIGKILL policy.
3. Delete the `seks-isolate-<pod>` CiliumNetworkPolicy once the pod is confirmed clean and the node decision is finalized.
4. If `patch_deployment(replicas=0)` was used, scale the Deployment back to its pre-incident replica count only after the pod template's privileged configuration has been corrected.
5. Rollback is never automatic; it requires explicit operator confirmation per the runbook's approval card.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation after a confirmed or suspected escape is a human-only break-glass decision, not an automated step.
- Do not leave `endpointSelector` empty in the CiliumNetworkPolicy; an empty selector isolates the entire namespace.
- Do not add a `toEntities: world` or equivalent `0.0.0.0/0` egress allow rule to the isolation policy.
- Do not take any action against a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not assume pod-level containment equals node-level containment; the pod-scoped CiliumNetworkPolicy has no effect on traffic the host network namespace itself might generate.
- Do not treat `detect-container-escape` as a false-positive filter without checking the calling binary; legitimate CNI or CSI components may call `unshare` as part of normal operation.

## References

- https://attack.mitre.org/techniques/T1611/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
