# Runbook: Lateral Movement

- runbook_id: lateral-movement
- mitre: T1210 Exploitation of Remote Services
- default_severity: P2
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker who has compromised one container pivots to other pods, namespaces, or in-cluster services, usually by abusing a mounted ServiceAccount token against the Kubernetes API or by scanning internal network ranges. The goal is to widen the blast radius beyond the first compromised workload before the operator can respond, often by chaining into a second pod with broader permissions than the one originally compromised.

## Detection signals

### GuardDuty
- `Discovery:EKS/MaliciousIPCaller` — internal EKS API call made from a known-malicious IP
- `CredentialAccess:EKS/AnomalousBehavior` — anomalous credential usage pattern against the API server
- `Discovery:EKS/TorIPCaller` — API call routed through the Tor network

### Falco
- `Suspicious network tool in container` — `nmap`, `socat`, `tcpdump`, `tshark`, `mitmproxy`, `ncat`, or `netcat` launched inside a non-infrastructure container, tagged `mitre_discovery`, `T1046`

### Tetragon
- No TracingPolicy in `kubernetes/tetragon/tracing-policies.yaml` targets lateral movement directly. Not applicable until a dedicated policy ships; `kill-compromised-outbound` only fires after the pod is already labeled `security.incident/compromised: "true"`.

### Network indicators
- A pod with no prior history of contacting `kubernetes.default.svc` begins calling the API server directly via `curl`/`wget` instead of a client library.
- A short burst of connections to many distinct internal IPs or ports from the same source pod, consistent with a port scan.
- A new pod-to-pod connection appears between workloads that have never communicated before.
- CoreDNS logs show a spike of lookups for internal service names that the source pod has no legitimate reason to resolve.

## Correlation and severity

This threat starts at P2 per the severity table. If Falco's `Suspicious network tool in container` fires alongside a GuardDuty `Discovery:EKS/MaliciousIPCaller` or `CredentialAccess:EKS/AnomalousBehavior` finding against the same workload within a 10-minute window, that is 2 distinct sensor types correlating, which raises the incident to P2 at minimum (it is already P2 by default, so correlation mainly confirms rather than escalates further here). If a third sensor type also fires in that window, the incident is raised to P1. Because `Suspicious network tool in container` is a broad rule that can fire on legitimate debugging tools, apply noisy-rule down-weighting if it has fired on 5 or more distinct workloads in the trailing 24 hours before treating a single hit as conclusive.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` — forensic checkpoint of the pivoting pod; must return `status=success` before any destructive step below.
2. `capture_hubble_flows(namespace, pod_name)` — capture east-west flow records to map which peer pods and services the source pod actually reached.
3. `collect_tetragon_timeline(pod_uid)` — pull the kernel-level process and connection timeline for the pod.
4. `collect_audit_events(namespace, pod_name)` — pull Kubernetes API server audit events tied to this pod's ServiceAccount.
5. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` — arms the pre-deployed `kill-compromised-outbound` Tetragon policy, which SIGKILLs the pod's process on its next outbound `tcp_connect` to anything other than loopback.
6. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` — hard-isolate the pivoting pod once `checkpoint_pod` has succeeded.
7. `delete_pod(namespace, pod_name)` — remove the pivoting pod after isolation and evidence capture are confirmed.
8. `patch_deployment(namespace, deployment_name, replicas=0)` — only if the Deployment's pod template itself is compromised (for example, a leaked image or ServiceAccount binding baked into the spec); otherwise skip, since the Deployment will recreate a clean replacement pod automatically.

### Human follow-up (not automated)
- Inspect every peer pod identified in the `capture_hubble_flows` output for signs of successful access (new files, unexpected processes, modified RBAC), not just the originating pod.
- Review the ServiceAccount's RoleBindings and ClusterRoleBindings for over-broad grants; SEKS has no automated RBAC mutation tool, so any binding change is a human action.
- Confirm whether the pod's ServiceAccount token should have `automountServiceAccountToken` disabled going forward; this is a Deployment spec change outside the automated response path.

## Approval card

- What: Isolate and remove the pivoting pod via Cilium network policy and pod deletion; forensics run first and are non-destructive.
- Impact: The pod loses all network connectivity immediately on isolation; if Deployment-managed, Kubernetes recreates a replacement pod after deletion. If any peer pod was also compromised, it is handled as a separate incident with its own checkpoint.
- Rollback: Delete the `seks-isolate-<pod>` CiliumNetworkPolicy and remove the `security.incident/compromised` label from any surviving pod once the operator confirms the incident is resolved.

## Rollback

Follow the Section 8 standard rollback sequence from `response-policy.md`: restore the Deployment's pre-incident replica count if it was scaled to 0, remove the `security.incident/compromised=true` label to disarm the Tetragon SIGKILL policy, then delete the `seks-isolate-<pod>` CiliumNetworkPolicy once the pod is confirmed clean or already replaced. A `delete_pod` on a Deployment-managed pod is reversible because the Deployment recreates it; on a standalone pod it is not. Rollback never runs automatically; it waits for an operator to confirm the incident is resolved.

## Do not

- Do not call `cordon_node` or `drain_node`; these are human-only break-glass actions and are never part of automated response.
- Do not set `endpointSelector: {}` in the isolation policy; it must match only `security.incident/compromised: "true"` for the single affected pod.
- Do not add a `toEntities: [world]` or equivalent `0.0.0.0/0` egress allow rule to the isolation policy; isolation means deny, not partial allow.
- Do not target any resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not delete or patch a ClusterRoleBinding automatically; RBAC changes are human-only under this policy regardless of how the lateral movement was achieved.
- Do not assume a single peer-pod hit means the whole namespace is compromised; isolate the pods that showed actual access, not every pod in the namespace.
- Do not skip the ServiceAccount RBAC review even after isolating the pod; the token itself remains valid until a human revokes or rotates it.

## References

- https://attack.mitre.org/techniques/T1210/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- https://kubernetes.io/docs/concepts/security/
