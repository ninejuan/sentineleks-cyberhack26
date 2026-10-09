# Runbook: Reverse Shell

- runbook_id: reverse-shell
- mitre: T1059 Command and Scripting Interpreter
- default_severity: P1
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker inside a container opens an outbound connection to a command-and-control server and attaches a shell to it, letting them run commands remotely while sidestepping inbound firewall rules. Because the shell originates the connection from inside the cluster, standard ingress controls never see it. This is treated as an active compromise and is P1 the moment it is confirmed, since the attacker already has interactive command execution inside the cluster network.

## Detection signals

### GuardDuty
- `Backdoor:EKS/C2Activity.B` — connection to a known command-and-control server
- `Backdoor:EKS/MaliciousFile.Binary` — execution of a known reverse-shell binary
- `UnauthorizedAccess:EKS/TorIPCaller` — access routed through the Tor network

### Falco
- `Suspicious network tool in container` — `ncat`, `netcat`, or `socat` launched in a non-infrastructure container, the closest matching custom rule in `kubernetes/falco/values.yaml` for shell-driven outbound tooling, tagged `mitre_discovery`, `T1046`

### Tetragon
- `kill-compromised-outbound` — once the pod carries the `security.incident/compromised: "true"` label, this policy SIGKILLs any process making a `tcp_connect` to a destination other than `127.0.0.1`, which is the mechanism used to cut the shell's live connection.
- `detect-privilege-escalation` — if the shell process additionally calls `setuid(0)` to gain root inside the container, this policy posts an event; treat it as corroborating evidence that the shell is being used to escalate, not just execute commands.

### Network indicators
- A shell process (`bash`, `sh`, `zsh`) holds an established TCP connection where its stdin/stdout maps to a network socket instead of a TTY.
- A connection to `/dev/tcp/<ip>/<port>` or an equivalent descriptor-redirect pattern from a shell.
- A script interpreter (Python, Perl, Ruby) opens a raw socket and then execs a shell on it.
- The destination IP or domain for the outbound connection has no prior history of being contacted by any workload in the cluster.

## Correlation and severity

Reverse shell is P1 by default per the severity table because it represents active compromise with likely control-plane impact. If a second sensor type (for example, Falco's `Suspicious network tool in container` alongside a GuardDuty `Backdoor:EKS/C2Activity.B` finding) corroborates the same workload within 10 minutes, this confirms rather than raises the severity, since P1 is already the ceiling triggered by GuardDuty's Backdoor category alone. Apply noisy-rule down-weighting only if the triggering Falco rule has independently fired on 5 or more distinct workloads in the trailing 24 hours; a genuine Backdoor GuardDuty finding should not be down-weighted.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` — capture forensic state before anything else runs; destructive steps are blocked server-side until this returns `status=success`.
2. `capture_hubble_flows(namespace, pod_name)` — record the live network flow to the C2 destination while it still exists.
3. `collect_tetragon_timeline(pod_uid)` — pull the kernel-level process tree and connection history showing which process opened the shell and which parent spawned it.
4. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` — arms `kill-compromised-outbound`, which SIGKILLs the shell process on its next outbound connection attempt.
5. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` — cut all remaining ingress/egress for the pod once `checkpoint_pod` has succeeded.
6. `delete_pod(namespace, pod_name)` — remove the compromised pod after isolation and evidence capture.
7. `patch_deployment(namespace, deployment_name, replicas=0)` — scale down the Deployment if the vulnerability that let the shell in is baked into the current image or spec, pending a patched rollout.

### Human follow-up (not automated)
- Identify and patch the vulnerability that let the shell execute (web application exploit, exposed debug endpoint, vulnerable dependency) before scaling the Deployment back up.
- Review the C2 destination IP/domain against threat intelligence and decide whether to add it to a longer-lived network block outside the per-incident isolation policy.
- Confirm whether the shell's command history (captured in `collect_tetragon_timeline` output) reveals any additional lateral actions that need their own incident.
- Check whether any other pod shares the same image or deployment pattern as the compromised pod, since a single vulnerable image is often rolled out to several workloads.

## Approval card

- What: Arm the kernel-level kill switch, isolate network, and delete the pod running the reverse shell; forensics run first and are non-destructive.
- Impact: The shell's active connection is terminated and the pod loses all network connectivity; if Deployment-managed, Kubernetes recreates a replacement pod. Any in-progress work in that pod unrelated to the shell is also interrupted.
- Rollback: Delete the `seks-isolate-<pod>` CiliumNetworkPolicy and remove the `security.incident/compromised` label once the operator confirms the vulnerability is patched and the incident is resolved.

## Rollback

Follow the Section 8 standard rollback sequence: scale the Deployment back to its pre-incident replica count once a patched image is ready, remove the `security.incident/compromised=true` label to disarm `kill-compromised-outbound`, then delete the `seks-isolate-<pod>` CiliumNetworkPolicy. A `delete_pod` on a Deployment-managed pod is reversible; on a standalone pod it is not, and the operator must redeploy it manually. Rollback never runs automatically; an operator confirms the vulnerability is patched and the incident resolved before any rollback step executes.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass, never automated.
- Do not set `endpointSelector: {}` in the isolation policy; scope it to `security.incident/compromised: "true"` on this one pod only.
- Do not add a `toEntities: [world]` or `0.0.0.0/0` egress allow rule to the isolation policy.
- Do not target a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not scale the Deployment back up before the vulnerability is patched; redeploying the same vulnerable image reopens the same shell.
- Do not skip `checkpoint_pod` to isolate faster; the handler blocks `apply_cilium_network_policy` and `delete_pod` until it succeeds, and skipping evidence capture destroys the forensic trail for an active-compromise incident.
- Do not rely on killing the shell process alone as containment; `label_pod` and `apply_cilium_network_policy` are both required because a persistent process could re-establish the connection before the pod is deleted.

## References

- https://attack.mitre.org/techniques/T1059/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
