# Runbook: Cryptomining

- runbook_id: cryptomining
- mitre: T1496 Resource Hijacking
- default_severity: P2
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker runs a cryptomining binary inside a compromised container to consume cluster compute for their own profit. The binary typically connects outbound to a mining pool over a stratum port within seconds of execution, which makes network behavior as reliable a signal as the process name itself. Left unchecked it drives sustained CPU load and inflates the account's compute bill.

## Detection signals

### GuardDuty

- `CryptoCurrency:EKS/BitcoinTool.B!DNS` - DNS query to a known mining pool domain.
- `CryptoCurrency:EKS/BitcoinTool.B` - direct outbound connection to a known mining pool IP.
- `Execution:EKS/MaliciousFile.Binary` - execution of a binary matching a known-malicious file hash.

### Falco

- `Crypto mining process detected` (`kubernetes/falco/values.yaml`) - fires on `spawned_process` where `proc.name` matches a known miner binary (`xmrig`, `minerd`, `minergate`, `cpuminer`, `ethminer`, `cgminer`, `bfgminer`, `t-rex`, `nbminer`, `phoenixminer`). Priority `CRITICAL`.

### Tetragon

- `detect-cryptominer-egress` (`kubernetes/tetragon/tracing-policies.yaml`) - kprobe on `tcp_connect` posting an event whenever a pod opens a TCP connection to a stratum mining port (3333, 4444, 5555, 7777, 14444, 45700). Forwarded to SNS by the Tetragon forwarder and counted as the `tetragon` sensor in correlation.
- `kill-compromised-outbound` - not a detector; once `label_pod` sets `security.incident/compromised=true` it SIGKILLs any further non-loopback outbound connection from that pod.

### Network indicators

- Outbound TCP to stratum protocol ports: 3333, 4444, 5555, 7777, 14444, 45700.
- Sustained node CPU utilization above 90%.
- Unexpected increase in outbound connection count from a single pod.

## Correlation and severity

Default severity is P2 on a single Falco hit for `Crypto mining process detected`, since the rule's process-name match alone is high-confidence but does not yet confirm sustained resource theft or external pool connectivity.

Per the response policy's correlation rule, when Tetragon `detect-cryptominer-egress` also fires on the same workload within the 10-minute window, that is 2 distinct sensor types: the floor is P2 and the stratum connection is confirmed. When GuardDuty `CryptoCurrency:EKS/BitcoinTool.B` or `BitcoinTool.B!DNS` adds a third distinct sensor type in the same window, the incident escalates to P1 under the "all 3 sensor types correlate" rule.

If `Crypto mining process detected` has fired on 5 or more distinct workloads in the trailing 24 hours, down-weight its individual contribution per the noisy-rule rule; this does not skip evidence collection, it only prevents a single broad match from forcing every affected workload to P1 on its own.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` - forensic snapshot before any destructive step; required precondition for everything below.
2. `capture_hubble_flows(namespace, pod_name)` - capture the outbound stratum-port connections for the incident record.
3. `collect_live_pod_forensics(namespace, pod_name, profile="process_snapshot")` - record the running miner process and command line.
4. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` - arms the pre-deployed Tetragon SIGKILL policy on this pod's outbound connections.
5. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` - cuts off the mining pool connection. The `endpointSelector` must match only the labeled, compromised pod. Selecting by an `app` or deployment label instead would isolate every healthy replica of that workload along with the compromised one, turning a single-pod containment into a service-wide outage.
6. `delete_pod(namespace, pod_name)` - the Deployment recreates a clean replacement pod.
7. `patch_deployment(namespace, deployment_name, replicas=0)` - only if the Deployment's image itself is confirmed compromised (not just one pod); otherwise skip this step and let the Deployment's normal recreate cycle stand.

### Human follow-up (not automated)

- Scan the image repository (ECR) for the compromised image tag and decide whether to remove it from the registry.
- Review how the miner binary reached the container (supply chain, exposed service, stolen credentials) before redeploying.

## Approval card

- What: Isolate and remove the pod running the detected cryptomining binary; forensics run first, then network containment, then pod replacement.
- Impact: The affected pod is terminated and replaced by its Deployment; no other replicas are touched because isolation targets only the labeled pod.
- Rollback: Remove the `security.incident/compromised` label and delete the `seks-isolate-<pod>` CiliumNetworkPolicy once the replacement pod is confirmed clean.

## Rollback

1. Confirm the new pod created by the Deployment shows no stratum-port connections and no matching Falco hits for at least one observation window.
2. Remove the `security.incident/compromised=true` label from any surviving pod, disarming the Tetragon SIGKILL policy.
3. Delete the `seks-isolate-<pod>` CiliumNetworkPolicy.
4. If `patch_deployment(replicas=0)` was used, scale the Deployment back to its pre-incident replica count recorded in the incident's `execution_log`.
5. An operator confirms the incident is resolved before any rollback step runs; rollback is never automatic.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass, not an automated-response step.
- Do not leave `endpointSelector` empty in the CiliumNetworkPolicy; an empty selector isolates the entire namespace.
- Do not add a `toEntities: world` or equivalent `0.0.0.0/0` egress allow rule to the isolation policy; that defeats containment.
- Do not take any action against a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not select the CiliumNetworkPolicy by an `app` or deployment-wide label; it must target only the single compromised pod's incident label.
- Do not claim a Tetragon rule name for this threat in Slack messages or citations; none exists yet in `kubernetes/tetragon/tracing-policies.yaml`.

## References

- https://attack.mitre.org/techniques/T1496/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
