# Runbook: Data Exfiltration

- runbook_id: data-exfiltration
- mitre: T1048 Exfiltration Over Alternative Protocol
- default_severity: P1
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker transfers sensitive data out of a compromised container to an external destination over HTTP/HTTPS, DNS tunneling, or a cloud storage API. Typical targets are database dumps, configuration files containing secrets, and user data. Because data impact is likely once this is confirmed, it is treated as P1 from detection, and the priority is stopping any transfer still in flight before investigating scope.

## Detection signals

### GuardDuty
- `UnauthorizedAccess:EKS/ExfiltratedData.Suspicious` — abnormal outbound data transfer pattern
- `Exfiltration:S3/AnomalousBehavior` — anomalous large-volume download from an S3 bucket
- `Exfiltration:IAM/AnomalousBehavior` — data exfiltration via IAM credentials
- `Trojan:EKS/DNSDataExfiltration` — DNS tunneling used to move data out

### Falco
- `Credential file access in container` — read of `/etc/shadow` or `/etc/gshadow` by a non-infrastructure container, which frequently precedes staging credential material for exfiltration, tagged `mitre_credential_access`, `T1003`
- `Suspicious network tool in container` — `tcpdump`, `tshark`, `mitmproxy`, `ncat`, or `netcat` launched in a non-infrastructure container, which can double as an exfil channel, tagged `mitre_discovery`, `T1046`

### Tetragon
- No TracingPolicy in `kubernetes/tetragon/tracing-policies.yaml` directly detects large-file-read-then-send behavior. Not applicable until a dedicated policy ships; `kill-compromised-outbound` applies only after `label_pod` has already armed it for this incident.

### Network indicators
- Outbound traffic volume for the pod is far above its historical baseline, often multiple gigabytes.
- Large data transfer outside normal business hours with no corresponding deployment or batch-job schedule.
- Sustained connection to an unfamiliar external IP or domain that is not part of the workload's known dependency list.
- A sudden spike in DNS query volume or query length to a single domain, consistent with DNS tunneling rather than normal name resolution.

## Correlation and severity

Data exfiltration is P1 by default because confirmed data impact is in scope of the P1 definition. If a second sensor type corroborates the same workload within 10 minutes (for example, Falco's `Credential file access in container` followed by a GuardDuty `Exfiltration:S3/AnomalousBehavior` finding), that confirms the P1 classification rather than raising it further, since P1 is already the ceiling. Apply noisy-rule down-weighting to `Credential file access in container` if it has fired on 5 or more distinct workloads in the trailing 24 hours before treating a single hit in isolation as proof of exfiltration; combine it with the network volume signal before escalating.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` — capture forensic state immediately; this must return `status=success` before any destructive step runs.
2. `capture_hubble_flows(namespace, pod_name)` — capture the live outbound flow records showing destination IP/domain and transfer volume while the connection may still be active.
3. `collect_tetragon_timeline(pod_uid)` — pull the kernel-level file-read and process timeline to identify what was accessed before the transfer.
4. `collect_audit_events(namespace, pod_name)` — pull Kubernetes API audit events in case the exfiltrated data came from a Secret or ConfigMap read via the API rather than the filesystem.
5. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` — arms `kill-compromised-outbound` to SIGKILL the exfiltrating process on its next outbound connection.
6. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` — cut all network traffic for the pod once `checkpoint_pod` has succeeded, stopping any transfer still in progress.
7. `delete_pod(namespace, pod_name)` — remove the pod after isolation and evidence capture are confirmed complete.
8. `patch_deployment(namespace, deployment_name, replicas=0)` — scale down if the exfiltration path is baked into the current image or configuration and a safe replacement is not yet ready.

### Human follow-up (not automated)
- Determine exactly what data left the cluster (file type, approximate size, sensitivity) from the `collect_tetragon_timeline` and `capture_hubble_flows` evidence, and assess whether a regulatory breach notification is required.
- Rotate any credential or secret that the exfiltrated data could have exposed; SEKS has no automated secret-rotation tool, so this is always a human action.
- Review whether the destination IP/domain needs a longer-lived network block beyond the per-incident isolation policy.

## Approval card

- What: Capture forensics, arm the kernel-level kill switch, fully isolate network, and delete the pod that exfiltrated data.
- Impact: Any in-progress transfer is cut immediately on isolation; the pod loses all connectivity; if Deployment-managed, Kubernetes recreates a replacement pod. Legitimate traffic from this pod is also interrupted for the duration of the incident.
- Rollback: Delete the `seks-isolate-<pod>` CiliumNetworkPolicy and remove the `security.incident/compromised` label once the operator confirms rotated credentials are in place and the incident is resolved.

## Rollback

Follow the Section 8 standard rollback sequence: restore the Deployment's pre-incident replica count once a safe image/config is ready, remove the `security.incident/compromised=true` label to disarm `kill-compromised-outbound`, then delete the `seks-isolate-<pod>` CiliumNetworkPolicy. Any credential rotation performed by a human operator is tracked and confirmed separately; it is not reversed as part of this rollback. A `delete_pod` on a Deployment-managed pod is reversible; on a standalone pod it is not. Rollback is never automatic and waits on operator confirmation that the leak is contained.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass.
- Do not set `endpointSelector: {}` in the isolation policy; scope it to `security.incident/compromised: "true"` on this one pod.
- Do not add a `toEntities: [world]` or `0.0.0.0/0` egress allow rule to the isolation policy; any allow rule defeats the point of stopping an active transfer.
- Do not target a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not wait for Slack approval before running `checkpoint_pod`, `capture_hubble_flows`, or `label_pod`; forensics and the reversible kill-switch label run immediately per the P1 approval rule, only the fully destructive steps wait on approval.
- Do not assume the transfer stopped just because the connection dropped; confirm via `capture_hubble_flows` and VPC-level evidence that no further egress occurred after isolation.
- Do not close the incident before a human confirms whether a regulatory breach notification is required; that determination is never automated.

## References

- https://attack.mitre.org/techniques/T1048/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
