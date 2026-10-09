# Runbook: Image Tampering

- runbook_id: image-tampering
- mitre: T1525 Implant Internal Image
- default_severity: P2
- sensors: falco, tetragon, guardduty
- automated_response: human_only

## Summary

An attacker inserts malicious code into a container image or deploys an image from an untrusted registry, typically through a compromised CI/CD pipeline, stolen ECR push credentials, or image-tag hijacking. A tampered image can spread to every pod that pulls it, so the running workload is isolated immediately while the registry-side fix is handled by a human. The automated plan buys time by stopping the currently running pod and blocking new replicas, not by fixing the underlying registry trust problem.

## Detection signals

### GuardDuty
- `Trojan:EKS/DockerLayerInjection.B` — malicious code detected in a container image layer
- `Execution:EKS/MaliciousFile.Binary` — execution of a malicious binary originating from the image
- `Backdoor:EKS/MaliciousFile` — backdoor file detected inside the image
- `UnauthorizedAccess:ECR/MaliciousIPCaller` — ECR accessed from a known-malicious IP

### Falco
- `Binary modified in running container` — a write to `/bin`, `/usr/bin`, or `/sbin` inside a running container, the exact signal for a tampered image modifying its own binaries at runtime, tagged `mitre_persistence`, `T1554`, priority CRITICAL

### Tetragon
- No TracingPolicy in `kubernetes/tetragon/tracing-policies.yaml` is scoped to image-tampering specifically. `detect-sensitive-file-access` and `detect-container-escape` are adjacent but not applicable to this threat; treat Tetragon as not applicable here beyond the general `kill-compromised-outbound` containment policy once the pod is labeled.

### Network indicators
- Not applicable as a primary signal. Image tampering is detected through binary/layer integrity, not network behavior; a tampered image may later produce network indicators covered by other runbooks (reverse-shell, data-exfiltration) once it executes malicious code.

### Other indicators
- The running pod's image digest does not match the digest currently tagged in the registry for that image reference.
- A new image layer appears in the image history that was not produced by the known CI/CD pipeline.

## Correlation and severity

Image tampering is P2 by default. If a second sensor type corroborates the same workload within 10 minutes (for example, Falco's `Binary modified in running container` alongside a GuardDuty `Trojan:EKS/DockerLayerInjection.B` finding), the incident is confirmed at P2 or raised to P1 if a third sensor type also correlates in that window. `Binary modified in running container` carries CRITICAL priority and is not expected to be a high-volume rule; apply noisy-rule down-weighting only if it has genuinely fired on 5 or more distinct workloads in the trailing 24 hours, which would itself suggest a cluster-wide supply-chain compromise rather than a single tampered image.

## Automated response plan

The automated portion of this runbook ends at forensics and containment of the running pod. SEKS has no registry-mutation tool exposed to the Remediation Agent (no image-digest pinning, no repository policy change, no image-signature verification trigger); fixing the registry side and redeploying from a trusted digest is a human action.

1. `checkpoint_pod(namespace, pod_name)` — capture forensic state of the pod running the suspected tampered image; required before any further pod-scoped action.
2. `capture_hubble_flows(namespace, pod_name)` — capture network flows in case the tampered image is also phoning out, which would hand off to the reverse-shell or data-exfiltration runbook.
3. `collect_tetragon_timeline(pod_uid)` — pull the kernel-level process and file-write timeline covering the binary modification event.
4. `collect_live_pod_forensics(namespace, pod_name, profile="filesystem_triage")` — capture a filesystem triage snapshot of the running container to compare against the expected image contents.
5. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` — arms `kill-compromised-outbound` as a containment measure in case the tampered binary attempts outbound connections.
6. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` — isolate the pod's network once `checkpoint_pod` has succeeded.
7. `delete_pod(namespace, pod_name)` — remove the pod running the tampered image after isolation and evidence capture are confirmed complete.
8. `patch_deployment(namespace, deployment_name, replicas=0)` — scale the Deployment to zero to stop it from creating further replicas of the tampered image while the registry-side fix is pending.

### Human follow-up (not automated)
- Compare the running image digest against the expected digest in the registry; a mismatch confirms tampering versus a legitimate but unexpected deployment.
- Investigate how the tampered image reached the registry (compromised CI/CD credentials, stolen push access, tag hijacking) and revoke the credential used.
- Redeploy the Deployment from a known-good, trusted image digest only after the registry-side issue is fixed; this is the actual remediation and has no automated path in SEKS.

## Approval card

- What: Capture forensics and a filesystem triage snapshot, isolate network, delete the pod, and scale the Deployment to zero; the registry fix and redeploy are handled separately by a human.
- Impact: The pod running the tampered image loses network connectivity and is removed; the Deployment stops producing new replicas until a human redeploys from a trusted digest, meaning the workload is unavailable for the duration of the incident.
- Rollback: Scale the Deployment back to its pre-incident replica count only after redeploying from a trusted image digest; delete the `seks-isolate-<pod>` CiliumNetworkPolicy and remove the `security.incident/compromised` label once the operator confirms the new deployment is clean.

## Rollback

Follow the Section 8 standard rollback sequence: scale the Deployment back to its pre-incident replica count only once a trusted image digest is confirmed and set in the Deployment spec by a human operator, remove the `security.incident/compromised=true` label to disarm `kill-compromised-outbound`, then delete the `seks-isolate-<pod>` CiliumNetworkPolicy. A `delete_pod` on a Deployment-managed pod is reversible once the Deployment is scaled back up with a trusted image; redeploying with the same tampered digest would simply recreate the incident. Rollback is never automatic and waits for the operator's explicit confirmation.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass.
- Do not scale the Deployment back up before a human confirms the image digest in use is trusted; the automated plan has no way to verify registry-side trust on its own.
- Do not set `endpointSelector: {}` in the isolation policy; scope it to `security.incident/compromised: "true"` on this one pod.
- Do not add a `toEntities: [world]` or `0.0.0.0/0` egress allow rule to the isolation policy.
- Do not target a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not attempt to delete or re-tag an ECR image, change a repository policy, or trigger an image scan through any MCP tool; no such tool exists, and the registry-side fix is human-only.
- Do not treat a missing GuardDuty finding as proof the image is clean; the Falco `Binary modified in running container` rule can be the only sensor to fire if tampering happens entirely at runtime rather than at the image-pull stage.

## References

- https://attack.mitre.org/techniques/T1525/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
