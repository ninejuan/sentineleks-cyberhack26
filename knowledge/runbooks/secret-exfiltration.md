# Runbook: Secret Exfiltration

- runbook_id: secret-exfiltration
- mitre: T1552.007 Unsecured Credentials: Container API
- default_severity: P1
- sensors: falco, tetragon, guardduty
- automated_response: allowed

## Summary

An attacker inside a container reads Kubernetes Secrets, ServiceAccount tokens, or credential files mounted into the pod, with the goal of using those credentials for lateral movement or direct AWS API access. Because stolen credentials remain valid until explicitly revoked, this threat is treated as P1 regardless of whether exfiltration off the pod has been confirmed yet.

## Detection signals

### GuardDuty

- `CredentialAccess:EKS/AnomalousBehavior` - credential-access pattern inconsistent with the workload's baseline.
- `UnauthorizedAccess:IAM/InstanceCredentialExfiltration.OutsideAWS` - EC2 instance metadata credentials used from outside AWS.
- `Recon:IAM/UserPermissions` - enumeration of IAM permissions, often a precursor to targeted credential theft.
- `Discovery:EKS/MaliciousIPCaller` - EKS API call from a known-malicious IP.

### Falco

- `Credential file access in container` (`kubernetes/falco/values.yaml`) - fires on `open`/`openat`/`openat2` read access to `/etc/shadow` or `/etc/gshadow` from a container outside the infrastructure namespaces. Priority `ERROR`, tagged `mitre_credential_access`, `T1003`.

### Tetragon

- `detect-sensitive-file-access` (`kubernetes/tetragon/tracing-policies.yaml`) - kprobe on `security_file_open` matching a path prefix of `/etc/shadow` or `/etc/gshadow`, excluding known legitimate binaries (`passwd`, `useradd`, `apt`, `apk`, and similar package-management tools). This is a tighter, allowlist-aware version of the same signal the Falco rule provides.

### Network indicators

- Access to the Instance Metadata Service endpoint (`169.254.169.254`) from a pod that does not normally call it, visible in `collect_live_pod_forensics` network snapshot.
- Repeated small outbound data transfers to an external IP following a credential-file read, suggestive of staged exfiltration.

## Correlation and severity

Default severity is P1 on a single confirmed hit from either `Credential file access in container` or `detect-sensitive-file-access`, matching the response policy's P1 definition for secret exfiltration.

If both the Falco rule and the Tetragon policy fire against the same pod within the 10-minute window, that is still functionally one detection path corroborated twice; treat GuardDuty's `CredentialAccess:EKS/AnomalousBehavior` or `UnauthorizedAccess:IAM/InstanceCredentialExfiltration.OutsideAWS` as the second distinct sensor type needed to firmly establish correlation. If all 3 sensor types (falco, tetragon, guardduty) report within the window, the incident is confirmed P1 with maximum confidence per the "all 3 sensor types" rule, and should be flagged in Slack as a likely successful exfiltration rather than a mere attempt.

Noisy-rule down-weighting applies to `Credential file access in container` if it fires on 5 or more distinct workloads in 24 hours; a misconfigured sidecar that legitimately reads `/etc/shadow` during startup is a plausible cause. Down-weighting adjusts the severity score only; it does not skip forensics on any individual finding.

## Automated response plan

1. `checkpoint_pod(namespace, pod_name)` - forensic snapshot before any destructive step; required precondition for everything below.
2. `capture_hubble_flows(namespace, pod_name)` - capture any outbound transfer that followed the credential-file read, including IMDS access.
3. `collect_tetragon_timeline(pod_uid)` - pull the `security_file_open` kprobe event sequence against `/etc/shadow` or `/etc/gshadow`.
4. `collect_audit_events(namespace, pod_name)` - correlate Kubernetes Secret `get`/`list` events from the audit log against the pod's ServiceAccount.
5. `collect_live_pod_forensics(namespace, pod_name, profile="env_redacted")` - record environment variables with credential-shaped values redacted, and the pod's mounted Secret volumes.
6. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` - arms the pre-deployed Tetragon SIGKILL policy on this pod's outbound connections.
7. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` - selects only the compromised pod; stops further exfiltration attempts over the network while leaving the credential's validity untouched.
8. `delete_pod(namespace, pod_name)` - removes the pod that read the credential material.
9. `patch_deployment(namespace, deployment_name, replicas=0)` - scale down only if the Deployment's pod template itself over-mounts credentials it does not need, pending a corrected manifest.

### Human follow-up (not automated)

- Rotate every Kubernetes Secret and AWS IAM credential the compromised pod could reach. SEKS has no `rotate_secret` tool on the EKS MCP server; this step is entirely human-only and must be done through the normal Secrets Manager or `kubectl create secret` workflow by an operator.
- Review CloudTrail for use of the exposed credential outside the cluster before considering the incident closed.
- Audit RBAC bindings that granted the pod's ServiceAccount access to the Secret in the first place.

## Approval card

- What: Contain and remove the pod that accessed credential material; forensics first, then network isolation, then pod deletion. Credential rotation is explicitly excluded from automation.
- Impact: The pod is terminated and replaced by its Deployment. The underlying Secret or IAM credential remains valid until a human operator rotates it.
- Rollback: Remove the `security.incident/compromised` label and delete the `seks-isolate-<pod>` CiliumNetworkPolicy only after an operator confirms the exposed credentials have been rotated.

## Rollback

1. Do not roll back containment until a human operator confirms the exposed Secret or IAM credential has been rotated; the exfiltrated value remains live until then.
2. Remove the `security.incident/compromised=true` label from any surviving pod, disarming the Tetragon SIGKILL policy.
3. Delete the `seks-isolate-<pod>` CiliumNetworkPolicy once rotation is confirmed and the pod is replaced.
4. If `patch_deployment(replicas=0)` was used, scale the Deployment back to its pre-incident replica count only after the pod template's credential mounts have been corrected.
5. Rollback is never automatic; an operator confirms resolution before any rollback step runs.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass and unrelated to credential exposure containment.
- Do not leave `endpointSelector` empty in the CiliumNetworkPolicy; an empty selector isolates the entire namespace.
- Do not add a `toEntities: world` or equivalent `0.0.0.0/0` egress allow rule to the isolation policy.
- Do not take any action against a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not call a `rotate_secret` tool; it does not exist on the EKS MCP server. Credential rotation is always a human-only step.
- Do not treat pod deletion as equivalent to credential invalidation; deleting the pod stops further reads, it does not revoke what was already exposed.

## References

- https://attack.mitre.org/techniques/T1552/007/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
