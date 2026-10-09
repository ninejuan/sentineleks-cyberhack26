# Runbook: RBAC Abuse

- runbook_id: rbac-abuse
- mitre: T1078 Valid Accounts
- default_severity: P2
- sensors: falco, tetragon, guardduty
- automated_response: human_only

## Summary

An attacker abuses an over-provisioned Kubernetes RBAC grant, or creates a new ClusterRoleBinding, to obtain cluster-admin privileges. Because this uses otherwise-valid credentials, it is hard to distinguish from a legitimate operational change, and a successful attempt can give the attacker control of the entire cluster. Detection depends almost entirely on the Kubernetes API audit trail rather than runtime sensors, since the attack happens at the control-plane object level.

## Detection signals

### GuardDuty
- `PrivilegeEscalation:EKS/AnomalousBehavior` — anomalous privilege-escalation pattern
- `Persistence:EKS/AnomalousBehavior` — anomalous RBAC resource creation consistent with establishing persistence
- `Discovery:EKS/MaliciousIPCaller` — RBAC resources queried from a known-malicious IP

### Falco
- No custom rule in `kubernetes/falco/values.yaml` directly inspects ClusterRole or ClusterRoleBinding creation (Falco's visibility here is syscall/file/process level, not Kubernetes API object level). Not applicable; RBAC object changes are observed through the EKS control-plane audit log instead, surfaced via `collect_audit_events`.

### Tetragon
- `detect-privilege-escalation` — fires on `setuid(0)` inside a container, which can accompany an attacker consolidating root access after an RBAC grant succeeds, though it detects in-container privilege escalation rather than the Kubernetes RBAC change itself.

### Network indicators
- Not applicable. RBAC abuse is an API-object-level attack; it has no direct network signature. Correlate instead with `collect_audit_events` output for the affected ServiceAccount or user.

### Other indicators
- A `ClusterRoleBinding` is created outside business hours and binds to `cluster-admin`.
- A ServiceAccount or user performs a burst of `list` calls against `roles`, `clusterroles`, or `rolebindings` in a short window, consistent with permission enumeration before an escalation attempt.
- A `ClusterRole` is created or modified with a wildcard `*` verb or `*` resource, granting broader access than any legitimate workload role in the cluster normally requires.

## Correlation and severity

RBAC abuse is P2 by default. If a second sensor type corroborates the same identity within 10 minutes (for example, GuardDuty's `PrivilegeEscalation:EKS/AnomalousBehavior` alongside Tetragon's `detect-privilege-escalation` firing in a pod using the implicated ServiceAccount), the incident is confirmed at P2 or raised to P1 if a third sensor type also correlates in that window. Audit-log evidence of an actual `cluster-admin` ClusterRoleBinding creation, independent of sensor correlation, should be treated as high-confidence regardless of down-weighting, since this rule type does not fire often enough across workloads to qualify for the noisy-rule exception.

## Automated response plan

Automated response for this threat is forensics only. SEKS has no RBAC mutation tool (no `delete_cluster_role_binding`, no `patch_cluster_role_binding`); revoking the RoleBinding or ClusterRoleBinding is a human action end to end.

1. `checkpoint_pod(namespace, pod_name)` — if the abuse is tied to a specific running pod (for example, the pod whose ServiceAccount was used to create the binding), checkpoint it first; this is the only step that unlocks any further pod-scoped action.
2. `collect_audit_events(namespace, pod_name)` — pull the Kubernetes API audit trail for the implicated ServiceAccount or pod, including the RBAC object creation/modification events, as the primary evidence for the human responder.
3. `collect_tetragon_timeline(pod_uid)` — pull the kernel-level timeline for the pod in case `detect-privilege-escalation` or related process activity corroborates the RBAC finding.
4. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` — only if the pod itself (not just the identity) shows signs of compromise; this arms `kill-compromised-outbound` as a containment measure for that pod while the human reviews the RBAC grant.

No `apply_cilium_network_policy`, `delete_pod`, or `patch_deployment` step is included here, because network isolation or pod removal does nothing to revoke an already-granted ClusterRoleBinding; those steps may still apply to a specific compromised pod per the general ordering in Section 3 if forensics reveal in-pod compromise, but they do not address the RBAC grant itself.

### Human follow-up (not automated)
- Review and delete the suspicious ClusterRoleBinding or RoleBinding directly via `kubectl` or GitOps, per the project's break-glass procedure; this is the actual fix and SEKS provides no automated path for it.
- Confirm whether the credential used to create the binding (IAM user, ServiceAccount token) needs to be deactivated or rotated.
- Audit the cluster for other `cluster-admin` bindings or wildcard ClusterRoles created around the same time window, since one successful RBAC abuse often indicates a broader credential compromise.

## Approval card

- What: Collect forensic evidence (pod checkpoint, audit events, Tetragon timeline) on the implicated pod and identity; no RBAC object is modified automatically.
- Impact: Forensic collection is non-destructive and has no effect on cluster availability or the live RBAC configuration. The actual fix (removing the binding) is applied by a human and is not covered by this automated plan.
- Rollback: Not applicable to the automated steps, since none of them mutate RBAC or delete anything. If `label_pod` was applied to a specific pod, remove the label once the human responder confirms that pod is not independently compromised.

## Rollback

The automated steps here are entirely non-destructive forensics, so there is nothing to roll back on the SEKS side. If `label_pod` was applied to a pod as a containment measure, remove the `security.incident/compromised=true` label to disarm `kill-compromised-outbound` once the operator confirms that pod is clean. The RBAC fix itself (deleting the binding) is applied and, if needed, reverted entirely by the human operator outside this policy, following the operator's own change-management process for RBAC resources.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is human-only break-glass and unrelated to an RBAC-only finding.
- Do not call `delete_pod` or `apply_cilium_network_policy` on a pod solely because its ServiceAccount was implicated; only do so if forensics on that specific pod show independent compromise.
- Do not attempt to delete or patch a ClusterRoleBinding or RoleBinding through any MCP tool; no such tool exists, and this is a human-only action end to end.
- Do not use an empty `endpointSelector` or a `toEntities: [world]` egress rule if a network policy is applied to a genuinely compromised pod under this incident.
- Do not target a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not treat the absence of a Falco signal as evidence of no RBAC abuse; Falco does not observe Kubernetes API objects, so `collect_audit_events` is the authoritative source here.
- Do not close the incident until the human responder confirms the suspicious binding is deleted; forensic collection alone does not remediate the exposure.

## References

- https://attack.mitre.org/techniques/T1078/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- https://kubernetes.io/docs/concepts/security/
