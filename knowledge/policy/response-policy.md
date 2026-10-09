# SEKS Automated Response Policy

- policy_id: seks-response-policy
- version: 1.0
- scope: EKS cluster workload incidents detected by SentinelEKS (SEKS)
- owner: SEKS security engineering

This document is the master policy for the SEKS Solution Agent and Remediation Agent. Every automated recommendation the Solution Agent makes must trace back to this policy and to a runbook in `knowledge/runbooks/`. If a proposed action is not listed in Section 2, it does not exist as an automated response option, regardless of what a runbook's prose describes.

## 1. Scope

This policy governs automated and semi-automated incident response on Amazon EKS clusters managed by SEKS. It applies to:

- Workload-level threats detected by Falco, Tetragon, and AWS GuardDuty EKS Protection, individually or in correlation.
- Containment, forensics, and remediation actions executed through the EKS MCP server.
- Severity classification, approval routing, and rollback for any action taken against a Kubernetes resource in a monitored cluster.

This policy does not govern Terraform or Helm changes to the SEKS platform itself, CI/CD pipeline security, or IAM policy for the SEKS control plane. Those are operator-only and go through `make infra-up` / `make platform-up`, never through the Remediation Agent.

All automated remediation executes exclusively through the EKS MCP server. The Remediation Agent holds an MCP client and an MCP auth token; it does not hold a kubeconfig, does not call the Kubernetes API directly, and does not shell out to `kubectl`. The call path is fixed: Remediation Agent -> MCP client/token -> EKS MCP server -> Kubernetes API.

## 2. Allowed automated actions

These are the only actions the Remediation Agent may invoke. Any runbook step that is not one of these tool names is informational only and requires a human operator.

| action | class | destructive | precondition |
|---|---|---|---|
| `checkpoint_pod` | forensic | no | none; first step of every incident |
| `capture_hubble_flows` | forensic | no | none; runs alongside `checkpoint_pod` |
| `collect_tetragon_timeline` | forensic | no | none |
| `collect_audit_events` | forensic | no | none |
| `collect_live_pod_forensics` | forensic | no | profile in {process_snapshot, network_snapshot, filesystem_triage, env_redacted}; requires approval to inject ephemeral container |
| `label_pod` | containment | no (reversible) | none; sets `security.incident/compromised=true`, which arms the pre-deployed Tetragon SIGKILL TracingPolicy against that pod's outbound connections |
| `apply_cilium_network_policy` | containment | no (reversible) | `checkpoint_pod` returned `status=success` for this incident; `endpointSelector` must match the single compromised pod's `security.incident/compromised=true` label, never `{}` |
| `delete_pod` | containment | yes | `checkpoint_pod` returned `status=success` for this incident |
| `patch_deployment` (replicas=0) | containment | yes | `checkpoint_pod` returned `status=success` for this incident |

`checkpoint_container_experimental` exists on the MCP server but is not a standard automated-response action. It is Experimental tier (see `docs/07-forensics.md` depth tiers): it runs only on explicit approval, reports `status=unsupported` with a `fallback_recommendation` when the node lacks CRIU/checkpoint support, and never blocks or fails the incident pipeline.

`cordon_node` and `drain_node` are **not permitted for automated response in SEKS**. They exist on the MCP server for human-only break-glass use when an operator has independently decided node-level isolation is required. The Remediation Agent must never call them, and no runbook in this knowledge base may recommend them as an automated step.

No other tool names are valid. In particular, there is no `isolate_pod`, `sigkill_label`, `scale_deployment`, `forensic_snapshot`, `rotate_secret`, or `delete_cluster_role_binding` tool on the EKS MCP server exposed to the Remediation Agent. Where a runbook's threat requires a secret rotation or an RBAC change, the automated response ends at forensics and containment, and the runbook marks `automated_response: human_only` for the remediation step.

## 3. Mandatory ordering

Automated response for a given pod follows this fixed sequence:

```
forensics (checkpoint_pod, capture_hubble_flows, ...)
  -> label_pod
  -> apply_cilium_network_policy
  -> delete_pod
  -> patch_deployment (replicas=0)
```

Destructive steps (`delete_pod`, `apply_cilium_network_policy`, `patch_deployment` with `replicas=0`) are blocked server-side until `checkpoint_pod` has returned `status=success` in the current incident's `execution_log`. This is enforced in the Remediation handler, not only in the agent's system prompt, because an LLM tool-use loop can reorder calls. The handler is the last line of defense: if `checkpoint_pod` has not succeeded, every destructive tool call returns `status=blocked` regardless of what the agent requests.

`label_pod` may run immediately after `checkpoint_pod` succeeds, since it is reversible (removing the label disarms the Tetragon SIGKILL policy) and does not itself destroy anything. `apply_cilium_network_policy` follows the same precondition as the hard-destructive actions because, once applied, it halts all traffic to the pod and can mask further forensic signal if evidence capture was incomplete.

## 4. Protected namespaces

No automated action may ever target a resource in these namespaces, regardless of severity, correlation, or approval status:

- `kube-system`
- `kube-public`
- `kube-node-lease`
- `seks`
- `falco`
- `tetragon`
- `monitoring`
- `external-secrets`
- `cilium`

A finding whose affected pod lives in one of these namespaces is downgraded to human-only handling and routed to Slack for manual triage. The Solution Agent must not recommend `label_pod`, `apply_cilium_network_policy`, `delete_pod`, or `patch_deployment` against any resource in a protected namespace, and the EKS MCP server rejects such calls server-side as a second line of defense.

## 5. Severity and approval

| severity | meaning | approval |
|---|---|---|
| P1 (Critical) | Active compromise with likely data or control-plane impact (reverse shell, data exfiltration, secret exfiltration, privilege escalation, container escape) | Slack human approval required before destructive steps; forensics and `label_pod` run immediately |
| P2 (High) | Confirmed malicious behavior without confirmed data impact (cryptomining, lateral movement, RBAC abuse, image tampering) | Slack human approval required |
| P3 (Medium) | Suspicious but lower-confidence signal (DNS anomaly without confirmed tunneling) | Auto-remediate allowed without prior approval; result posted to Slack for visibility |
| P4 (Low) | Informational or noisy signal | Log only; no remediation action is taken |

Correlation escalation rule: if 2 or more distinct sensor types (falco, tetragon, guardduty) report findings against the same workload within a 10-minute window, the incident severity is raised to at least P2 even if any single sensor's finding alone would have scored lower. If all 3 sensor types correlate on the same workload within the same 10-minute window, the incident is raised to P1.

Noisy-rule down-weighting: if a specific detection rule has fired on 5 or more distinct workloads within a trailing 24-hour window, that rule's individual contribution to severity scoring is down-weighted for new findings until the rate subsides. This prevents a single misconfigured or overly broad rule from forcing every workload it touches to P1 through correlation alone. Down-weighting adjusts the severity score; it does not suppress the finding or skip evidence collection.

## 6. Evidence requirements

Every remediation recommendation the Solution Agent produces must cite at least one runbook document from `knowledge/runbooks/` by its `runbook_id`. A recommendation with no citation is not actionable: the Solution Agent must degrade it to a human-review item rather than present it as an automated-response candidate.

Citations must reference the specific runbook section that supports the recommended action (for example, the "Automated response plan" or "Correlation and severity" section), not just the runbook as a whole. If the correlation engine itself is degraded (see Section 5 and the postmortem examples in `knowledge/postmortems/`), the Solution Agent must say so explicitly in the Slack message rather than silently falling back to single-sensor severity.

## 7. Network policy constraints

Any `CiliumNetworkPolicy` generated by the Remediation Agent must satisfy all of the following before it is applied:

- `endpointSelector` must never be empty (`{}`). An empty selector matches every pod in the namespace and converts a single-pod isolation into a namespace-wide outage. The selector must match exactly `security.incident/compromised: "true"` scoped to the one pod being isolated.
- The policy must not include a `toEntities: [world]` or an equivalent `0.0.0.0/0` allow rule in an isolation policy. An isolation policy's purpose is to deny; any egress allow rule defeats containment.
- The policy must not target a protected namespace (Section 4).
- No generated Kubernetes manifest (Pod, Deployment patch, or NetworkPolicy) may set `privileged: true`, `hostPID: true`, or `hostNetwork: true`. These fields are never valid in a remediation-generated manifest, since remediation only isolates or scales down workloads, it does not create new privileged ones.

These constraints are enforced by a Semgrep gate on every AI-generated manifest before it reaches the MCP server, in addition to the server-side `_sanitize_incident_id` and label/annotation sanitization already required by project convention.

## 8. Rollback

Every containment action taken under this policy must be reversible unless the underlying resource was deleted as part of normal pod lifecycle (a `delete_pod` on a Deployment-managed pod is reversible because the Deployment recreates it; a `delete_pod` on a standalone pod is not, and runbooks must flag that distinction).

Standard rollback sequence, in reverse order of the Section 3 ordering:

1. Scale the Deployment back to its pre-incident replica count (recorded in the incident's `execution_log` before `patch_deployment` set it to 0).
2. Remove the `security.incident/compromised=true` label from any surviving pod, which disarms the Tetragon SIGKILL policy for that pod.
3. Delete the incident-specific `CiliumNetworkPolicy` (named `seks-isolate-<pod>`) once the pod is confirmed clean or already replaced.
4. Confirm no other automated action (RBAC change, secret rotation, image repository policy) was left in a partial state; those are human-only actions under this policy and are rolled back manually by the responding operator per the runbook's "Rollback" section.

Rollback is never automatic. An operator confirms the incident is resolved (via the runbook's "Approval card" and verification evidence) before any rollback step runs.
