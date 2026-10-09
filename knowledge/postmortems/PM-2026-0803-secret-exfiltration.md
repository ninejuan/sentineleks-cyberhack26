# Post-mortem: Secret exfiltration on `auth-gateway`, correlation outage handled by explicit degradation

Example post-mortem from the SEKS demo environment.

- incident_id: inc-20260803-032017-guardduty-9c4e5a
- severity: P1
- status: resolved
- detected_at: 2026-08-03T03:20:17Z
- resolved_at: 2026-08-03T04:02:33Z
- mttd: 3m22s
- mttr: 42m16s
- sensors: guardduty, falco
- runbook_cited: secret-exfiltration

## Summary

A GuardDuty finding reported anomalous credential access behavior from a pod in the `auth-gateway` deployment in the `demo` namespace on cluster `seks-demo`, consistent with a process reading the pod's service account token outside its normal startup window. Falco's `Credential file access in container` rule corroborated the finding about three minutes later. Secret exfiltration is a direct P1 category under the policy, so the incident started at P1 immediately. The notable event in this incident is that the ClickHouse correlation query that normally confirms sensor overlap timed out once during triage. Rather than silently falling back to single-sensor severity, the system recorded `correlation: unavailable` in the incident record and posted that fact to Slack as required by policy Section 6. The on-call operator saw the degraded-correlation note, manually confirmed the second sensor by reading the raw Falco log, and proceeded with the P1 response. Because SEKS has no automated secret or IAM credential rotation tool, the token invalidation and IAM key rotation were completed by a human operator after the automated containment finished.

## Impact

- One pod (`auth-gateway-5f9c8b7d6-qnw3r`) had its service account token read by an unexpected process for an unknown duration before detection; the token's `iat` claim showed it was minted 6 hours before the read, consistent with normal pod lifetime rather than a freshly minted token.
- CloudTrail review (performed manually by the operator, since SEKS does not automate CloudTrail correlation) found no AWS API calls using the pod's associated IAM role outside the cluster's own IP range, meaning the token read was caught before any external use was confirmed.
- No other pod was affected. `auth-gateway` runs with 2 replicas; the healthy replica continued serving traffic.

## Timeline (UTC)

| time | source | event |
|---|---|---|
| 2026-08-03T03:20:17Z | guardduty | `CredentialAccess:EKS/AnomalousBehavior` finding reports anomalous service account token access on `auth-gateway-5f9c8b7d6-qnw3r` |
| 2026-08-03T03:20:49Z | seks-triage | Secret exfiltration matches the P1 critical category directly per Section 5; severity set to P1 |
| 2026-08-03T03:21:05Z | seks-triage | ClickHouse correlation query (Q1 on `sensor_events`) times out after a 2000ms budget; triage records `correlation: unavailable` for this incident rather than falling back to a single-sensor score |
| 2026-08-03T03:21:12Z | seks-solution | Solution Agent posts to Slack `#security-incidents`, stating explicitly that sensor correlation is degraded and the P1 classification rests on the GuardDuty finding alone pending manual confirmation, per policy Section 6 |
| 2026-08-03T03:23:40Z | human-operator | On-call operator manually greps the Falco DaemonSet log and finds `Credential file access in container` fired at 03:23:08Z against the same pod, confirming the second sensor by hand |
| 2026-08-03T03:24:02Z | human-operator | Operator posts the manual confirmation to the incident thread and escalates proceeding with the P1 plan |
| 2026-08-03T03:24:30Z | seks-remediation | Forensics begins: `checkpoint_pod`, `capture_hubble_flows`, and `collect_audit_events` invoked |
| 2026-08-03T03:26:51Z | eks-mcp-server | `checkpoint_pod` returns `status=success` |
| 2026-08-03T03:27:14Z | eks-mcp-server | `collect_audit_events` returns `status=success`; audit log shows a `get` on the pod's mounted secret 90 seconds before the GuardDuty finding |
| 2026-08-03T03:28:00Z | seks-solution | Containment plan posted citing runbook_id `secret-exfiltration`; plan notes the secret rotation and IAM key deactivation are human-only steps per policy Section 2 |
| 2026-08-03T03:30:55Z | slack | `@oncall-secops` approves the containment plan |
| 2026-08-03T03:31:10Z | seks-remediation | `label_pod` sets `security.incident/compromised=true` |
| 2026-08-03T03:31:40Z | seks-remediation | `apply_cilium_network_policy` applied, scoped to the labeled pod |
| 2026-08-03T03:32:20Z | seks-remediation | `delete_pod` removes the pod; Deployment recreates it with a freshly issued token |
| 2026-08-03T03:40:00Z | human-operator | Operator manually rotates the Kubernetes service account token and deactivates the associated IAM access key, outside SEKS automation since no rotation tool exists in the MCP server |
| 2026-08-03T04:02:33Z | human-operator | New pod confirmed healthy with rotated credentials; CloudTrail shows no further use of the old access key; incident marked resolved |

## Detection and correlation

- Distinct sensors firing against `auth-gateway` inside the 10-minute window: 2 (guardduty, falco), confirmed manually after the automated correlation query failed.
- `correlation: unavailable` was recorded for 2m35s, from the first timeout at 03:21:05Z until the manual confirmation at 03:23:40Z.
- The ClickHouse query timeout was a single transient failure; a retry of the same query 4 minutes later at 03:25:00Z returned normally in 112ms, confirming the correlation backend itself was healthy and this was not a sustained outage.
- Falco rule `Credential file access in container` had fired on 1 distinct workload in the trailing 24 hours, below the noisy-rule threshold.

## Response actions

| step | MCP tool | status | evidence_uri |
|---|---|---|---|
| 1 | checkpoint_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260803-032017-guardduty-9c4e5a/checkpoints/auth-gateway-5f9c8b7d6-qnw3r/checkpoint.tar.gz |
| 2 | capture_hubble_flows | success | s3://seks-forensics-<account-id>/incidents/inc-20260803-032017-guardduty-9c4e5a/hubble/auth-gateway-5f9c8b7d6-qnw3r/flows.json |
| 3 | collect_audit_events | success | s3://seks-forensics-<account-id>/incidents/inc-20260803-032017-guardduty-9c4e5a/audit/auth-gateway-5f9c8b7d6-qnw3r/events.json |
| 4 | label_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260803-032017-guardduty-9c4e5a/actions/label_pod.json |
| 5 | apply_cilium_network_policy | success | s3://seks-forensics-<account-id>/incidents/inc-20260803-032017-guardduty-9c4e5a/actions/seks-isolate-auth-gateway-5f9c8b7d6-qnw3r.yaml |
| 6 | delete_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260803-032017-guardduty-9c4e5a/actions/delete_pod.json |

Secret rotation and IAM access key deactivation are not listed above because SEKS has no `rotate_secret` or equivalent tool on the EKS MCP server; both were completed by the human operator per policy Section 2's human-only path for credential rotation.

## Approval

- approver: @oncall-secops
- decision: approved
- decided_at: 2026-08-03T03:30:55Z
- time-to-approve: 2m55s

## Root cause

A sidecar container in the `auth-gateway` pod ran a logging utility with a misconfigured debug flag that caused it to read and print the full contents of its mount directory, including the mounted service account token path, into its own stdout on an unrelated error condition. This was not an external attacker; it was a misconfigured internal component producing attacker-shaped behavior. GuardDuty and Falco both correctly flagged the token read as anomalous because the reading process was the logging sidecar, not the expected application process.

## What went well

- The correlation outage was handled exactly as policy Section 6 requires: the system stated the degradation explicitly in Slack rather than silently scoring the incident as if only GuardDuty had fired. The operator had the information needed to manually confirm the second sensor without guessing.
- Forensics completed and returned `status=success` before any containment step, preserving the audit trail that later confirmed the root cause was a misconfigured sidecar rather than external access.
- The Solution Agent correctly flagged secret rotation and IAM key deactivation as human-only steps in its initial plan rather than attempting to invoke a nonexistent `rotate_secret` tool, consistent with policy Section 2.

## What went wrong

- The ClickHouse correlation query timeout added roughly 2.5 minutes of manual verification work before the operator could proceed with confidence; a cached fallback for the correlation query would have avoided the gap entirely.
- The root cause, a debug flag left enabled in the logging sidecar, had been in that configuration for an unknown period before this incident; no earlier signal caught the misconfiguration itself, only its eventual token-read side effect.

## Action items

| action | owner role | due | status |
|---|---|---|---|
| Add a short-TTL cache in front of the Q1 correlation query so a single query timeout does not block correlation for the full retry interval | platform engineering | 2026-08-10 | done |
| Audit all sidecar containers across `demo` for debug flags that read mount paths into logs | application engineering | 2026-08-17 | in_progress |
| Document the manual secret-rotation runbook steps as a standing checklist in the on-call handbook, since this remains human-only under current policy | security engineering | 2026-08-24 | open |

## Evidence and citations

- Solution Agent cited runbook_id `secret-exfiltration`, section "Detection signals", for the GuardDuty and Falco rule names used to confirm the finding.
- Solution Agent cited `knowledge/policy/response-policy.md` Section 6, "Evidence requirements", for the explicit degraded-correlation statement posted to Slack instead of a silent single-sensor fallback.
- Solution Agent cited `knowledge/policy/response-policy.md` Section 2, "Allowed automated actions", for marking secret rotation and IAM key deactivation as human-only since no such tool exists on the EKS MCP server.
</content>
