# Post-mortem: Reverse shell on `checkout-api`, killed by Tetragon before the network policy landed

Example post-mortem from the SEKS demo environment.

- incident_id: inc-20260827-091844-falco-b2e091
- severity: P1
- status: resolved
- detected_at: 2026-08-27T09:18:44Z
- resolved_at: 2026-08-27T09:31:12Z
- mttd: 1m05s
- mttr: 12m28s
- sensors: falco, guardduty
- runbook_cited: reverse-shell

## Summary

A pod in the `checkout-api` deployment in the `demo` namespace on cluster `seks-demo` spawned an interactive shell with a live outbound TCP connection to an external IP, the textbook signature of a reverse shell. Falco's `Suspicious network tool in container` rule (an `ncat` launched by the shell) and GuardDuty `Backdoor:EKS/C2Activity.B` both fired within a minute of each other. Because reverse shell matches the P1 critical category by itself under the policy's severity table, the incident did not need correlation to escalate; it started at P1 immediately. The Slack approval came back in under two minutes. The notable detail in this incident is ordering: the pre-deployed Tetragon SIGKILL policy fired the moment `label_pod` applied the `security.incident/compromised=true` label, killing the shell's outbound connection before the `CiliumNetworkPolicy` had finished propagating through Cilium's agents. Evidence capture had already completed by that point, so nothing was lost.

## Impact

- One pod (`checkout-api-6b8f7d4c9-ht5mz`) had an active outbound connection to an external IP for roughly 9 minutes before the shell was killed.
- No other pod in `demo` was affected. `checkout-api` runs with 3 replicas behind a Service; the other 2 replicas continued serving traffic without interruption.
- No data exfiltration was observed in the Hubble flow capture; the connection was interactive-shell traffic only, consistent with command execution rather than bulk transfer.

## Timeline (UTC)

| time | source | event |
|---|---|---|
| 2026-08-27T09:18:44Z | falco | `Suspicious network tool in container` fires on `checkout-api-6b8f7d4c9-ht5mz`; TTY-attached `bash` process detected |
| 2026-08-27T09:19:49Z | guardduty | `Backdoor:EKS/C2Activity.B` reports the same pod connecting to a known command-and-control endpoint on port 4444 |
| 2026-08-27T09:19:55Z | seks-triage | Reverse shell matches the P1 critical category directly per Section 5; severity set to P1 without needing correlation |
| 2026-08-27T09:20:15Z | seks-remediation | Forensics begins: `checkpoint_pod` and `capture_hubble_flows` invoked in parallel |
| 2026-08-27T09:21:58Z | eks-mcp-server | `checkpoint_pod` returns `status=success` |
| 2026-08-27T09:22:04Z | eks-mcp-server | `capture_hubble_flows` returns `status=success`; flow records show the live outbound connection to the external IP on port 4444 |
| 2026-08-27T09:22:30Z | seks-solution | Solution Agent drafts the containment plan citing runbook_id `reverse-shell`, posts P1 approval card to Slack `#security-incidents` |
| 2026-08-27T09:24:12Z | slack | `@oncall-secops` approves |
| 2026-08-27T09:24:29Z | seks-remediation | `label_pod` sets `security.incident/compromised=true` on the pod |
| 2026-08-27T09:24:31Z | tetragon | Pre-deployed `kill-compromised-outbound` TracingPolicy observes the label and SIGKILLs the shell process's outbound connection |
| 2026-08-27T09:25:40Z | seks-remediation | `apply_cilium_network_policy` completes and propagates to the node's Cilium agent, roughly 69 seconds after the Tetragon kill, confirming defense in depth rather than being the primary kill mechanism this time |
| 2026-08-27T09:26:03Z | seks-remediation | `delete_pod` removes the compromised pod; Deployment recreates it |
| 2026-08-27T09:31:12Z | seks-remediation | New pod confirmed healthy, no shell process, no outbound connection to the flagged IP; incident marked resolved |

## Detection and correlation

- Distinct sensors firing against `checkout-api` inside the 10-minute window: 2 (falco, guardduty). Correlation was not required for escalation since reverse shell is a direct P1 category under Section 5, but the second sensor confirmed the finding before forensics started.
- Falco rule `Suspicious network tool in container` had fired on 1 distinct workload in the trailing 24 hours, well below the 5-workload noisy-rule threshold.
- ClickHouse correlation query (Q1, 10-minute window on `sensor_events`) returned in 97ms.
- `collect_tetragon_timeline` returned the shell's process ancestry and the `tcp_connect` to port 4444 from Tetragon's kernel-level event stream, so no follow-up exec into the pod was needed.

## Response actions

| step | MCP tool | status | evidence_uri |
|---|---|---|---|
| 1 | checkpoint_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260827-091844-falco-b2e091/checkpoints/checkout-api-6b8f7d4c9-ht5mz/checkpoint.tar.gz |
| 2 | capture_hubble_flows | success | s3://seks-forensics-<account-id>/incidents/inc-20260827-091844-falco-b2e091/hubble/checkout-api-6b8f7d4c9-ht5mz/flows.json |
| 3 | collect_tetragon_timeline | success | s3://seks-forensics-<account-id>/incidents/inc-20260827-091844-falco-b2e091/tetragon/checkout-api-6b8f7d4c9-ht5mz/timeline.json |
| 4 | label_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260827-091844-falco-b2e091/actions/label_pod.json |
| 5 | apply_cilium_network_policy | success | s3://seks-forensics-<account-id>/incidents/inc-20260827-091844-falco-b2e091/actions/seks-isolate-checkout-api-6b8f7d4c9-ht5mz.yaml |
| 6 | delete_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260827-091844-falco-b2e091/actions/delete_pod.json |

## Approval

- approver: @oncall-secops
- decision: approved
- decided_at: 2026-08-27T09:24:12Z
- time-to-approve: 1m42s

## Root cause

`checkout-api` exposes an internal debug endpoint that was mistakenly left reachable from inside the cluster network after a configuration change two days earlier. An attacker who already had a foothold on another compromised pod reached the debug endpoint and used it to spawn an interactive shell with a reverse connection out to an attacker-controlled listener. The entry vector was the debug endpoint, not a vulnerability in `checkout-api` itself; the shell spawn and outbound connection are what Falco and Tetragon caught.

## What went well

- Tetragon's SIGKILL policy, armed the instant `label_pod` applied the compromise label, cut the live connection roughly a minute before the network policy would have. This is the labeling-then-network-policy design working as intended: the reversible, fast action (`label_pod`) provided an immediate kill switch while the heavier, also-reversible `apply_cilium_network_policy` propagated.
- Forensics (`checkpoint_pod`, `capture_hubble_flows`, `collect_tetragon_timeline`) completed and returned `status=success` before any containment step ran, satisfying the mandatory ordering in policy Section 3 and preserving a complete evidence trail even though the shell was killed quickly afterward.
- Approval came back in under two minutes, well inside the P1 approval requirement for destructive steps.

## What went wrong

- The internal debug endpoint should never have been reachable from other pods in `demo`; this was a configuration gap that predated the incident by two days and was not itself caught by any sensor until it was actively exploited.
- The Hubble flow capture window was limited to the default lookback, which captured the live connection but not the full session that established it; a longer default lookback for P1 incidents would have given the root cause analysis more to work with without a follow-up query.

## Action items

| action | owner role | due | status |
|---|---|---|---|
| Remove the internal debug endpoint from `checkout-api` or restrict it behind an explicit allow-list NetworkPolicy | application engineering | 2026-09-03 | done |
| Extend the default `capture_hubble_flows` lookback window for P1 incidents from 10 minutes to 30 minutes | security engineering | 2026-09-10 | in_progress |
| Add a Falco rule for debug-endpoint-triggered shell spawns specifically, to shorten MTTD on this entry vector | security engineering | 2026-09-17 | open |

## Evidence and citations

- Solution Agent cited runbook_id `reverse-shell`, section "Detection signals", for the Falco and Tetragon rule names used to confirm the finding.
- Solution Agent cited `knowledge/policy/response-policy.md` Section 5, "Severity and approval", for the direct P1 classification without requiring correlation.
- Solution Agent cited `knowledge/policy/response-policy.md` Section 3, "Mandatory ordering", confirming that `label_pod` and `apply_cilium_network_policy` ran only after `checkpoint_pod` returned `status=success`.
</content>
