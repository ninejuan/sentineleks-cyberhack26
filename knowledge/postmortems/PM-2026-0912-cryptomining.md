# Post-mortem: Cryptominer execution on `ledger-worker`, caught by sensor correlation and a Semgrep gate

Example post-mortem from the SEKS demo environment.

- incident_id: inc-20260912-141205-falco-7f3a1c
- severity: P1 (escalated from P2)
- status: resolved
- detected_at: 2026-09-12T14:12:05Z
- resolved_at: 2026-09-12T14:34:51Z
- mttd: 2m10s
- mttr: 22m46s
- sensors: falco, tetragon, guardduty
- runbook_cited: cryptomining

## Summary

Falco and Tetragon both fired within two minutes of each other against the `ledger-worker` deployment in the `demo` namespace on cluster `seks-demo`. A Falco rule caught a known cryptominer binary executing inside the pod; a Tetragon TracingPolicy independently caught its outbound connection to a stratum port at the kprobe layer. The Triage Agent correlated the two sensors and held the incident at P2. Six minutes later, GuardDuty reported a DNS query to a known mining pool domain from the same workload. That third sensor pushed the correlation count to three distinct sensor types inside the 10-minute window, and the policy's correlation rule escalated the incident to P1. The Remediation Agent generated an isolation plan, but a Semgrep gate caught a bad `CiliumNetworkPolicy` before it reached the EKS MCP server and the plan was regenerated correctly. The pod was contained and deleted without affecting the other five pods in the namespace.

## Impact

- One pod (`ledger-worker-7d4b9c6f8-xk2qp`) was running a cryptominer binary for roughly 8 minutes before containment started.
- No other workload in `demo` was infected. The near-miss was architectural, not operational: a bad network policy would have cut off all 6 pods in the namespace for the duration of the incident, but the Semgrep gate stopped it before it reached the cluster.
- No customer-facing service degradation. `ledger-worker` is a background batch processor with no synchronous callers.
- Estimated cost impact: node CPU usage on the affected node held near 95% for 8 minutes before the pod was isolated.

## Timeline (UTC)

| time | source | event |
|---|---|---|
| 2026-09-12T14:12:05Z | falco | `Crypto mining process detected` fires on `ledger-worker-7d4b9c6f8-xk2qp`; process `xmrig` detected |
| 2026-09-12T14:13:41Z | tetragon | `detect-cryptominer-egress` TracingPolicy reports a `tcp_connect` from the same pod to a stratum port (3333) |
| 2026-09-12T14:13:52Z | seks-triage | Correlation engine matches falco + tetragon on the same workload within the 10-minute window; severity set to P2 per Section 5 escalation rule |
| 2026-09-12T14:14:30Z | seks-solution | Solution Agent drafts remediation plan citing runbook_id `cryptomining`, posts to Slack `#security-incidents` for P2 approval |
| 2026-09-12T14:18:22Z | guardduty | `CryptoCurrency:EKS/BitcoinTool.B!DNS` finding reports a DNS query to a known mining pool domain from the same pod IP |
| 2026-09-12T14:18:40Z | seks-triage | Third distinct sensor type correlates on the same workload inside the same 10-minute window; severity escalated to P1 per Section 5 |
| 2026-09-12T14:19:05Z | seks-remediation | Remediation Agent begins forensics: `checkpoint_pod` and `capture_hubble_flows` invoked in parallel |
| 2026-09-12T14:20:58Z | eks-mcp-server | `checkpoint_pod` returns `status=success`; checkpoint archive written to S3 |
| 2026-09-12T14:21:10Z | seks-remediation | Remediation Agent generates first `CiliumNetworkPolicy` draft with `endpointSelector: {}` |
| 2026-09-12T14:21:11Z | semgrep-gate | Rule `seks-isolation-empty-endpoint-selector` blocks the manifest before it reaches the EKS MCP server |
| 2026-09-12T14:21:34Z | seks-remediation | Plan regenerated with `endpointSelector` scoped to `security.incident/compromised: "true"`; passes the Semgrep gate |
| 2026-09-12T14:22:05Z | slack | Approval card posted to `#security-incidents` for the regenerated P1 plan |
| 2026-09-12T14:23:45Z | slack | `@oncall-secops` approves |
| 2026-09-12T14:24:02Z | seks-remediation | `label_pod` sets `security.incident/compromised=true` on the affected pod |
| 2026-09-12T14:24:19Z | seks-remediation | `apply_cilium_network_policy` applied, scoped to the single labeled pod |
| 2026-09-12T14:24:51Z | seks-remediation | `delete_pod` removes the infected pod; Deployment recreates it from the last known-good image |
| 2026-09-12T14:34:51Z | seks-remediation | New pod confirmed healthy, no mining process, no stratum connection; incident marked resolved |

## Detection and correlation

- Distinct sensors firing against `ledger-worker` inside the 10-minute correlation window: 3 (falco, tetragon, guardduty).
- The Falco rule `Crypto mining process detected` had fired on 2 distinct workloads in the trailing 24 hours at the time of this incident, below the 5-workload noisy-rule threshold, so no down-weighting applied to its contribution.
- Outbound connection observed to a stratum mining protocol port, 3333, matching the Network indicators section of the cryptomining runbook.
- ClickHouse correlation query (Q1, 10-minute window on `sensor_events`) returned in 184ms, well inside the alerting budget, so the P1 escalation decision used fresh data.

## Response actions

| step | MCP tool | status | evidence_uri |
|---|---|---|---|
| 1 | checkpoint_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260912-141205-falco-7f3a1c/checkpoints/ledger-worker-7d4b9c6f8-xk2qp/checkpoint.tar.gz |
| 2 | capture_hubble_flows | success | s3://seks-forensics-<account-id>/incidents/inc-20260912-141205-falco-7f3a1c/hubble/ledger-worker-7d4b9c6f8-xk2qp/flows.json |
| 3 | label_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260912-141205-falco-7f3a1c/actions/label_pod.json |
| 4 | apply_cilium_network_policy | success | s3://seks-forensics-<account-id>/incidents/inc-20260912-141205-falco-7f3a1c/actions/seks-isolate-ledger-worker-7d4b9c6f8-xk2qp.yaml |
| 5 | delete_pod | success | s3://seks-forensics-<account-id>/incidents/inc-20260912-141205-falco-7f3a1c/actions/delete_pod.json |

## Approval

- approver: @oncall-secops
- decision: approved
- decided_at: 2026-09-12T14:23:45Z
- time-to-approve: 1m40s

## Root cause

`ledger-worker` pulls its base image from a public registry mirror that was not pinned to a digest, only a mutable tag. The upstream mirror served a tampered layer containing the `xmrig` binary disguised as a logging helper, which executed on container start. The compromised layer had been in the image for roughly 11 hours before Falco caught the running process; the gap was time-to-exploit, not time-to-detect, since the binary did not run until a scheduled job inside the container triggered it.

## What went well

- Correlation across falco and tetragon held the incident at P2 immediately, which meant forensics started as soon as the first finding arrived rather than waiting on a single sensor.
- The Semgrep gate caught the empty `endpointSelector` before it reached the cluster. Without it, this incident would have taken down all 6 pods in `demo`, not just the compromised one.
- GuardDuty's independent DNS-based detection confirmed the mining pool connection without needing to inspect pod-internal network state, giving the third correlation signal that triggered the P1 escalation.
- Approval took under two minutes once posted, inside the 15-minute P2 window and well inside the P1 pre-destructive-step requirement.

## What went wrong

- The regenerated `CiliumNetworkPolicy` depended on `label_pod` having already run; the Remediation Agent's first draft tried to write the isolation policy before confirming the label was applied, which the Semgrep gate caught as a byproduct of the empty-selector check rather than a dedicated ordering check.
- The base image's mutable tag was not caught by the ECR scan pipeline before deployment, since the scan ran against the tag at push time and the registry mirror served a different layer at pull time days later.

## Action items

| action | owner role | due | status |
|---|---|---|---|
| Pin `ledger-worker` base image to a digest instead of a mutable tag | platform engineering | 2026-09-19 | done |
| Add a dedicated Semgrep rule asserting `label_pod` success precedes `apply_cilium_network_policy` generation, independent of the empty-selector check | security engineering | 2026-09-26 | in_progress |
| Add registry mirror layer-hash verification to the image pull path | platform engineering | 2026-10-03 | open |

## Evidence and citations

- Solution Agent cited runbook_id `cryptomining`, section "Automated response plan", for the forensics-then-isolate-then-delete sequence.
- Solution Agent cited `knowledge/policy/response-policy.md` Section 5, "Correlation escalation rule", for the P2-to-P1 escalation when the third sensor type correlated.
- Solution Agent cited `knowledge/policy/response-policy.md` Section 7, "Network policy constraints", in the Slack message explaining why the first isolation plan was rejected and regenerated.
</content>
