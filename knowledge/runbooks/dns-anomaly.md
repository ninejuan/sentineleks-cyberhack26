# Runbook: DNS Anomaly

- runbook_id: dns-anomaly
- mitre: T1071.004 Application Layer Protocol: DNS
- default_severity: P3
- sensors: guardduty
- automated_response: allowed

## Summary

A pod queries a known-malicious domain, a cryptomining pool's DNS name, or exhibits a query pattern consistent with DNS tunneling. DNS is an attractive covert channel because it routinely passes through firewalls that block other outbound protocols, but a single anomalous query is low-confidence on its own: it may be a one-off resolver hiccup, a stale allowlist, or genuine tunneling. SEKS treats this as the lowest-severity automated-response tier and escalates quickly once a second signal appears.

## Detection signals

### GuardDuty

- `CryptoCurrency:EKS/BitcoinTool.B!DNS` - DNS query to a known cryptomining pool domain.
- `Backdoor:EKS/C2Activity.B!DNS` - DNS query to a known command-and-control domain.
- `Trojan:EKS/DNSDataExfiltration` - query pattern consistent with DNS tunneling.
- `UnauthorizedAccess:EKS/MaliciousDomain.Rep` - query to a domain with a known-malicious reputation.

### Falco

- Not applicable. No DNS-specific rule exists in `kubernetes/falco/values.yaml` as of this writing. Do not cite a Falco rule name for this threat.

### Tetragon

- Not applicable. No DNS-specific TracingPolicy exists in `kubernetes/tetragon/tracing-policies.yaml` as of this writing. Do not cite a Tetragon policy name for this threat.

### Network indicators

- Unusually long subdomains (a DNS-tunneling signature, for example a base64-like label such as `aGVsbG8gd29ybGQ.evil.com`).
- High query rate against a single domain (approximately 100 queries per minute or more) within a short window.
- Spike in TXT, NULL, or CNAME record-type queries relative to the pod's baseline.
- Direct queries to an external resolver (`8.8.8.8`, `1.1.1.1`) bypassing the cluster's internal DNS, visible in `capture_hubble_flows` DNS-protocol filtering.

## Correlation and severity

Default severity is P3 on a single GuardDuty DNS finding, consistent with the response policy's P3 definition for a suspicious but lower-confidence signal.

Since Falco and Tetragon currently carry no DNS-specific rule, correlation for this threat in practice means GuardDuty firing more than once (for example, both `CryptoCurrency:EKS/BitcoinTool.B!DNS` and the matching stratum-port finding from the cryptomining runbook) or a second sensor type reporting against the same workload within the 10-minute window through an unrelated rule (for instance, Falco's `Suspicious network tool in container` if a tunneling tool like `socat` is also observed). Per the response policy's correlation rule, 2 distinct sensor types correlating on the same workload raises the incident to at least P2, which also means it now requires Slack approval before any containment step runs, overriding the P3 auto-remediate default.

Noisy-rule down-weighting applies if a specific GuardDuty finding type has fired on 5 or more distinct workloads in 24 hours (common for an overly broad threat-intel domain list); this adjusts the severity score but does not skip evidence collection.

## Automated response plan

P3 permits auto-remediation without prior approval, but only through forensics, labeling, and isolation; no destructive step runs at P3.

1. `checkpoint_pod(namespace, pod_name)` - forensic snapshot before any destructive step; required precondition for everything below, including `apply_cilium_network_policy`.
2. `capture_hubble_flows(namespace, pod_name)` - capture the DNS query flow and record the queried domain, record type, and frequency.
3. `collect_audit_events(namespace, pod_name)` - correlate pod creation and recent configuration changes from the Kubernetes audit log.
4. `label_pod(namespace, pod_name, labels={"security.incident/compromised": "true"})` - arms the pre-deployed Tetragon SIGKILL policy on this pod's outbound connections; reversible.
5. `apply_cilium_network_policy(namespace, policy_name="seks-isolate-<pod>", pod_selector={"security.incident/compromised": "true"}, deny_all=true)` - selects only the flagged pod; blocks further queries to the suspicious domain.

If correlation raises the incident to P2 (a second distinct sensor type within 10 minutes), stop after step 3, post to Slack for approval, and only proceed to `label_pod` and `apply_cilium_network_policy` once approved. `delete_pod` and `patch_deployment` are not part of this runbook's automated plan at any severity; a confirmed DNS-tunneling pod that needs removal is escalated to a human operator.

### Human follow-up (not automated)

- Decide whether to delete and redeploy the pod if DNS tunneling is confirmed; this runbook's automated plan stops at isolation.
- Add the malicious domain to a permanent CoreDNS blocklist or threat-intelligence feed through the normal GitOps pipeline, not through an ad hoc ConfigMap patch.

## Approval card

- What: Isolate the pod making the anomalous DNS queries; forensics and labeling run automatically at P3, with no approval gate unless correlation escalates the incident.
- Impact: The flagged pod loses network access entirely once isolated; it is not deleted or scaled down by this runbook.
- Rollback: Remove the `security.incident/compromised` label and delete the `seks-isolate-<pod>` CiliumNetworkPolicy once the domain is confirmed benign or the pod has been manually remediated.

## Rollback

1. Confirm the queried domain was a false positive, or that a human operator has manually remediated a confirmed tunneling pod.
2. Remove the `security.incident/compromised=true` label from the pod, disarming the Tetragon SIGKILL policy.
3. Delete the `seks-isolate-<pod>` CiliumNetworkPolicy.
4. No `patch_deployment` rollback is needed since this runbook never scales a Deployment to zero.
5. Rollback is never automatic; an operator confirms resolution before any rollback step runs, even at P3 where the initial containment itself required no approval.

## Do not

- Do not call `cordon_node` or `drain_node`; node-level isolation is never appropriate for a DNS-only finding.
- Do not leave `endpointSelector` empty in the CiliumNetworkPolicy; an empty selector isolates the entire namespace.
- Do not add a `toEntities: world` or equivalent `0.0.0.0/0` egress allow rule to the isolation policy.
- Do not take any action against a resource in a protected namespace (`kube-system`, `kube-public`, `kube-node-lease`, `seks`, `falco`, `tetragon`, `monitoring`, `external-secrets`, `cilium`).
- Do not call `delete_pod` or `patch_deployment` for this threat at P3; isolation is the ceiling for automated response until correlation escalates the severity and a human approves further action.
- Do not cite a Falco or Tetragon rule name for DNS anomaly detection; neither sensor has a DNS-specific rule in this codebase today.

## References

- https://attack.mitre.org/techniques/T1071/004/
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-kubernetes.html
- https://falco.org/docs/reference/rules/default-rules/
- https://docs.cilium.io/en/stable/security/policy/
- https://tetragon.io/docs/
- https://kubernetes.io/docs/concepts/security/
