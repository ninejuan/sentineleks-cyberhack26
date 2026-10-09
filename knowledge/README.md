# SEKS Knowledge Base

Verified context for the Solution Agent, ingested into Senso. These are the only sources the Solution Agent may cite in a remediation recommendation.

- `policy/response-policy.md`: master policy. Allowed MCP tools, severity table, correlation rules, protected namespaces, network policy constraints.
- `runbooks/`: 10 runbook_id documents, one per threat type: `cryptomining`, `container-escape`, `privilege-escalation`, `secret-exfiltration`, `dns-anomaly`, `lateral-movement`, `reverse-shell`, `data-exfiltration`, `rbac-abuse`, `image-tampering`. Each cites the policy for allowed actions.
- `postmortems/`: resolved incident examples showing how triage, correlation, approval, and MCP remediation played out in practice, including degraded-correlation and gate-rejection cases.

A recommendation that cannot cite a `runbook_id` from `runbooks/` and a section of `policy/response-policy.md` is not actionable; the Solution Agent must degrade it to a human-review item instead.
</content>
