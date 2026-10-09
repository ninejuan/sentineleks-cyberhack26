"""Triage agent (plan: 상관 승격은 코드가 먼저).

1. Query ClickHouse for what other sensors saw on the same workload in the last 10 minutes (Q1)
   and how noisy this rule is across the tenant in 24h (Q2).
2. Code computes a severity floor from distinct sensors (>=2 -> P2, >=3 -> P1).
3. The fast model classifies and writes the rationale, citing the correlation numbers.
4. Final severity = the stricter of the model's severity and the code floor. The LLM cannot lower it.
If correlation is unavailable it is recorded as such and surfaced to Slack, never silently skipped.
"""

import json
import logging
import os

from app.shared.config import Config
from app.shared.json_extract import extract_json
from app.shared.llm import LlmRouter, Role
from app.sink.clickhouse import Correlation, SensorSink, apply_floor

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

CORRELATION_WINDOW_MIN = int(os.environ.get("CORRELATION_WINDOW_MIN", "10"))

SYSTEM_PROMPT = """You are the SEKS triage agent for an EKS cluster.
Given an incident summary and a cross-sensor correlation result computed from ClickHouse, classify it.

Severity levels:
- P1: confirmed active compromise (container escape, active exfiltration, multi-sensor confirmed cryptomining)
- P2: high-confidence malicious activity on one workload (cryptominer, reverse shell, privilege escalation)
- P3: suspicious but unconfirmed (anomalous DNS, unusual process)
- P4: informational

Output ONLY a JSON object:
{"severity": "P1|P2|P3|P4", "confidence": 0.0-1.0,
 "category": "cryptomining|container_escape|privilege_escalation|secret_exfiltration|data_exfiltration|
              lateral_movement|reverse_shell|dns_anomaly|rbac_abuse|image_tampering|unknown",
 "rationale": "2 sentences. Quote the correlation numbers: distinct sensors, window, rule 24h count."}"""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    summary = event.get("summary", {}).get("body", event)
    affected = summary.get("affected") or {}
    rule_id = summary.get("rule_id") or ""

    correlation = _correlate(config, affected, rule_id)

    completion = LlmRouter(config).complete(
        Role.TRIAGE,
        SYSTEM_PROMPT,
        "INCIDENT SUMMARY:\n"
        + json.dumps({k: v for k, v in summary.items() if k != "raw_event"}, indent=2, ensure_ascii=False)
        + "\n\nCORRELATION (ClickHouse, computed by code):\n"
        + json.dumps(correlation.to_dict(), indent=2),
        max_tokens=800,
    )
    try:
        model_view = extract_json(completion.text)
    except json.JSONDecodeError:
        logger.warning("Triage model returned non-JSON; defaulting to P2")
        model_view = {"severity": "P2", "confidence": 0.5, "category": "unknown", "rationale": completion.text[:500]}

    model_severity = str(model_view.get("severity", "P2")).upper()
    severity = apply_floor(model_severity, correlation.severity_floor)
    triage = {
        "severity": severity,
        "model_severity": model_severity,
        "escalated_by_correlation": severity != model_severity,
        "confidence": model_view.get("confidence", 0.5),
        "category": model_view.get("category", "unknown"),
        "reasoning": model_view.get("rationale", ""),
        "correlation": correlation.to_dict(),
        "requires_approval": severity in {"P1", "P2"},
        "auto_remediate": severity == "P3",
        "model": {"provider": completion.provider, "model": completion.model, "latency_ms": completion.latency_ms},
    }

    _record(config, summary.get("incident_id", ""), triage)
    _notify_slack(config, triage, summary)
    return triage


def _correlate(config: Config, affected: dict, rule_id: str) -> Correlation:
    namespace, workload = affected.get("namespace", ""), affected.get("workload", "")
    if not namespace or not workload:
        return Correlation(
            available=False, window_min=CORRELATION_WINDOW_MIN, error="summary has no namespace/workload"
        )
    try:
        sink = SensorSink.from_config(config)
    except Exception as error:
        return Correlation(available=False, window_min=CORRELATION_WINDOW_MIN, error=f"clickhouse connect: {error}")
    return sink.correlate(config.tenant_id, namespace, workload, rule_id, window_min=CORRELATION_WINDOW_MIN)


def _record(config: Config, incident_id: str, triage: dict) -> None:
    if not config.store_enabled or not incident_id:
        return
    from app.shared.store import IncidentStore

    IncidentStore(config).update_incident(
        incident_id,
        {
            "severity": triage["severity"],
            "category": triage["category"],
            "triage_reasoning": triage["reasoning"],
            "correlation": triage["correlation"],
            "requires_approval": triage["requires_approval"],
            "status": "triaged",
        },
        stage="triaged",
    )


def _notify_slack(config: Config, triage: dict, summary: dict) -> None:
    from app.shared.slack_notifier import SlackNotifier

    correlation = triage["correlation"]
    if correlation["available"]:
        corr_line = (
            f"{correlation['distinct_sources']} sensors ({', '.join(correlation['sources']) or 'none'}) "
            f"in {correlation['window_min']}m · rule 24h={correlation['rule_24h'].get('n', 0)} on "
            f"{correlation['rule_24h'].get('workloads', 0)} workloads · {correlation['query_ms']}ms"
        )
    else:
        corr_line = f"correlation: unavailable ({correlation.get('error')})"
    reasoning = triage["reasoning"]
    if triage["escalated_by_correlation"]:
        reasoning = f"Escalated {triage['model_severity']}→{triage['severity']} by correlation. {reasoning}"

    SlackNotifier(project=config.project).send_incident(
        {
            "incident_id": summary.get("incident_id", "unknown"),
            "severity": triage["severity"],
            "source": summary.get("source", "unknown"),
            "summary": summary.get("summary", "No summary"),
            "category": triage["category"],
            "reasoning": f"{reasoning}\n*Correlation:* {corr_line}",
            "requires_approval": triage["requires_approval"],
        }
    )
