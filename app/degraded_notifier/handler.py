import json
import logging
import os

from app.shared.config import Config
from app.shared.slack_notifier import SlackNotifier

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    notifier = SlackNotifier(project=config.project)

    raw_event = event.get("raw_event", {})
    source = event.get("source", "unknown")
    error_info = event.get("error") or {"Cause": degraded_reason(event)}
    incident_id = event.get("summary", {}).get("body", {}).get("incident_id")
    severity = event.get("triage", {}).get("body", {}).get("severity")

    incident = {
        "source": source,
        "raw_event": raw_event,
        "error": error_info,
        "mode": "DEGRADED",
        "incident_id": incident_id,
        "severity": severity,
    }

    notifier.send_incident(incident, mode="degraded")

    logger.info(
        "Sent degraded notification for %s event, error: %s",
        source,
        json.dumps(error_info, default=str)[:200],
    )

    return {"status": "degraded_notification_sent", "source": source}


def degraded_reason(event: dict) -> str:
    """Explain why the pipeline fell back to a human when no Lambda error was caught."""
    lines: list[str] = []
    correlation = event.get("triage", {}).get("body", {}).get("correlation", {})
    if correlation and not correlation.get("available", True):
        lines.append(f"Correlation unavailable (ClickHouse): {correlation.get('error', 'unknown')}")
    solution = event.get("solution", {}).get("body", {})
    if solution and not solution.get("grounded", True):
        lines.append(f"No verified evidence (Senso): {solution.get('reason', 'unknown')}")
    gate = event.get("gate", {}).get("body", {})
    if gate and not gate.get("passed", True):
        last = (gate.get("attempts") or [{}])[-1]
        violations = [f"{v['check']}: {v['detail']}" for v in last.get("verify", {}).get("violations", [])]
        findings = [f"semgrep {f['rule_id']}" for f in last.get("semgrep", {}).get("findings", [])]
        lines.append(
            "Safety gate blocked automated remediation: " + "; ".join(violations + findings or [gate.get("reason", "")])
        )
    return "\n".join(lines) or "Unknown failure"
