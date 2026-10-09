import json
import logging
import os

from app.shared.config import Config
from app.shared.secrets import get_secret
from app.shared.slack_notifier import to_slack_mrkdwn

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

CARD_ARG_KEYS = frozenset({"namespace", "pod_name", "deployment_name", "policy_name", "replicas", "labels", "profile"})


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    task_token = event.get("task_token", "")
    execution = event.get("execution", {})

    summary = execution.get("summary", {}).get("body", {})
    triage = execution.get("triage", {}).get("body", {})
    solution = execution.get("solution", {}).get("body", {})
    gate = execution.get("gate", {}).get("body", {})
    incident_id = summary.get("incident_id", "unknown")

    blocks = build_approval_blocks(summary, triage, solution, gate, task_token)
    _store_task_token(config, incident_id, task_token)
    _post(config, blocks)

    logger.info("Approval request sent for incident %s", incident_id)
    return {"status": "approval_requested", "incident_id": incident_id}


def build_approval_blocks(summary: dict, triage: dict, solution: dict, gate: dict, task_token: str) -> list[dict]:
    """Approval card (plan: 무엇·왜·영향·롤백) plus the evidence an approver needs to trust it."""
    incident_id = summary.get("incident_id", "unknown")
    affected = summary.get("affected", {})
    card = solution.get("approval_card", {})
    correlation = triage.get("correlation", {})
    plan = gate.get("approved_plan", [])

    steps = "\n".join(f"{i + 1}. `{c['tool']}` {_args(c)}" for i, c in enumerate(plan)) or "_none_"
    what = card.get("what") or steps
    impact = card.get("impact") or solution.get("estimated_impact", "")
    rollback = card.get("rollback") or "; ".join(solution.get("rollback_steps", []))
    citations = "\n".join(
        f"• {c.get('title')} (`{str(c.get('content_id', ''))[:8]}`)" for c in solution.get("citations", [])
    )

    if correlation.get("available"):
        corr = (
            f"{correlation.get('distinct_sources', 0)} sensors ({', '.join(correlation.get('sources', []))}) "
            f"in {correlation.get('window_min')}m · ClickHouse {correlation.get('query_ms')}ms"
        )
    else:
        corr = f"unavailable ({correlation.get('error', 'n/a')})"
    escalation = (
        f" (escalated from {triage.get('model_severity')} by correlation)"
        if triage.get("escalated_by_correlation")
        else ""
    )
    caught = gate.get("caught_by_semgrep", [])
    semgrep_line = (
        f"Semgrep blocked the first AI plan ({', '.join(sorted({f['rule_id'] for f in caught}))}); "
        "regenerated plan passed."
        if caught
        else "Semgrep: no blocking findings."
    )
    value = f"{incident_id}|{task_token}"

    def section(title: str, body: str) -> dict:
        return {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\n{to_slack_mrkdwn(body) or '_n/a_'}"}}

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Approval required · {triage.get('severity', '?')}"},
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Target*\n`{affected.get('namespace')}/{affected.get('pod')}`"},
                {"type": "mrkdwn", "text": f"*Severity*\n{triage.get('severity')}{escalation}"},
                {"type": "mrkdwn", "text": f"*Correlation*\n{corr}"},
            ],
        },
        section("What", what),
        section("Why", triage.get("reasoning", "")),
        section("Impact", impact),
        section("Rollback", rollback),
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Plan (gate-verified)*\n{steps}"}},
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"*Evidence (Senso)*\n{citations or '_none_'}"},
                {"type": "mrkdwn", "text": semgrep_line},
            ],
        },
        {
            "type": "actions",
            "block_id": "approval",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "style": "primary",
                    "action_id": "approve_remediation",
                    "value": value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "style": "danger",
                    "action_id": "reject_remediation",
                    "value": value,
                },
            ],
        },
    ]


def _args(call: dict) -> str:
    return json.dumps({k: v for k, v in call.get("args", {}).items() if k in CARD_ARG_KEYS}, ensure_ascii=False)


def _store_task_token(config: Config, incident_id: str, task_token: str) -> None:
    if not config.store_enabled or not task_token:
        return
    from app.shared.store import IncidentStore

    IncidentStore(config).update_incident(
        incident_id, {"task_token": task_token, "status": "awaiting_approval"}, stage="awaiting_approval"
    )


def _post(config: Config, blocks: list[dict]) -> None:
    from urllib.request import Request, urlopen

    secret = get_secret(f"{config.project}/slack/bot-token")
    token, channel = secret.get("token", ""), config.slack_incident_channel
    is_bot_api_call = bool(token and channel)
    if is_bot_api_call:
        req = Request(
            "https://slack.com/api/chat.postMessage",
            data=json.dumps({"channel": channel, "blocks": blocks, "text": "SEKS approval required"}).encode(),
            headers={"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {token}"},
        )
    else:
        webhook_url = secret.get("webhook_url", "")
        if not webhook_url:
            logger.warning("Slack not configured for approval card")
            return
        req = Request(  # noqa: S310 - Slack incoming webhook from Secrets Manager
            webhook_url, data=json.dumps({"blocks": blocks}).encode(), headers={"Content-Type": "application/json"}
        )
    with urlopen(req, timeout=10) as resp:  # noqa: S310
        body = resp.read()
        if is_bot_api_call:
            result = json.loads(body.decode())
            if not result.get("ok"):
                raise RuntimeError(f"Slack chat.postMessage failed: {result.get('error')}")
        logger.info("Approval request sent to Slack: %s", resp.status)
