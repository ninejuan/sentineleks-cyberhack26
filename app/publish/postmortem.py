"""Publish an incident.io-style status page / post-mortem as a Slack Canvas (plan: M12).

Rendered from the MongoDB incident document (single source of truth) and the approval audit.
Creates the canvas on first publish and replaces its content on every later stage, so the same
URL tracks the incident from detection to resolution. Falls back to a threaded channel message
when the workspace refuses canvases.
"""

import json
import logging
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

SLACK_API = "https://slack.com/api/"


class SlackApiError(RuntimeError):
    def __init__(self, method: str, error: str):
        super().__init__(f"{method}: {error}")
        self.error = error


def slack_call(token: str, method: str, payload: dict, timeout: float = 10.0) -> dict:
    request = urllib.request.Request(  # noqa: S310 - fixed Slack API host
        SLACK_API + method,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json; charset=utf-8", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        body = json.loads(response.read())
    if not body.get("ok"):
        raise SlackApiError(method, str(body.get("error", "unknown_error")))
    return body


def render_markdown(incident: dict[str, Any], approvals: list[dict[str, Any]]) -> str:
    affected = incident.get("affected", {})
    correlation = incident.get("correlation", {}) or {}
    solution = incident.get("solution", {}) or {}
    gate = incident.get("gate", {}) or {}
    status = str(incident.get("status", "detected")).upper()

    lines = [
        f"# {incident.get('severity', '?')} · {incident.get('title', 'Security incident')}",
        "",
        f"**Status:** {status}  ",
        f"**Incident:** `{incident.get('incident_id')}`  ",
        f"**Target:** `{affected.get('cluster')}/{affected.get('namespace')}/{affected.get('pod')}`  ",
        f"**MITRE:** {incident.get('mitre_technique') or 'n/a'}  ",
        f"**Detected:** {incident.get('created_at')}  ·  **Updated:** {incident.get('updated_at')}",
        "",
        "## Summary",
        str(incident.get("summary", "")),
        "",
        "## Detection and correlation (ClickHouse)",
    ]
    if correlation.get("available"):
        lines += [
            (
                f"- Distinct sensors in {correlation.get('window_min')} min: "
                f"**{correlation.get('distinct_sources')}** ({', '.join(correlation.get('sources', []))})"
            ),
            (
                f"- Rule frequency (24h): {correlation.get('rule_24h', {}).get('n', 0)} events on "
                f"{correlation.get('rule_24h', {}).get('workloads', 0)} workloads"
                + (" · flagged noisy" if correlation.get("noisy_rule") else "")
            ),
            (
                f"- Severity floor from correlation: {correlation.get('severity_floor') or 'none'} · "
                f"query {correlation.get('query_ms')} ms"
            ),
        ]
    else:
        lines.append(f"- Correlation unavailable: {correlation.get('error', 'n/a')}")

    lines += ["", "## Verified response procedure (Senso)"]
    citations = solution.get("citations", [])
    lines += [f"- {c.get('title')} (`{c.get('content_id')}`)" for c in citations] or ["- none (degraded to human)"]

    lines += ["", "## Safety gate"]
    semgrep = gate.get("semgrep", {})
    if gate:
        lines.append(f"- Gate: **{'PASSED' if gate.get('passed') else 'BLOCKED'}**")
        if semgrep.get("caught"):
            lines.append(
                f"- Semgrep caught an unsafe AI-generated manifest ({', '.join(semgrep['caught'])}); "
                "plan regenerated and re-scanned"
            )
        lines.append(f"- Semgrep findings on final plan: {semgrep.get('findings', 0)}")
    else:
        lines.append("- not run yet")

    lines += ["", "## Approval"]
    lines += [f"- **{a.get('decision', '').upper()}** by `{a.get('by')}` at {a.get('at')}" for a in approvals] or [
        "- pending"
    ]

    lines += ["", "## Response actions (EKS MCP)", "| # | Tool | Status | Evidence |", "|---|---|---|---|"]
    for index, entry in enumerate(incident.get("execution_log", []) or [], start=1):
        if not entry.get("tool"):
            continue
        result = entry.get("result", {}) or {}
        lines.append(
            f"| {index} | `{entry['tool']}` | {result.get('status', '?')} | {result.get('evidence_uri', '') or ''} |"
        )

    lines += ["", "## Timeline"]
    lines += [f"- {a.get('at')} · **{a.get('stage')}** {a.get('detail', '')}" for a in incident.get("audit", [])]
    return "\n".join(lines)


class PostmortemPublisher:
    def __init__(self, token: str, channel_id: str):
        self._token = token
        self._channel = channel_id

    def publish(self, incident: dict[str, Any], approvals: list[dict[str, Any]]) -> dict[str, str]:
        markdown = render_markdown(incident, approvals)
        canvas_id = incident.get("canvas_id")
        try:
            if canvas_id:
                slack_call(
                    self._token,
                    "canvases.edit",
                    {
                        "canvas_id": canvas_id,
                        "changes": [
                            {"operation": "replace", "document_content": {"type": "markdown", "markdown": markdown}}
                        ],
                    },
                )
                return {"mode": "canvas", "canvas_id": canvas_id, "action": "updated"}
            created = slack_call(
                self._token,
                "canvases.create",
                {
                    "title": f"[{incident.get('severity', '?')}] {incident.get('incident_id')}",
                    "document_content": {"type": "markdown", "markdown": markdown},
                },
            )
            canvas_id = created["canvas_id"]
            slack_call(
                self._token,
                "canvases.access.set",
                {"canvas_id": canvas_id, "access_level": "read", "channel_ids": [self._channel]},
            )
            permalink = self._permalink(canvas_id)
            slack_call(
                self._token,
                "chat.postMessage",
                {
                    "channel": self._channel,
                    "text": f"Incident status page for `{incident.get('incident_id')}`: {permalink}",
                },
            )
            return {"mode": "canvas", "canvas_id": canvas_id, "action": "created", "url": permalink}
        except SlackApiError as error:
            logger.warning("Canvas publish failed (%s); falling back to channel message", error)
            posted = slack_call(self._token, "chat.postMessage", {"channel": self._channel, "text": markdown[:39000]})
            return {"mode": "message", "ts": posted.get("ts", ""), "fallback_reason": error.error}

    def _permalink(self, canvas_id: str) -> str:
        try:
            info = slack_call(self._token, "files.info", {"file": canvas_id})
            return str(info.get("file", {}).get("permalink", ""))
        except SlackApiError:
            return ""
