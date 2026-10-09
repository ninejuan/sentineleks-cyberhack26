"""Summary agent (plan: 이벤트[] -> {summary, affected:{ns, workload}}).

Identity is system-owned: incident_id, namespace/workload/pod, rule_id and source come from the
ingestor's normalized event, not from the model. The fast model only writes the human summary.
"""

import json
import logging
import os
import uuid
from datetime import UTC, datetime

from app.shared.config import Config
from app.shared.json_extract import extract_json
from app.shared.llm import LlmRouter, Role
from app.shared.normalize import normalize

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You summarize one EKS runtime security event for an on-call engineer.
Use only facts present in the event. Do not speculate, do not recommend actions.

Output ONLY a JSON object:
{"title": "<one line, <= 90 chars>",
 "summary": "<2-3 sentences: what ran, where, what it contacted>",
 "raw_indicators": ["<ips, domains, binaries, file paths seen in the event>"],
 "mitre_technique": "<Txxxx if clearly implied by the event, else empty>"}"""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    raw_event = event.get("raw_event") or event
    normalized = event.get("normalized") or normalize(
        raw_event, tenant_id=config.tenant_id, cluster=config.eks_cluster_name
    )

    completion = LlmRouter(config).complete(
        Role.SUMMARY,
        SYSTEM_PROMPT,
        "NORMALIZED:\n"
        + json.dumps({k: v for k, v in normalized.items() if k != "raw_hash"}, ensure_ascii=False)
        + "\n\nRAW EVENT:\n"
        + json.dumps(raw_event, ensure_ascii=False, default=str)[:12000],
        max_tokens=800,
    )
    try:
        model_view = extract_json(completion.text)
    except json.JSONDecodeError:
        logger.warning("Summary model returned non-JSON; using raw text")
        model_view = {"title": normalized.get("rule_id", "Security event"), "summary": completion.text[:600]}

    incident_id = _incident_id(normalized)
    summary = {
        "incident_id": incident_id,
        "tenant_id": normalized["tenant_id"],
        "source": normalized["source"],
        "rule_id": normalized["rule_id"],
        "timestamp": normalized["ts"],
        "title": model_view.get("title") or normalized["rule_id"],
        "summary": model_view.get("summary", ""),
        "affected": {
            "cluster": normalized["cluster"],
            "namespace": normalized["namespace"],
            "workload": normalized["workload"],
            "pod": normalized["pod"],
        },
        "affected_resources": [r for r in (normalized["namespace"], normalized["workload"], normalized["pod"]) if r],
        "raw_indicators": model_view.get("raw_indicators", []),
        "mitre_technique": normalized["mitre_technique"] or model_view.get("mitre_technique", ""),
        "process": normalized["process"],
        "network": normalized["network"],
        "raw_event": raw_event,
        "model": {"provider": completion.provider, "model": completion.model, "latency_ms": completion.latency_ms},
    }
    _store_incident(config, summary)
    return summary


def _incident_id(normalized: dict) -> str:
    stamp = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S")
    return f"inc-{stamp}-{normalized.get('source') or 'unknown'}-{uuid.uuid4().hex[:6]}"


def _store_incident(config: Config, summary: dict) -> None:
    if not config.store_enabled:
        return
    from app.shared.store import IncidentStore

    IncidentStore(config).put_incident(
        incident_id=summary["incident_id"],
        data={
            "tenant_id": summary["tenant_id"],
            "source": summary["source"],
            "rule_id": summary["rule_id"],
            "title": summary["title"],
            "summary": summary["summary"],
            "status": "detected",
            "mitre_technique": summary["mitre_technique"],
            "affected": summary["affected"],
            "affected_resources": summary["affected_resources"],
            "raw_indicators": summary["raw_indicators"],
        },
    )
