"""Solution agent (plan: Akash 대형 추론 + Senso 근거 강제).

1. Ask Senso, scoped to the verified knowledge manifest, for the official procedure.
2. No citations -> degraded: no recommendation, a human decides.
3. Otherwise the reasoning model (AkashML Llama 3.3 70B, Bedrock Terra fallback) turns the cited
   procedure into a concrete, whitelisted action plan for this incident.
"""

import json
import logging
import os

from app.gate.verify import ALLOWED_AUTOMATED_TOOLS
from app.shared.config import Config
from app.shared.credentials import resolve_secret
from app.shared.json_extract import extract_json
from app.shared.llm import LlmRouter, Role
from app.shared.senso import SensoClient, SensoError, load_manifest

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = f"""You are the SEKS Solution agent. You turn a VERIFIED runbook excerpt into an action plan
for one EKS security incident. You must not use knowledge outside the evidence you are given.

Allowed actions (exact names): {", ".join(sorted(ALLOWED_AUTOMATED_TOOLS))}.
cordon_node and drain_node are human-only and must never appear.

Return ONLY a JSON object:
{{
  "runbook_id": "<runbook_id from the evidence>",
  "recommended_actions": [
    {{"action": "<allowed action>", "target": "<pod or deployment name>", "namespace": "<ns>",
      "priority": 1, "reason": "<one sentence, quote the runbook step>"}}
  ],
  "approval_card": {{"what": "...", "impact": "...", "rollback": "..."}},
  "estimated_impact": "...",
  "rollback_steps": ["..."],
  "grounded": true
}}
Rules:
- Order: forensic actions first (checkpoint_pod before anything destructive), then label_pod,
  apply_cilium_network_policy, delete_pod, patch_deployment replicas=0.
- Targets must come from the incident facts. Never invent pod names.
- If the evidence does not cover this incident, return {{"grounded": false, "reason": "..."}} and nothing else."""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    summary = event.get("summary", {}).get("body", {})
    triage = event.get("triage", {}).get("body", {})

    manifest = load_manifest()
    query = _evidence_query(summary, triage)
    try:
        senso = SensoClient(config.senso_base_url, resolve_secret("SENSO_API_KEY", config.senso_secret_id, "api_key"))
        evidence = senso.search_scoped(query, content_ids=list(manifest), max_results=5)
    except (SensoError, KeyError) as error:
        logger.warning("Senso evidence lookup failed: %s", error)
        return _degraded(f"evidence_unavailable: {error}", query)

    if not evidence.citations:
        return _degraded("no verified runbook covers this incident", query, evidence.to_dict())

    router = LlmRouter(config)
    completion = router.complete(
        Role.SOLUTION,
        SYSTEM_PROMPT,
        _user_message(summary, triage, evidence.answer, [c.to_dict() for c in evidence.citations]),
        max_tokens=2048,
    )
    try:
        plan = extract_json(completion.text)
    except json.JSONDecodeError:
        return _degraded("solution model returned non-JSON output", query, evidence.to_dict())

    if not plan.get("grounded", True) or not plan.get("recommended_actions"):
        return _degraded(plan.get("reason", "model declared evidence insufficient"), query, evidence.to_dict())

    plan["recommended_actions"] = [a for a in plan["recommended_actions"] if a.get("action") in ALLOWED_AUTOMATED_TOOLS]
    plan.update(
        {
            "grounded": True,
            "citations": [c.to_dict() for c in evidence.citations],
            "evidence": {"query": query, "answer": evidence.answer, "latency_ms": evidence.latency_ms},
            "model": {
                "provider": completion.provider,
                "model": completion.model,
                "latency_ms": completion.latency_ms,
                "fallback_reason": completion.fallback_reason,
            },
        }
    )
    _record(config, summary.get("incident_id"), plan)
    return plan


def _evidence_query(summary: dict, triage: dict) -> str:
    technique = summary.get("mitre_technique") or ""
    category = triage.get("category") or ""
    title = summary.get("title") or ""
    return f"Official SEKS automated response procedure for {category} {technique}: {title}".strip()


def _user_message(summary: dict, triage: dict, answer: str, citations: list[dict]) -> str:
    facts = {
        "incident_id": summary.get("incident_id"),
        "title": summary.get("title"),
        "mitre_technique": summary.get("mitre_technique"),
        "affected": summary.get("affected", {}),
        "affected_resources": summary.get("affected_resources", []),
        "severity": triage.get("severity"),
        "category": triage.get("category"),
        "correlation": triage.get("correlation"),
    }
    excerpts = "\n\n".join(f"[{c['title']} | content_id={c['content_id']}]\n{c['excerpt']}" for c in citations)
    return (
        f"INCIDENT FACTS:\n{json.dumps(facts, indent=2, ensure_ascii=False)}\n\n"
        f"VERIFIED ANSWER (Senso):\n{answer}\n\nVERIFIED EXCERPTS:\n{excerpts}"
    )


def _degraded(reason: str, query: str, evidence: dict | None = None) -> dict:
    logger.warning("Solution degraded: %s", reason)
    return {
        "grounded": False,
        "degraded": True,
        "reason": reason,
        "recommended_actions": [],
        "citations": (evidence or {}).get("citations", []),
        "evidence": {"query": query, **({"answer": evidence.get("answer")} if evidence else {})},
    }


def _record(config: Config, incident_id: str | None, plan: dict) -> None:
    if not config.store_enabled or not incident_id:
        return
    from app.shared.store import IncidentStore

    IncidentStore(config).update_incident(
        incident_id,
        {
            "solution": {
                "runbook_id": plan.get("runbook_id"),
                "actions": plan.get("recommended_actions"),
                "citations": [{"content_id": c["content_id"], "title": c["title"]} for c in plan["citations"]],
                "model": plan["model"],
            }
        },
        stage="solution",
    )
