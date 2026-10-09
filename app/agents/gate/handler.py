"""Gate agent (plan: ③ 실행 전 안전검사).

Runs between Solution and the human approval card:
  1. Terra (tool-use, no execution) turns the cited solution into concrete MCP tool calls.
  2. Render the manifests those calls would create; Semgrep scans them (custom SEKS rules + p/kubernetes).
  3. verify(): citations in the verified manifest, whitelist, protected namespaces, forensic ordering.
  4. If Semgrep blocks, the findings are fed back once and the plan is regenerated. Both attempts
     are kept, so the Slack card and post-mortem show exactly what the AI got wrong and how it was fixed.
Fail closed: anything not passing goes to Degraded (human), nothing is executed from here.
"""

import json
import logging
import os

from app.agents.remediation.handler import REMEDIATION_TOOLS
from app.gate.manifests import render_tool_calls
from app.gate.semgrep_check import scan_manifests
from app.gate.verify import ALLOWED_AUTOMATED_TOOLS, verify
from app.shared.config import Config
from app.shared.llm import LlmRouter, Role
from app.shared.senso import load_manifest

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

MAX_ATTEMPTS = 2
MAX_PLANNING_TURNS = 10
PLANNED_ACK = '{"status": "planned", "note": "not executed; continue planning the next step or finish"}'

PLANNER_PROMPT = """You are the SEKS remediation planner. Convert the cited action plan into MCP tool calls.
You are only PLANNING: nothing executes. Each call returns status=planned; then call the next step.
When every step is planned, reply with a one-line summary and no tool call.
Rules from the verified response policy:
- checkpoint_pod first, then capture_hubble_flows, then label_pod (security.incident/compromised=true),
  then apply_cilium_network_policy, then delete_pod, then patch_deployment replicas=0.
- apply_cilium_network_policy must isolate ONLY the compromised pod.
- Never act on platform namespaces. Never use node-level tools."""


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    summary = event.get("summary", {}).get("body", {})
    solution = event.get("solution", {}).get("body", {})
    incident_id = summary.get("incident_id")

    if not solution.get("grounded"):
        return _result(False, [], reason=f"solution not grounded: {solution.get('reason', 'unknown')}")

    verified_ids = set(load_manifest())
    planner_tools = [t for t in REMEDIATION_TOOLS if t["name"] in ALLOWED_AUTOMATED_TOOLS]
    router = LlmRouter(config)
    attempts: list[dict] = []
    feedback = ""

    for attempt in range(1, MAX_ATTEMPTS + 1):
        tool_calls = _plan(router, planner_tools, summary, solution, feedback)
        manifests = render_tool_calls(tool_calls)
        semgrep = scan_manifests(manifests)
        verdict = verify(
            citations=solution.get("citations", []),
            verified_ids=verified_ids,
            tool_calls=tool_calls,
            semgrep_passed=semgrep.passed,
        )
        attempts.append(
            {
                "attempt": attempt,
                "tool_calls": tool_calls,
                "manifests": [{"name": n, "yaml": y} for n, y in manifests],
                "semgrep": semgrep.to_dict(),
                "verify": verdict.to_dict(),
            }
        )
        if verdict.passed:
            break
        feedback = _feedback(semgrep.to_dict(), verdict.to_dict())
        logger.warning("Gate attempt %d blocked: %s", attempt, feedback)

    passed = attempts[-1]["verify"]["passed"]
    result = _result(
        passed,
        attempts,
        reason=None if passed else "gate blocked after regeneration",
        approved_plan=attempts[-1]["tool_calls"] if passed else [],
    )
    _record(config, incident_id, result)
    return result


def _plan(router: LlmRouter, tools: list[dict], summary: dict, solution: dict, feedback: str) -> list[dict]:
    facts = {
        "incident_id": summary.get("incident_id"),
        "affected": summary.get("affected", {}),
        "runbook_id": solution.get("runbook_id"),
        "recommended_actions": solution.get("recommended_actions", []),
    }
    content = "Plan the tool calls for this incident:\n" + json.dumps(facts, indent=2, ensure_ascii=False)
    if feedback:
        content += f"\n\nYOUR PREVIOUS PLAN WAS BLOCKED BY THE SAFETY GATE. Fix exactly these problems:\n{feedback}"
    messages: list[dict] = [{"role": "user", "content": content}]
    planned: list[dict] = []
    bedrock = router.bedrock_for(Role.REMEDIATION)
    for _ in range(MAX_PLANNING_TURNS):
        response = bedrock.invoke_with_tools(
            system_prompt=PLANNER_PROMPT, messages=messages, tools=tools, max_tokens=2048
        )
        calls = [b for b in response.get("content", []) if b.get("type") == "tool_use"]
        if response.get("stop_reason") != "tool_use" or not calls:
            break
        planned += [{"tool": b["name"], "args": b.get("input", {})} for b in calls]
        messages.append({"role": "assistant", "content": response["content"]})
        messages.append(
            {
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": b["id"], "content": PLANNED_ACK} for b in calls],
            }
        )
    return planned


def _feedback(semgrep: dict, verdict: dict) -> str:
    lines = [f"- semgrep {f['rule_id']} ({f['file']}:{f['line']}): {f['message']}" for f in semgrep["findings"]]
    lines += [f"- {v['check']}: {v['detail']}" for v in verdict["violations"] if v["check"] != "semgrep"]
    return "\n".join(lines) or "- unknown gate failure"


def _result(passed: bool, attempts: list[dict], reason: str | None, approved_plan: list | None = None) -> dict:
    first_block = next((a for a in attempts if not a["verify"]["passed"]), None)
    return {
        "passed": passed,
        "reason": reason,
        "attempts": attempts,
        "approved_plan": approved_plan or [],
        "regenerated": len(attempts) > 1,
        "caught_by_semgrep": list((first_block or {}).get("semgrep", {}).get("findings", [])),
    }


def _record(config: Config, incident_id: str | None, result: dict) -> None:
    if not config.store_enabled or not incident_id:
        return
    from app.shared.store import IncidentStore

    last = result["attempts"][-1] if result["attempts"] else {}
    IncidentStore(config).update_incident(
        incident_id,
        {
            "gate": {
                "passed": result["passed"],
                "regenerated": result["regenerated"],
                "semgrep": {
                    "passed": last.get("semgrep", {}).get("passed"),
                    "findings": len(last.get("semgrep", {}).get("findings", [])),
                    "caught": [f["rule_id"] for f in result["caught_by_semgrep"]],
                },
                "verify": last.get("verify", {}),
            },
            "approved_plan": result["approved_plan"],
        },
        stage="gate_passed" if result["passed"] else "gate_blocked",
    )
