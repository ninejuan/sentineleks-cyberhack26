import json
import logging
import os

from app.shared.bedrock import BedrockClient
from app.shared.config import Config

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

SYSTEM_PROMPT = """You are a security remediation executor for SEKS (AI Threat Detection and Response).
You receive a list of recommended remediation actions and execute them against an EKS cluster
using the available MCP tools.

You MUST follow this execution order for pod isolation:
1. checkpoint_pod (preserve forensic evidence)
2. capture_hubble_flows (capture network flows)
3. label_pod with security.incident/compromised=true (triggers Tetragon SIGKILL)
4. apply_cilium_network_policy deny-all
5. delete_pod with --force --grace-period=0
6. patch_deployment to scale replicas=0

For each action, report:
- action: what was executed
- status: success or failed
- details: execution output or error message
- timestamp: when the action was executed

If an action fails, continue with remaining actions unless it's a critical dependency.
Never skip checkpoint_pod before isolation.

SEKS enforces this ordering server-side: any destructive tool (delete_pod, apply_cilium_network_policy,
cordon_node, drain_node, patch_deployment with replicas=0) returns status=blocked until checkpoint_pod
has returned status=success in this run. If you receive a blocked response, re-issue the forensic
tools first, then retry the destructive action. Do not ignore blocked responses."""

REMEDIATION_TOOLS = [
    {
        "name": "label_pod",
        "description": "Add or update labels on a pod",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "labels": {"type": "object"},
            },
            "required": ["pod_name", "namespace", "labels"],
        },
    },
    {
        "name": "apply_cilium_network_policy",
        "description": "Apply a CiliumNetworkPolicy to isolate a pod or namespace",
        "input_schema": {
            "type": "object",
            "properties": {
                "policy_name": {"type": "string"},
                "namespace": {"type": "string"},
                "pod_selector": {"type": "object"},
                "deny_all": {"type": "boolean"},
            },
            "required": ["policy_name", "namespace"],
        },
    },
    {
        "name": "delete_pod",
        "description": "Delete a pod, optionally with force",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "force": {"type": "boolean"},
                "grace_period_seconds": {"type": "integer"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "patch_deployment",
        "description": "Patch a deployment (e.g., scale replicas)",
        "input_schema": {
            "type": "object",
            "properties": {
                "deployment_name": {"type": "string"},
                "namespace": {"type": "string"},
                "replicas": {"type": "integer"},
            },
            "required": ["deployment_name", "namespace", "replicas"],
        },
    },
    {
        "name": "checkpoint_pod",
        "description": "Capture pod forensics evidence and export it to the SEKS forensics S3 bucket before isolation",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "container_name": {"type": "string"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "capture_hubble_flows",
        "description": "Capture Cilium/Hubble flow evidence for a pod and export it to the SEKS forensics S3 bucket",
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "collect_tetragon_timeline",
        "description": (
            "Retrieve the recent Tetragon process/file/network events recorded for the given pod UID. "
            "Use the pod UID from checkpoint_pod output or the raw event to correlate the attacker's activity."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_uid": {"type": "string"},
                "since_minutes": {"type": "integer"},
                "max_events": {"type": "integer"},
            },
            "required": ["pod_uid"],
        },
    },
    {
        "name": "collect_audit_events",
        "description": (
            "Run a CloudWatch Logs Insights query against the EKS audit log to retrieve all API "
            "operations involving the given pod (create, exec, delete, etc.). Helps attribute who "
            "made changes and identify lateral RBAC abuse."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "since_minutes": {"type": "integer"},
                "max_events": {"type": "integer"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "collect_live_pod_forensics",
        "description": (
            "Inject a short-lived debug container into the target pod (via Kubernetes ephemeral "
            "containers) and run a read-only forensic profile. Available profiles: "
            "'process_snapshot', 'network_snapshot', 'filesystem_triage', 'env_redacted'. "
            "The debug image and commands are owned by the MCP server; do not attempt to pass "
            "arbitrary shell commands."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "profile": {
                    "type": "string",
                    "enum": [
                        "process_snapshot",
                        "network_snapshot",
                        "filesystem_triage",
                        "env_redacted",
                    ],
                },
                "target_container": {"type": "string"},
            },
            "required": ["pod_name", "namespace", "profile"],
        },
    },
    {
        "name": "checkpoint_container_experimental",
        "description": (
            "EXPERIMENTAL. Attempt a CRIU-based container checkpoint through the kubelet "
            "/checkpoint endpoint. Requires a node with ContainerCheckpoint feature gate + CRIU + "
            "containerd checkpoint support. On unsupported nodes returns status='unsupported' with "
            "a fallback_recommendation; this is expected and does not indicate an incident failure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pod_name": {"type": "string"},
                "namespace": {"type": "string"},
                "container_name": {"type": "string"},
            },
            "required": ["pod_name", "namespace"],
        },
    },
    {
        "name": "cordon_node",
        "description": "Mark a node as unschedulable",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_name": {"type": "string"},
            },
            "required": ["node_name"],
        },
    },
    {
        "name": "drain_node",
        "description": "Drain all pods from a node",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_name": {"type": "string"},
                "ignore_daemonsets": {"type": "boolean"},
            },
            "required": ["node_name"],
        },
    },
]

# Tools that alter or remove a compromised workload. They MUST NOT execute
# before forensic capture has succeeded in the current execution_log. The
# SYSTEM_PROMPT alone is not enough because the LLM reorders tool calls.
DESTRUCTIVE_TOOLS = frozenset(
    {
        "delete_pod",
        "apply_cilium_network_policy",
        "cordon_node",
        "drain_node",
    }
)

REQUIRED_FORENSIC_TOOLS = ("checkpoint_pod",)


def _is_destructive_scaledown(tool_name: str, tool_input: dict) -> bool:
    if tool_name != "patch_deployment":
        return False
    try:
        return int(tool_input.get("replicas", -1)) == 0
    except (TypeError, ValueError):
        return False


def _is_destructive(tool_name: str, tool_input: dict) -> bool:
    if tool_name in DESTRUCTIVE_TOOLS:
        return True
    return _is_destructive_scaledown(tool_name, tool_input)


def _forensic_precondition_met(execution_log: list, required: tuple = REQUIRED_FORENSIC_TOOLS) -> list:
    """Return the list of required forensic tools that have NOT yet succeeded.

    Empty list means the precondition is satisfied and destructive actions may proceed.
    """
    succeeded = {
        entry["tool"]
        for entry in execution_log
        if isinstance(entry, dict)
        and entry.get("tool") in required
        and isinstance(entry.get("result"), dict)
        and entry["result"].get("status") == "success"
    }
    return [tool for tool in required if tool not in succeeded]


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    summary = event.get("summary", {}).get("body", {})
    incident_id = summary.get("incident_id") if isinstance(summary, dict) else None
    gate = event.get("gate", {}).get("body")

    if isinstance(gate, dict):
        result = _execute_approved_plan(gate, incident_id)
    else:
        result = _llm_tool_loop(config, event, incident_id)

    _update_incident_status(config, event, result)
    return result


SUCCESS_EQUIVALENT_STATUSES = frozenset({"success", "unsupported"})


def _execution_log_all_succeeded(execution_log: list[dict]) -> bool:
    """True only if the plan ran at least one step and every result succeeded.

    "unsupported" (checkpoint_container_experimental on an incapable node) counts
    as success-equivalent per MCP experimental-tool contract; it is not a failure.
    """
    if not execution_log:
        return False
    for entry in execution_log:
        result = entry.get("result", {})
        if not isinstance(result, dict) or result.get("status") not in SUCCESS_EQUIVALENT_STATUSES:
            return False
    return True


def _execute_approved_plan(gate: dict, incident_id: str | None) -> dict:
    """Execute exactly the plan the gate verified and the human approved. No LLM in the loop."""
    from app.gate.verify import ALLOWED_AUTOMATED_TOOLS

    if not gate.get("passed"):
        return {
            "status": "blocked_by_gate",
            "execution_log": [{"type": "gate", "text": gate.get("reason", "gate did not pass")}],
            "actions_taken": 0,
        }
    execution_log: list[dict] = []
    for call in gate.get("approved_plan", []):
        tool_name, tool_input = call.get("tool", ""), dict(call.get("args", {}))
        if tool_name not in ALLOWED_AUTOMATED_TOOLS:
            result = {"status": "blocked", "action": tool_name, "error": "not in automated whitelist"}
        else:
            result = _execute_tool(tool_name, tool_input, execution_log, incident_id=incident_id)
        execution_log.append({"tool": tool_name, "input": tool_input, "result": result})
    status = "completed" if _execution_log_all_succeeded(execution_log) else "failed"
    return {
        "status": status,
        "mode": "approved_plan",
        "execution_log": execution_log,
        "actions_taken": len(execution_log),
    }


def _llm_tool_loop(config: Config, event: dict, incident_id: str | None) -> dict:
    client = BedrockClient(model_id=config.bedrock_model_id or config.bedrock_smart_model_id, region=config.region)

    summary = event.get("summary", {}).get("body", {})
    triage = event.get("triage", {}).get("body", {})
    solution = event.get("solution", {}).get("body", {})

    context_json = json.dumps(
        {"summary": summary, "triage": triage, "solution": solution},
        indent=2,
        ensure_ascii=False,
    )

    messages = [
        {
            "role": "user",
            "content": f"Execute the recommended remediation actions:\n\n{context_json}",
        }
    ]

    execution_log = []
    max_iterations = 10

    for _ in range(max_iterations):
        response = client.invoke_with_tools(
            system_prompt=SYSTEM_PROMPT,
            messages=messages,
            tools=REMEDIATION_TOOLS,
            max_tokens=4096,
        )

        stop_reason = response.get("stop_reason", "end_turn")

        if stop_reason != "tool_use":
            final_text = ""
            for block in response.get("content", []):
                if block.get("type") == "text":
                    final_text = block["text"]
            execution_log.append({"type": "completion", "text": final_text})
            break

        messages.append({"role": "assistant", "content": response["content"]})

        tool_results = []
        for block in response.get("content", []):
            if block.get("type") == "tool_use":
                tool_name = block["name"]
                tool_input = block["input"]
                tool_id = block["id"]

                result = _execute_tool(tool_name, tool_input, execution_log, incident_id=incident_id)
                execution_log.append({"tool": tool_name, "input": tool_input, "result": result})

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tool_id,
                        "content": json.dumps(result),
                    }
                )

        messages.append({"role": "user", "content": tool_results})

    return {
        "status": "completed",
        "mode": "llm_tool_loop",
        "execution_log": execution_log,
        "actions_taken": len([e for e in execution_log if "tool" in e]),
    }


def _update_incident_status(config: Config, event: dict, result: dict) -> None:
    from app.shared.store import IncidentStore

    if not config.store_enabled:
        return

    summary = event.get("summary", {}).get("body", {})
    incident_id = summary.get("incident_id")
    if not incident_id:
        return

    execution_log = result.get("execution_log", [])
    evidence_uris = []
    for entry in execution_log:
        r = entry.get("result", {})
        if isinstance(r, dict) and r.get("evidence_uri"):
            evidence_uris.append(r["evidence_uri"])

    remediation_status = result.get("status", "unknown")
    incident_status = "remediated" if remediation_status == "completed" else "remediation_failed"

    store = IncidentStore(config)
    store.update_incident(
        incident_id=incident_id,
        updates={
            "status": incident_status,
            "actions_taken": [e["tool"] for e in execution_log if e.get("tool")],
            "actions_count": result.get("actions_taken", 0),
            "remediation_status": remediation_status,
            "execution_log": execution_log,
            "evidence_uris": evidence_uris,
        },
    )

    _notify_remediation_complete(config, incident_id, execution_log, evidence_uris, remediation_status)


def _notify_remediation_complete(
    config: Config, incident_id: str, execution_log: list, evidence_uris: list, remediation_status: str = "unknown"
) -> None:
    from urllib.request import Request, urlopen

    from app.shared.secrets import get_secret

    secret = get_secret(f"{config.project}/slack/bot-token")
    webhook_url = secret.get("webhook_url", "")
    if not webhook_url:
        return

    succeeded = [e for e in execution_log if e.get("tool") and e.get("result", {}).get("status") == "success"]
    failed = [e for e in execution_log if e.get("tool") and e.get("result", {}).get("status") != "success"]

    is_failed = remediation_status == "failed"
    status_emoji = "❌" if is_failed else ("✅" if not failed else "⚠️")
    header_text = "Remediation FAILED" if is_failed else "Remediation Complete"
    summary_text = f"{len(succeeded)} succeeded, {len(failed)} failed"

    tool_lines = []
    for entry in execution_log:
        if "tool" not in entry:
            continue
        r = entry.get("result", {})
        status = r.get("status", "unknown")
        marker = "✅" if status == "success" else "❌"
        tool_lines.append(f"{marker} `{entry['tool']}` — {status}")

    evidence_text = ""
    if evidence_uris:
        evidence_text = "\n*Forensic Evidence:*\n" + "\n".join(f"• `{uri}`" for uri in evidence_uris)

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{status_emoji} {header_text}: {incident_id}"},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Result:* {summary_text}\n\n" + "\n".join(tool_lines)},
        },
    ]

    if evidence_text:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": evidence_text}})

    color = "#d93025" if is_failed else ("#36a64f" if not failed else "#ff9900")
    payload = json.dumps({"attachments": [{"color": color, "blocks": blocks}]}).encode()
    req = Request(webhook_url, data=payload, headers={"Content-Type": "application/json"})  # noqa: S310
    try:
        with urlopen(req, timeout=10) as resp:  # noqa: S310
            logger.info("Remediation notification sent: %s", resp.status)
    except Exception as error:
        logger.warning("Failed to send remediation notification: %s", error)


def _execute_tool(tool_name: str, tool_input: dict, execution_log: list, *, incident_id: str | None = None) -> dict:
    from app.agents.remediation.tools import execute_tool

    if _is_destructive(tool_name, tool_input):
        missing = _forensic_precondition_met(execution_log)
        if missing:
            logger.warning(
                "Blocked destructive tool %s: forensic precondition not met (missing=%s)",
                tool_name,
                missing,
            )
            return {
                "status": "blocked",
                "action": tool_name,
                "error": (
                    f"forensic_precondition_not_met: required tool(s) {missing} must succeed before destructive actions"
                ),
                "required_forensic_tools": list(REQUIRED_FORENSIC_TOOLS),
            }

    return execute_tool(tool_name, tool_input, incident_id=incident_id)
