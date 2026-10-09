"""Render the exact manifests a remediation plan will apply, so they can be scanned before execution.

Mirrors mcp_server.apply_cilium_network_policy body construction. The MCP server stays the
authority at apply time; this rendering exists so Semgrep sees the same YAML a human would review.
"""

import yaml

COMPROMISED_LABEL = {"security.incident/compromised": "true"}


def cilium_isolation_policy(policy_name: str, namespace: str, pod_selector: dict | None, deny_all: bool) -> dict:
    spec: dict = {
        "endpointSelector": {"matchLabels": dict(pod_selector) if pod_selector is not None else COMPROMISED_LABEL}
    }
    if deny_all:
        spec["ingressDeny"] = [{"fromEntities": ["all"]}]
        spec["egressDeny"] = [{"toEntities": ["all"]}]
    return {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {"name": policy_name, "namespace": namespace, "labels": {"seks.juany.dev/managed": "true"}},
        "spec": spec,
    }


def render_tool_calls(tool_calls: list[dict]) -> list[tuple[str, str]]:
    """Return (filename, yaml_text) for every tool call that materialises a Kubernetes object."""
    manifests: list[tuple[str, str]] = []
    for index, call in enumerate(tool_calls):
        tool, args = call.get("tool"), call.get("args", {})
        if tool == "apply_cilium_network_policy":
            raw_selector = args.get("pod_selector")
            selector = raw_selector.get("matchLabels", raw_selector) if isinstance(raw_selector, dict) else None
            body = cilium_isolation_policy(
                policy_name=str(args.get("policy_name", f"seks-isolate-{index}")),
                namespace=str(args.get("namespace", "")),
                pod_selector=selector,
                deny_all=bool(args.get("deny_all", True)),
            )
            manifests.append(
                (f"{index:02d}-cnp-{body['metadata']['name']}.yaml", yaml.safe_dump(body, sort_keys=False))
            )
        elif tool == "patch_deployment":
            body = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": str(args.get("deployment_name", "")), "namespace": str(args.get("namespace", ""))},
                "spec": {"replicas": args.get("replicas")},
            }
            manifests.append((f"{index:02d}-deploy-patch.yaml", yaml.safe_dump(body, sort_keys=False)))
        elif tool == "label_pod":
            body = {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": str(args.get("pod_name", "")),
                    "namespace": str(args.get("namespace", "")),
                    "labels": dict(args.get("labels") or {}),
                },
            }
            manifests.append((f"{index:02d}-pod-label.yaml", yaml.safe_dump(body, sort_keys=False)))
    return manifests
