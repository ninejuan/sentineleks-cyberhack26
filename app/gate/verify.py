"""Pre-execution verification gate (plan: gate/verify.py, Pi removed).

Checks, in order, and reports every violation (not only the first):
  1. citations   - the solution cites at least one document from the verified Senso manifest
  2. whitelist   - every tool call is in the automated-response whitelist (no node-level tools)
  3. protected   - no tool call targets a protected platform namespace
  4. ordering    - destructive steps come after a successful-to-be forensic capture
  5. semgrep     - rendered manifests pass the Semgrep gate (supplied by the caller)
"""

from dataclasses import dataclass, field

FORENSIC_TOOLS = frozenset(
    {
        "checkpoint_pod",
        "capture_hubble_flows",
        "collect_tetragon_timeline",
        "collect_audit_events",
        "collect_live_pod_forensics",
    }
)
CONTAINMENT_TOOLS = frozenset({"label_pod", "apply_cilium_network_policy", "delete_pod", "patch_deployment"})
ALLOWED_AUTOMATED_TOOLS = FORENSIC_TOOLS | CONTAINMENT_TOOLS
HUMAN_ONLY_TOOLS = frozenset({"cordon_node", "drain_node", "checkpoint_container_experimental"})
DESTRUCTIVE_TOOLS = frozenset({"apply_cilium_network_policy", "delete_pod"})
PROTECTED_NAMESPACES = frozenset(
    {
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "seks",
        "falco",
        "tetragon",
        "monitoring",
        "external-secrets",
        "cilium",
    }
)


@dataclass(frozen=True)
class Violation:
    check: str
    detail: str

    def to_dict(self) -> dict:
        return {"check": self.check, "detail": self.detail}


@dataclass(frozen=True)
class GateVerdict:
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "violations": [v.to_dict() for v in self.violations],
            "checks": self.checks,
        }


def _is_destructive(call: dict) -> bool:
    if call.get("tool") in DESTRUCTIVE_TOOLS:
        return True
    if call.get("tool") == "patch_deployment":
        try:
            return int(call.get("args", {}).get("replicas", -1)) == 0
        except (TypeError, ValueError):
            return True
    return False


def check_plan(tool_calls: list[dict]) -> list[Violation]:
    if not tool_calls:
        return [Violation("plan", "planner produced no tool calls")]
    return []


def check_citations(citations: list[dict], verified_ids: set[str]) -> list[Violation]:
    if not citations:
        return [Violation("citations", "solution has no citations; ungrounded recommendations go to a human")]
    unknown = [c.get("content_id", "") for c in citations if c.get("content_id") not in verified_ids]
    if unknown:
        return [Violation("citations", f"citations not in verified knowledge manifest: {unknown}")]
    return []


def check_whitelist(tool_calls: list[dict]) -> list[Violation]:
    violations = []
    for call in tool_calls:
        tool = call.get("tool", "")
        if tool in HUMAN_ONLY_TOOLS:
            violations.append(Violation("whitelist", f"{tool} is human-only (break-glass) and cannot be automated"))
        elif tool not in ALLOWED_AUTOMATED_TOOLS:
            violations.append(Violation("whitelist", f"{tool} is not an allowed automated action"))
    return violations


def check_protected_namespaces(tool_calls: list[dict]) -> list[Violation]:
    return [
        Violation("protected_namespace", f"{call.get('tool')} targets protected namespace {ns}")
        for call in tool_calls
        if (ns := str(call.get("args", {}).get("namespace", ""))) in PROTECTED_NAMESPACES
    ]


def check_ordering(tool_calls: list[dict]) -> list[Violation]:
    first_destructive = next((i for i, c in enumerate(tool_calls) if _is_destructive(c)), None)
    if first_destructive is None:
        return []
    checkpoint_index = next((i for i, c in enumerate(tool_calls) if c.get("tool") == "checkpoint_pod"), None)
    if checkpoint_index is None or checkpoint_index > first_destructive:
        return [
            Violation(
                "ordering",
                f"{tool_calls[first_destructive].get('tool')} planned before checkpoint_pod; forensics must come first",
            )
        ]
    return []


def verify(
    *,
    citations: list[dict],
    verified_ids: set[str],
    tool_calls: list[dict],
    semgrep_passed: bool | None,
) -> GateVerdict:
    results = {
        "plan": check_plan(tool_calls),
        "citations": check_citations(citations, verified_ids),
        "whitelist": check_whitelist(tool_calls),
        "protected_namespace": check_protected_namespaces(tool_calls),
        "ordering": check_ordering(tool_calls),
    }
    if semgrep_passed is not None:
        results["semgrep"] = [] if semgrep_passed else [Violation("semgrep", "Semgrep reported blocking findings")]
    violations = [v for vs in results.values() for v in vs]
    return GateVerdict(passed=not violations, violations=violations, checks={k: not v for k, v in results.items()})
