import pytest

from app.gate.manifests import render_tool_calls
from app.gate.semgrep_check import scan_manifests, semgrep_binary
from app.gate.verify import verify

GOOD_PLAN = [
    {"tool": "checkpoint_pod", "args": {"namespace": "demo", "pod_name": "miner-abc"}},
    {"tool": "capture_hubble_flows", "args": {"namespace": "demo", "pod_name": "miner-abc"}},
    {
        "tool": "label_pod",
        "args": {"namespace": "demo", "pod_name": "miner-abc", "labels": {"security.incident/compromised": "true"}},
    },
    {
        "tool": "apply_cilium_network_policy",
        "args": {
            "namespace": "demo",
            "policy_name": "seks-isolate-miner-abc",
            "pod_selector": {"security.incident/compromised": "true"},
            "deny_all": True,
        },
    },
    {"tool": "delete_pod", "args": {"namespace": "demo", "pod_name": "miner-abc"}},
    {"tool": "patch_deployment", "args": {"namespace": "demo", "deployment_name": "miner", "replicas": 0}},
]
CITATIONS = [{"content_id": "cid-1", "title": "Cryptomining"}]


def test_empty_plan_fails():
    verdict = verify(citations=CITATIONS, verified_ids={"cid-1"}, tool_calls=[], semgrep_passed=True)
    assert not verdict.passed
    assert verdict.checks["plan"] is False
    assert any(v.check == "plan" for v in verdict.violations)


def test_good_plan_passes_all_checks():
    verdict = verify(citations=CITATIONS, verified_ids={"cid-1"}, tool_calls=GOOD_PLAN, semgrep_passed=True)
    assert verdict.passed
    assert all(verdict.checks.values())


def test_missing_or_unverified_citations_fail():
    assert not verify(citations=[], verified_ids={"cid-1"}, tool_calls=GOOD_PLAN, semgrep_passed=True).passed
    verdict = verify(
        citations=[{"content_id": "made-up"}], verified_ids={"cid-1"}, tool_calls=GOOD_PLAN, semgrep_passed=True
    )
    assert verdict.checks["citations"] is False


def test_node_tools_and_unknown_tools_are_rejected():
    plan = [*GOOD_PLAN, {"tool": "drain_node", "args": {"node_name": "ip-10-0-1-1"}}, {"tool": "rm_rf", "args": {}}]
    verdict = verify(citations=CITATIONS, verified_ids={"cid-1"}, tool_calls=plan, semgrep_passed=True)
    assert verdict.checks["whitelist"] is False
    assert len([v for v in verdict.violations if v.check == "whitelist"]) == 2


def test_protected_namespace_is_rejected():
    plan = [{"tool": "checkpoint_pod", "args": {"namespace": "kube-system", "pod_name": "coredns-x"}}]
    verdict = verify(citations=CITATIONS, verified_ids={"cid-1"}, tool_calls=plan, semgrep_passed=True)
    assert verdict.checks["protected_namespace"] is False


def test_destructive_before_checkpoint_is_rejected():
    plan = [GOOD_PLAN[4], GOOD_PLAN[0]]
    verdict = verify(citations=CITATIONS, verified_ids={"cid-1"}, tool_calls=plan, semgrep_passed=True)
    assert verdict.checks["ordering"] is False


def test_semgrep_failure_fails_gate():
    verdict = verify(citations=CITATIONS, verified_ids={"cid-1"}, tool_calls=GOOD_PLAN, semgrep_passed=False)
    assert not verdict.passed
    assert verdict.checks["semgrep"] is False


def test_renderer_keeps_compromised_selector_and_empty_selector_stays_empty():
    good = dict(render_tool_calls(GOOD_PLAN))
    cnp = next(text for name, text in good.items() if "cnp" in name)
    assert "security.incident/compromised" in cnp
    bad = render_tool_calls(
        [{"tool": "apply_cilium_network_policy", "args": {"namespace": "demo", "policy_name": "p", "pod_selector": {}}}]
    )
    assert "matchLabels: {}" in bad[0][1]


@pytest.mark.skipif(semgrep_binary() is None, reason="semgrep CLI not installed")
def test_semgrep_blocks_empty_selector_and_passes_scoped_policy(monkeypatch):
    monkeypatch.setattr("app.gate.semgrep_check.REGISTRY_CONFIGS", ())
    bad = render_tool_calls(
        [
            {
                "tool": "apply_cilium_network_policy",
                "args": {"namespace": "demo", "policy_name": "seks-isolate-x", "pod_selector": {}, "deny_all": True},
            }
        ]
    )
    blocked = scan_manifests(bad)
    assert not blocked.passed
    assert "seks-isolation-empty-endpoint-selector" in {f.rule_id for f in blocked.findings}

    assert scan_manifests(render_tool_calls(GOOD_PLAN)).passed
