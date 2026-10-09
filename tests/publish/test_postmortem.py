from unittest.mock import patch

from app.publish.postmortem import PostmortemPublisher, SlackApiError, render_markdown

INCIDENT = {
    "incident_id": "inc-1",
    "severity": "P1",
    "title": "Cryptominer",
    "status": "remediated",
    "affected": {"cluster": "seks-demo", "namespace": "demo", "pod": "miner-abc"},
    "correlation": {
        "available": True,
        "window_min": 10,
        "distinct_sources": 2,
        "sources": ["falco", "tetragon"],
        "rule_24h": {"n": 3, "workloads": 1},
        "severity_floor": "P2",
        "query_ms": 120,
    },
    "solution": {"citations": [{"content_id": "cid-1", "title": "Cryptomining"}]},
    "gate": {"passed": True, "semgrep": {"caught": ["seks-isolation-empty-endpoint-selector"], "findings": 0}},
    "execution_log": [{"tool": "checkpoint_pod", "result": {"status": "success", "evidence_uri": "s3://b/k"}}],
    "audit": [{"stage": "detected", "at": "t0", "detail": ""}],
}


def test_markdown_contains_every_evidence_section():
    md = render_markdown(INCIDENT, [{"decision": "approve", "by": "alice", "at": "t1"}])
    assert "2** (falco, tetragon)" in md
    assert "`cid-1`" in md
    assert "seks-isolation-empty-endpoint-selector" in md
    assert "APPROVE" in md
    assert "| 1 | `checkpoint_pod` | success | s3://b/k |" in md


def test_existing_canvas_is_replaced_not_recreated():
    calls = []
    with patch("app.publish.postmortem.slack_call", side_effect=lambda t, m, p: calls.append(m) or {"ok": True}):
        result = PostmortemPublisher("xoxb", "C1").publish({**INCIDENT, "canvas_id": "F1"}, [])
    assert calls == ["canvases.edit"]
    assert result == {"mode": "canvas", "canvas_id": "F1", "action": "updated"}


def test_channel_share_failure_keeps_canvas_id_and_falls_back():
    def fake(token, method, payload):
        if method == "canvases.create":
            return {"canvas_id": "F2"}
        if method == "canvases.access.set":
            raise SlackApiError(method, "channel_not_found")
        return {"ts": "1.0"}

    with patch("app.publish.postmortem.slack_call", side_effect=fake):
        result = PostmortemPublisher("xoxb", "C1").publish(INCIDENT, [])
    assert result["mode"] == "message"
    assert result["canvas_id"] == "F2"
    assert result["fallback_reason"] == "channel_not_found"
