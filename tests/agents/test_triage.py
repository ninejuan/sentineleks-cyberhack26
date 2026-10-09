import json
from unittest.mock import MagicMock

import pytest

from app.agents.triage import handler
from app.shared.llm import Completion
from app.sink.clickhouse import Correlation

SUMMARY = {
    "incident_id": "inc-1",
    "source": "falco",
    "rule_id": "Crypto mining process detected",
    "summary": "xmrig in demo/miner",
    "affected": {"namespace": "demo", "workload": "miner", "pod": "miner-7f9c-abcde"},
}


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setenv("INCIDENT_STORE_ENABLED", "false")
    router = MagicMock()
    monkeypatch.setattr(handler, "LlmRouter", lambda config: router)
    monkeypatch.setattr(handler, "_notify_slack", lambda config, triage, summary: None)
    return router


def _with_correlation(monkeypatch, correlation: Correlation):
    sink = MagicMock()
    sink.correlate.return_value = correlation
    monkeypatch.setattr(handler.SensorSink, "from_config", classmethod(lambda cls, config: sink))
    return sink


def test_correlation_floor_overrides_lower_model_severity(wired, monkeypatch, context):
    sink = _with_correlation(
        monkeypatch,
        Correlation(
            available=True,
            window_min=10,
            distinct_sources=3,
            sources=["falco", "guardduty", "tetragon"],
            severity_floor="P1",
            query_ms=12,
        ),
    )
    wired.complete.return_value = Completion(
        json.dumps({"severity": "P2", "confidence": 0.8, "category": "cryptomining", "rationale": "3 sensors"}),
        "bedrock",
        "luna",
        300,
    )

    result = handler.lambda_handler({"summary": {"body": SUMMARY}}, context)

    assert result["severity"] == "P1"
    assert result["model_severity"] == "P2"
    assert result["escalated_by_correlation"] is True
    assert result["requires_approval"] is True
    args = sink.correlate.call_args.args
    assert args[1:4] == ("demo", "miner", "Crypto mining process detected")


def test_model_cannot_lower_below_floor_and_higher_model_wins(wired, monkeypatch, context):
    _with_correlation(
        monkeypatch,
        Correlation(
            available=True, window_min=10, distinct_sources=2, sources=["falco", "tetragon"], severity_floor="P2"
        ),
    )
    wired.complete.return_value = Completion('{"severity": "P1", "category": "cryptomining"}', "bedrock", "luna", 1)

    result = handler.lambda_handler({"summary": {"body": SUMMARY}}, context)

    assert result["severity"] == "P1"
    assert result["escalated_by_correlation"] is False


def test_unavailable_correlation_is_recorded_not_skipped(wired, monkeypatch, context):
    _with_correlation(monkeypatch, Correlation(available=False, window_min=10, error="timeout"))
    wired.complete.return_value = Completion('{"severity": "P3", "category": "dns_anomaly"}', "bedrock", "luna", 1)

    result = handler.lambda_handler({"summary": {"body": SUMMARY}}, context)

    assert result["severity"] == "P3"
    assert result["correlation"]["available"] is False
    assert result["correlation"]["error"] == "timeout"
    assert result["auto_remediate"] is True


def test_non_json_model_output_defaults_to_p2(wired, monkeypatch, context):
    _with_correlation(monkeypatch, Correlation(available=True, window_min=10, distinct_sources=1, sources=["falco"]))
    wired.complete.return_value = Completion("not json", "bedrock", "luna", 1)

    result = handler.lambda_handler({"summary": {"body": SUMMARY}}, context)

    assert result["severity"] == "P2"
    assert result["category"] == "unknown"


def test_missing_workload_marks_correlation_unavailable(wired, context):
    wired.complete.return_value = Completion('{"severity": "P4"}', "bedrock", "luna", 1)

    result = handler.lambda_handler({"summary": {"body": {"incident_id": "inc-2"}}}, context)

    assert result["correlation"]["available"] is False
    assert result["severity"] == "P4"
