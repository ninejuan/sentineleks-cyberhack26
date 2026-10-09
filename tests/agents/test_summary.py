from unittest.mock import MagicMock

import pytest

from app.agents.summary import handler
from app.shared.llm import Completion

FALCO_EVENT = {
    "rule": "Crypto mining process detected",
    "priority": "Critical",
    "time": "2026-10-09T21:00:00Z",
    "output": "Crypto miner detected (user=root command=xmrig pod=miner-7f9c8d6b5-x2k9q ns=demo)",
    "output_fields": {
        "k8s.ns.name": "demo",
        "k8s.pod.name": "miner-7f9c8d6b5-x2k9q",
        "proc.name": "xmrig",
        "proc.cmdline": "xmrig -o pool.example:3333",
    },
    "tags": ["mitre_impact", "T1496"],
}


@pytest.fixture
def router(monkeypatch):
    monkeypatch.setenv("INCIDENT_STORE_ENABLED", "false")
    fake = MagicMock()
    monkeypatch.setattr(handler, "LlmRouter", lambda config: fake)
    return fake


def test_identity_fields_come_from_code_not_model(router, context):
    router.complete.return_value = Completion(
        '{"title": "Miner", "summary": "xmrig ran", "raw_indicators": ["xmrig"], "mitre_technique": "T9999"}',
        "bedrock",
        "luna",
        200,
    )

    result = handler.lambda_handler({"raw_event": FALCO_EVENT}, context)

    assert result["incident_id"].startswith("inc-")
    assert "-falco-" in result["incident_id"]
    assert result["affected"]["namespace"] == "demo"
    assert result["affected"]["workload"] == "miner"
    assert result["affected"]["pod"] == "miner-7f9c8d6b5-x2k9q"
    assert result["rule_id"] == "Crypto mining process detected"
    assert result["mitre_technique"] == "T1496"
    assert result["title"] == "Miner"
    assert result["raw_event"] == FALCO_EVENT


def test_prefers_normalized_event_from_ingestor(router, context):
    router.complete.return_value = Completion('{"title": "t", "summary": "s"}', "bedrock", "luna", 1)
    normalized = {
        "tenant_id": "t",
        "cluster": "c",
        "namespace": "ns",
        "workload": "wl",
        "pod": "wl-abc",
        "source": "tetragon",
        "rule_id": "detect-cryptominer-egress",
        "mitre_technique": "",
        "severity_hint": "",
        "process": {"exe": "/usr/bin/xmrig", "cmdline": ""},
        "network": {"remote": "203.0.113.5:3333"},
        "raw_hash": "h",
        "ts": "2026-10-09T21:00:00+00:00",
    }

    result = handler.lambda_handler({"raw_event": {"process_kprobe": {}}, "normalized": normalized}, context)

    assert result["affected"]["workload"] == "wl"
    assert result["source"] == "tetragon"
    assert result["network"]["remote"] == "203.0.113.5:3333"


def test_non_json_summary_falls_back(router, context):
    router.complete.return_value = Completion("plain text", "bedrock", "luna", 1)

    result = handler.lambda_handler({"raw_event": FALCO_EVENT}, context)

    assert result["summary"] == "plain text"
    assert result["title"] == "Crypto mining process detected"
