import json
from unittest.mock import MagicMock

import pytest

from app.agents.solution import handler
from app.shared.llm import Completion
from app.shared.senso import Citation, GroundedAnswer

MANIFEST = {"cid-crypto": {"content_id": "cid-crypto", "title": "SEKS runbooks: Cryptomining"}}
SUMMARY = {
    "incident_id": "inc-1",
    "title": "Cryptominer in demo/miner",
    "mitre_technique": "T1496",
    "affected": {"namespace": "demo", "workload": "miner", "pod": "miner-7f9c-abcde"},
}
TRIAGE = {"severity": "P1", "category": "cryptomining"}


@pytest.fixture
def wired(monkeypatch):
    monkeypatch.setenv("SENSO_API_KEY", "tgr_test")
    monkeypatch.setenv("INCIDENT_STORE_ENABLED", "false")
    monkeypatch.setattr(handler, "load_manifest", lambda: MANIFEST)
    senso = MagicMock()
    monkeypatch.setattr(handler, "SensoClient", lambda base, key: senso)
    router = MagicMock()
    monkeypatch.setattr(handler, "LlmRouter", lambda config: router)
    return senso, router


def _event():
    return {"summary": {"body": SUMMARY}, "triage": {"body": TRIAGE}}


def test_grounded_plan_carries_citations_and_model(wired, context):
    senso, router = wired
    senso.search_scoped.return_value = GroundedAnswer(
        query="q", answer="checkpoint then isolate", citations=[Citation("cid-crypto", "Cryptomining", 0.9, "1. ...")]
    )
    plan = {
        "runbook_id": "cryptomining",
        "grounded": True,
        "recommended_actions": [
            {"action": "checkpoint_pod", "target": "miner-7f9c-abcde", "namespace": "demo"},
            {"action": "drain_node", "target": "node-1", "namespace": ""},
        ],
    }
    router.complete.return_value = Completion(json.dumps(plan), "akashml", "meta-llama/Llama-3.3-70B-Instruct", 900)

    result = handler.lambda_handler(_event(), context)

    assert result["grounded"] is True
    assert [c["content_id"] for c in result["citations"]] == ["cid-crypto"]
    assert [a["action"] for a in result["recommended_actions"]] == ["checkpoint_pod"]
    assert result["model"]["provider"] == "akashml"
    assert senso.search_scoped.call_args.kwargs["content_ids"] == ["cid-crypto"]


def test_no_citations_degrades_without_calling_model(wired, context):
    senso, router = wired
    senso.search_scoped.return_value = GroundedAnswer(query="q", answer="", citations=[])

    result = handler.lambda_handler(_event(), context)

    assert result["grounded"] is False
    assert result["degraded"] is True
    assert result["recommended_actions"] == []
    router.complete.assert_not_called()


def test_senso_failure_degrades(wired, context):
    senso, router = wired
    senso.search_scoped.side_effect = handler.SensoError("down", status=503)

    result = handler.lambda_handler(_event(), context)

    assert result["degraded"] is True
    assert "evidence_unavailable" in result["reason"]
    router.complete.assert_not_called()


def test_model_declaring_insufficient_evidence_degrades(wired, context):
    senso, router = wired
    senso.search_scoped.return_value = GroundedAnswer(
        query="q", answer="a", citations=[Citation("cid-crypto", "Cryptomining", 0.4, "x")]
    )
    router.complete.return_value = Completion('{"grounded": false, "reason": "not covered"}', "bedrock", "terra", 500)

    result = handler.lambda_handler(_event(), context)

    assert result["degraded"] is True
    assert result["reason"] == "not covered"
