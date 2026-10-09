import json
import urllib.error
from email.message import Message
from io import BytesIO
from unittest.mock import MagicMock

import pytest

from app.shared.config import Config
from app.shared.llm import Completion, LlmRouter, Role


class FakeBedrockClient:
    """Stand-in for app.shared.llm.BedrockClient; records calls and returns a fixed completion."""

    def __init__(self, model_id: str, region: str = "us-east-1"):
        self.model_id = model_id
        self.region = region

    def invoke(self, system_prompt: str, user_message: str, max_tokens: int = 4096) -> str:
        return "ok"


@pytest.fixture(autouse=True)
def fake_bedrock(monkeypatch):
    monkeypatch.setattr("app.shared.llm.BedrockClient", FakeBedrockClient)


def _akash_http_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode()
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    return response


def test_solution_uses_akash_when_available(monkeypatch):
    monkeypatch.setenv("AKASHML_API_KEY", "test-akash-key")
    response = _akash_http_response({"choices": [{"message": {"content": "akash answer"}}]})
    monkeypatch.setattr("urllib.request.urlopen", MagicMock(return_value=response))

    router = LlmRouter(config=Config())
    completion = router.complete(Role.SOLUTION, "system", "user message")

    assert isinstance(completion, Completion)
    assert completion.provider == "akashml"
    assert completion.fallback_reason is None


def test_solution_falls_back_to_bedrock_on_akash_http_error(monkeypatch):
    monkeypatch.setenv("AKASHML_API_KEY", "test-akash-key")
    http_error = urllib.error.HTTPError(
        url="https://api.akashml.com/v1/chat/completions",
        code=500,
        msg="Internal Server Error",
        hdrs=Message(),
        fp=BytesIO(b"server exploded"),
    )
    monkeypatch.setattr("urllib.request.urlopen", MagicMock(side_effect=http_error))

    router = LlmRouter(config=Config())
    completion = router.complete(Role.SOLUTION, "system", "user message")

    assert completion.provider == "bedrock"
    assert completion.text == "ok"
    assert completion.fallback_reason is not None
    assert "akash" in completion.fallback_reason.lower()


def test_solution_falls_back_to_bedrock_when_secret_resolution_raises(monkeypatch):
    monkeypatch.delenv("AKASHML_API_KEY", raising=False)
    monkeypatch.setattr(
        "app.shared.llm.resolve_secret",
        MagicMock(side_effect=RuntimeError("secrets manager unreachable")),
    )

    router = LlmRouter(config=Config())
    completion = router.complete(Role.SOLUTION, "system", "user message")

    assert completion.provider == "bedrock"
    assert completion.fallback_reason is not None
    assert "akash" in completion.fallback_reason.lower()


def test_solution_falls_back_to_bedrock_on_non_json_akash_body(monkeypatch):
    monkeypatch.setenv("AKASHML_API_KEY", "test-akash-key")
    response = MagicMock()
    response.read.return_value = b"not json at all"
    response.__enter__.return_value = response
    response.__exit__.return_value = False
    monkeypatch.setattr("urllib.request.urlopen", MagicMock(return_value=response))

    router = LlmRouter(config=Config())
    completion = router.complete(Role.SOLUTION, "system", "user message")

    assert completion.provider == "bedrock"
    assert completion.fallback_reason is not None
    assert "akash" in completion.fallback_reason.lower()


@pytest.mark.parametrize(
    ("role", "expected_model_attr"),
    [
        (Role.SUMMARY, "bedrock_fast_model_id"),
        (Role.TRIAGE, "bedrock_fast_model_id"),
        (Role.REMEDIATION, "bedrock_smart_model_id"),
    ],
)
def test_non_solution_roles_use_expected_bedrock_model(role, expected_model_attr):
    config = Config()
    router = LlmRouter(config=config)

    completion = router.complete(role, "system", "user message")

    assert completion.provider == "bedrock"
    assert completion.model == getattr(config, expected_model_attr)
    assert completion.fallback_reason is None
