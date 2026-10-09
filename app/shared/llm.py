"""Role-based model router (plan: 모델 라우터).

summary/triage -> Bedrock GPT-5.6 Luna, remediation -> Bedrock GPT-5.6 Terra (tool-use),
solution -> AkashML Llama 3.3 70B (OpenAI-compatible) with Bedrock Terra as fallback.
Every completion reports which provider/model actually answered so it can be audited.
"""

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import StrEnum

from app.shared.bedrock import BedrockClient
from app.shared.config import Config
from app.shared.credentials import resolve_secret

logger = logging.getLogger(__name__)


class Role(StrEnum):
    SUMMARY = "summary"
    TRIAGE = "triage"
    SOLUTION = "solution"
    REMEDIATION = "remediation"
    FORENSICS = "forensic_synthesis"


@dataclass(frozen=True)
class Completion:
    text: str
    provider: str
    model: str
    latency_ms: int
    fallback_reason: str | None = None


class AkashError(RuntimeError):
    pass


class AkashClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout_seconds: float = 60.0):
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._api_key = api_key
        self._model = model
        self._timeout = timeout_seconds

    @property
    def model(self) -> str:
        return self._model

    def chat(self, system_prompt: str, user_message: str, max_tokens: int, json_mode: bool) -> str:
        body: dict = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        request = urllib.request.Request(  # noqa: S310 - fixed https endpoint from Config
            self._url,
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                payload = json.loads(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:300]
            raise AkashError(f"AkashML HTTP {error.code}: {detail}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise AkashError(f"AkashML unreachable: {error}") from error
        try:
            return payload["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as error:
            raise AkashError(f"AkashML unexpected response shape: {str(payload)[:300]}") from error


class LlmRouter:
    def __init__(self, config: Config | None = None, akash: AkashClient | None = None):
        self._config = config or Config()
        self._akash = akash
        self._bedrock: dict[str, BedrockClient] = {}

    def bedrock_for(self, role: Role) -> BedrockClient:
        model = self._bedrock_model(role)
        if model not in self._bedrock:
            self._bedrock[model] = BedrockClient(model_id=model, region=self._config.region)
        return self._bedrock[model]

    def complete(self, role: Role, system_prompt: str, user_message: str, max_tokens: int = 2048) -> Completion:
        if role is Role.SOLUTION:
            fallback_reason = None
            try:
                return self._akash_complete(system_prompt, user_message, max_tokens)
            except (AkashError, KeyError) as error:
                fallback_reason = f"akash_unavailable: {error}"
                logger.warning("Solution falling back to Bedrock: %s", error)
            return self._bedrock_complete(role, system_prompt, user_message, max_tokens, fallback_reason)
        return self._bedrock_complete(role, system_prompt, user_message, max_tokens, None)

    def _bedrock_model(self, role: Role) -> str:
        if role in {Role.SUMMARY, Role.TRIAGE}:
            return self._config.bedrock_fast_model_id
        return self._config.bedrock_smart_model_id

    def _bedrock_complete(
        self, role: Role, system_prompt: str, user_message: str, max_tokens: int, fallback_reason: str | None
    ) -> Completion:
        started = time.monotonic()
        text = self.bedrock_for(role).invoke(system_prompt, user_message, max_tokens=max_tokens)
        return Completion(
            text=text,
            provider="bedrock",
            model=self._bedrock_model(role),
            latency_ms=int((time.monotonic() - started) * 1000),
            fallback_reason=fallback_reason,
        )

    def _akash_complete(self, system_prompt: str, user_message: str, max_tokens: int) -> Completion:
        akash = self._akash or self._build_akash()
        started = time.monotonic()
        text = akash.chat(system_prompt, user_message, max_tokens=max_tokens, json_mode=True)
        return Completion(
            text=text, provider="akashml", model=akash.model, latency_ms=int((time.monotonic() - started) * 1000)
        )

    def _build_akash(self) -> AkashClient:
        api_key = resolve_secret("AKASHML_API_KEY", self._config.akash_secret_id, "api_key")
        self._akash = AkashClient(self._config.akash_base_url, api_key, self._config.akash_model_id)
        return self._akash
