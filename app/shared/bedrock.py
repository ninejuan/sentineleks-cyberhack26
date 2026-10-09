import logging

import boto3

logger = logging.getLogger(__name__)

FAST_MODEL_CHAIN = [
    "us.openai.gpt-5.6-luna",
    "global.openai.gpt-5.6-luna",
]

SMART_MODEL_CHAIN = [
    "us.openai.gpt-5.6-terra",
    "global.openai.gpt-5.6-terra",
    "us.openai.gpt-5.6-luna",
]

_CHAIN_BY_MODEL = {model: chain for chain in (FAST_MODEL_CHAIN, SMART_MODEL_CHAIN) for model in chain}


class BedrockClient:
    """Bedrock Converse client that keeps the Anthropic-Messages dict shape at its boundary.

    Agents build messages/tools as {type: text|tool_use|tool_result} blocks and read back
    {stop_reason, content}; this class translates to and from Converse so any Bedrock model works.
    """

    def __init__(self, model_id: str, region: str = "us-east-1"):
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def invoke(self, system_prompt: str, user_message: str, max_tokens: int = 4096) -> str:
        response = self._converse(
            system_prompt=system_prompt,
            messages=[{"role": "user", "content": [{"text": user_message}]}],
            max_tokens=max_tokens,
        )
        blocks = response["output"]["message"]["content"]
        return "".join(block["text"] for block in blocks if "text" in block)

    def invoke_with_tools(
        self,
        system_prompt: str,
        messages: list[dict],
        tools: list[dict],
        max_tokens: int = 4096,
    ) -> dict:
        response = self._converse(
            system_prompt=system_prompt,
            messages=[_to_converse_message(m) for m in messages],
            max_tokens=max_tokens,
            tool_config={"tools": [_to_converse_tool(t) for t in tools]},
        )
        blocks = response["output"]["message"]["content"]
        return {
            "stop_reason": response.get("stopReason", "end_turn"),
            "content": [_from_converse_block(b) for b in blocks if "text" in b or "toolUse" in b],
            "usage": response.get("usage", {}),
        }

    def _models(self) -> list[str]:
        if not self._model_id:
            return SMART_MODEL_CHAIN
        chain = _CHAIN_BY_MODEL.get(self._model_id, [])
        return [self._model_id, *[m for m in chain if m != self._model_id]]

    def _converse(
        self, system_prompt: str, messages: list[dict], max_tokens: int, tool_config: dict | None = None
    ) -> dict:
        kwargs: dict = {
            "system": [{"text": system_prompt}],
            "messages": messages,
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if tool_config:
            kwargs["toolConfig"] = tool_config

        last_error: Exception | None = None
        for model_id in self._models():
            try:
                return self._client.converse(modelId=model_id, **kwargs)
            except self._client.exceptions.AccessDeniedException as error:
                logger.warning("Model %s access denied, trying next: %s", model_id, error)
                last_error = error
            except self._client.exceptions.ResourceNotFoundException as error:
                logger.warning("Model %s not found, trying next: %s", model_id, error)
                last_error = error
        if last_error is None:
            raise RuntimeError("No Bedrock model configured")
        raise last_error


def _to_converse_tool(tool: dict) -> dict:
    return {
        "toolSpec": {
            "name": tool["name"],
            "description": tool.get("description", tool["name"]),
            "inputSchema": {"json": tool.get("input_schema", {"type": "object", "properties": {}})},
        }
    }


def _to_converse_message(message: dict) -> dict:
    content = message["content"]
    if isinstance(content, str):
        return {"role": message["role"], "content": [{"text": content}]}
    return {"role": message["role"], "content": [_to_converse_block(block) for block in content]}


def _to_converse_block(block: dict) -> dict:
    kind = block.get("type")
    if kind == "text":
        return {"text": block["text"]}
    if kind == "tool_use":
        return {"toolUse": {"toolUseId": block["id"], "name": block["name"], "input": block.get("input", {})}}
    if kind == "tool_result":
        payload = block.get("content", "")
        text = payload if isinstance(payload, str) else str(payload)
        return {"toolResult": {"toolUseId": block["tool_use_id"], "content": [{"text": text}]}}
    raise ValueError(f"Unsupported content block type: {kind}")


def _from_converse_block(block: dict) -> dict:
    if "text" in block:
        return {"type": "text", "text": block["text"]}
    tool_use = block["toolUse"]
    return {"type": "tool_use", "id": tool_use["toolUseId"], "name": tool_use["name"], "input": tool_use["input"]}
