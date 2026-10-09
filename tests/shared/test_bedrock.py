from app.shared.bedrock import FAST_MODEL_CHAIN, SMART_MODEL_CHAIN, BedrockClient


def _converse_reply(content: list[dict], stop_reason: str = "end_turn") -> dict:
    return {"output": {"message": {"role": "assistant", "content": content}}, "stopReason": stop_reason, "usage": {}}


def test_invoke_returns_text_from_converse_response(aws_mocks):
    bedrock = aws_mocks["clients"]["bedrock-runtime"]
    bedrock.converse.return_value = _converse_reply([{"text": '{"ok": true}'}])
    client = BedrockClient(model_id="model-1", region="eu-central-1")

    result = client.invoke("system", "user", max_tokens=123)

    assert result == '{"ok": true}'
    kwargs = bedrock.converse.call_args.kwargs
    assert kwargs["modelId"] == "model-1"
    assert kwargs["system"] == [{"text": "system"}]
    assert kwargs["messages"] == [{"role": "user", "content": [{"text": "user"}]}]
    assert kwargs["inferenceConfig"] == {"maxTokens": 123}
    assert "toolConfig" not in kwargs


def test_invoke_with_tools_translates_both_directions(aws_mocks):
    bedrock = aws_mocks["clients"]["bedrock-runtime"]
    bedrock.converse.return_value = _converse_reply(
        [
            {"text": "isolating"},
            {"toolUse": {"toolUseId": "t-2", "name": "label_pod", "input": {"pod_name": "p"}}},
        ],
        stop_reason="tool_use",
    )
    client = BedrockClient(model_id="model-2", region="us-east-1")
    messages = [
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": "t-1", "name": "checkpoint_pod", "input": {}}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t-1", "content": '{"status":"success"}'}]},
    ]
    tools = [{"name": "label_pod", "description": "d", "input_schema": {"type": "object", "properties": {}}}]

    result = client.invoke_with_tools("system", messages, tools, 55)

    assert result["stop_reason"] == "tool_use"
    assert result["content"] == [
        {"type": "text", "text": "isolating"},
        {"type": "tool_use", "id": "t-2", "name": "label_pod", "input": {"pod_name": "p"}},
    ]
    kwargs = bedrock.converse.call_args.kwargs
    assert kwargs["toolConfig"]["tools"][0]["toolSpec"]["name"] == "label_pod"
    assert kwargs["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"] == {"json": tools[0]["input_schema"]}
    assert kwargs["messages"][1]["content"][0] == {
        "toolUse": {"toolUseId": "t-1", "name": "checkpoint_pod", "input": {}}
    }
    assert kwargs["messages"][2]["content"][0] == {
        "toolResult": {"toolUseId": "t-1", "content": [{"text": '{"status":"success"}'}]}
    }
    assert kwargs["inferenceConfig"] == {"maxTokens": 55}


def test_falls_back_within_chain_on_access_denied(aws_mocks):
    bedrock = aws_mocks["clients"]["bedrock-runtime"]

    class AccessDeniedError(Exception):
        pass

    class NotFoundError(Exception):
        pass

    bedrock.exceptions.AccessDeniedException = AccessDeniedError
    bedrock.exceptions.ResourceNotFoundException = NotFoundError
    bedrock.converse.side_effect = [AccessDeniedError("no"), _converse_reply([{"text": "ok"}])]
    client = BedrockClient(model_id=SMART_MODEL_CHAIN[0], region="us-east-1")

    assert client.invoke("s", "u") == "ok"
    tried = [call.kwargs["modelId"] for call in bedrock.converse.call_args_list]
    assert tried == SMART_MODEL_CHAIN[:2]


def test_model_chains_are_openai_gpt_5_6():
    assert all("openai.gpt-5.6-luna" in m for m in FAST_MODEL_CHAIN)
    assert SMART_MODEL_CHAIN[0] == "us.openai.gpt-5.6-terra"
