import base64
import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock
from urllib.parse import quote

from app.slack_bot import handler


def _signature(body, timestamp, secret="slack-signing-secret"):
    return "v0=" + hmac.new(secret.encode(), f"v0:{timestamp}:{body}".encode(), hashlib.sha256).hexdigest()


def _signed_event(path, body):
    timestamp = str(int(time.time()))
    return {
        "rawPath": path,
        "body": body,
        "headers": {"x-slack-request-timestamp": timestamp, "x-slack-signature": _signature(body, timestamp)},
    }


def test_verify_slack_signature_accepts_valid_signature(aws_mocks):
    body = "command=%2Fseks&text=status"
    timestamp = str(int(time.time()))

    assert handler._verify_slack_signature(
        body,
        {"x-slack-request-timestamp": timestamp, "x-slack-signature": _signature(body, timestamp)},
        "test-seks",
    )


def test_verify_slack_signature_rejects_missing_or_old_signature(aws_mocks):
    body = "payload={}"
    assert not handler._verify_slack_signature(body, {}, "test-seks")
    old_timestamp = str(int(time.time()) - handler.SLACK_TIMESTAMP_MAX_AGE - 10)
    assert not handler._verify_slack_signature(
        body,
        {"x-slack-request-timestamp": old_timestamp, "x-slack-signature": _signature(body, old_timestamp)},
        "test-seks",
    )


def test_lambda_handler_rejects_invalid_signature(aws_mocks, context):
    result = handler.lambda_handler({"rawPath": "/slack/events", "body": "{}", "headers": {}}, context)

    assert result == {"statusCode": 401, "body": "Invalid signature"}


def test_events_url_verification_returns_challenge(aws_mocks, context):
    body = json.dumps({"type": "url_verification", "challenge": "challenge-token"})

    result = handler.lambda_handler(_signed_event("/slack/events", body), context)

    assert result["statusCode"] == 200
    assert result["headers"] == {"Content-Type": "text/plain"}
    assert result["body"] == "challenge-token"


def test_events_non_verification_returns_ok(aws_mocks, context):
    body = json.dumps(
        {
            "type": "event_callback",
            "event": {"type": "app_mention", "text": "hello", "channel": "C123", "bot_id": "B123"},
        }
    )

    result = handler.lambda_handler(_signed_event("/slack/events", body), context)

    assert result == {"statusCode": 200, "body": "ok"}


def test_interactions_missing_payload_returns_bad_request(aws_mocks, context):
    body = "not_payload=1"

    result = handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    assert result == {"statusCode": 400, "body": "Missing payload"}


def test_interactions_approve_action_writes_audit(aws_mocks, seed_incidents, context):
    db = seed_incidents({"incident_id": "inc-1", "status": "awaiting_approval"})
    payload = {
        "type": "block_actions",
        "user": {"username": "alice"},
        "message": {
            "ts": "1700000000.1",
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "isolate"}}],
        },
        "actions": [{"action_id": "approve_remediation", "value": "inc-1|task-token"}],
    }
    body = "payload=" + quote(json.dumps(payload))

    result = handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    assert result["statusCode"] == 200
    response_body = json.loads(result["body"])
    assert "blocks" in response_body
    assert any("approved" in json.dumps(block) for block in response_body["blocks"])
    audit = list(db["approval_audit"].find({"incident_id": "inc-1"}))
    assert [a["decision"] for a in audit] == ["approve"]
    assert audit[0]["by"] == "alice"
    assert db["incidents"].find_one({"_id": "inc-1"})["status"] == "approved"
    sfn = aws_mocks["clients"]["stepfunctions"]
    assert sfn.send_task_success.call_count == 1

    handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    assert sfn.send_task_success.call_count == 1
    assert db["approval_audit"].count_documents({"incident_id": "inc-1"}) == 1


def test_interactions_reject_action_writes_audit(aws_mocks, seed_incidents, context):
    db = seed_incidents({"incident_id": "inc-2", "status": "awaiting_approval"})
    payload = {
        "type": "block_actions",
        "user": {"username": "bob"},
        "actions": [{"action_id": "reject_remediation", "value": "inc-2|isolate"}],
    }
    body = "payload=" + quote(json.dumps(payload))

    result = handler.lambda_handler(_signed_event("/slack/interactions", body), context)

    response_body = json.loads(result["body"])
    assert any("rejected" in json.dumps(block) for block in response_body["blocks"])
    assert db["approval_audit"].find_one({"incident_id": "inc-2"})["decision"] == "deny"
    assert db["incidents"].find_one({"_id": "inc-2"})["status"] == "denied"


def test_commands_status_returns_blocks(aws_mocks, context):
    result = handler.lambda_handler(_signed_event("/slack/commands", "command=%2Fseks&text=status"), context)

    response_body = json.loads(result["body"])
    assert "blocks" in response_body
    blocks_text = json.dumps(response_body["blocks"])
    assert "SEKS System Status" in blocks_text
    assert "seks-demo" in blocks_text


def test_commands_help_returns_blocks(aws_mocks, context):
    result = handler.lambda_handler(_signed_event("/slack/commands", "command=%2Fseks&text=help"), context)

    response_body = json.loads(result["body"])
    assert "blocks" in response_body
    blocks_text = json.dumps(response_body["blocks"])
    assert "SEKS Bot" in blocks_text
    assert "/seks status" in blocks_text


def test_commands_unknown_returns_error_blocks(aws_mocks, context):
    result = handler.lambda_handler(_signed_event("/slack/commands", "command=%2Fseks&text=foobar"), context)

    response_body = json.loads(result["body"])
    assert "blocks" in response_body
    blocks_text = json.dumps(response_body["blocks"])
    assert "foobar" in blocks_text


def test_lambda_handler_decodes_base64_body(aws_mocks, context):
    plain_body = json.dumps(
        {"type": "event_callback", "event": {"type": "message", "text": "hi", "channel": "C1", "bot_id": "B1"}}
    )
    encoded_body = base64.b64encode(plain_body.encode()).decode()
    timestamp = str(int(time.time()))
    event = {
        "rawPath": "/slack/events",
        "body": encoded_body,
        "isBase64Encoded": True,
        "headers": {"x-slack-request-timestamp": timestamp, "x-slack-signature": _signature(plain_body, timestamp)},
    }

    result = handler.lambda_handler(event, context)

    assert result == {"statusCode": 200, "body": "ok"}


def test_lambda_handler_unknown_path_returns_not_found(aws_mocks, context):
    result = handler.lambda_handler(_signed_event("/slack/unknown", "{}"), context)

    assert result == {"statusCode": 404, "body": "Not found"}


def _add_lambda_client(aws_mocks):
    lambda_client = MagicMock()
    aws_mocks["clients"]["lambda"] = lambda_client
    return lambda_client


def test_remediate_without_gate_does_not_invoke_lambda(aws_mocks, seed_incidents, context):
    lambda_client = _add_lambda_client(aws_mocks)
    seed_incidents({"incident_id": "inc-3", "status": "triaged", "severity": "P2"})

    body = "command=%2Fseks&text=remediate+inc-3"
    result = handler.lambda_handler(_signed_event("/slack/commands", body), context)

    response_body = json.loads(result["body"])
    blocks_text = json.dumps(response_body["blocks"])
    assert "No gate-verified plan for" in blocks_text
    assert "inc-3" in blocks_text
    lambda_client.invoke.assert_not_called()


def test_remediate_with_passed_gate_invokes_lambda_with_wrapped_payload(aws_mocks, seed_incidents, context):
    lambda_client = _add_lambda_client(aws_mocks)
    seed_incidents(
        {
            "incident_id": "inc-4",
            "status": "triaged",
            "severity": "P1",
            "affected": {"pod": "pod-x", "namespace": "ns-a"},
            "gate": {"passed": True},
            "approved_plan": {"actions": ["cordon_node"]},
        }
    )

    body = "command=%2Fseks&text=remediate+inc-4"
    result = handler.lambda_handler(_signed_event("/slack/commands", body), context)

    response_body = json.loads(result["body"])
    blocks_text = json.dumps(response_body["blocks"])
    assert "Remediation triggered for" in blocks_text
    assert "inc-4" in blocks_text

    lambda_client.invoke.assert_called_once()
    call_kwargs = lambda_client.invoke.call_args.kwargs
    assert call_kwargs["FunctionName"] == "test-seks-remediation-agent"
    assert call_kwargs["InvocationType"] == "Event"
    payload = json.loads(call_kwargs["Payload"])
    assert payload["summary"]["body"] == {
        "incident_id": "inc-4",
        "affected": {"pod": "pod-x", "namespace": "ns-a"},
    }
    assert payload["gate"]["body"] == {"passed": True, "approved_plan": {"actions": ["cordon_node"]}}


def test_remediate_second_call_reports_already_handled(aws_mocks, seed_incidents, context):
    lambda_client = _add_lambda_client(aws_mocks)
    seed_incidents(
        {
            "incident_id": "inc-5",
            "status": "triaged",
            "severity": "P1",
            "gate": {"passed": True},
            "approved_plan": {"actions": ["cordon_node"]},
        }
    )

    body = "command=%2Fseks&text=remediate+inc-5"
    first = handler.lambda_handler(_signed_event("/slack/commands", body), context)
    second = handler.lambda_handler(_signed_event("/slack/commands", body), context)

    first_text = json.dumps(json.loads(first["body"])["blocks"])
    second_text = json.dumps(json.loads(second["body"])["blocks"])
    assert "Remediation triggered for" in first_text
    assert "already handled" in second_text
    lambda_client.invoke.assert_called_once()
