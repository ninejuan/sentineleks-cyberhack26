from unittest.mock import MagicMock

from app.degraded_notifier import handler


def test_lambda_handler_sends_degraded_notification(monkeypatch, context):
    notifier = MagicMock()
    monkeypatch.setattr(handler, "SlackNotifier", lambda project: notifier)
    event = {"source": "falco", "raw_event": {"rule": "x"}, "error": {"Cause": "ai failed"}}

    result = handler.lambda_handler(event, context)

    assert result == {"status": "degraded_notification_sent", "source": "falco"}
    notifier.send_incident.assert_called_once_with(
        {
            "source": "falco",
            "raw_event": {"rule": "x"},
            "error": {"Cause": "ai failed"},
            "mode": "DEGRADED",
            "incident_id": None,
            "severity": None,
        },
        mode="degraded",
    )


def test_lambda_handler_includes_incident_id_and_severity(monkeypatch, context):
    notifier = MagicMock()
    monkeypatch.setattr(handler, "SlackNotifier", lambda project: notifier)
    event = {
        "source": "falco",
        "raw_event": {"rule": "x"},
        "error": {"Cause": "ai failed"},
        "summary": {"body": {"incident_id": "inc-42"}},
        "triage": {"body": {"severity": "P1"}},
    }

    handler.lambda_handler(event, context)

    incident = notifier.send_incident.call_args.args[0]
    assert incident["incident_id"] == "inc-42"
    assert incident["severity"] == "P1"


def test_lambda_handler_defaults_missing_fields(monkeypatch, context):
    notifier = MagicMock()
    monkeypatch.setattr(handler, "SlackNotifier", lambda project: notifier)

    result = handler.lambda_handler({}, context)

    assert result["source"] == "unknown"
    incident = notifier.send_incident.call_args.args[0]
    assert incident["raw_event"] == {}
    assert incident["error"] == {"Cause": "Unknown failure"}


def test_lambda_handler_uses_project_from_config(monkeypatch, context):
    created = {}

    def make_notifier(project):
        created["project"] = project
        return MagicMock()

    monkeypatch.setattr(handler, "SlackNotifier", make_notifier)

    handler.lambda_handler({"source": "guardduty"}, context)

    assert created["project"] == "test-seks"


def test_degraded_reason_explains_gate_evidence_and_correlation():
    from app.degraded_notifier.handler import degraded_reason

    event = {
        "triage": {"body": {"correlation": {"available": False, "error": "timeout"}}},
        "solution": {"body": {"grounded": True}},
        "gate": {
            "body": {
                "passed": False,
                "attempts": [
                    {
                        "verify": {"violations": [{"check": "protected_namespace", "detail": "kube-system"}]},
                        "semgrep": {"findings": [{"rule_id": "seks-isolation-empty-endpoint-selector"}]},
                    }
                ],
            }
        },
    }

    reason = degraded_reason(event)

    assert "Correlation unavailable" in reason
    assert "protected_namespace" in reason
    assert "seks-isolation-empty-endpoint-selector" in reason
    assert degraded_reason({}) == "Unknown failure"
