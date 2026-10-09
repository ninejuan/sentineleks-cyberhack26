import json
from unittest.mock import MagicMock

import pytest

from app.approval_notifier import handler
from app.shared.config import Config


def test_post_raises_when_bot_api_call_not_ok(monkeypatch):
    monkeypatch.setenv("SLACK_INCIDENT_CHANNEL", "C-INCIDENT")
    monkeypatch.setattr(handler, "get_secret", lambda secret_id: {"token": "xoxb-test", "webhook_url": ""})

    response = MagicMock()
    response.read.return_value = json.dumps({"ok": False, "error": "channel_not_found"}).encode()
    response.status = 200
    response.__enter__.return_value = response
    response.__exit__.return_value = False

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: response)

    config = Config()

    with pytest.raises(RuntimeError, match=r"Slack chat\.postMessage failed: channel_not_found"):
        handler._post(config, [{"type": "section"}])


def test_post_succeeds_when_bot_api_call_ok(monkeypatch):
    monkeypatch.setenv("SLACK_INCIDENT_CHANNEL", "C-INCIDENT")
    monkeypatch.setattr(handler, "get_secret", lambda secret_id: {"token": "xoxb-test", "webhook_url": ""})

    response = MagicMock()
    response.read.return_value = json.dumps({"ok": True}).encode()
    response.status = 200
    response.__enter__.return_value = response
    response.__exit__.return_value = False

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: response)

    config = Config()

    handler._post(config, [{"type": "section"}])
