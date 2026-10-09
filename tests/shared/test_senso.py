import io
import json
from unittest.mock import patch

import pytest

from app.shared.senso import SensoClient, SensoError


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _reply(payload):
    return _Response(json.dumps(payload).encode())


def test_scoped_search_dedupes_and_filters_to_manifest():
    payload = {
        "answer": "checkpoint first",
        "results": [
            {"content_id": "a", "title": "Cryptomining", "chunk_text": "1. checkpoint_pod", "score": 0.9},
            {"content_id": "a", "title": "Cryptomining", "chunk_text": "2. label_pod", "score": 0.8},
            {"content_id": "zzz", "title": "Not ours", "chunk_text": "x", "score": 0.7},
        ],
    }
    with patch("urllib.request.urlopen", return_value=_reply(payload)) as urlopen:
        answer = SensoClient("https://senso.test/api/v1", "tgr_x").search_scoped("q", ["a", "b"])

    request = urlopen.call_args.args[0]
    body = json.loads(request.data)
    assert body["content_ids"] == ["a", "b"]
    assert body["require_scoped_ids"] is True
    assert request.get_header("X-api-key") == "tgr_x"
    assert [c.content_id for c in answer.citations] == ["a"]
    assert answer.answer == "checkpoint first"


def test_refuses_unscoped_search():
    with pytest.raises(SensoError):
        SensoClient("https://senso.test", "k").search_scoped("q", [])


def test_ingest_conflict_returns_none():
    import urllib.error

    error = urllib.error.HTTPError("u", 409, "conflict", {}, io.BytesIO(b"dup"))
    with patch("urllib.request.urlopen", side_effect=error):
        assert SensoClient("https://senso.test", "k").ingest_raw("t", "x") is None
