"""Senso verified-context client (plan: 근거 강제).

Only documents ingested from knowledge/ are trusted. `search_scoped` restricts retrieval to that
manifest via content_ids + require_scoped_ids, so an answer can never cite something outside the
verified corpus. Citations are built from `results[]` (Senso has no separate citations field).
"""

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_PATH = Path(__file__).resolve().parent / "senso_manifest.json"
# Senso sits behind Cloudflare, which rejects the default "Python-urllib/x.y" agent with error 1010.
USER_AGENT = "seks-agent/1.0 (+https://seks.juany.dev)"


class SensoError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Citation:
    content_id: str
    title: str
    score: float
    excerpt: str

    def to_dict(self) -> dict:
        return {"content_id": self.content_id, "title": self.title, "score": self.score, "excerpt": self.excerpt}


@dataclass(frozen=True)
class GroundedAnswer:
    query: str
    answer: str
    citations: list[Citation] = field(default_factory=list)
    latency_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "answer": self.answer,
            "citations": [c.to_dict() for c in self.citations],
            "latency_ms": self.latency_ms,
        }


def load_manifest(path: Path = MANIFEST_PATH) -> dict[str, dict]:
    """content_id -> {title, doc_id, kind, kb_node_id}. Empty dict when not yet ingested."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text())
    return {entry["content_id"]: entry for entry in data.get("documents", [])}


class SensoClient:
    def __init__(self, base_url: str, api_key: str, timeout_seconds: float = 30.0):
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout_seconds

    def me(self) -> dict:
        return self._request("GET", "/org/me")

    def ingest_raw(self, title: str, text: str, folder_id: str | None = None) -> dict | None:
        """Returns {id, kb_node_id, ...}; None when Senso reports the identical text already exists (409)."""
        body: dict = {"title": title, "text": text}
        if folder_id:
            body["kb_folder_node_id"] = folder_id
        try:
            return self._request("POST", "/org/kb/raw", body)
        except SensoError as error:
            if error.status == 409:
                return None
            raise

    def node_status(self, kb_node_id: str) -> str:
        node = self._request("GET", f"/org/kb/nodes/{kb_node_id}")
        return str((node.get("content") or {}).get("processing_status", "unknown"))

    def wait_until_ready(self, kb_node_id: str, timeout_seconds: float = 180.0, poll_seconds: float = 5.0) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status = self.node_status(kb_node_id)
            if status == "complete":
                return
            if status == "failed":
                raise SensoError(f"Senso processing failed for node {kb_node_id}")
            time.sleep(poll_seconds)
        raise SensoError(f"Senso node {kb_node_id} not ready after {timeout_seconds}s")

    def list_content(self, query: str, max_results: int = 20) -> list[dict]:
        return self._request("POST", "/org/search/content", {"query": query, "max_results": max_results}).get(
            "results", []
        )

    def search_scoped(self, query: str, content_ids: list[str], max_results: int = 5) -> GroundedAnswer:
        if not content_ids:
            raise SensoError("Refusing unscoped search: verified manifest is empty")
        started = time.monotonic()
        payload = self._request(
            "POST",
            "/org/search",
            {
                "query": query,
                "max_results": max_results,
                "content_ids": content_ids,
                "require_scoped_ids": True,
            },
        )
        allowed = set(content_ids)
        citations: dict[str, Citation] = {}
        for result in payload.get("results", []):
            content_id = result.get("content_id", "")
            if content_id not in allowed or content_id in citations:
                continue
            citations[content_id] = Citation(
                content_id=content_id,
                title=result.get("title", ""),
                score=float(result.get("score", 0.0)),
                excerpt=str(result.get("chunk_text", ""))[:600],
            )
        return GroundedAnswer(
            query=query,
            answer=str(payload.get("answer", "")),
            citations=list(citations.values()),
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        request = urllib.request.Request(  # noqa: S310 - base URL comes from Config, always https
            self._base + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "X-API-Key": self._api_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": USER_AGENT,
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:300]
            raise SensoError(f"Senso {method} {path} -> HTTP {error.code}: {detail}", status=error.code) from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise SensoError(f"Senso {method} {path} unreachable: {error}") from error
        return json.loads(raw) if raw else {}
