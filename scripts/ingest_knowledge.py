"""Ingest the verified SEKS knowledge base into Senso and write the content_id manifest.

Every markdown file under knowledge/ becomes one Senso raw document. The resulting
app/shared/senso_manifest.json is the allow-list the Solution agent scopes its searches to
(require_scoped_ids) and the gate checks citations against. Re-running is safe: unchanged files
return 409 from Senso and keep their existing manifest entry.

Usage: SENSO_API_KEY=... PYTHONPATH=. python scripts/ingest_knowledge.py
"""

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from app.shared.senso import MANIFEST_PATH, SensoClient, SensoError

ROOT = Path(__file__).resolve().parents[1]
KNOWLEDGE = ROOT / "knowledge"
BASE_URL = os.environ.get("SENSO_BASE_URL", "https://apiv2.senso.ai/api/v1")


def _doc_meta(path: Path, text: str) -> dict:
    kind = path.parent.name
    doc_id = path.stem
    match = re.search(r"^- (?:runbook_id|policy_id|incident_id): *(\S+)", text, re.MULTILINE)
    if match:
        doc_id = match.group(1)
    heading = next((line[2:].strip() for line in text.splitlines() if line.startswith("# ")), path.stem)
    return {"doc_id": doc_id, "kind": kind, "path": str(path.relative_to(ROOT)), "title": f"SEKS {kind}: {heading}"}


def main() -> int:
    client = SensoClient(BASE_URL, os.environ["SENSO_API_KEY"])
    print("org:", client.me().get("name"))

    previous = {}
    if MANIFEST_PATH.exists():
        previous = {d["path"]: d for d in json.loads(MANIFEST_PATH.read_text()).get("documents", [])}

    documents, pending = [], []
    for path in sorted(KNOWLEDGE.rglob("*.md")):
        if path.name == "README.md":
            continue
        text = path.read_text()
        meta = _doc_meta(path, text)
        digest = hashlib.sha256(text.encode()).hexdigest()
        known = previous.get(meta["path"])
        if known and known.get("sha256") == digest:
            documents.append(known)
            print(f"unchanged  {meta['path']}")
            continue
        created = client.ingest_raw(meta["title"], text)
        if created is None:
            if known:
                documents.append({**known, "sha256": digest})
                print(f"exists     {meta['path']}")
                continue
            print(f"409 without manifest entry, look up by title: {meta['path']}", file=sys.stderr)
            match = next((r for r in client.list_content(meta["title"]) if r.get("title") == meta["title"]), None)
            if match is None:
                raise SensoError(f"cannot resolve existing content for {meta['path']}")
            created = {"id": match["content_id"], "kb_node_id": match.get("kb_node_id", "")}
        entry = {**meta, "content_id": created["id"], "kb_node_id": created.get("kb_node_id", ""), "sha256": digest}
        documents.append(entry)
        if entry["kb_node_id"]:
            pending.append(entry)
        print(f"ingested   {meta['path']} -> {entry['content_id']}")

    for entry in pending:
        client.wait_until_ready(entry["kb_node_id"])
        print(f"ready      {entry['path']}")

    MANIFEST_PATH.write_text(json.dumps({"documents": documents}, indent=2) + "\n")
    print(f"manifest: {len(documents)} documents -> {MANIFEST_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
