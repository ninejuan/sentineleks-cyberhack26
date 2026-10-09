"""Incident state and approval audit on MongoDB Atlas (plan: DynamoDB 대체).

`IncidentStore` keeps the method surface the agents and Slack bot already call. The constructor
argument that used to be a DynamoDB table name is now ignored; the connection comes from the
MongoDB URI secret. The client is module-global so warm Lambdas reuse the connection pool.
`ApprovalAudit` exposes insert/read only — there is deliberately no update or delete method.
"""

import logging
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.shared.config import Config
from app.shared.credentials import resolve_secret

logger = logging.getLogger(__name__)

INCIDENTS = "incidents"
APPROVAL_AUDIT = "approval_audit"

_db_cache: dict[str, Any] = {}


def get_database(config: Config | None = None) -> Any:
    config = config or Config()
    if "db" not in _db_cache:
        import pymongo

        uri = resolve_secret("MONGODB_URI", config.mongodb_secret_id, "uri")
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000, appname=f"{config.project}-lambda")
        _db_cache["db"] = client[config.mongodb_database]
    return _db_cache["db"]


def set_database(database: Any) -> None:
    _db_cache["db"] = database


def ensure_indexes(database: Any) -> list[str]:
    return [
        database[INCIDENTS].create_index([("tenant_id", 1), ("status", 1)], name="tenant_status"),
        database[INCIDENTS].create_index([("created_at", -1)], name="created_desc"),
        database[INCIDENTS].create_index([("severity", 1), ("created_at", -1)], name="severity_created"),
        database[APPROVAL_AUDIT].create_index([("incident_id", 1)], name="incident"),
        database[APPROVAL_AUDIT].create_index(
            [("incident_id", 1), ("slack_message_ts", 1), ("decision", 1)], name="dedupe_click", unique=True
        ),
    ]


def _now() -> str:
    return datetime.now(tz=UTC).isoformat()


def _public(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    if doc is None:
        return None
    result = {k: v for k, v in doc.items() if k != "_id"}
    result.setdefault("incident_id", doc.get("_id"))
    return result


class IncidentStore:
    def __init__(self, config: Config | None = None, database: Any = None):
        self._collection = (database if database is not None else get_database(config))[INCIDENTS]

    def put_incident(self, incident_id: str, data: dict[str, Any]) -> None:
        now = _now()
        fields = {k: v for k, v in data.items() if k not in {"incident_id", "_id"}}
        fields.setdefault("status", "detected")
        self._collection.update_one(
            {"_id": incident_id},
            {
                "$setOnInsert": {"incident_id": incident_id, "created_at": now},
                "$set": {**fields, "updated_at": now},
                "$push": {"audit": {"stage": "detected", "at": now, "detail": fields.get("title", "")}},
            },
            upsert=True,
        )
        logger.info("Stored incident %s", incident_id)

    def update_incident(self, incident_id: str, updates: dict[str, Any], stage: str | None = None) -> None:
        now = _now()
        operation: dict[str, Any] = {"$set": {**updates, "updated_at": now}}
        if stage:
            operation["$push"] = {"audit": {"stage": stage, "at": now, "detail": updates.get("status", "")}}
        self._collection.update_one({"_id": incident_id}, operation, upsert=True)
        logger.info("Updated incident %s", incident_id)

    def transition(
        self, incident_id: str, from_statuses: list[str], to_status: str, updates: dict | None = None
    ) -> bool:
        """Conditional status change. False means another writer already moved it (duplicate click/retry)."""
        now = _now()
        result = self._collection.update_one(
            {"_id": incident_id, "status": {"$in": from_statuses}},
            {
                "$set": {**(updates or {}), "status": to_status, "updated_at": now},
                "$push": {"audit": {"stage": to_status, "at": now, "detail": f"from {from_statuses}"}},
            },
        )
        return result.modified_count == 1

    def append_audit(self, incident_id: str, stage: str, detail: str) -> None:
        self._collection.update_one(
            {"_id": incident_id}, {"$push": {"audit": {"stage": stage, "at": _now(), "detail": detail}}}
        )

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        return _public(self._collection.find_one({"_id": incident_id}))

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        cursor = self._collection.find({}).sort("created_at", -1).limit(limit)
        return [doc for doc in (_public(d) for d in cursor) if doc]

    def get_by_status(self, status: str, limit: int = 20) -> list[dict[str, Any]]:
        return self._find({"status": status}, limit)

    def get_by_severity(self, severity: str, limit: int = 20) -> list[dict[str, Any]]:
        return self._find({"severity": severity.upper()}, limit)

    def get_stats(self, days: int = 1) -> dict[str, Any]:
        cutoff = datetime.fromtimestamp(time.time() - days * 86400, tz=UTC).isoformat()
        items = [doc for doc in (_public(d) for d in self._collection.find({"created_at": {"$gte": cutoff}})) if doc]
        by_severity = Counter(str(item.get("severity", "UNKNOWN")).upper() for item in items)
        active_statuses = {"detected", "acknowledged", "investigating", "open", "triaged", "awaiting_approval"}
        resolved_statuses = {"resolved", "remediated", "closed"}
        top_mitre = Counter(_first_mitre(item) for item in items if _first_mitre(item)).most_common(5)
        return {
            "total": len(items),
            "by_severity": dict(by_severity),
            "active": sum(1 for item in items if str(item.get("status", "detected")).lower() in active_statuses),
            "resolved": sum(1 for item in items if str(item.get("status", "")).lower() in resolved_statuses),
            "top_mitre": top_mitre,
            "mean_time_to_acknowledge_seconds": _mean_transition(items, "created_at", "acknowledged_at"),
            "mean_time_to_resolve_seconds": _mean_transition(items, "created_at", "resolved_at"),
        }

    def _find(self, query: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        cursor = self._collection.find(query).sort("created_at", -1).limit(limit)
        return [doc for doc in (_public(d) for d in cursor) if doc]


class ApprovalAudit:
    def __init__(self, config: Config | None = None, database: Any = None):
        self._collection = (database if database is not None else get_database(config))[APPROVAL_AUDIT]

    def record(
        self,
        *,
        incident_id: str,
        decision: str,
        by: str,
        action_summary: str,
        slack_message_ts: str,
    ) -> bool:
        """Insert one decision. False when the same click was already recorded (unique index)."""
        from pymongo.errors import DuplicateKeyError

        try:
            self._collection.insert_one(
                {
                    "incident_id": incident_id,
                    "decision": decision,
                    "by": by,
                    "at": _now(),
                    "action_summary": action_summary,
                    "slack_message_ts": slack_message_ts,
                }
            )
        except DuplicateKeyError:
            return False
        return True

    def for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        return [
            {k: v for k, v in doc.items() if k != "_id"}
            for doc in self._collection.find({"incident_id": incident_id}).sort("at", 1)
        ]


def _epoch_seconds(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int | float):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    text = str(value).replace("Z", "+00:00")
    try:
        return int(float(text))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp())
    except ValueError:
        return None


def _mean_transition(items: list[dict[str, Any]], start_key: str, end_key: str) -> int | None:
    durations = []
    for item in items:
        start = _epoch_seconds(item.get(start_key))
        end = _epoch_seconds(item.get(end_key))
        if start and end and end >= start:
            durations.append(end - start)
    return int(sum(durations) / len(durations)) if durations else None


def _first_mitre(item: dict[str, Any]) -> str:
    value = item.get("mitre") or item.get("mitre_attack") or item.get("mitre_technique") or item.get("technique") or ""
    if isinstance(value, dict):
        value = " ".join(str(v) for v in value.values())
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    for token in str(value).replace(",", " ").split():
        if token.startswith("T"):
            return token
    return ""
