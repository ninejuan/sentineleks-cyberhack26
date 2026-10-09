import mongomock
import pytest

from app.shared import store
from app.shared.store import ApprovalAudit, IncidentStore


@pytest.fixture
def db():
    database = mongomock.MongoClient()["seks"]
    store.ensure_indexes(database)
    return database


def test_put_and_get_incident_with_audit_trail(db):
    incidents = IncidentStore(database=db)
    incidents.put_incident("inc-1", {"severity": "P2", "title": "miner"})
    incidents.update_incident("inc-1", {"status": "triaged"}, stage="triaged")

    doc = incidents.get_incident("inc-1")

    assert doc["incident_id"] == "inc-1"
    assert doc["status"] == "triaged"
    assert [a["stage"] for a in doc["audit"]] == ["detected", "triaged"]
    assert "_id" not in doc


def test_transition_is_idempotent_for_duplicate_clicks(db):
    incidents = IncidentStore(database=db)
    incidents.put_incident("inc-2", {"status": "awaiting_approval"})

    first = incidents.transition("inc-2", ["awaiting_approval"], "approved", {"approved_by": "alice"})
    second = incidents.transition("inc-2", ["awaiting_approval"], "approved", {"approved_by": "bob"})

    assert first is True
    assert second is False
    assert incidents.get_incident("inc-2")["approved_by"] == "alice"


def test_approval_audit_is_insert_only_and_dedupes_same_click(db):
    audit = ApprovalAudit(database=db)
    args = {"incident_id": "inc-3", "decision": "approve", "by": "alice", "action_summary": "isolate"}

    assert audit.record(**args, slack_message_ts="1.0") is True
    assert audit.record(**args, slack_message_ts="1.0") is False
    assert not hasattr(audit, "update")
    assert not hasattr(audit, "delete")
    assert len(audit.for_incident("inc-3")) == 1


def test_queries_by_status_severity_and_stats(db):
    incidents = IncidentStore(database=db)
    incidents.put_incident("a", {"severity": "P1", "status": "triaged", "mitre_technique": "T1496"})
    incidents.put_incident("b", {"severity": "P3", "status": "remediated"})

    assert [i["incident_id"] for i in incidents.get_by_severity("p1")] == ["a"]
    assert [i["incident_id"] for i in incidents.get_by_status("remediated")] == ["b"]
    stats = incidents.get_stats()
    assert stats["total"] == 2
    assert stats["by_severity"] == {"P1": 1, "P3": 1}
    assert stats["top_mitre"] == [("T1496", 1)]
