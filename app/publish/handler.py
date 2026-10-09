"""Publisher Lambda: refresh the incident's Slack Canvas from MongoDB at the end of the pipeline."""

import logging
import os

from app.publish.postmortem import PostmortemPublisher
from app.shared.config import Config
from app.shared.secrets import get_secret
from app.shared.store import ApprovalAudit, IncidentStore

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    summary = event.get("summary", {}).get("body", {})
    incident_id = summary.get("incident_id")
    if not incident_id or not config.slack_incident_channel:
        return {"status": "skipped", "reason": "missing incident_id or SLACK_INCIDENT_CHANNEL"}

    store = IncidentStore(config)
    incident = store.get_incident(incident_id) or {"incident_id": incident_id, **summary}
    approvals = ApprovalAudit(config).for_incident(incident_id)
    token = get_secret(f"{config.project}/slack/bot-token").get("token", "")
    published = PostmortemPublisher(token, config.slack_incident_channel).publish(incident, approvals)

    updates = {"published": published}
    if published.get("canvas_id"):
        updates["canvas_id"] = published["canvas_id"]
    store.update_incident(incident_id, updates, stage=f"published_{published['mode']}")
    return {"status": "published", **published}
