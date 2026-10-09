import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime

import boto3
from botocore.exceptions import ClientError

from app.shared.config import Config
from app.shared.normalize import normalize, to_sensor_event
from app.sink.clickhouse import SensorSink

logger = logging.getLogger(__name__)
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

DEDUP_WINDOW_SECONDS = 300
DEDUP_TABLE = os.environ.get("DEDUP_TABLE_NAME", "seks-event-dedup")
TETRAGON_TABLE = os.environ.get("TETRAGON_EVENTS_TABLE", "seks-tetragon-events")
TETRAGON_TTL_SECONDS = int(os.environ.get("TETRAGON_EVENT_TTL_SECONDS", str(30 * 60)))


def lambda_handler(event: dict, context) -> dict:
    config = Config()
    sfn_client = boto3.client("stepfunctions")
    dynamodb = boto3.resource("dynamodb")
    dedup_table = dynamodb.Table(DEDUP_TABLE)
    tetragon_table = dynamodb.Table(TETRAGON_TABLE) if TETRAGON_TABLE else None

    records = event.get("Records", [])
    results = []

    for record in records:
        raw_body = record.get("body", "{}")
        body = json.loads(raw_body)

        sns_message = body.get("Message")
        if sns_message:
            if isinstance(sns_message, str):
                try:
                    body = json.loads(sns_message)
                except json.JSONDecodeError:
                    logger.warning("SNS message not valid JSON: %s", sns_message[:200])
                    body = {"raw": sns_message, "source": "unknown"}
            elif isinstance(sns_message, dict):
                body = sns_message

        source = _detect_source(body)
        normalized = normalize(body, tenant_id=config.tenant_id, cluster=config.eks_cluster_name)
        sink_status = _sink(config, normalized)

        if source == "tetragon" and tetragon_table is not None:
            _retain_tetragon_event(tetragon_table, body)

        dedup_key = _dedup_key(body, source)

        if _is_duplicate(dedup_table, dedup_key):
            logger.info("Deduplicated event: %s", dedup_key[:80])
            results.append({"source": source, "status": "deduplicated", "sink": sink_status})
            continue

        execution_name = f"{source}-{datetime.now(tz=UTC).strftime('%Y%m%d-%H%M%S-%f')}"

        workflow_input = {
            "raw_event": body,
            "normalized": normalized,
            "source": source,
            "received_at": datetime.now(tz=UTC).isoformat(),
        }

        response = sfn_client.start_execution(
            stateMachineArn=config.state_machine_arn,
            name=execution_name[:80],
            input=json.dumps(workflow_input, default=str),
        )

        logger.info("Started execution %s for %s event", response["executionArn"], source)
        results.append(
            {"source": source, "execution_arn": response["executionArn"], "status": "started", "sink": sink_status}
        )

    return {"processed": len(results), "executions": results}


_sink_cache: dict[str, SensorSink] = {}


def _sink(config: Config, normalized: dict) -> str:
    """Every sensor event lands in ClickHouse (even ones later deduplicated) so correlation sees them all."""
    if not normalized.get("workload") or os.environ.get("SENSOR_SINK_ENABLED", "true").lower() != "true":
        return "skipped"
    try:
        if "sink" not in _sink_cache:
            _sink_cache["sink"] = SensorSink.from_config(config)
        _sink_cache["sink"].insert([to_sensor_event(normalized)])
        return "stored"
    except Exception as error:
        logger.warning("ClickHouse sink failed: %s", error)
        _sink_cache.pop("sink", None)
        return "failed"


def _retain_tetragon_event(table, event: dict) -> None:
    kprobe = event.get("process_kprobe") or event.get("process_exec") or {}
    proc = kprobe.get("process", {}) if isinstance(kprobe, dict) else {}
    pod = proc.get("pod", {}) if isinstance(proc, dict) else {}
    pod_uid = pod.get("uid")
    if not pod_uid:
        logger.debug("Tetragon event missing pod.uid; skipping retention")
        return

    event_time = kprobe.get("time") or event.get("time") or datetime.now(tz=UTC).isoformat()
    exec_id = (
        proc.get("exec_id") or hashlib.sha256(json.dumps(kprobe, sort_keys=True, default=str).encode()).hexdigest()[:32]
    )
    sort_key = f"{event_time}#{exec_id}"

    now = int(time.time())
    item = {
        "pod_uid": pod_uid,
        "sk": sort_key,
        "ttl": now + TETRAGON_TTL_SECONDS,
        "recorded_at": datetime.now(tz=UTC).isoformat(),
        "namespace": pod.get("namespace") or "",
        "pod_name": pod.get("name") or "",
        "container": (pod.get("container") or {}).get("name") or "",
        "policy_name": kprobe.get("policy_name") or "",
        "binary": proc.get("binary") or "",
        "arguments": proc.get("arguments") or "",
        "function_name": kprobe.get("function_name") or "",
        "event": json.dumps(event, default=str),
    }

    try:
        table.put_item(Item=item)
    except ClientError as error:
        logger.warning("Failed to retain Tetragon event for pod_uid=%s: %s", pod_uid, error)


def _dedup_key(event: dict, source: str) -> str:
    if source == "tetragon":
        kprobe = event.get("process_kprobe", {})
        proc = kprobe.get("process", {})
        pod = proc.get("pod", {})
        policy = kprobe.get("policy_name", "unknown")
        pod_name = pod.get("name", "")
        ns = pod.get("namespace", "")
    elif source == "falco":
        policy = event.get("rule", "unknown")
        pod_name = event.get("output_fields", {}).get("k8s.pod.name", "")
        ns = event.get("output_fields", {}).get("k8s.ns.name", "")
    else:
        policy = event.get("detail", {}).get("type", "unknown")
        pod_name = ""
        ns = ""

    window = int(time.time()) // DEDUP_WINDOW_SECONDS
    # One attack on one pod = one incident: Falco and Tetragon alerts for the same workload share a key.
    # Every event still reaches ClickHouse before dedup, so Triage correlation sees both sensors.
    raw = f"workload|{ns}|{pod_name}|{window}" if pod_name else f"{source}|{policy}|{window}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _is_duplicate(table, dedup_key: str) -> bool:
    now = int(time.time())
    ttl = now + DEDUP_WINDOW_SECONDS * 2

    try:
        table.put_item(
            Item={"dedup_key": dedup_key, "ttl": ttl, "created_at": now},
            ConditionExpression="attribute_not_exists(dedup_key)",
        )
        return False
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return True
        raise


def _detect_source(event: dict) -> str:
    if "detail-type" in event and "GuardDuty" in event.get("detail-type", ""):
        return "guardduty"

    if event.get("source") == "aws.guardduty":
        return "guardduty"

    if "rule" in event and "output" in event:
        return "falco"

    if "process_kprobe" in event or "process_exec" in event:
        return "tetragon"

    return "unknown"
