"""Normalize Falco / Tetragon / GuardDuty events into the plan's event schema (plan: 정규화 이벤트 스키마).

Identity fields (namespace, workload, pod, rule_id) are extracted by code, never by the LLM, because
correlation and remediation targets depend on them being exact.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

from app.sink.clickhouse import SensorEvent

_REPLICASET_POD = re.compile(r"^(?P<base>.+)-[a-z0-9]{6,10}-[a-z0-9]{5}$")
_STATEFUL_OR_JOB_POD = re.compile(r"^(?P<base>.+)-[a-z0-9]{5}$")
_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def detect_source(event: dict) -> str:
    if event.get("detail-type") == "GuardDuty Finding" or event.get("source") == "aws.guardduty":
        return "guardduty"
    if "process_kprobe" in event or "process_exec" in event:
        return "tetragon"
    if "rule" in event and "output" in event:
        return "falco"
    return "unknown"


def workload_from_pod(pod: str) -> str:
    for pattern in (_REPLICASET_POD, _STATEFUL_OR_JOB_POD):
        match = pattern.match(pod)
        if match:
            return match.group("base")
    return pod


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(tz=UTC)


def _mitre(*texts: Any) -> str:
    for value in texts:
        text = " ".join(str(t) for t in value) if isinstance(value, list) else str(value or "")
        match = _MITRE.search(text)
        if match:
            return match.group(0)
    return ""


def normalize(event: dict, *, tenant_id: str, cluster: str) -> dict:
    source = detect_source(event)
    explicit_workload = ""
    if source == "falco":
        fields = event.get("output_fields", {}) or {}
        namespace, pod = fields.get("k8s.ns.name") or "", fields.get("k8s.pod.name") or ""
        rule_id = event.get("rule", "")
        exe, cmdline = fields.get("proc.exepath") or fields.get("proc.name") or "", fields.get("proc.cmdline") or ""
        remote = ":".join(str(x) for x in (fields.get("fd.sip"), fields.get("fd.sport")) if x)
        ts, severity_hint = event.get("time"), str(event.get("priority", ""))
        mitre = _mitre(event.get("tags"), rule_id, event.get("output"))
    elif source == "tetragon":
        body = event.get("process_kprobe") or event.get("process_exec") or {}
        process = body.get("process", {}) or {}
        pod_info = process.get("pod", {}) or {}
        namespace, pod = pod_info.get("namespace") or "", pod_info.get("name") or ""
        explicit_workload = pod_info.get("workload") or ""
        rule_id = body.get("policy_name") or ("process_exec" if "process_exec" in event else "")
        exe, cmdline = process.get("binary") or "", process.get("arguments") or ""
        remote = _tetragon_remote(body)
        ts, severity_hint = body.get("time") or event.get("time"), ""
        mitre = _mitre(rule_id)
    elif source == "guardduty":
        detail = event.get("detail", {}) or {}
        k8s = (detail.get("resource") or {}).get("kubernetesDetails") or {}
        workload_details = k8s.get("kubernetesWorkloadDetails") or {}
        namespace, pod = workload_details.get("namespace") or "", workload_details.get("name") or ""
        explicit_workload = pod
        rule_id = detail.get("type", "")
        exe, cmdline, remote = "", "", ""
        ts, severity_hint = detail.get("updatedAt") or event.get("time"), str(detail.get("severity", ""))
        mitre = _mitre(rule_id, detail.get("description"))
    else:
        namespace = pod = rule_id = exe = cmdline = remote = severity_hint = mitre = ""
        ts = None

    workload = explicit_workload or (workload_from_pod(pod) if pod else "")

    return {
        "tenant_id": tenant_id,
        "cluster": cluster,
        "namespace": namespace,
        "workload": workload,
        "pod": pod,
        "source": source,
        "rule_id": rule_id,
        "mitre_technique": mitre,
        "severity_hint": severity_hint,
        "process": {"exe": exe, "cmdline": cmdline},
        "network": {"remote": remote},
        "raw_hash": hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest(),
        "ts": _parse_ts(ts).isoformat(),
    }


def _tetragon_remote(body: dict) -> str:
    for arg in body.get("args", []) or []:
        sock = arg.get("sock_arg") if isinstance(arg, dict) else None
        if isinstance(sock, dict) and sock.get("daddr"):
            return f"{sock['daddr']}:{sock.get('dport', '')}"
    return ""


def to_sensor_event(normalized: dict) -> SensorEvent:
    return SensorEvent(
        tenant_id=normalized["tenant_id"],
        cluster=normalized["cluster"],
        namespace=normalized["namespace"],
        workload=normalized["workload"],
        pod=normalized["pod"],
        source=normalized["source"],
        rule_id=normalized["rule_id"],
        mitre_technique=normalized["mitre_technique"],
        severity_hint=normalized["severity_hint"],
        process_exe=normalized["process"]["exe"],
        remote=normalized["network"]["remote"],
        raw_hash=normalized["raw_hash"],
        ts=_parse_ts(normalized["ts"]),
    )
