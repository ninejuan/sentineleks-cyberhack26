"""ClickHouse sensor-event sink and cross-sensor correlation (plan: 데이터 계약 Q1/Q2).

insert-only `sensor_events`. Escalation is computed in code, not by the LLM:
  distinct sources >= 3 in the window -> floor P1, >= 2 -> floor P2.
A rule that fired on many workloads in 24h is flagged noisy and does not count toward escalation.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

TABLE = "sensor_events"
COLUMNS = [
    "event_id",
    "tenant_id",
    "cluster",
    "namespace",
    "workload",
    "pod",
    "source",
    "rule_id",
    "mitre_technique",
    "severity_hint",
    "process_exe",
    "remote",
    "raw_hash",
    "ts",
]

DDL = """
CREATE TABLE IF NOT EXISTS sensor_events (
  event_id        UUID,
  tenant_id       LowCardinality(String),
  cluster         LowCardinality(String),
  namespace       String,
  workload        String,
  pod             String,
  source          LowCardinality(String),
  rule_id         String,
  mitre_technique LowCardinality(String),
  severity_hint   LowCardinality(String),
  process_exe     String,
  remote          String,
  raw_hash        String,
  ts              DateTime64(3, 'UTC')
) ENGINE = MergeTree
ORDER BY (tenant_id, namespace, workload, ts)
TTL toDateTime(ts) + INTERVAL 30 DAY
"""

Q1_WINDOW = """
SELECT source, rule_id, mitre_technique, count() AS n, max(ts) AS last_ts
FROM sensor_events
WHERE tenant_id = {tenant:String} AND namespace = {ns:String} AND workload = {wl:String}
  AND ts > now64(3) - toIntervalMinute({window:UInt32})
GROUP BY source, rule_id, mitre_technique
ORDER BY last_ts DESC
"""

Q2_RULE_NOISE = """
SELECT count() AS n_24h, uniqExact(workload) AS workloads
FROM sensor_events
WHERE tenant_id = {tenant:String} AND rule_id = {rule:String}
  AND ts > now64(3) - INTERVAL 24 HOUR
"""

SEVERITY_ORDER = ["P1", "P2", "P3", "P4"]
NOISY_RULE_WORKLOADS = 5


@dataclass(frozen=True)
class SensorEvent:
    tenant_id: str
    cluster: str
    namespace: str
    workload: str
    pod: str
    source: str
    rule_id: str
    mitre_technique: str = ""
    severity_hint: str = ""
    process_exe: str = ""
    remote: str = ""
    raw_hash: str = ""
    ts: datetime = field(default_factory=lambda: datetime.now(tz=UTC))
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def row(self) -> list[Any]:
        return [
            uuid.UUID(self.event_id),
            self.tenant_id,
            self.cluster,
            self.namespace,
            self.workload,
            self.pod,
            self.source,
            self.rule_id,
            self.mitre_technique,
            self.severity_hint,
            self.process_exe,
            self.remote,
            self.raw_hash,
            self.ts,
        ]


@dataclass(frozen=True)
class Correlation:
    available: bool
    window_min: int
    distinct_sources: int = 0
    sources: list[str] = field(default_factory=list)
    signals: list[dict] = field(default_factory=list)
    rule_24h: dict = field(default_factory=dict)
    noisy_rule: bool = False
    severity_floor: str | None = None
    query_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "window_min": self.window_min,
            "distinct_sources": self.distinct_sources,
            "sources": self.sources,
            "signals": self.signals,
            "rule_24h": self.rule_24h,
            "noisy_rule": self.noisy_rule,
            "severity_floor": self.severity_floor,
            "query_ms": self.query_ms,
            "error": self.error,
        }


def severity_floor_for(distinct_sources: int, noisy_rule: bool) -> str | None:
    effective = distinct_sources - (1 if noisy_rule and distinct_sources > 1 else 0)
    if effective >= 3:
        return "P1"
    if effective >= 2:
        return "P2"
    return None


def apply_floor(severity: str, floor: str | None) -> str:
    if floor is None or severity not in SEVERITY_ORDER:
        return floor or severity
    return floor if SEVERITY_ORDER.index(floor) < SEVERITY_ORDER.index(severity) else severity


class SensorSink:
    def __init__(self, client: Any):
        self._client = client

    @classmethod
    def from_config(cls, config: Any) -> "SensorSink":
        from app.shared.credentials import resolve_secret_dict

        creds = resolve_secret_dict("CLICKHOUSE", config.clickhouse_secret_id, ("host", "username", "password"))
        host = str(creds["host"]).removeprefix("https://").split(":")[0].rstrip("/")
        return cls.connect(host=host, username=creds["username"], password=creds["password"])

    @classmethod
    def connect(cls, host: str, username: str, password: str, port: int = 8443) -> "SensorSink":
        import clickhouse_connect

        client = clickhouse_connect.get_client(
            host=host, port=port, username=username, password=password, secure=True, connect_timeout=5
        )
        return cls(client)

    def ensure_schema(self) -> None:
        self._client.command(DDL)

    def insert(self, events: list[SensorEvent]) -> int:
        if not events:
            return 0
        self._client.insert(TABLE, [e.row() for e in events], column_names=COLUMNS)
        return len(events)

    def correlate(self, tenant: str, namespace: str, workload: str, rule_id: str, window_min: int = 10) -> Correlation:
        started = time.monotonic()
        try:
            window = self._client.query(
                Q1_WINDOW, parameters={"tenant": tenant, "ns": namespace, "wl": workload, "window": window_min}
            )
            noise = self._client.query(Q2_RULE_NOISE, parameters={"tenant": tenant, "rule": rule_id})
        except Exception as error:
            logger.warning("Correlation query failed: %s", error)
            return Correlation(available=False, window_min=window_min, error=str(error)[:300])

        signals = [
            {
                "source": row[0],
                "rule_id": row[1],
                "mitre_technique": row[2],
                "count": int(row[3]),
                "last_ts": row[4].isoformat() if hasattr(row[4], "isoformat") else str(row[4]),
            }
            for row in window.result_rows
        ]
        sources = sorted({s["source"] for s in signals})
        n_24h, workloads = (int(noise.result_rows[0][0]), int(noise.result_rows[0][1])) if noise.result_rows else (0, 0)
        noisy = workloads >= NOISY_RULE_WORKLOADS
        return Correlation(
            available=True,
            window_min=window_min,
            distinct_sources=len(sources),
            sources=sources,
            signals=signals,
            rule_24h={"n": n_24h, "workloads": workloads},
            noisy_rule=noisy,
            severity_floor=severity_floor_for(len(sources), noisy),
            query_ms=int((time.monotonic() - started) * 1000),
        )
