"""Idempotent SaaS setup for SEKS: ClickHouse schema + MongoDB indexes.

Reads credentials from the environment (export them from .credentials). Safe to re-run.
Usage: PYTHONPATH=. python scripts/setup_datastores.py
"""

import os
import sys

from app.shared import store
from app.sink.clickhouse import TABLE, SensorSink


def setup_clickhouse() -> None:
    sink = SensorSink.connect(
        host=os.environ["CLICKHOUSE_HOST"].removeprefix("https://").split(":")[0].rstrip("/"),
        username=os.environ.get("CLICKHOUSE_USERNAME", "default"),
        password=os.environ["CLICKHOUSE_PASSWORD"],
    )
    sink.ensure_schema()
    count = sink._client.query("SELECT count() FROM sensor_events").result_rows[0][0]  # noqa: SLF001
    print(f"clickhouse: {TABLE} ready, rows={count}")


def setup_mongodb() -> None:
    import pymongo

    database = pymongo.MongoClient(os.environ["MONGODB_URI"], serverSelectionTimeoutMS=8000)[
        os.environ.get("MONGODB_DATABASE", "seks")
    ]
    created = store.ensure_indexes(database)
    print(f"mongodb: db={database.name} indexes={created}")


if __name__ == "__main__":
    targets = sys.argv[1:] or ["clickhouse", "mongodb"]
    if "clickhouse" in targets:
        setup_clickhouse()
    if "mongodb" in targets:
        setup_mongodb()
