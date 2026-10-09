from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

from app.shared.normalize import normalize, to_sensor_event, workload_from_pod
from app.sink.clickhouse import COLUMNS, SensorSink, apply_floor, severity_floor_for


def test_severity_floor_rules():
    assert severity_floor_for(1, noisy_rule=False) is None
    assert severity_floor_for(2, noisy_rule=False) == "P2"
    assert severity_floor_for(3, noisy_rule=False) == "P1"
    assert severity_floor_for(3, noisy_rule=True) == "P2"
    assert severity_floor_for(2, noisy_rule=True) is None


def test_apply_floor_only_raises():
    assert apply_floor("P3", "P1") == "P1"
    assert apply_floor("P1", "P2") == "P1"
    assert apply_floor("P4", None) == "P4"


def test_correlate_uses_server_side_bindings_and_computes_floor():
    client = MagicMock()
    now = datetime.now(tz=UTC)
    client.query.side_effect = [
        SimpleNamespace(
            result_rows=[
                ("falco", "Crypto mining process detected", "T1496", 2, now),
                ("tetragon", "detect-cryptominer-egress", "", 5, now),
            ]
        ),
        SimpleNamespace(result_rows=[(3, 1)]),
    ]

    correlation = SensorSink(client).correlate("t", "demo", "miner", "Crypto mining process detected")

    assert correlation.available
    assert correlation.sources == ["falco", "tetragon"]
    assert correlation.severity_floor == "P2"
    assert correlation.rule_24h == {"n": 3, "workloads": 1}
    first_call = client.query.call_args_list[0]
    assert first_call.kwargs["parameters"] == {"tenant": "t", "ns": "demo", "wl": "miner", "window": 10}
    assert "{ns:String}" in first_call.args[0]


def test_correlate_failure_reports_unavailable():
    client = MagicMock()
    client.query.side_effect = ConnectionError("boom")

    correlation = SensorSink(client).correlate("t", "demo", "miner", "r")

    assert correlation.available is False
    assert "boom" in correlation.error


def test_insert_uses_explicit_columns():
    client = MagicMock()
    event = to_sensor_event(
        normalize(
            {
                "rule": "r",
                "output": "o",
                "output_fields": {"k8s.ns.name": "demo", "k8s.pod.name": "web-5d4f8b7c9-abcde"},
            },
            tenant_id="t",
            cluster="c",
        )
    )

    assert SensorSink(client).insert([event]) == 1
    assert client.insert.call_args.kwargs["column_names"] == COLUMNS
    assert len(client.insert.call_args.args[1][0]) == len(COLUMNS)


def test_workload_from_pod_name():
    assert workload_from_pod("ledger-worker-7d4b9c6f8-xk2qp") == "ledger-worker"
    assert workload_from_pod("db-0") == "db-0"


def test_normalize_tetragon_and_guardduty():
    tetragon = normalize(
        {
            "process_kprobe": {
                "policy_name": "detect-cryptominer-egress",
                "process": {"binary": "/xmrig", "pod": {"namespace": "demo", "name": "miner-7f9c8d6b5-x2k9q"}},
                "args": [{"sock_arg": {"daddr": "203.0.113.5", "dport": 3333}}],
            }
        },
        tenant_id="t",
        cluster="c",
    )
    assert (tetragon["source"], tetragon["workload"], tetragon["network"]["remote"]) == (
        "tetragon",
        "miner",
        "203.0.113.5:3333",
    )
    guardduty = normalize(
        {
            "source": "aws.guardduty",
            "detail": {
                "type": "CryptoCurrency:EKS/BitcoinTool.B!DNS",
                "resource": {
                    "kubernetesDetails": {"kubernetesWorkloadDetails": {"namespace": "demo", "name": "miner"}}
                },
            },
        },
        tenant_id="t",
        cluster="c",
    )
    assert (guardduty["source"], guardduty["workload"], guardduty["rule_id"]) == (
        "guardduty",
        "miner",
        "CryptoCurrency:EKS/BitcoinTool.B!DNS",
    )
