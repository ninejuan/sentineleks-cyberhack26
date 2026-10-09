"""Load sponsor credentials from the local .credentials file into the Terraform-managed secrets.

The secret containers are created by `make infra-up` (terraform/envs/demo/main.tf); this only
writes their values. Values are never printed.
Usage: PROJECT=seks REGION=us-east-1 python scripts/put_sponsor_secrets.py .credentials
"""

import json
import os
import sys
from pathlib import Path

import boto3


def parse(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().removeprefix("export ").strip()] = value.strip().strip('"').strip("'")
    return values


def main(path: str) -> None:
    project, region = os.environ["PROJECT"], os.environ["REGION"]
    env = parse(path)
    secrets = {
        f"{project}/akashml/api-key": {"api_key": env["AKASHML_API_KEY"]},
        f"{project}/senso/api-key": {"api_key": env["SENSO_API_KEY"]},
        f"{project}/clickhouse/credentials": {
            "host": env["CLICKHOUSE_HOST"],
            "username": env.get("CLICKHOUSE_USERNAME", "default"),
            "password": env["CLICKHOUSE_PASSWORD"],
        },
        f"{project}/mongodb/uri": {"uri": env["MONGODB_URI"]},
    }
    client = boto3.client("secretsmanager", region_name=region)
    for secret_id, value in secrets.items():
        client.put_secret_value(SecretId=secret_id, SecretString=json.dumps(value))
        print(f"  {secret_id}: done")


if __name__ == "__main__":
    main(sys.argv[1])
