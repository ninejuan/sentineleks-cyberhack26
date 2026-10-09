import json
import os
from typing import Any

from app.shared.secrets import get_secret


def resolve_secret(env_name: str, secret_id: str, key: str) -> str:
    """Prefer a plain env var (local runs, tests); otherwise read `key` from the Secrets Manager JSON."""
    direct = os.environ.get(env_name, "")
    if direct:
        return direct
    value = get_secret(secret_id).get(key, "")
    if not isinstance(value, str) or not value:
        raise KeyError(f"Secret {secret_id} has no non-empty '{key}'")
    return value


def resolve_secret_dict(env_prefix: str, secret_id: str, keys: tuple[str, ...]) -> dict[str, Any]:
    direct = {k: os.environ.get(f"{env_prefix}_{k.upper()}", "") for k in keys}
    if all(direct.values()):
        return direct
    secret = get_secret(secret_id)
    missing = [k for k in keys if not secret.get(k)]
    if missing:
        raise KeyError(f"Secret {secret_id} missing keys: {json.dumps(missing)}")
    return {k: secret[k] for k in keys}
