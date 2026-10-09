"""Package every zip-based Lambda with the full `app` package so cross-module imports resolve.

Each zip contains: handler.py (the function entrypoint) at the root + the whole app/ tree +
knowledge manifest. The gate agent is a container image (make build-gate), not packaged here.
Usage: python scripts/package_lambdas.py <lambda_module_dir> <slack_module_dir>
"""

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

ZIP_FUNCTIONS = {
    "summary": "app/agents/summary/handler.py",
    "triage": "app/agents/triage/handler.py",
    "solution": "app/agents/solution/handler.py",
    "remediation": "app/agents/remediation/handler.py",
    "forensic_synthesis": "app/agents/forensic_synthesis/handler.py",
    "ingestor": "app/ingestor/handler.py",
    "degraded_notifier": "app/degraded_notifier/handler.py",
    "approval_notifier": "app/approval_notifier/handler.py",
    "publisher": "app/publish/handler.py",
}
SLACK_ENTRY = "app/slack_bot/handler.py"


def _app_files() -> list[Path]:
    return [
        p
        for p in APP.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix in {".py", ".json"} and p.name != "Dockerfile"
    ]


def _write(out: Path, entry: str) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(ROOT / entry, "handler.py")
        for path in _app_files():
            archive.write(path, path.relative_to(ROOT).as_posix())
    print(f"  {out.relative_to(ROOT)}")


def main(lambda_dir: str, slack_dir: str) -> None:
    for name, entry in ZIP_FUNCTIONS.items():
        _write(ROOT / lambda_dir / f"{name}.zip", entry)
    _write(ROOT / slack_dir / "slack_bot.zip", SLACK_ENTRY)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
