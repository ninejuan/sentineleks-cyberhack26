"""Semgrep gate: scan AI-generated remediation manifests before anything is applied (plan: M10).

Runs the SEKS custom rules plus the p/kubernetes registry ruleset. Any ERROR finding fails the gate.
The JSON findings are returned verbatim enough for the Slack card, the incident record and the
Canvas post-mortem. Optional upload to Semgrep AppSec Platform happens only when SEMGREP_APP_TOKEN
and a repo URL are configured; upload failure never changes the verdict.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

RULES_DIR = Path(os.environ.get("SEKS_SEMGREP_RULES", Path(__file__).resolve().parents[2] / "rules" / "semgrep"))
REGISTRY_CONFIGS = tuple(c for c in os.environ.get("SEKS_SEMGREP_REGISTRY", "p/kubernetes").split(",") if c)
BLOCKING_SEVERITIES = frozenset({"ERROR"})


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    snippet: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class SemgrepResult:
    passed: bool
    findings: list[Finding] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)
    duration_ms: int = 0
    engine_version: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "findings": [f.to_dict() for f in self.findings],
            "blocking": sum(1 for f in self.findings if f.severity in BLOCKING_SEVERITIES),
            "scanned_files": self.scanned_files,
            "duration_ms": self.duration_ms,
            "engine_version": self.engine_version,
            "error": self.error,
        }


def semgrep_binary() -> str | None:
    return shutil.which(os.environ.get("SEMGREP_BIN", "semgrep"))


def scan_manifests(manifests: list[tuple[str, str]], timeout_seconds: int = 90) -> SemgrepResult:
    if not manifests:
        return SemgrepResult(passed=True)
    binary = semgrep_binary()
    if binary is None:
        return SemgrepResult(passed=False, error="semgrep binary not available in this runtime")

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="seks-gate-") as workdir:
        for name, text in manifests:
            (Path(workdir) / name).write_text(text)
        command = [binary, "scan", "--json", "--metrics=off", "--quiet", "--disable-version-check"]
        command += ["--config", str(RULES_DIR)]
        for config in REGISTRY_CONFIGS:
            command += ["--config", config]
        command.append(workdir)
        env = {k: v for k, v in os.environ.items() if k != "SEMGREP_APP_TOKEN"}
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                command, capture_output=True, text=True, timeout=timeout_seconds, env=env, check=False
            )
        except subprocess.TimeoutExpired:
            return SemgrepResult(passed=False, error=f"semgrep timed out after {timeout_seconds}s")
        duration_ms = int((time.monotonic() - started) * 1000)
        return _parse(completed.stdout, completed.stderr, completed.returncode, workdir, duration_ms)


def _parse(stdout: str, stderr: str, returncode: int, workdir: str, duration_ms: int) -> SemgrepResult:
    try:
        report = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return SemgrepResult(passed=False, duration_ms=duration_ms, error=f"unparseable semgrep output: {stderr[:300]}")

    findings = [
        Finding(
            rule_id=str(r.get("check_id", "")).rsplit(".", 1)[-1],
            severity=str(r.get("extra", {}).get("severity", "INFO")).upper(),
            message=" ".join(str(r.get("extra", {}).get("message", "")).split())[:400],
            file=Path(r.get("path", "")).name,
            line=int(r.get("start", {}).get("line", 0)),
            snippet=str(r.get("extra", {}).get("lines", "")).strip()[:200],
        )
        for r in report.get("results", [])
    ]
    errors = report.get("errors", [])
    fatal = returncode not in {0, 1} or any(str(e.get("level", "")).lower() == "error" for e in errors)
    blocking = any(f.severity in BLOCKING_SEVERITIES for f in findings)
    scanned = [Path(p).name for p in report.get("paths", {}).get("scanned", [])]
    return SemgrepResult(
        passed=not blocking and not fatal,
        findings=findings,
        scanned_files=scanned or [p.name for p in Path(workdir).iterdir()],
        duration_ms=duration_ms,
        engine_version=str(report.get("version", "")),
        error=(f"semgrep errors: {json.dumps(errors)[:300]}" if fatal else None),
    )
