#!/usr/bin/env python3
"""Prove the Uvicorn shutdown hook flushes a completed request before SIGTERM."""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(base: str, method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
    request_object = urllib.request.Request(base + path, data=body, method=method)
    try:
        with urllib.request.urlopen(request_object, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_ready(base: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited before readiness: {process.returncode}")
        try:
            status, _ = request(base, "GET", "/health")
            if status == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.05)
    raise TimeoutError("server did not become ready")


def read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def wait_for_file(path: Path, timeout: float = 2.0) -> dict | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = read_json(path)
        if value is not None:
            return value
        time.sleep(0.05)
    return read_json(path)


def run(args: argparse.Namespace) -> dict:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Keep the venv shim path intact; Path.resolve() follows it to the system
    # interpreter and would bypass the wheel installed in that venv.
    interpreter = args.python.absolute()
    probe_environment = os.environ.copy()
    probe_environment["PYTHONPATH"] = ""
    package_location = subprocess.run(
        [str(interpreter), "-c", "import securitycontext; print(securitycontext.__file__)"],
        check=True,
        capture_output=True,
        text=True,
        env=probe_environment,
    ).stdout.strip()
    if "site-packages" not in package_location:
        raise RuntimeError(f"shutdown case is not using an installed wheel: {package_location}")

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    evidence = output / "evidence.jsonl"
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": "/workspace/python/samples",
            "SECURITY_ENABLED": "true",
            "SECURITY_PYTHON_INCLUDE": "security_sample",
            "SECURITY_PYTHON_EXCLUDE": "",
            "SECURITY_OUTPUT": str(output),
            "SECURITY_EVIDENCE_FILE": str(evidence),
            "SECURITY_CONTROL_FILE": str(output / "control.json"),
            "SECURITY_SBOM_ENABLED": "false",
            "OTEL_TRACES_EXPORTER": "none",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_LOGS_EXPORTER": "none",
            "OTEL_TRACES_SAMPLER": "always_on",
            "OTEL_PYTHON_LOG_CORRELATION": "false",
            "DJANGO_SETTINGS_MODULE": "security_sample.django_settings",
        }
    )
    auto_instrument = "from opentelemetry.instrumentation.auto_instrumentation import run; run()"
    command = [
        str(interpreter),
        "-c",
        auto_instrument,
        str(interpreter),
        "-m",
        "uvicorn",
        "security_sample.django_asgi:application",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--log-level",
        "warning",
    ]
    log_path = output / "server.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd="/workspace/python",
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_ready(base, process)
            query = urllib.parse.urlencode(
                {
                    "q": "shutdown-query",
                    "filename": "safe.txt",
                    "callback": base + "/target",
                }
            )
            status, body = request(
                base,
                "POST",
                "/probe/path-item?" + query,
                body=b"{}",
            )
            response = {"status": status, "json": json.loads(body.decode("utf-8"))}
            if status != 200:
                raise RuntimeError(f"probe failed: {response}")
            # Deliberately do not poll health here.  The only flush proof is
            # the hook run during Uvicorn's SIGTERM shutdown path.
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    health_path = output / "health.json"
    findings_path = output / "findings.json"
    health = wait_for_file(health_path)
    findings = wait_for_file(findings_path)
    evidence_lines = []
    if evidence.exists():
        evidence_lines = [
            json.loads(line)
            for line in evidence.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    finding_items = findings.get("findings", []) if isinstance(findings, dict) else []
    health_identity = (health or {}).get("identity", {}).get("instance_id")
    finding_identity = (findings or {}).get("identity", {}).get("instance_id")
    evidence_identities = {
        item.get("instance_id")
        for item in evidence_lines
        if isinstance(item, dict) and item.get("instance_id")
    }
    counts = (health or {}).get("counts", {})
    checks = {
        "installed_wheel": "site-packages" in package_location,
        "query_http_200": response["status"] == 200,
        "health_present": isinstance(health, dict),
        "health_active_zero": isinstance(health, dict) and health.get("active_requests") == 0,
        "health_requests_completed": isinstance(counts, dict) and counts.get("requests_completed", 0) > 0,
        "health_source_and_sink": isinstance(counts, dict)
        and counts.get("requests_with_sources", 0) > 0
        and counts.get("requests_with_sinks", 0) > 0,
        "findings_present": bool(finding_items),
        "evidence_present": bool(evidence_lines),
        "health_finding_identity": bool(health_identity and health_identity == finding_identity),
        "health_evidence_identity": bool(health_identity and health_identity in evidence_identities),
        "no_pre_sigterm_drain_barrier": True,
    }
    summary = {
        "schema_version": 2,
        "source": "security_context",
        "passed": all(checks.values()),
        "checks": checks,
        "command": command,
        "returncode": process.returncode,
        "package_location": package_location,
        "response": response,
        "health_path": str(health_path),
        "findings_path": str(findings_path),
        "evidence_path": str(evidence),
        "server_log": str(log_path),
        "health": health,
        "finding_count": len(finding_items),
        "evidence_count": len(evidence_lines),
        "health_identity": health_identity,
        "finding_identity": finding_identity,
        "evidence_identities": sorted(identity for identity in evidence_identities if identity),
    }
    (output / "shutdown-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        summary = run(args)
    except Exception as error:
        print(json.dumps({"passed": False, "error": f"{type(error).__name__}: {error}"}, indent=2))
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
