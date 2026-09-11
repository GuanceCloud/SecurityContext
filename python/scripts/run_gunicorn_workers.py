#!/usr/bin/env python3
"""Exercise Gunicorn's worker-specific SecurityContext lifecycle."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(base: str, index: int) -> int:
    query = f"worker-query-{index}"
    url = f"{base}/probe/worker-{index}?q={query}&filename=safe.txt"
    body = json.dumps({"query": query, "filename": "safe.txt"}).encode("utf-8")
    request_object = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Security-Query": f"worker-header-{index}",
        },
    )
    with urllib.request.urlopen(request_object, timeout=5) as response:
        response.read()
        return response.status


def wait_ready(base: str, process: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"gunicorn exited before readiness: code={process.returncode}; log={log_path}")
        try:
            with urllib.request.urlopen(base + "/health", timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise TimeoutError(f"gunicorn did not become ready: log={log_path}")


def read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        value
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
        for value in (json.loads(line),)
        if isinstance(value, dict)
    ]


def run(output: Path, workers: int = 2) -> dict:
    if workers < 2:
        raise ValueError("workers must be at least 2")
    output.mkdir(parents=True, exist_ok=True)
    temp_root = output / "sample-temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    evidence_path = output / "evidence.jsonl"
    control_path = output / "control.json"
    sbom_path = output / "application.cdx.json"
    log_path = output / "gunicorn.log"
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": "/workspace/python/samples",
            "SECURITY_ENABLED": "true",
            "SECURITY_PYTHON_INCLUDE": "security_sample",
            "SECURITY_PYTHON_EXCLUDE": "",
            "SECURITY_OUTPUT": str(output),
            "SECURITY_EVIDENCE_FILE": str(evidence_path),
            "SECURITY_CONTROL_FILE": str(control_path),
            "SECURITY_SBOM_OUTPUT": str(sbom_path),
            "SECURITY_SBOM_ENABLED": "false",
            "SECURITY_SAMPLE_TEMP": str(temp_root),
            "OTEL_SERVICE_NAME": "security-sample-gunicorn-workers",
            "OTEL_TRACES_EXPORTER": "none",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_LOGS_EXPORTER": "none",
            "OTEL_PYTHON_LOG_CORRELATION": "false",
            "DJANGO_SETTINGS_MODULE": "security_sample.django_settings",
        }
    )
    command = [
        "gunicorn",
        "-c",
        "python:securitycontext.gunicorn",
        "--bind",
        f"127.0.0.1:{port}",
        "--workers",
        str(workers),
        "--threads",
        "2",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "security_sample.django_app:wsgi",
    ]
    process: subprocess.Popen[bytes] | None = None
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd="/workspace/python",
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_ready(base, process, log_path)
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers * 2) as pool:
                statuses = list(pool.map(lambda index: request(base, index), range(16)))
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    worker_dirs = sorted(path for path in output.glob("worker-*") if path.is_dir())
    health = []
    worker_events = {}
    for directory in worker_dirs:
        health_path = directory / "health.json"
        evidence = directory / "evidence.jsonl"
        if health_path.exists():
            health.append((directory, json.loads(health_path.read_text(encoding="utf-8"))))
        worker_events[directory.name] = read_events(evidence)

    profiles = {document.get("instrumentation_profile") for _, document in health}
    instances = {
        document.get("identity", {}).get("instance_id")
        for _, document in health
    }
    observed = [
        event
        for events in worker_events.values()
        for event in events
        if event.get("event_name") == "security.dataflow.observed"
    ]
    raw_inputs = (
        "worker-query-",
        "worker-header-",
    )
    encoded = "\n".join(json.dumps(event, sort_keys=True) for event in observed)
    checks = {
        "normal_gunicorn_command": "opentelemetry-instrument" not in command,
        "no_preload_flag": "--preload" not in command,
        "worker_directories": len(worker_dirs) >= workers,
        "worker_health_files": len(health) >= workers,
        "profiles_same": len(profiles) == 1 and None not in profiles,
        "instances_distinct": len(instances) == len(health) and None not in instances,
        "threads_requests_completed": all(
            document.get("counts", {}).get("requests_completed", 0) > 0
            for _, document in health
        ),
        "clean_exit": process is not None and process.returncode == 0,
        "worker_evidence_files": all(
            (directory / "evidence.jsonl").exists() for directory in worker_dirs
        ),
        "observed_evidence": bool(observed),
        "no_raw_inputs": not any(raw in encoded for raw in raw_inputs),
    }
    summary = {
        "schema_version": 2,
        "source": "security_context",
        "command": command,
        "workers_requested": workers,
        "worker_directories": [str(path) for path in worker_dirs],
        "health": [document for _, document in health],
        "worker_event_counts": {
            name: len(events) for name, events in worker_events.items()
        },
        "responses": {"count": len(statuses), "statuses": statuses}
        if process is not None and "statuses" in locals()
        else {"count": 0, "statuses": []},
        "checks": checks,
        "passed": all(checks.values()),
        "log": str(log_path),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args()
    try:
        summary = run(args.output, args.workers)
    except Exception as error:
        print(json.dumps({"passed": False, "error": f"{type(error).__name__}: {error}"}, indent=2))
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
