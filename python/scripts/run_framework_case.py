#!/usr/bin/env python3
"""Run one real framework fixture under ``opentelemetry-instrument``.

The script is intentionally stdlib-only so it can execute in each isolated
Python container. It writes a JSON summary next to the evidence stream and
returns non-zero when an observed behavior check fails.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


FRAMEWORKS = {"fastapi", "flask", "django"}
EXPECTED_HTTP_REQUESTS = 6


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(base: str, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
    data = body
    request_object = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers=headers or {},
    )
    try:
        with urllib.request.urlopen(request_object, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_ready(base: str, process: subprocess.Popen[bytes], log_path: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited before readiness: code={process.returncode}; log={log_path}")
        try:
            status, _ = request(base, "GET", "/health")
            if status == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    raise TimeoutError(f"server did not become ready: log={log_path}")


def server_command(framework: str, port: int, interpreter: Path | None = None) -> list[str]:
    if interpreter is not None:
        python = str(interpreter)
        auto_instrument = "from opentelemetry.instrumentation.auto_instrumentation import run; run()"
        prefix = [python, "-c", auto_instrument, python, "-m"]
        if framework == "fastapi":
            return prefix + [
                "uvicorn",
                "security_sample.fastapi_app:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ]
        if framework == "flask":
            return prefix + [
                "flask",
                "--app",
                "security_sample.flask_app",
                "run",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--no-reload",
            ]
        # The package's Gunicorn post-fork configuration initializes OTel in
        # each worker; wrapping the master with auto-instrumentation would
        # violate that fork boundary.
        return [
            python,
            "-m",
            "gunicorn",
            "-c",
            "python:securitycontext.gunicorn",
            "--bind",
            f"127.0.0.1:{port}",
            "--workers",
            "1",
            "--threads",
            "4",
            "--access-logfile",
            "-",
            "security_sample.django_app:wsgi",
        ]
    prefix = ["opentelemetry-instrument"]
    if framework == "fastapi":
        return prefix + [
            sys.executable,
            "-m",
            "uvicorn",
            "security_sample.fastapi_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ]
    if framework == "flask":
        return prefix + [
            "flask",
            "--app",
            "security_sample.flask_app",
            "run",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-reload",
        ]
    # Gunicorn owns the fork boundary.  Its post_fork hook moves configured
    # output paths into worker-specific directories before OTel initializes;
    # wrapping the master in opentelemetry-instrument would initialize the
    # wrong process and can preload application state.
    return [
        "gunicorn",
        "-c",
        "python:securitycontext.gunicorn",
        "--bind",
        f"127.0.0.1:{port}",
        "--workers",
        "1",
        "--threads",
        "4",
        "--access-logfile",
        "-",
        "security_sample.django_app:wsgi",
    ]


def parse_json(payload: bytes) -> dict:
    value = json.loads(payload.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("fixture response is not a JSON object")
    return value


def read_events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            result.append(value)
    return result


def health_documents(output: Path) -> list[tuple[Path, dict]]:
    paths = sorted(output.glob("worker-*/health.json"))
    direct = output / "health.json"
    if direct.exists():
        paths.append(direct)
    documents: list[tuple[Path, dict]] = []
    for path in paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            documents.append((path, value))
    return documents


def health_progress(output: Path) -> dict[str, int]:
    progress: dict[str, int] = {}
    for path, document in health_documents(output):
        counts = document.get("counts")
        if not isinstance(counts, dict):
            counts = {}
        try:
            progress[str(path)] = int(counts.get("requests_completed", 0))
        except (TypeError, ValueError):
            progress[str(path)] = 0
    return progress


def wait_for_drain(
    output: Path,
    expected_completed: int,
    baseline: dict[str, int],
    timeout: float = 5.0,
) -> dict:
    deadline = time.monotonic() + timeout
    last_completed = 0
    last_active = 0
    last_paths: list[str] = []
    while time.monotonic() < deadline:
        documents = health_documents(output)
        completed_delta = 0
        active_requests = 0
        paths: list[str] = []
        for path, document in documents:
            path_key = str(path)
            paths.append(path_key)
            counts = document.get("counts")
            if not isinstance(counts, dict):
                counts = {}
            try:
                completed = int(counts.get("requests_completed", 0))
            except (TypeError, ValueError):
                completed = 0
            try:
                active = int(document.get("active_requests", 0))
            except (TypeError, ValueError):
                active = 0
            completed_delta += max(0, completed - baseline.get(path_key, 0))
            active_requests += max(0, active)
        last_completed = completed_delta
        last_active = active_requests
        last_paths = paths
        if completed_delta >= expected_completed and active_requests == 0:
            return {
                "passed": True,
                "expected_completed": expected_completed,
                "completed_delta": completed_delta,
                "active_requests": active_requests,
                "timeout_seconds": timeout,
                "health_paths": paths,
            }
        time.sleep(0.05)
    return {
        "passed": False,
        "expected_completed": expected_completed,
        "completed_delta": last_completed,
        "active_requests": last_active,
        "timeout_seconds": timeout,
        "health_paths": last_paths,
        "failure": "health_drain_timeout",
    }


def run(framework: str, output: Path, interpreter: Path | None = None) -> dict:
    if framework not in FRAMEWORKS:
        raise ValueError(f"unsupported framework: {framework}")
    output = output.resolve()
    if interpreter is not None:
        # Make relative installed-venv paths usable from the server cwd while
        # retaining the venv shim instead of resolving its interpreter link.
        interpreter = interpreter.absolute()
    output.mkdir(parents=True, exist_ok=True)
    temp_root = output / "sample-temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    evidence_path = output / "evidence.jsonl"
    log_path = output / "server.log"
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": "/workspace/python/samples",
            "SECURITY_ENABLED": "true",
            "SECURITY_PYTHON_INCLUDE": "security_sample",
            "SECURITY_PYTHON_EXCLUDE": "",
            "SECURITY_OUTPUT": str(output),
            "SECURITY_EVIDENCE_FILE": str(evidence_path),
            "SECURITY_CONTROL_FILE": str(output / "control.json"),
            "SECURITY_SBOM_OUTPUT": str(output / "application.cdx.json"),
            "SECURITY_SBOM_ENABLED": "false",
            "SECURITY_SAMPLE_TEMP": str(temp_root),
            "SECURITY_SAMPLE_PORT": str(port),
            "OTEL_SERVICE_NAME": f"security-sample-{framework}",
            "OTEL_TRACES_EXPORTER": "none",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_LOGS_EXPORTER": "none",
            "OTEL_PYTHON_LOG_CORRELATION": "false",
        }
    )
    if framework == "django":
        environment["DJANGO_SETTINGS_MODULE"] = "security_sample.django_settings"
    command = server_command(framework, port, interpreter)
    checks: dict[str, bool] = {}
    responses: dict[str, int] = {}
    process: subprocess.Popen[bytes] | None = None
    graceful_shutdown = {
        "timeout_seconds": 40.0 if framework == "django" else 10.0,
        "elapsed_seconds": None,
        "force_kill": False,
        "returncode": None,
    }
    drain_barrier = {
        "passed": False,
        "expected_completed": EXPECTED_HTTP_REQUESTS,
        "completed_delta": 0,
        "active_requests": 0,
        "failure": "not_reached",
    }
    health_baseline = health_progress(output)
    with log_path.open("wb") as log:
        process = subprocess.Popen(command, cwd="/workspace/python", env=environment, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_ready(base, process, log_path)

            status, payload = request(base, "GET", "/source-only/path-item?q=source-only")
            responses["source_only"] = status
            checks["source_only_ok"] = status == 200

            query = urllib.parse.urlencode(
                {"q": "integration-query", "filename": "safe.txt", "callback": base + "/target"}
            )
            status, payload = request(
                base,
                "POST",
                "/probe/path-item?" + query,
                body=json.dumps({"query": "body-query", "filename": "safe.txt"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-Security-Query": "header-query"},
            )
            responses["probe"] = status
            probe = parse_json(payload)
            checks["probe_ok"] = status == 200
            checks["eval_once"] = probe.get("eval_count") == 1 and probe.get("eval_order") == ["once"]
            checks["eval_order"] = probe.get("order") == ["left", "right"]
            checks["result_types"] = all(
                probe.get(key) == "str"
                for key in (
                    "formatted_type",
                    "represented_type",
                    "concat_type",
                    "percent_type",
                    "format_type",
                    "join_type",
                    "slice_type",
                )
            )
            checks["parameterized_negative"] = probe.get("sql", {}).get("parameterized_rows") == 0
            source_attempts = probe.get("sql", {}).get("source_attempts", {})
            checks["source_sql_attempts"] = all(
                source_attempts.get(name) in {"OperationalError", "executed"}
                for name in ("path", "header", "raw_body", "body_query")
            )
            checks["command_completed"] = probe.get("command", {}).get("constant_returncode") == 0

            status, payload = request(
                base,
                "POST",
                "/probe/body-item",
                body=json.dumps({"query": "body-only-query", "filename": "safe.txt"}).encode("utf-8"),
                headers={"Content-Type": "application/json", "X-Security-Query": "header-body"},
            )
            responses["body_probe"] = status
            checks["body_probe_ok"] = status == 200

            form_value = "form-query"
            status, payload = request(
                base,
                "POST",
                "/form",
                body=urllib.parse.urlencode({"query": form_value}).encode("ascii"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            responses["form"] = status
            form_result = parse_json(payload)
            checks["form_ok"] = status == 200 and form_result.get("value_type") == "str"
            checks["form_parameterized_negative"] = form_result.get("parameterized_rows") == 0
            checks["form_sql_attempt"] = form_result.get("unsafe_status") in {"OperationalError", "executed"}

            text_value = "text-body-query"
            status, payload = request(
                base,
                "POST",
                "/text",
                body=text_value.encode("ascii"),
                headers={"Content-Type": "text/plain"},
            )
            responses["text"] = status
            text_result = parse_json(payload)
            checks["text_body_ok"] = status == 200 and text_result.get("value_type") == "str"
            checks["text_parameterized_negative"] = text_result.get("parameterized_rows") == 0
            checks["text_sql_attempt"] = text_result.get("unsafe_status") in {"OperationalError", "executed"}

            status, payload = request(
                base,
                "POST",
                "/stream/stream-item",
                body=json.dumps({"query": "stream-query"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            responses["stream"] = status
            checks["stream_closed"] = status == 200 and b"chunk-" in payload and payload.endswith(b"\n")
            drain_barrier = wait_for_drain(
                output,
                EXPECTED_HTTP_REQUESTS,
                health_baseline,
            )
        finally:
            shutdown_started = time.monotonic()
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=graceful_shutdown["timeout_seconds"])
                except subprocess.TimeoutExpired:
                    graceful_shutdown["force_kill"] = True
                    process.kill()
                    process.wait(timeout=5)
            graceful_shutdown["elapsed_seconds"] = time.monotonic() - shutdown_started
            graceful_shutdown["returncode"] = process.returncode

    evidence_paths = sorted(output.glob("worker-*/evidence.jsonl"))
    if not evidence_paths:
        evidence_paths = [evidence_path]
    events = [event for path in evidence_paths for event in read_events(path)]
    observed = [event for event in events if event.get("event_name") == "security.dataflow.observed"]
    source_types = {source.get("type") for event in observed for source in event.get("sources", [])}
    source_names = {
        (source.get("type"), source.get("name"))
        for event in observed
        for source in event.get("sources", [])
    }
    rules = {event.get("rule") for event in observed}
    encoded = "\n".join(
        path.read_text(encoding="utf-8") for path in evidence_paths if path.exists()
    )
    checks["evidence_present"] = bool(observed)
    checks["source_parameter"] = "http.request.parameter" in source_types
    checks["source_path"] = "http.request.path" in source_types
    checks["source_header"] = "http.request.header" in source_types
    checks["source_body"] = "http.request.body" in source_types
    form_sql_events = [
        event
        for event in observed
        if "scenario#form_sql_case" in event.get("sink", {}).get("location", "")
    ]
    checks["form_dataflow_source"] = any(
        source.get("type") == "http.request.body" and source.get("name") == "body.query"
        for event in form_sql_events
        for source in event.get("sources", [])
    )
    checks["text_dataflow_source"] = any(
        source.get("type") == "http.request.body" and source.get("name") == "body"
        for event in form_sql_events
        for source in event.get("sources", [])
    )
    parameterized_events = [
        event
        for event in observed
        if event.get("sink", {}).get("function") == "sqlite3.Connection.execute"
        and "_parameterized_sql_exercise" in event.get("sink", {}).get("location", "")
    ]
    checks["parameterized_negative"] = (
        probe.get("sql", {}).get("parameterized_rows") == 0
        and not parameterized_events
    )
    checks["sql_positive"] = "sql_injection" in rules
    checks["command_positive"] = bool({"command_execution", "command_injection"} & rules)
    checks["http_positive"] = bool({"ssrf", "http_request_input"} & rules)
    checks["unique_evidence_ids"] = len({event.get("evidence_id") for event in observed}) == len(observed)
    checks["no_raw_input_in_evidence"] = all(
        raw not in encoded
        for raw in (
            "integration-query",
            "body-query",
            "body-only-query",
            "stream-query",
            "header-query",
            "form-query",
            "text-body-query",
        )
    )
    checks["exit_status"] = process is not None and process.returncode in (0, -signal.SIGTERM)
    checks["health_drain"] = drain_barrier["passed"]
    summary = {
        "schema_version": 2,
        "source": "security_context",
        "framework": framework,
        "python": sys.version.split()[0],
        "architecture": os.uname().machine,
        "command": command,
        "responses": responses,
        "checks": checks,
        "passed": all(checks.values()),
        "evidence_count": len(observed),
        "rules": sorted(str(rule) for rule in rules if rule),
        "source_types": sorted(str(kind) for kind in source_types if kind),
        "source_names": sorted(
            f"{kind}|{name}" for kind, name in source_names if kind and name
        ),
        "evidence_file": str(evidence_path),
        "evidence_files": [str(path) for path in evidence_paths if path.exists()],
        "server_log": str(log_path),
        "health_drain_barrier": drain_barrier,
        "graceful_shutdown": graceful_shutdown,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", choices=sorted(FRAMEWORKS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--python",
        type=Path,
        default=None,
        help="Use this installed interpreter; auto-instrument FastAPI/Flask and use package Gunicorn config for Django.",
    )
    args = parser.parse_args()
    try:
        summary = run(args.framework, args.output, args.python)
    except Exception as error:
        args.output.mkdir(parents=True, exist_ok=True)
        summary = {
            "schema_version": 2,
            "source": "security_context",
            "framework": args.framework,
            "python": sys.version.split()[0],
            "architecture": os.uname().machine,
            "passed": False,
            "error": f"{type(error).__name__}: {error}",
            "server_log": str(args.output / "server.log"),
        }
        (args.output / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(summary, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
