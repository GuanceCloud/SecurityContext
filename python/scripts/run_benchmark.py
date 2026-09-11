#!/usr/bin/env python3
"""Run the serial FastAPI baseline/OTel/security benchmark.

The benchmark is intentionally a small, repeatable QA measurement rather
than a capacity claim.  It runs one mode at a time in a shared OrbStack
container and records the workload, exact mode order, and process metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import venv
from concurrent.futures import ThreadPoolExecutor

import psutil
import requests


MODES = ("baseline", "otel", "security")
ROOT = Path(__file__).resolve().parents[1]
CONSTRAINTS = ROOT / "constraints-python-v0.1.0-arm64.txt"
FIXTURE = ROOT / "samples" / "security_sample" / "benchmark_app.py"
MODE_ORDERS = (
    ("baseline", "otel", "security"),
    ("otel", "security", "baseline"),
    ("security", "baseline", "otel"),
    ("baseline", "security", "otel"),
    ("otel", "baseline", "security"),
)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wait_ready(base: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 20.0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"benchmark server exited before readiness: {process.returncode}")
        try:
            request = urllib.request.Request(
                base + "/bench?query=benchmark-warmup", method="GET"
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.05)
    raise TimeoutError(f"benchmark server was not ready: {last_error!r}")


def installed_python(wheel: Path, output: Path) -> tuple[Path, tempfile.TemporaryDirectory[str]]:
    temporary = tempfile.TemporaryDirectory(prefix="securitycontext-benchmark-", dir=output)
    virtualenv = Path(temporary.name) / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False, clear=False).create(virtualenv)
    interpreter = virtualenv / "bin" / "python"
    subprocess.run(
        [str(interpreter), "-m", "pip", "install", "-r", str(CONSTRAINTS)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    subprocess.run(
        [str(interpreter), "-m", "pip", "install", "--no-deps", "--force-reinstall", str(wheel)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    location = subprocess.run(
        [str(interpreter), "-c", "import securitycontext; print(securitycontext.__file__)"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if str(virtualenv) not in location:
        temporary.cleanup()
        raise RuntimeError(f"benchmark package is not loaded from installed wheel: {location}")
    return interpreter, temporary


def mode_command(mode: str, interpreter: Path, port: int) -> list[str]:
    application = [
        str(interpreter),
        "-m",
        "uvicorn",
        "security_sample.benchmark_app:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--workers",
        "1",
        "--log-level",
        "warning",
    ]
    if mode == "baseline":
        return application
    # Invoke the same installed interpreter for OTel auto-instrumentation;
    # relying on a system opentelemetry-instrument script would bypass the
    # wheel under test.
    auto_instrument = "from opentelemetry.instrumentation.auto_instrumentation import run; run()"
    return [str(interpreter), "-c", auto_instrument, *application]


def mode_environment(mode: str, security_output: Path) -> dict[str, str]:
    environment = os.environ.copy()
    security_output = security_output.resolve()
    environment.update(
        {
            "PYTHONPATH": "/workspace/python/samples",
            "SECURITY_ENABLED": "true" if mode == "security" else "false",
            "SECURITY_PYTHON_INCLUDE": "security_sample" if mode == "security" else "",
            "SECURITY_PYTHON_EXCLUDE": "",
            "SECURITY_OUTPUT": str(security_output),
            "SECURITY_EVIDENCE_FILE": str(security_output / "evidence.jsonl"),
            "SECURITY_SBOM_ENABLED": "false",
            "OTEL_TRACES_EXPORTER": "none",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_LOGS_EXPORTER": "none",
            "OTEL_TRACES_SAMPLER": "always_on",
            "OTEL_PYTHON_LOG_CORRELATION": "false",
        }
    )
    key = "OTEL_PYTHON_DISABLED_INSTRUMENTATIONS"
    disabled = [
        item.strip()
        for item in environment.get(key, "").split(",")
        if item.strip()
    ]
    if mode != "security" and "securitycontext" not in disabled:
        disabled.append("securitycontext")
    if mode == "security":
        disabled = [item for item in disabled if item != "securitycontext"]
    if disabled:
        environment[key] = ",".join(disabled)
    else:
        environment.pop(key, None)
    return environment


def read_json(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def health_progress(path: Path) -> dict[str, int]:
    document = read_json(path)
    if document is None:
        return {}
    counts = document.get("counts")
    if not isinstance(counts, dict):
        counts = {}
    try:
        completed = int(counts.get("requests_completed", 0))
    except (TypeError, ValueError):
        completed = 0
    return {str(path): completed}


def wait_for_drain(
    path: Path,
    expected_completed: int,
    baseline: dict[str, int],
    timeout: float = 5.0,
) -> dict:
    deadline = time.monotonic() + timeout
    last_completed = 0
    last_active = 0
    while time.monotonic() < deadline:
        document = read_json(path)
        if document is not None:
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
            last_completed = max(0, completed - baseline.get(str(path), 0))
            last_active = max(0, active)
            if last_completed >= expected_completed and last_active == 0:
                return {
                    "passed": True,
                    "expected_completed": expected_completed,
                    "completed_delta": last_completed,
                    "active_requests": last_active,
                    "timeout_seconds": timeout,
                    "health_path": str(path),
                }
        time.sleep(0.05)
    return {
        "passed": False,
        "expected_completed": expected_completed,
        "completed_delta": last_completed,
        "active_requests": last_active,
        "timeout_seconds": timeout,
        "health_path": str(path),
        "failure": "health_drain_timeout",
    }


def validate_health(health: dict | None) -> dict:
    if health is None:
        return {"applicable": True, "passed": False, "failures": ["health_missing"]}
    counts = health.get("counts") if isinstance(health.get("counts"), dict) else {}
    failures: list[str] = []
    if health.get("status") != "observed":
        failures.append(f"status:{health.get('status')}")
    if health.get("effective") is not True:
        failures.append("collection_not_effective")
    if health.get("active_requests") != 0:
        failures.append("active_requests_not_zero")
    if counts.get("requests_with_sources", 0) <= 0:
        failures.append("no_sources")
    if counts.get("requests_with_sinks", 0) <= 0:
        failures.append("no_sinks")
    for key in (
        "requests_budget_skipped",
        "requests_incomplete",
        "delivery_loss",
        "delivery_failure",
        "finding_capacity_dropped",
        "request_completion_errors",
    ):
        value = health.get(key, counts.get(key, 0))
        if isinstance(value, (int, float)) and value:
            failures.append(f"{key}:{value}")
    return {
        "applicable": True,
        "passed": not failures,
        "failures": failures,
        "status": health.get("status"),
        "active_requests": health.get("active_requests"),
        "source_requests": counts.get("requests_with_sources", 0),
        "sink_requests": counts.get("requests_with_sinks", 0),
        "counts": counts,
    }


def dependency_versions(interpreter: Path) -> dict[str, str | None]:
    names = (
        "securitycontext",
        "opentelemetry-api",
        "opentelemetry-sdk",
        "opentelemetry-instrumentation",
        "fastapi",
        "starlette",
        "uvicorn",
        "pydantic",
        "psutil",
        "requests",
    )
    # PackageNotFoundError is deliberately handled inside the probe so an
    # optional system dependency is reported as null instead of hiding the
    # benchmark result.
    code = (
        "import importlib.metadata as m, json; "
        f"names={names!r}; "
        "out={}; "
        "\nfor name in names:\n"
        "    try: out[name] = m.version(name)\n"
        "    except m.PackageNotFoundError: out[name] = None\n"
        "print(json.dumps(out, sort_keys=True))"
    )
    result = subprocess.run(
        [str(interpreter), "-c", code],
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(result.stdout)
    return value if isinstance(value, dict) else {}


class ProcessMonitor:
    def __init__(self, process: subprocess.Popen[bytes]):
        self.process = process
        self.peak_rss = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="benchmark-process-monitor")

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        process = psutil.Process(self.process.pid)
        while not self._stop.is_set():
            try:
                self.peak_rss = max(self.peak_rss, process.memory_info().rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return
            self._stop.wait(0.01)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def request_batch(base: str, count: int, concurrency: int) -> tuple[float, list[float]]:
    local = threading.local()

    def request_once(_: int) -> float:
        session = getattr(local, "session", None)
        if session is None:
            session = requests.Session()
            session.trust_env = False
            local.session = session
        started = time.perf_counter()
        response = session.get(
            base + "/bench",
            params={"query": "benchmark-query"},
            timeout=10,
        )
        elapsed = time.perf_counter() - started
        if response.status_code != 200 or response.json() != {"ok": True, "matched": 0}:
            raise RuntimeError(f"unexpected benchmark response: {response.status_code} {response.text}")
        return elapsed

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies = list(executor.map(request_once, range(count)))
    return time.perf_counter() - started, latencies


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction)))
    return ordered[index]


def run_mode(
    mode: str,
    interpreter: Path,
    output: Path,
    round_number: int,
    warmup_requests: int,
    measured_requests: int,
    concurrency: int,
) -> dict:
    mode_output = output / mode / f"round-{round_number}"
    mode_output.mkdir(parents=True, exist_ok=True)
    port = free_port()
    security_output = mode_output / "security-output"
    environment = mode_environment(mode, security_output)
    log_path = mode_output / "server.log"
    command = mode_command(mode, interpreter, port)
    process_started = time.perf_counter()
    health_path = security_output / "health.json"
    health_baseline = health_progress(health_path)
    drain_barrier = {
        "passed": False,
        "expected_completed": warmup_requests + measured_requests,
        "completed_delta": 0,
        "active_requests": 0,
        "failure": "not_reached",
        "health_path": str(health_path),
    }
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command,
            cwd="/workspace/python",
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        monitor = ProcessMonitor(process)
        monitor.start()
        try:
            wait_ready(f"http://127.0.0.1:{port}", process)
            startup_seconds = time.perf_counter() - process_started
            warmup_started = time.perf_counter()
            warmup_elapsed, _ = request_batch(
                f"http://127.0.0.1:{port}", warmup_requests, concurrency
            )
            warmup_seconds = time.perf_counter() - warmup_started
            cpu_before = psutil.Process(process.pid).cpu_times()
            measured_seconds, latencies = request_batch(
                f"http://127.0.0.1:{port}", measured_requests, concurrency
            )
            cpu_after = psutil.Process(process.pid).cpu_times()
            cpu_seconds = (cpu_after.user + cpu_after.system) - (
                cpu_before.user + cpu_before.system
            )
            if mode == "security":
                drain_barrier = wait_for_drain(
                    health_path,
                    warmup_requests + measured_requests,
                    health_baseline,
                )
        finally:
            process.send_signal(signal.SIGTERM)
            clean_shutdown = True
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                clean_shutdown = False
                process.kill()
                process.wait(timeout=5)
            monitor.stop()
    evidence_path = security_output / "evidence.jsonl"
    health = read_json(health_path) if mode == "security" else None
    health_validation = (
        validate_health(health)
        if mode == "security"
        else {"applicable": False, "passed": True, "failures": []}
    )
    if mode == "security" and not drain_barrier["passed"]:
        health_validation["failures"].append("health_drain_timeout")
        health_validation["passed"] = False
    try:
        evidence_events = sum(1 for _ in evidence_path.open("r", encoding="utf-8"))
    except OSError:
        evidence_events = 0
    return {
        "mode": mode,
        "round": round_number,
        "command": command,
        "route": "/bench",
        "query": "benchmark-query",
        "workers": 1,
        "concurrency": concurrency,
        "warmup_requests": warmup_requests,
        "warmup_seconds": warmup_seconds,
        "measured_requests": measured_requests,
        "measurement_seconds": measured_seconds,
        "startup_seconds": startup_seconds,
        "rps": measured_requests / measured_seconds,
        "p95_latency_ms": percentile(latencies, 0.95) * 1000,
        "cpu_seconds": cpu_seconds,
        "cpu_percent_one_core": (cpu_seconds / measured_seconds * 100.0),
        "rss_peak_bytes": monitor.peak_rss,
        "clean_shutdown": clean_shutdown,
        "log": str(log_path),
        "security_output": str(security_output),
        "health_path": str(health_path) if mode == "security" else None,
        "evidence_path": str(evidence_path) if mode == "security" else None,
        "evidence_events": evidence_events,
        "health": health,
        "health_validation": health_validation,
        "health_drain_barrier": drain_barrier,
        "export_mode": "OTel traces/logs/metrics none; security local evidence only"
        if mode == "security"
        else "OTel traces/logs/metrics none; security disabled",
        "sampling": "always_on",
    }


def run(args: argparse.Namespace) -> dict:
    output = args.output.absolute()
    output.mkdir(parents=True, exist_ok=True)
    wheel = args.wheel.absolute()
    interpreter, temporary = installed_python(wheel, output)
    try:
        fixture_sha = sha256(FIXTURE)
        constraints_sha = sha256(CONSTRAINTS) if CONSTRAINTS.is_file() else None
        constraints = (
            [
                line.strip()
                for line in CONSTRAINTS.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            if CONSTRAINTS.is_file()
            else []
        )
        batch_started = time.perf_counter()
        rounds = []
        for round_number, order in enumerate(MODE_ORDERS[: args.rounds], start=1):
            for mode in order:
                rounds.append(
                    run_mode(
                        mode,
                        interpreter,
                        output,
                        round_number,
                        args.warmup_requests,
                        args.requests,
                        args.concurrency,
                    )
                )
        batch_duration_seconds = time.perf_counter() - batch_started
        summary = {}
        for mode in MODES:
            values = [item for item in rounds if item["mode"] == mode]
            summary[mode] = {
                "rounds": len(values),
                "startup_seconds_median": statistics.median(item["startup_seconds"] for item in values),
                "rps_median": statistics.median(item["rps"] for item in values),
                "p95_latency_ms_median": statistics.median(item["p95_latency_ms"] for item in values),
                "cpu_seconds_median": statistics.median(item["cpu_seconds"] for item in values),
                "cpu_percent_one_core_median": statistics.median(
                    item["cpu_percent_one_core"] for item in values
                ),
                "rss_peak_bytes_max": max(item["rss_peak_bytes"] for item in values),
                "all_clean_shutdown": all(item["clean_shutdown"] for item in values),
                "all_health_valid": all(item["health_validation"]["passed"] for item in values),
            }
        valid = all(item["clean_shutdown"] for item in rounds) and all(
            item["health_validation"]["passed"] for item in rounds
        )
        report = {
            "schema_version": 2,
            "source": "security_context",
            "suite": "python-benchmark-fastapi",
            "status": "measured_not_sla" if valid else "invalid_health_or_shutdown",
            "valid": valid,
            "host_note": "Shared OrbStack Linux/aarch64 host; other workloads may be present; no SLA claim.",
            "runtime": {
                "python": sys.version.split()[0],
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
                "architecture": platform.machine(),
            },
            "wheel": {"path": str(wheel), "sha256": sha256(wheel)},
            "fixture": {"path": str(FIXTURE), "sha256": fixture_sha},
            "constraints": {
                "path": str(CONSTRAINTS),
                "sha256": constraints_sha,
                "pins": constraints,
            },
            "dependencies": dependency_versions(interpreter),
            "workload": {
                "route": "/bench",
                "method": "GET",
                "body": None,
                "query": "benchmark-query",
                "response": {"ok": True, "matched": 0},
                "operation": "string propagation into parameterized in-memory SQLite query",
                "requests_per_round_per_mode": args.requests,
                "concurrency": args.concurrency,
                "warmup_requests": args.warmup_requests,
                "rounds": args.rounds,
                "mode_order": [list(order) for order in MODE_ORDERS[: args.rounds]],
            },
            "batch": {
                "mode_runs": len(rounds),
                "duration_seconds": batch_duration_seconds,
                "includes": "warmup, measured requests, drain barriers, and clean shutdown for every mode run",
                "excludes": "temporary venv creation and wheel installation",
            },
            "modes": summary,
            "rounds": rounds,
        }
        (output / "benchmark-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return report
    finally:
        temporary.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=5, choices=range(1, 6))
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--warmup-requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=16)
    args = parser.parse_args()
    try:
        report = run(args)
    except Exception as error:
        print(json.dumps({"passed": False, "error": f"{type(error).__name__}: {error}"}, indent=2))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("valid") else 1


if __name__ == "__main__":
    raise SystemExit(main())
