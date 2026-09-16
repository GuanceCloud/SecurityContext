#!/usr/bin/env python3
"""Run a small, repeatable three-mode cost comparison in OrbStack.

The result is a local comparison of one fixed Spring Boot workload.  It is
intentionally bounded and does not make a production performance claim.
Only containers created by this process are stopped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


JAVA_ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = JAVA_ROOT / "build" / "validation" / "benchmark"
AGENT = JAVA_ROOT / "build" / "deps" / "opentelemetry-javaagent-2.31.1.jar"
BUILT_EXTENSION = JAVA_ROOT / "security-otel-extension" / "build" / "libs" / "securitycontext.jar"
EXTENSION = pathlib.Path(os.environ.get("SECURITY_BENCHMARK_EXTENSION", str(BUILT_EXTENSION)))
APP = JAVA_ROOT / "samples" / "boot2" / "build" / "libs" / "security-validation-boot2.jar"
IMAGE = "eclipse-temurin:17-jre"


def run(command: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, text=True, capture_output=capture)


def docker(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return run(["docker", "--context", "orbstack", *args], check=check, capture=capture)


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def free_port(excluded: set[int] | None = None) -> int:
    excluded = excluded or set()
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port not in excluded:
            return port


def wait_http(url: str, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except (OSError, urllib.error.URLError) as error:
            last_error = str(error)
        time.sleep(0.25)
    raise RuntimeError(f"timeout waiting for {url}: {last_error}")


def wait_tcp(port: int, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                return
        except OSError as error:
            last_error = str(error)
        time.sleep(0.25)
    raise RuntimeError(f"timeout waiting for TCP port {port}: {last_error}")


def request(url: str) -> tuple[int, float, bytes]:
    started = time.perf_counter()
    with urllib.request.urlopen(url, timeout=10) as response:
        payload = response.read()
        elapsed = time.perf_counter() - started
        if response.status != 200:
            raise RuntimeError(f"{url}: HTTP {response.status}: {payload[:500]!r}")
        return response.status, elapsed, payload


def read_rss_kib(name: str) -> int | None:
    result = docker(
        "exec", name, "sh", "-c", "awk '/^VmRSS:/ {print $2; exit}' /proc/1/status",
        check=False, capture=True,
    )
    try:
        return int(result.stdout.strip())
    except (TypeError, ValueError):
        return None


def app_logs(name: str) -> str:
    result = docker("logs", name, check=False, capture=True)
    return result.stdout + result.stderr


def wait_log(name: str, marker: str, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    last_logs = ""
    while time.monotonic() < deadline:
        last_logs = app_logs(name)
        if marker in last_logs:
            return
        time.sleep(0.25)
    raise RuntimeError(f"timeout waiting for {marker!r} in {name}; logs: {last_logs[-2000:]}")


def stop_app(name: str) -> None:
    docker("stop", "--timeout", "15", name, check=False)
    docker("rm", name, check=False)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) * fraction) + 0.999999) - 1))
    return ordered[index]


def launch_app(name: str, port: int, output: pathlib.Path, mode: str) -> tuple[float, list[str], list[str]]:
    output.mkdir(parents=True, exist_ok=True)
    security = mode == "all"
    sbom = mode != "otel-only"
    command = [
        "java",
        "-javaagent:/opt/otel/opentelemetry-javaagent.jar",
        "-Dotel.traces.sampler=always_off",
        f"-Dotel.service.name=benchmark-{mode}",
        "-Dotel.metrics.exporter=none",
        "-Dotel.logs.exporter=none",
        "-Dotel.traces.exporter=none",
        f"-Dsecurity.enabled={'true' if security else 'false'}",
        f"-Dsecurity.sbom.enabled={'true' if sbom else 'false'}",
    ]
    volumes = [
        f"{APP}:/opt/app/application.jar:ro",
        f"{AGENT}:/opt/otel/opentelemetry-javaagent.jar:ro",
    ]
    if sbom:
        command.extend([
            "-Dotel.javaagent.extensions=/opt/otel/securitycontext.jar",
            "-Dsecurity.output=/opt/security-output",
            "-Dsecurity.evidence.file=/opt/security-output/evidence.jsonl",
            "-Dsecurity.sbom.output=/opt/security-output/application.cdx.json",
        ])
        volumes.extend([
            f"{EXTENSION}:/opt/otel/securitycontext.jar:ro",
            f"{output}:/opt/security-output",
        ])
    command.extend(["-jar", "/opt/app/application.jar"])
    started = time.monotonic()
    docker_args = [
        "run", "--detach", "--name", name, "--platform", "linux/arm64",
        "--publish", f"{port}:8080",
        *sum((["--volume", value] for value in volumes), []),
        IMAGE, *command,
    ]
    docker(*docker_args)
    # The health endpoint can respond while Spring is still completing
    # CommandLineRunner initialization. Wait for the application-start marker
    # before issuing DB-backed requests.
    wait_log(name, "Started ValidationApplication")
    wait_log(name, "HikariPool-1 - Start completed.")
    # DemoData creates the H2 table from a CommandLineRunner after the lazy
    # pool initialization; keep the readiness probe out of the request count.
    time.sleep(0.25)
    # Use a TCP probe here: an HTTP readiness request would be counted by the
    # security instrumentation and skew the requested 1100-request workload.
    wait_tcp(port)
    return time.monotonic() - started, command, ["docker", "--context", "orbstack", *docker_args]


def run_mode(run_dir: pathlib.Path, run_id: str, mode: str, port: int, warmup: int, samples: int) -> dict[str, object]:
    name = f"security-benchmark-{mode}-{run_id}"
    output = run_dir / mode
    url = "http://127.0.0.1:" + str(port) + "/api/sql?" + urllib.parse.urlencode({"value": "benchmark-marker"})
    started_at = time.time()
    startup_seconds = None
    command: list[str] = []
    docker_command: list[str] = []
    latencies: list[float] = []
    statuses: list[int] = []
    errors: list[str] = []
    result: dict[str, object] = {
        "mode": mode,
        "container": name,
        "port": port,
        "workload": {"method": "GET", "url": url, "warmup_requests": warmup, "measured_requests": samples},
    }
    try:
        startup_seconds, command, docker_command = launch_app(name, port, output, mode)
        for _ in range(warmup):
            status, _, _ = request(url)
            statuses.append(status)
        rss_before = read_rss_kib(name)
        measurement_started = time.perf_counter()
        for _ in range(samples):
            status, elapsed, _ = request(url)
            statuses.append(status)
            latencies.append(elapsed)
        measurement_seconds = time.perf_counter() - measurement_started
        rss_after = read_rss_kib(name)
        if len(latencies) != samples or any(status != 200 for status in statuses):
            raise RuntimeError(f"unexpected workload responses: {statuses[-5:]}")
        result.update({
            "startup_seconds": startup_seconds,
            "samples": len(latencies),
            "measurement_seconds": measurement_seconds,
            "throughput_requests_per_second": len(latencies) / measurement_seconds,
            "latency_ms": {
                "min": min(latencies) * 1000,
                "p50": percentile(latencies, 0.50) * 1000,
                "p95": percentile(latencies, 0.95) * 1000,
                "max": max(latencies) * 1000,
            },
            "rss_kib_after_warmup": rss_before,
            "rss_kib_after_workload": rss_after,
            "status_codes": {"200": statuses.count(200)},
        })
    except Exception as error:
        errors.append(f"{type(error).__name__}: {error}")
        result["errors"] = errors
        log_path = output / "application.log"
        log_path.write_text(app_logs(name), encoding="utf-8")
        result["application_log"] = str(log_path)
    finally:
        result["command"] = docker_command
        result["output_directory"] = str(output)
        result["observed_at_unix"] = started_at
        stop_app(name)
    if errors:
        raise RuntimeError(f"{mode} benchmark failed: {errors[0]}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--samples", type=int, default=1000)
    args = parser.parse_args()
    if args.warmup < 0 or args.samples < 5:
        raise SystemExit("--warmup must be >= 0 and --samples must be >= 5")
    for path in (AGENT, EXTENSION, APP):
        if not path.is_file():
            raise SystemExit(f"missing benchmark artifact: {path}")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    run_id = f"{os.getpid()}-{int(time.time())}"
    run_dir = OUTPUT / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    used_ports: set[int] = set()
    result: dict[str, object] = {
        "scope": "small local comparison; not a production performance claim",
        "run_id": run_id,
        "environment": {
            "docker_context": "orbstack",
            "image": IMAGE,
            "java": "17",
            "host_platform": platform.platform(),
            "warmup_requests": args.warmup,
            "measured_requests_per_mode": args.samples,
        },
        "artifacts": {
            "application": str(APP),
            "application_sha256": sha256(APP),
            "agent": str(AGENT),
            "agent_sha256": sha256(AGENT),
            "extension": str(EXTENSION),
            "extension_sha256": sha256(EXTENSION),
        },
        "modes": [],
    }
    try:
        for mode in ("otel-only", "otel-sbom", "all"):
            port = free_port(used_ports)
            used_ports.add(port)
            print(f"running {mode} on port {port}", flush=True)
            result["modes"].append(run_mode(run_dir, run_id, mode, port, args.warmup, args.samples))
    except Exception:
        (run_dir / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise
    output = run_dir / "summary.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUTPUT / "summary.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
