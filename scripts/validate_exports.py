#!/usr/bin/env python3
"""Run the exporter failure and OTLP Logs acceptance checks in OrbStack.

The script owns only the containers named with its run-specific prefix. It
does not stop unrelated workloads on the OrbStack context.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
VALIDATION = ROOT / "build" / "validation" / "exports"
AGENT = ROOT / "build" / "deps" / "opentelemetry-javaagent-2.31.1.jar"
EXTENSION = ROOT / "security-otel-extension" / "build" / "libs" / "securitycontext.jar"
APP = ROOT / "samples" / "boot2" / "build" / "libs" / "security-validation-boot2.jar"
IMAGE = "eclipse-temurin:17-jre"


def run(command: list[str], *, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=check, text=True, capture_output=capture)


def docker(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return run(["docker", "--context", "orbstack", *args], check=check, capture=capture)


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
        time.sleep(0.5)
    raise RuntimeError(f"timeout waiting for {url}: {last_error}")


def request(url: str) -> str:
    with urllib.request.urlopen(url, timeout=10) as response:
        payload = response.read().decode("utf-8")
        if response.status != 200:
            raise RuntimeError(f"{url}: HTTP {response.status}: {payload[:500]}")
        return payload


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_text(path: pathlib.Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def free_port(excluded: set[int] | None = None) -> int:
    excluded = excluded or set()
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = int(probe.getsockname()[1])
        if port not in excluded:
            return port


def collector_up(project: str) -> None:
    docker(
        "compose", "-p", project, "-f", str(ROOT / "deploy" / "docker-compose.collector.yml"),
        "up", "-d", "otel-collector"
    )
    wait_http("http://127.0.0.1:13133/")


def collector_logs(project: str) -> str:
    result = docker(
        "compose", "-p", project, "-f", str(ROOT / "deploy" / "docker-compose.collector.yml"),
        "logs", "--no-color", "otel-collector", check=False, capture=True
    )
    return result.stdout + result.stderr


def collector_down(project: str) -> None:
    docker(
        "compose", "-p", project, "-f", str(ROOT / "deploy" / "docker-compose.collector.yml"),
        "down", "--remove-orphans", check=False
    )


def launch_app(name: str, port: int, output: pathlib.Path, *, service: str,
               sampler: str | None, otlp: bool, security: bool = True,
               sbom: bool = True, otlp_endpoint: str | None = None) -> float:
    output.mkdir(parents=True, exist_ok=True)
    command = [
        "java",
        f"-javaagent:/opt/otel/opentelemetry-javaagent.jar",
    ]
    if security or sbom:
        command.append("-Dotel.javaagent.extensions=/opt/otel/securitycontext.jar")
    command.extend([
        f"-Dotel.service.name={service}",
        "-Dotel.metrics.exporter=none",
        f"-Dotel.logs.exporter={'otlp' if otlp else 'none'}",
        f"-Dotel.traces.exporter={'otlp' if otlp else 'none'}",
        f"-Dotel.exporter.otlp.endpoint={otlp_endpoint or 'http://host.docker.internal:4318'}",
        "-Dotel.exporter.otlp.protocol=http/protobuf",
        # Keep the validation process alive long enough for the SDK batch
        # processors to deliver both the span and security LogRecords before
        # the container is stopped.
        "-Dotel.bsp.schedule.delay=100",
        "-Dotel.blrp.schedule.delay=100",
        f"-Dsecurity.enabled={'true' if security else 'false'}",
        f"-Dsecurity.sbom.enabled={'true' if sbom else 'false'}",
        "-Dsecurity.evidence.file=/opt/security-output/evidence.jsonl",
        "-Dsecurity.sbom.output=/opt/security-output/application.cdx.json",
        "-jar", "/opt/app/application.jar",
    ])
    if sampler is not None:
        command.insert(2, f"-Dotel.traces.sampler={sampler}")
    started = time.monotonic()
    docker(
        "run", "--detach", "--name", name, "--platform", "linux/arm64",
        "--publish", f"{port}:8080",
        "--volume", f"{APP}:/opt/app/application.jar:ro",
        "--volume", f"{AGENT}:/opt/otel/opentelemetry-javaagent.jar:ro",
        "--volume", f"{EXTENSION}:/opt/otel/securitycontext.jar:ro",
        "--volume", f"{output}:/opt/security-output",
        IMAGE, *command,
    )
    wait_http(f"http://127.0.0.1:{port}/health")
    return time.monotonic() - started


def app_logs(name: str) -> str:
    result = docker("logs", name, check=False, capture=True)
    return result.stdout + result.stderr


def stop_app(name: str) -> None:
    # SIGTERM lets the Java SDK flush its batch processors.  The old forceful
    # removal could kill the process before the 5-second default BSP flush.
    docker("stop", "--time", "15", name, check=False)
    docker("rm", name, check=False)


def resource_blocks(logs: str, kind: str) -> list[str]:
    """Split debug exporter output into ResourceLog/ResourceSpans records."""
    header = re.compile(rf"{kind} #\d+")
    blocks: list[str] = []
    current: list[str] = []
    for line in logs.splitlines():
        if header.search(line):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    return blocks


def resource_has_signal(logs: str, kind: str, service: str, marker: str) -> bool:
    service_marker = f"service.name: Str({service})"
    return any(service_marker in block and marker in block for block in resource_blocks(logs, kind))


def wait_collector_signal(project: str, kind: str, service: str, marker: str, timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    last_logs = ""
    while time.monotonic() < deadline:
        last_logs = collector_logs(project)
        if resource_has_signal(last_logs, kind, service, marker):
            return last_logs
        time.sleep(0.25)
    raise RuntimeError(f"collector did not receive {marker!r} for {service}; last logs had {len(last_logs)} bytes")


def assert_log_and_span_records(logs: str) -> dict[str, object]:
    # Bind the service and marker to one ResourceSpans/ResourceLog block. A
    # whole-output contains check could pair an always-on span with an
    # unrelated always-off log batch and report a false positive.
    always_on = resource_has_signal(logs, "ResourceSpans", "exporter-always-on", "security.detected")
    always_off = resource_has_signal(logs, "ResourceLog", "exporter-always-off", "security.dataflow.observed")
    if not always_on:
        raise AssertionError("collector output did not contain a sampled span summary attribute")
    if not always_off:
        raise AssertionError("collector output did not contain security logs from always_off trace run")
    off_logs = [
        block for block in resource_blocks(logs, "ResourceLog")
        if "service.name: Str(exporter-always-off)" in block
    ]
    return {
        "always_on_span_summary_seen": always_on,
        "always_off_security_log_seen": always_off,
        "security_dataflow_records": sum(block.count("security.dataflow.observed") for block in off_logs),
        "sbom_records": len(re.findall(r"security\.sbom\.(?:snapshot|component)", logs)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-containers", action="store_true")
    args = parser.parse_args()
    VALIDATION.mkdir(parents=True, exist_ok=True)
    for path in (AGENT, EXTENSION, APP):
        if not path.is_file():
            raise SystemExit(f"missing validation artifact: {path}")
    run_id = f"{os.getpid()}-{int(time.time())}"
    collector_project = f"security-exporter-validation-{run_id}"
    on_name = f"security-exporter-on-{run_id}"
    off_name = f"security-exporter-off-{run_id}"
    unavailable_name = f"security-exporter-unavailable-{run_id}"
    summary: dict[str, object] = {
        "environment": {"docker_context": "orbstack", "image": IMAGE, "java": "17"},
        "artifacts": {"application": str(APP), "agent": sha256(AGENT), "extension": sha256(EXTENSION)},
        "checks": {},
    }
    used_ports: set[int] = set()
    ports = {}
    for key in ("always_on", "always_off", "collector_unavailable"):
        ports[key] = free_port(used_ports)
        used_ports.add(ports[key])
    summary["ports"] = ports
    try:
        collector_up(collector_project)
        on_dir = VALIDATION / "always-on"
        off_dir = VALIDATION / "always-off"
        launch_app(on_name, ports["always_on"], on_dir, service="exporter-always-on", sampler="always_on", otlp=True)
        try:
            on_response = request(f"http://127.0.0.1:{ports['always_on']}/api/sql?value=exporter-on-marker")
            write_text(on_dir / "response.json", on_response)
            write_text(on_dir / "application.log", app_logs(on_name))
            wait_collector_signal(collector_project, "ResourceSpans", "exporter-always-on", "security.detected")
        finally:
            stop_app(on_name)
        launch_app(off_name, ports["always_off"], off_dir, service="exporter-always-off", sampler="always_off", otlp=True)
        try:
            off_response = request(f"http://127.0.0.1:{ports['always_off']}/api/sql?value=exporter-off-marker")
            write_text(off_dir / "response.json", off_response)
            write_text(off_dir / "application.log", app_logs(off_name))
            wait_collector_signal(collector_project, "ResourceLog", "exporter-always-off", "security.dataflow.observed")
        finally:
            stop_app(off_name)
        time.sleep(3)
        logs = collector_logs(collector_project)
        write_text(VALIDATION / "collector.log", logs)
        summary["checks"]["otlp"] = assert_log_and_span_records(logs)

        unavailable_dir = VALIDATION / "collector-unavailable"
        launch_app(unavailable_name, ports["collector_unavailable"], unavailable_dir, service="exporter-unavailable",
                   sampler="always_on", otlp=True, otlp_endpoint="http://127.0.0.1:4318")
        try:
            response = request(f"http://127.0.0.1:{ports['collector_unavailable']}/api/sql?value=collector-unavailable-marker")
            write_text(unavailable_dir / "response.json", response)
            write_text(unavailable_dir / "application.log", app_logs(unavailable_name))
            summary["checks"]["collector_unavailable_business_path"] = "HTTP 200"
        finally:
            stop_app(unavailable_name)
    finally:
        if not args.keep_containers:
            stop_app(on_name)
            stop_app(off_name)
            stop_app(unavailable_name)
            collector_down(collector_project)
    write_text(VALIDATION / "summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"export validation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
