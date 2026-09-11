#!/usr/bin/env python3
"""Validate the local Collector file-backed retry queue without an external backend.

The backend is a host-local HTTP receiver. It deliberately returns 503 first, so
the Collector has to enqueue the OTLP payload in file_storage. After a graceful
Collector restart the receiver returns 200 and the script requires the original
marker to be replayed. All containers are created and removed by this script.
"""

from __future__ import annotations

import argparse
import gzip
import http.client
import http.server
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = "otel/opentelemetry-collector-contrib:0.143.0"
CONFIG = ROOT / "deploy" / "otel-collector-persistent.yaml"
DEFAULT_OUTPUT = ROOT / "build" / "validation" / "persistent-collector"
IMAGE_DIGEST = "sha256:3bc07732530c87c53f9103b01a3afed972fdeba26087a590c1098781736e58c2"


def run(args: list[str], *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, capture_output=capture)


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["docker", "--context", "orbstack", *args], check=check)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def varint(value: int) -> bytes:
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def bytes_field(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def varint_field(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def fixed64_field(number: int, value: int) -> bytes:
    return varint((number << 3) | 1) + struct.pack("<Q", value)


def otlp_logs(marker: str) -> bytes:
    # Minimal opentelemetry.proto.collector.logs.v1.ExportLogsServiceRequest:
    # ResourceLogs.scope_logs.log_records.body(string_value), plus a timestamp.
    any_value = bytes_field(1, marker.encode("utf-8"))
    log_record = fixed64_field(1, int(time.time() * 1_000_000_000)) + bytes_field(5, any_value)
    scope_logs = bytes_field(2, log_record)
    resource_logs = bytes_field(2, scope_logs)
    return bytes_field(1, resource_logs)


class Backend(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int]) -> None:
        self.mode = "offline"
        self.records: list[dict[str, object]] = []
        self.recorded = threading.Event()
        super().__init__(address, Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    server: Backend

    def do_POST(self) -> None:  # noqa: N802 - stdlib HTTP handler API
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        decoded = gzip.decompress(body) if self.headers.get("content-encoding") == "gzip" else body
        status = 503 if self.server.mode == "offline" else 200
        self.server.records.append({"path": self.path, "mode": self.server.mode, "status": status,
                                    "bytes": len(body), "decoded_bytes": len(decoded), "body": decoded})
        if status == 200:
            self.server.recorded.set()
        self.send_response(status)
        self.send_header("content-type", "application/x-protobuf")
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


def wait_http(port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"collector receiver port {port} did not open")


def wait_collector_ready(name: str, timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        logs = docker("logs", name, check=False)
        last = logs.stdout + logs.stderr
        if "Everything is ready. Begin running and processing data." in last:
            return last
        time.sleep(0.2)
    raise RuntimeError(f"collector {name} did not become ready; logs:\n{last}")


def post_logs(port: int, payload: bytes) -> int:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/logs",
        data=payload,
        method="POST",
        headers={"content-type": "application/x-protobuf"},
    )
    deadline = time.monotonic() + 20
    while True:
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
                return response.status
        except urllib.error.HTTPError as error:
            error.read()
            return error.code
        except (urllib.error.URLError, http.client.RemoteDisconnected, ConnectionResetError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def wait_backend(backend: Backend, marker: bytes, timeout: float = 30.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for record in backend.records:
            body = record["body"]
            if record["status"] == 200 and marker in body:
                return record
        time.sleep(0.25)
    raise RuntimeError("backend did not receive the queued marker after restart")


def wal_files(path: Path) -> list[str]:
    return sorted(str(item.relative_to(path)) for item in path.rglob("*") if item.is_file())


def collector_command(name: str, receiver_port: int, backend_port: int, wal: Path) -> list[str]:
    return [
        "docker", "--context", "orbstack", "run", "-d", "--name", name,
        "-p", f"127.0.0.1:{receiver_port}:4318",
        "-e", f"SECURITY_BACKEND_OTLP_ENDPOINT=http://host.docker.internal:{backend_port}",
        "-e", "SECURITY_BACKEND_AUTHORIZATION=",
        "-v", f"{CONFIG}:/etc/otelcol/config.yaml:ro",
        "-v", f"{wal}:/var/lib/otelcol/security",
        IMAGE, "--config=/etc/otelcol/config.yaml",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output: Path = args.output.resolve()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    wal = output / "wal"
    wal.mkdir()
    container = f"security-persistent-collector-{os.getpid()}"
    backend_port = free_port()
    receiver_port = free_port()
    marker = f"persistent-replay-{os.getpid()}-{int(time.time())}".encode("ascii")
    backend = Backend(("127.0.0.1", backend_port))
    thread = threading.Thread(target=backend.serve_forever, name="local-collector-backend", daemon=True)
    thread.start()
    first_logs = ""
    second_logs = ""
    first_status = 0
    second_status = 0
    first_command = collector_command(container, receiver_port, backend_port, wal)
    try:
        validation = docker("run", "--rm", "-e", f"SECURITY_BACKEND_OTLP_ENDPOINT=http://host.docker.internal:{backend_port}",
                            "-v", f"{CONFIG}:/etc/otelcol/config.yaml:ro", IMAGE,
                            "validate", "--config=/etc/otelcol/config.yaml")
        (output / "config-validate.log").write_text(validation.stdout + validation.stderr)

        run(first_command)
        wait_http(receiver_port)
        first_logs = wait_collector_ready(container)
        first_status = post_logs(receiver_port, otlp_logs(marker.decode("ascii")))
        if first_status != 200:
            raise RuntimeError(f"collector receiver rejected the OTLP request: HTTP {first_status}")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not wal_files(wal):
            time.sleep(0.25)
        offline_wal = wal_files(wal)
        if not offline_wal:
            raise RuntimeError("offline backend did not leave a file-backed queue entry")
        first_logs = docker("logs", container, check=False).stdout + docker("logs", container, check=False).stderr
        docker("stop", "--time", "20", container)
        docker("rm", container, check=False)

        backend.mode = "online"
        backend.recorded.clear()
        second_command = collector_command(container, receiver_port, backend_port, wal)
        run(second_command)
        wait_http(receiver_port)
        second_logs = wait_collector_ready(container)
        replay = wait_backend(backend, marker)
        second_status = int(replay["status"])
        second_logs = docker("logs", container, check=False).stdout + docker("logs", container, check=False).stderr
        if second_status != 200:
            raise RuntimeError(f"unexpected replay status: {second_status}")

        summary = {
            "image": IMAGE,
            "image_digest": IMAGE_DIGEST,
            "config": str(CONFIG),
            "backend": "127.0.0.1 controlled receiver (no external backend)",
            "marker": marker.decode("ascii"),
            "offline_receiver_status": first_status,
            "offline_wal_files": offline_wal,
            "replay_receiver_status": second_status,
            "replay_bytes": replay["bytes"],
            "backend_request_count": len(backend.records),
            "successful_replay_count": sum(
                1 for record in backend.records
                if record["status"] == 200 and marker in record["body"]
            ),
            "backend_requests": [
                {key: value for key, value in record.items() if key != "body"}
                for record in backend.records
            ],
            "restart": "collector stopped gracefully and restarted with the same WAL directory",
            "limitations": [
                "This verifies graceful stop and restart with the same file-backed WAL; it does not claim crash, SIGKILL, host failure, or power-loss recovery.",
                "The receiver is a controlled local HTTP endpoint; no external backend availability or acknowledgement was tested.",
            ],
        }
        (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        (output / "collector-offline.log").write_text(first_logs)
        (output / "collector-replay.log").write_text(second_logs)
        print(json.dumps(summary, indent=2))
        return 0
    except Exception as error:
        running_logs = docker("logs", container, check=False).stdout + docker("logs", container, check=False).stderr
        (output / "collector-failure.log").write_text(running_logs)
        failure = {
            "error": str(error),
            "offline_receiver_status": first_status,
            "wal_files": wal_files(wal),
            "backend_requests": [{**{key: value for key, value in record.items() if key != "body"},
                                  "body_hex": record["body"].hex()}
                                 for record in backend.records],
        }
        (output / "failure.json").write_text(json.dumps(failure, indent=2) + "\n")
        raise
    finally:
        docker("rm", "-f", container, check=False)
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
