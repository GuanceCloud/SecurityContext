#!/usr/bin/env python3
"""Run the Python v0.2.0 product contract against a live runtime.

This runner deliberately uses the runtime API and the canonical repository
``scripts/securityctl.py`` in one process.  It records the three verification
outcomes and the control/snapshot evidence without claiming that an external
Collector acknowledged an OTel API call.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _wait_for(path: Path, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.05)
    raise TimeoutError(f"runtime did not create {path}")


def _configure_otel() -> tuple[Any, Any, Any, Any]:
    """Install real SDK providers before SecurityContext is created."""

    from opentelemetry import trace
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import (
        InMemoryLogRecordExporter,
        SimpleLogRecordProcessor,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    resource = Resource.create({"service.name": "securitycontext-product-qa"})
    tracer_provider = TracerProvider(resource=resource)
    trace.set_tracer_provider(tracer_provider)

    log_exporter = InMemoryLogRecordExporter()
    logger_provider = LoggerProvider(resource=resource)
    logger_provider.add_log_record_processor(SimpleLogRecordProcessor(log_exporter))
    set_logger_provider(logger_provider)
    return trace.get_tracer("product-qa"), log_exporter, tracer_provider, logger_provider


def _cli(output: Path, *arguments: str, expected: tuple[int, ...] = (0,)) -> dict[str, Any]:
    command = [
        sys.executable,
        str(_repository_root() / "scripts" / "securityctl.py"),
        "--dir",
        str(output),
        *arguments,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    result: Any = None
    if completed.stdout.strip():
        result = json.loads(completed.stdout)
    record = {
        "command": command,
        "returncode": completed.returncode,
        "result": result,
        "stderr": completed.stderr.strip(),
    }
    if completed.returncode not in expected:
        raise RuntimeError(json.dumps(record, ensure_ascii=False, indent=2))
    return record


def _drive_request(runtime: Any, tracer: Any, label: str, risk: bool) -> dict[str, Any]:
    """Create one real request state, source, sink site, and OTel span."""

    import securitycontext.runtime as security_runtime

    with tracer.start_as_current_span(label) as span:
        state = security_runtime.start_request(
            {"route": "/product-contract", "method": "GET", "status_code": 200}
        )
        token = security_runtime.attach_state(state)
        try:
            value = "product-query-" + uuid.uuid4().hex
            security_runtime.source(
                value,
                "http.request.parameter",
                "q",
                location="security_sample.scenario#product_contract",
            )
            marks = state.marks(value) if risk else ()
            event = security_runtime.sink(
                "sql_injection",
                "sqlite3.Connection.execute",
                "query",
                value,
                marks=marks,
                location="security_sample.scenario#product_contract",
            )
        finally:
            security_runtime.detach_state(token)
            security_runtime.end_request(state)
    return {
        "label": label,
        "risk_requested": risk,
        "event_observed": event is not None,
        "span_trace_id": format(span.get_span_context().trace_id, "032x"),
        "span_id": format(span.get_span_context().span_id, "016x"),
    }


def _events(paths: list[Path]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for path in paths:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    result.append(value)
    return result


def run(output: Path) -> dict[str, Any]:
    output = output.absolute()
    output.mkdir(parents=True, exist_ok=True)
    evidence = output / "evidence.jsonl"
    control = output / "control.json"
    os.environ.update(
        {
            "SECURITY_ENABLED": "true",
            "SECURITY_PYTHON_INCLUDE": "security_sample",
            "SECURITY_PYTHON_EXCLUDE": "",
            "SECURITY_OUTPUT": str(output),
            "SECURITY_EVIDENCE_FILE": str(evidence),
            "SECURITY_CONTROL_FILE": str(control),
            "SECURITY_SBOM_OUTPUT": str(output / "application.cdx.json"),
            "SECURITY_SBOM_ENABLED": "true",
            "SECURITY_SBOM_REFRESH_SECONDS": "300",
            "SECURITY_SBOM_CACHE_SECONDS": "0",
            "SECURITY_CODE_REPOSITORY": "securitycontext/product-qa",
            "SECURITY_CODE_COMMIT": "qa-working-tree",
            "SECURITY_CODE_BUILD_ID": "python-v0.2.0-product-qa",
            "OTEL_SERVICE_NAME": "securitycontext-product-qa",
            "OTEL_TRACES_EXPORTER": "none",
            "OTEL_METRICS_EXPORTER": "none",
            "OTEL_LOGS_EXPORTER": "none",
        }
    )

    source_root = _repository_root() / "python" / "src"
    samples_root = _repository_root() / "python" / "samples"
    sys.path.insert(0, str(source_root))
    sys.path.insert(0, str(samples_root))
    import security_sample.scenario  # noqa: F401 - loaded-module SBOM observation
    import securitycontext.runtime as security_runtime

    tracer, log_exporter, tracer_provider, logger_provider = _configure_otel()
    runtime = security_runtime.start(["product-qa"])
    cli_records: list[dict[str, Any]] = []
    requests: list[dict[str, Any]] = []
    checks: dict[str, bool] = {}
    unexecuted = [
        "external OTel Collector receipt: no Collector container was provided or started for this independent QA slice",
        "installed securityctl console script: shared QA container has no installed console entry point",
    ]
    try:
        _wait_for(output / "health.json")
        if runtime.inventory is not None:
            runtime.inventory.refresh()

        cli_records.append(_cli(output, "status"))
        cli_records.append(_cli(output, "pause"))
        paused_health = _read_json(output / "health.json")
        requests.append(_drive_request(runtime, tracer, "paused-request", risk=True))
        cli_records.append(_cli(output, "resume"))
        resumed_health = _read_json(output / "health.json")
        checks["pause_acknowledged"] = paused_health.get("status") == "paused" and not paused_health.get("effective")
        checks["resume_acknowledged"] = resumed_health.get("effective") is True

        cli_records.append(
            _cli(
                output,
                "run-start",
                "--id",
                "baseline",
                "--case",
                "product-sql",
                "--rule",
                "sql_injection",
                "--suite",
                "python-v01-product",
                "--fixture",
                "direct-runtime",
                "--expected-requests",
                "1",
            )
        )
        requests.append(_drive_request(runtime, tracer, "baseline-risk", risk=True))
        cli_records.append(_cli(output, "run-stop", "--output", str(output / "baseline.json")))

        before_dir = output / "compare-before"
        before_dir.mkdir(exist_ok=True)
        shutil.copy2(output / "findings.json", before_dir / "findings.json")

        cli_records.append(
            _cli(
                output,
                "run-start",
                "--id",
                "candidate-observed",
                "--case",
                "product-sql",
                "--rule",
                "sql_injection",
                "--suite",
                "python-v01-product",
                "--fixture",
                "direct-runtime",
                "--expected-requests",
                "1",
            )
        )
        requests.append(_drive_request(runtime, tracer, "candidate-observed", risk=True))
        cli_records.append(_cli(output, "run-stop", "--output", str(output / "candidate-observed.json")))

        cli_records.append(
            _cli(
                output,
                "run-start",
                "--id",
                "candidate-not-observed",
                "--case",
                "product-sql",
                "--rule",
                "sql_injection",
                "--suite",
                "python-v01-product",
                "--fixture",
                "direct-runtime",
                "--expected-requests",
                "1",
            )
        )
        requests.append(_drive_request(runtime, tracer, "candidate-not-observed", risk=False))
        cli_records.append(_cli(output, "run-stop", "--output", str(output / "candidate-not-observed.json")))

        cli_records.append(
            _cli(
                output,
                "run-start",
                "--id",
                "candidate-inconclusive",
                "--case",
                "product-sql",
                "--rule",
                "sql_injection",
                "--suite",
                "python-v01-product",
                "--fixture",
                "direct-runtime",
                "--expected-requests",
                "2",
            )
        )
        requests.append(_drive_request(runtime, tracer, "candidate-inconclusive", risk=False))
        cli_records.append(_cli(output, "run-stop", "--output", str(output / "candidate-inconclusive.json")))

        verify_outcomes: dict[str, str] = {}
        verify_specs = {
            "observed": "candidate-observed.json",
            "not_observed": "candidate-not-observed.json",
            "inconclusive": "candidate-inconclusive.json",
        }
        for label, candidate_name in verify_specs.items():
            record = _cli(
                output,
                "verify",
                "--baseline",
                str(output / "baseline.json"),
                "--candidate",
                str(output / candidate_name),
                "--output",
                str(output / f"verify-{label}.json"),
                expected=(0, 3) if label == "inconclusive" else (0,),
            )
            cli_records.append(record)
            verify_outcomes[label] = str(record["result"]["outcome"])
        checks["three_verify_outcomes"] = set(verify_outcomes.values()) == {
            "observed",
            "not_observed",
            "inconclusive",
        }

        cli_records.append(
            _cli(
                output,
                "compare",
                "--before",
                str(before_dir),
                "--after",
                str(output),
            )
        )
        findings = _read_json(output / "findings.json").get("findings", [])
        finding_id = next(
            (str(item.get("finding_id")) for item in findings if item.get("rule") == "sql_injection"),
            "",
        )
        if not finding_id:
            raise RuntimeError("product run produced no sql_injection finding for exception control")
        cli_records.append(
            _cli(
                output,
                "exception-add",
                "--finding",
                finding_id,
                "--decision",
                "accepted_risk",
                "--reason",
                "QA control-path exercise",
                "--ttl",
                "300",
            )
        )
        cli_records.append(_cli(output, "exception-remove", "--finding", finding_id))
        checks["cli_compare"] = cli_records[-3]["returncode"] == 0
        checks["cli_exception_add_remove"] = cli_records[-2]["returncode"] == 0 and cli_records[-1]["returncode"] == 0

        checks["ledger_aggregation"] = False
        runs = _read_json(output / "runs.json").get("runs", [])
        baseline = next((item for item in runs if item.get("run_id") == "baseline"), {})
        checks["ledger_aggregation"] = all(
            baseline.get(key, 0) == expected
            for key, expected in {
                "status": "closed",
                "requests": 1,
                "source_requests": 1,
                "sink_requests": 1,
            }.items()
        ) and baseline.get("observations", 0) >= 1

        checks["normal_flush"] = runtime.exporter.flush(timeout=5.0)
    finally:
        security_runtime.stop()
        try:
            tracer_provider.shutdown()
        finally:
            logger_provider.shutdown()

    evidence_paths = sorted(output.glob("evidence.jsonl*"))
    all_events = _events(evidence_paths)
    observed = [event for event in all_events if event.get("event_name") == "security.dataflow.observed"]
    sbom = _read_json(output / "application.cdx.json")
    serial = sbom.get("serialNumber")
    refs = {str(item.get("bom-ref")) for item in sbom.get("components", [])}
    metadata_component = sbom.get("metadata", {}).get("component", {})
    if isinstance(metadata_component, dict) and metadata_component.get("bom-ref"):
        refs.add(str(metadata_component["bom-ref"]))
    checks["evidence_jsonl"] = bool(observed) and all(
        isinstance(event.get("component", {}).get("revision"), int)
        and event.get("component", {}).get("sbom_id") == serial
        and (
            event.get("component", {}).get("status") != "resolved"
            or event.get("component", {}).get("bom-ref") in refs
        )
        for event in observed
    )
    log_records = []
    for record in log_exporter.get_finished_logs():
        log_record = getattr(record, "log_record", record)
        try:
            body = json.loads(str(log_record.body))
        except (TypeError, ValueError):
            continue
        if body.get("event_name") == "security.dataflow.observed":
            log_records.append(
                {
                    "event_name": body.get("event_name"),
                    "trace_id": format(log_record.trace_id, "032x") if log_record.trace_id else "",
                    "span_id": format(log_record.span_id, "016x") if log_record.span_id else "",
                }
            )
    checks["otel_api_emit_and_trace_context"] = bool(log_records) and any(
        item["trace_id"] == request["span_trace_id"]
        for item in log_records
        for request in requests
        if request["risk_requested"]
    )

    summary = {
        "schema_version": 2,
        "source": "security_context",
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "output": str(output),
        "checks": checks,
        "passed": all(checks.values()),
        "verify_outcomes": verify_outcomes,
        "requests": requests,
        "cli": cli_records,
        "evidence_count": len(observed),
        "otel_api_records": log_records,
        "sbom": {
            "path": str(output / "application.cdx.json"),
            "serial_number": serial,
            "revision": sbom.get("version"),
            "component_count": len(sbom.get("components", [])),
        },
        "unexecuted": unexecuted,
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        summary = run(args.output)
    except Exception as error:
        print(json.dumps({"passed": False, "error": f"{type(error).__name__}: {error}"}, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
